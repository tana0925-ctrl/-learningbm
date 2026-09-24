# -*- coding: utf-8 -*-
"""
patch_plan_loop_v1.py — 計画の輪を閉じる
2026-09-25  PLAN_LOOP_V1

いま切れているのは「先生から子どもへ戻る矢印」。
  ・先生が返したコメントは、その週が「今週」のあいだしか読めない（過去の週では
    通知枠ごと隠され、そもそも取りにも行かない）。週が変わると二度と読めない。
  ・先生が計画に一言書く欄が、どこにも無い（AIの下書き経由でしか書けない）
  ・子どもが書いたことにも、先生が返したことにも、気づく印が無い

直すのは4つ。画面は増やさない。
  1. 過去の週でも先生のコメントが読めるようにする（表示だけ。編集は今までどおり不可）
     ⚠ 受け取りボタンは今週のぶんだけ出す。過去の週は文章だけ。
        受け取りの記録がブラウザにしか無いので、もらい直せてしまうのを避けるため。
  2. 月曜に開いたとき、先週ぶんのおへんじも一緒に読めるようにする
     （先生が金曜に返したものを、月曜の計画づくりで読む、という流れにする）
  3. 先生の計画カードに「計画へひとこと」の入力欄を1本足す
     （既存の /api/teacher/plan-ai-comments をそのまま使う。新しいAPIは作らない）
  4. 気づく印 … 折りたたみの見出しに「◯/◯人が提出・未返信◯人」を出す／
     子ども側の赤い「返却あり！」バッジに、計画アドバイスと振り返り返却を含める

読み取りは増やさない：
  ・weekly-plan-status は同じ表を3回引いていたので1回にまとめた（3→1）
  ・先週ぶんを足しても 2クエリ。いままでの3クエリより少ない。
  ・weekly-plans は SELECT に1列足すだけ（クエリ数は同じ）
"""
import io
import sys

TSX = 'src/index.tsx'
HTML = 'public/index.html'


def apply_tsx(s):
    # ---- 1) weekly-plan-status: 同じ表を3回引いていたのを1回に。複数週もまとめて返す ----
    old = """  const weekKey = c.req.query('weekKey') || getWeekKey()
  const row = await c.env.DB.prepare(`
    SELECT plan_approved as planApproved, plan_reward_coins as planRewardCoins,
           reflection_comment as reflectionComment, reflection_returned_at as reflectionReturnedAt,
           reflection_reward_coins as reflectionRewardCoins
    FROM student_weekly_plans WHERE user_id=? AND week_key=?
  `).bind(u.id, weekKey).first<any>()
  let planAiComment: any = null
  try { const _pc = await c.env.DB.prepare('SELECT plan_ai_comment as planAiComment FROM student_weekly_plans WHERE user_id=? AND week_key=?').bind(u.id, weekKey).first<any>(); if (_pc) planAiComment = _pc.planAiComment || null } catch {}
  let planSuggestion: any = null
  try { const _ps = await c.env.DB.prepare('SELECT plan_suggestion as planSuggestion FROM student_weekly_plans WHERE user_id=? AND week_key=?').bind(u.id, weekKey).first<any>(); if (_ps) planSuggestion = _ps.planSuggestion || null } catch {}
  const status2 = row ? { ...row, planAiComment, planSuggestion } : ((planAiComment || planSuggestion) ? { planAiComment, planSuggestion } : null)
  return c.json({ ok: true, status: status2 })"""
    new = """  // 📌 2026-09-25 PLAN_LOOP_V1:
  //   もとは同じ表を3回引いていた（row / plan_ai_comment / plan_suggestion）。1回にまとめる。
  //   さらに ?weekKeys=A,B で複数週をまとめて取れるようにした（月曜に先週ぶんも読むため）。
  //   ぜんぶ1クエリなので、先週ぶんを足しても読み取りは前より減る。
  const weekKey = c.req.query('weekKey') || getWeekKey()
  const rawKeys = String(c.req.query('weekKeys') || '').split(',').map((x) => x.trim()).filter(Boolean).slice(0, 2)
  const keys = rawKeys.length ? rawKeys : [weekKey]
  const ph = keys.map(() => '?').join(',')
  let rows: any = { results: [] }
  try {
    rows = await c.env.DB.prepare(
      `SELECT week_key as weekKey, plan_approved as planApproved, plan_reward_coins as planRewardCoins,
              reflection_comment as reflectionComment, reflection_returned_at as reflectionReturnedAt,
              reflection_reward_coins as reflectionRewardCoins,
              plan_ai_comment as planAiComment, plan_suggestion as planSuggestion
       FROM student_weekly_plans WHERE user_id=? AND week_key IN (${ph})`
    ).bind(u.id, ...keys).all<any>()
  } catch (e) {}
  const byWeek: Record<string, any> = {}
  for (const r of (((rows && rows.results) || []) as any[])) byWeek[String(r.weekKey)] = r
  const status2 = byWeek[keys[0]] || null
  return c.json({ ok: true, status: status2, statuses: byWeek })"""
    assert s.count(old) == 1, 'T1: %d' % s.count(old)
    s = s.replace(old, new)

    # ---- 2) 先生の一覧に plan_ai_comment を1列足す（クエリは増やさない） ----
    old = """           swp.reflection_comment as reflectionComment, swp.reflection_returned_at as reflectionReturnedAt,
           swp.revision_count as revisionCount,
           u.id as userId, u.login_id as loginId, u.name as studentName, u.grade, u.class_name as className
    FROM student_weekly_plans swp"""
    new = """           swp.reflection_comment as reflectionComment, swp.reflection_returned_at as reflectionReturnedAt,
           swp.revision_count as revisionCount,
           swp.plan_ai_comment as planAiComment,
           u.id as userId, u.login_id as loginId, u.name as studentName, u.grade, u.class_name as className
    FROM student_weekly_plans swp"""
    assert s.count(old) == 1, 'T2: %d' % s.count(old)
    s = s.replace(old, new)

    # ---- 3) 計画カードに「計画へひとこと」の欄を足す（振り返り返却欄のとなり） ----
    old = """            // 金曜の振り返り
            const friKey = keys[4] || '';"""
    new = """            // 📌 2026-09-25 PLAN_LOOP_V1: 計画に一言返す欄。いままで手で返す場所が無く、
            //   分析タブでAIの下書きを作るしか手段が無かった（先生が「返していない」のではなく
            //   返す欄が無かった）。保存は既存の /api/teacher/plan-ai-comments をそのまま使う。
            if(p.planAiComment && String(p.planAiComment).trim()){
              html += '<div class="text-xs mt-1 p-1.5 bg-violet-50 rounded border border-violet-200">'
                + '<span class="font-bold text-violet-700">📋 計画へのひとこと：</span>'+escH(p.planAiComment)
                + ' <button class="ml-1 text-[10px] underline text-violet-600" onclick="planCommentEdit(\\''+escH(p.userId)+'\\',this)">直す</button>'
                + '</div>';
            }
            html += '<div class="flex items-center gap-1 mt-1'+((p.planAiComment && String(p.planAiComment).trim())?' hidden':'')+'" id="planCmtBox_'+escH(p.userId)+'">'
              + '<textarea id="planCmt_'+escH(p.userId)+'" class="flex-1 border rounded p-1.5 text-xs" rows="1" placeholder="計画へひとこと（子どもの画面に出ます）"></textarea>'
              + '<button class="bg-violet-600 text-white rounded px-2 py-1 text-[11px] font-bold hover:opacity-90 shrink-0" onclick="savePlanComment(\\''+escH(p.userId)+'\\',this)">返す</button>'
              + '</div>';

            // 金曜の振り返り
            const friKey = keys[4] || '';"""
    assert s.count(old) == 1, 'T3: %d' % s.count(old)
    s = s.replace(old, new)

    # ---- 4) 保存関数と、折りたたみ見出しの件数バッジ ----
    old = """      async function loadStudentPlans(){"""
    new = """      // 📌 2026-09-25 PLAN_LOOP_V1: 計画への一言を返す（既存APIをそのまま使う）
      async function savePlanComment(userId, btn){
        var ta = document.getElementById('planCmt_'+userId);
        if(!ta) return;
        var txt = String(ta.value||'').trim();
        if(!txt){ alert('ひとことを書いてください'); return; }
        btn.disabled = true;
        try{
          await api('/api/teacher/plan-ai-comments', {method:'POST', headers:{'content-type':'application/json'},
            body: JSON.stringify({ weekKey: getWeekKeyLocal(), comments: [{ studentId: userId, comment: txt }] })});
          await loadStudentPlans();
        }catch(e){ btn.disabled = false; alert('エラー: '+String(e.message||e)); }
      }
      function planCommentEdit(userId, btn){
        var box = document.getElementById('planCmtBox_'+userId);
        if(box) box.classList.remove('hidden');
        if(btn) btn.style.display = 'none';
      }

      async function loadStudentPlans(){"""
    assert s.count(old) == 1, 'T4: %d' % s.count(old)
    s = s.replace(old, new)

    # 折りたたみ見出しに件数を出す場所（span を用意）
    old = '<summary class="cursor-pointer font-bold text-sm text-blue-800 select-none">📝 生徒の今週の計画</summary>'
    new = '<summary class="cursor-pointer font-bold text-sm text-blue-800 select-none">📝 生徒の今週の計画 <span id="hwPlanCount" class="ml-1 text-[11px] font-normal text-slate-500"></span></summary>'
    assert s.count(old) == 1, 'T5: %d' % s.count(old)
    s = s.replace(old, new)

    # ---- 6) 折りたたみ見出しに「◯/◯人が提出・未返信◯人」を出す ----
    #   閉じていると、20人が書いていても見た目が変わらず、先生が気づけなかった。
    #   すでに取ってあるデータを数えるだけなので、クエリは1本も増えない。
    old = """          // 一括パネル表示
          const bulkPanel = document.getElementById('bulkRefPanel');"""
    new = """          // 📌 2026-09-25 PLAN_LOOP_V1: 見出しに件数を出す（取ってあるデータを数えるだけ）
          try{
            var _cnt = document.getElementById('hwPlanCount');
            if(_cnt){
              var _wrote = 0, _noReply = 0;
              plans.forEach(function(q){
                var _o = {}; try{ _o = JSON.parse(q.plansJson||'{}'); }catch(_e){}
                var _has = false;
                Object.keys(_o).forEach(function(k){
                  if(k === '_modified') return;
                  var v = _o[k];
                  var tx = (v && typeof v === 'object') ? (v.free || '') : (v || '');
                  if(String(tx).trim()) _has = true;
                });
                if(_has) _wrote++;
                if(_has && !(q.planAiComment && String(q.planAiComment).trim())) _noReply++;
              });
              _cnt.textContent = '（' + _wrote + '人が提出' + (_noReply ? ' / 未返信 ' + _noReply + '人' : '') + '）';
            }
          }catch(_e){}
          // 一括パネル表示
          const bulkPanel = document.getElementById('bulkRefPanel');"""
    assert s.count(old) == 1, 'T6: %d' % s.count(old)
    s = s.replace(old, new)

    return s


def apply_html(s):
    # ---- 5) 子ども側：過去の週でも読める＋先週ぶんも一緒に読める ----
    old = """    if(isPastWeek){
      const notice = document.getElementById('hwRewardNotice');
      if(notice){ notice.classList.add('hidden'); notice.innerHTML = ''; }
      const sugBoxP = document.getElementById('hwPlanSuggestBox');
      if(sugBoxP){ sugBoxP.classList.add('hidden'); sugBoxP.innerHTML = ''; }
    }
    if(!isPastWeek) try{
      const statusRes = await fetch('/api/student/weekly-plan-status?weekKey='+encodeURIComponent(weekKey)).then(r=>r.json()).catch(()=>null);
      const st = statusRes && statusRes.status;"""
    new = """    // 📌 2026-09-25 PLAN_LOOP_V1:
    //   前は「過去の週では通知枠を隠し、そもそも取りにも行かない」作りだった。
    //   そのため先生が返したコメントは、その週が今週のあいだしか読めず、
    //   週が変わると二度と読めなかった（先生が返す意味が消えていた）。
    //   ここを直して、過去の週でも文章は読めるようにする。
    //   ⚠ 受け取りボタンだけは今週のぶんに限る。受け取りの記録がブラウザにしか無く、
    //     過去の週にボタンを出すと、もらい直せてしまうため。
    try{
      // 今週を見ているときは、先週ぶんも一緒にもらう（月曜に先生のおへんじを読んでから計画を書く流れ）
      var _wkPrev = (typeof hsPrevWeekKey === 'function') ? hsPrevWeekKey(weekKey) : null;
      var _qs = (!isPastWeek && _wkPrev) ? ('weekKeys='+encodeURIComponent(weekKey+','+_wkPrev))
                                         : ('weekKey='+encodeURIComponent(weekKey));
      const statusRes = await fetch('/api/student/weekly-plan-status?'+_qs).then(r=>r.json()).catch(()=>null);
      const st = statusRes && statusRes.status;
      const stPrev = (statusRes && statusRes.statuses && _wkPrev) ? statusRes.statuses[_wkPrev] : null;"""
    assert s.count(old) == 1, 'H1: %d' % s.count(old)
    s = s.replace(old, new)

    # 受け取りボタンは今週だけ。過去の週は文章だけ。さらに先週ぶんのおへんじを出す。
    old = """        // 計画承認報酬
        if(st.planApproved && !localStorage.getItem('hwPlanReward_'+weekKey)){"""
    new = """        // 計画承認報酬（⚠ 受け取りは今週のぶんだけ。過去の週は上の文章だけ出す）
        if(!isPastWeek && st.planApproved && !localStorage.getItem('hwPlanReward_'+weekKey)){"""
    assert s.count(old) == 1, 'H2: %d' % s.count(old)
    s = s.replace(old, new)

    old = """        // 振り返り返却報酬
        if(st.reflectionReturnedAt && !localStorage.getItem('hwRefReward_'+weekKey)){"""
    new = """        // 振り返り返却報酬（⚠ 受け取りは今週のぶんだけ）
        if(!isPastWeek && st.reflectionReturnedAt && !localStorage.getItem('hwRefReward_'+weekKey)){"""
    assert s.count(old) == 1, 'H3: %d' % s.count(old)
    s = s.replace(old, new)

    # 先週ぶんの「おへんじ」を、いちばん上に出す
    old = """        if(html){ notice.innerHTML = html; notice.classList.remove('hidden'); }
        else { notice.classList.add('hidden'); notice.innerHTML = ''; }"""
    new = """        // 📌 2026-09-25: 先週ぶんの「先生からのおへんじ」を、いちばん上に出す。
        //   金曜に返してもらったものを、月曜に計画を書くときに読めるようにするため。
        if(stPrev && (stPrev.planAiComment || stPrev.reflectionComment)){
          var _ph = '<div class="bg-sky-50 border-2 border-sky-300 rounded-xl p-3 space-y-1">'
            + '<div class="font-bold text-sky-800 text-sm">💬 先生からのおへんじ <span class="text-[10px] font-normal text-sky-600">（先週ぶん）</span></div>';
          if(stPrev.planAiComment)    _ph += '<div class="text-xs text-slate-700 whitespace-pre-wrap"><b>📋 計画に…</b> '+escapeHtml(stPrev.planAiComment)+'</div>';
          if(stPrev.reflectionComment)_ph += '<div class="text-xs text-slate-700 whitespace-pre-wrap"><b>🔄 ふりかえりに…</b> '+escapeHtml(stPrev.reflectionComment)+'</div>';
          _ph += '<div class="text-[10px] text-sky-600">読んでから、今週の計画を書いてみよう。</div></div>';
          html = _ph + html;
        }
        if(html){ notice.innerHTML = html; notice.classList.remove('hidden'); }
        else { notice.classList.add('hidden'); notice.innerHTML = ''; }"""
    assert s.count(old) == 1, 'H4: %d' % s.count(old)
    s = s.replace(old, new)

    # 前の週のキーを出すヘルパー（無ければ作る）
    old = """function hsGetWeekKey(dayKey){"""
    new = """// 📌 2026-09-25 PLAN_LOOP_V1: 前の週のキー（2026-W38 -> 2026-W37）
function hsPrevWeekKey(wk){
  var m = String(wk||'').match(/^(\\d{4})-W(\\d{2})$/);
  if(!m) return null;
  var y = parseInt(m[1],10), w = parseInt(m[2],10);
  w--; if(w < 1){ y--; w = 52; }
  return y + '-W' + String(w).padStart(2,'0');
}

function hsGetWeekKey(dayKey){"""
    assert s.count(old) == 1, 'H5: %d' % s.count(old)
    s = s.replace(old, new)

    # ---- 6) 赤い「返却あり！」バッジに、計画アドバイスと振り返り返却も含める ----
    old = """    const badge = document.getElementById('hsReturnBadge');
    if (badge) badge.style.display = pending.length > 0 ? '' : 'none';
    const navBadge = document.getElementById('hsNavBadge');
    if (navBadge) navBadge.style.display = pending.length > 0 ? '' : 'none';"""
    new = """    // 📌 2026-09-25 PLAN_LOOP_V1: いままでバッジは「毎日の家庭学習の返却」だけを見ていた。
    //   計画アドバイスと振り返りの返却は、どこにも印が出ず、子どもが気づけなかった。
    //   今週と先週のぶんを1クエリで見て、未読があればバッジを出す。
    var _extra = 0;
    try{
      var _wk = (typeof hsGetWeekKey === 'function' && typeof hsGetDayKey830 === 'function')
        ? hsGetWeekKey(hsGetDayKey830(new Date())) : null;
      var _pv = (_wk && typeof hsPrevWeekKey === 'function') ? hsPrevWeekKey(_wk) : null;
      if(_wk){
        var _q = _pv ? ('weekKeys='+encodeURIComponent(_wk+','+_pv)) : ('weekKey='+encodeURIComponent(_wk));
        var _sr = await fetch('/api/student/weekly-plan-status?'+_q).then(function(x){return x.json();}).catch(function(){return null;});
        var _map = (_sr && _sr.statuses) || {};
        Object.keys(_map).forEach(function(k){
          var v = _map[k]; if(!v) return;
          if(v.planAiComment && !localStorage.getItem('hwSeenPlanCmt_'+k)) _extra++;
          if(v.reflectionComment && !localStorage.getItem('hwSeenRefCmt_'+k)) _extra++;
        });
      }
    }catch(_e){}
    var _show = (pending.length + _extra) > 0;
    const badge = document.getElementById('hsReturnBadge');
    if (badge) badge.style.display = _show ? '' : 'none';
    const navBadge = document.getElementById('hsNavBadge');
    if (navBadge) navBadge.style.display = _show ? '' : 'none';"""
    assert s.count(old) == 1, 'H6: %d' % s.count(old)
    s = s.replace(old, new)

    # ---- 7) おへんじを画面に出したら「読んだ」印を付ける（付けないとバッジが消えない） ----
    old = """        if(html){ notice.innerHTML = html; notice.classList.remove('hidden'); }
        else { notice.classList.add('hidden'); notice.innerHTML = ''; }"""
    new = """        // 📌 2026-09-25: 画面に出したものは「読んだ」印を付ける。
        //   付けないと赤いバッジが永久に消えない。
        try{
          if(st && st.planAiComment)     localStorage.setItem('hwSeenPlanCmt_'+weekKey, '1');
          if(st && st.reflectionComment) localStorage.setItem('hwSeenRefCmt_'+weekKey, '1');
          if(_wkPrev && stPrev){
            if(stPrev.planAiComment)     localStorage.setItem('hwSeenPlanCmt_'+_wkPrev, '1');
            if(stPrev.reflectionComment) localStorage.setItem('hwSeenRefCmt_'+_wkPrev, '1');
          }
        }catch(_e){}
        if(html){ notice.innerHTML = html; notice.classList.remove('hidden'); }
        else { notice.classList.add('hidden'); notice.innerHTML = ''; }"""
    assert s.count(old) == 1, 'H7: %d' % s.count(old)
    s = s.replace(old, new)

    return s


def main():
    a = io.open(TSX, encoding='utf-8').read()
    b = apply_tsx(a)
    h1 = io.open(HTML, encoding='utf-8').read()
    h2 = apply_html(h1)
    if b == a or h2 == h1:
        print('NO CHANGE'); sys.exit(1)
    io.open(TSX, 'w', encoding='utf-8').write(b)
    io.open(HTML, 'w', encoding='utf-8').write(h2)
    print('src/index.tsx     %d -> %d' % (len(a), len(b)))
    print('public/index.html %d -> %d' % (len(h1), len(h2)))


if __name__ == '__main__':
    main()

