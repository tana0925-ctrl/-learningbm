#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_hw_old_return.py --- 家庭学習：古い提出を返せるようにする

  症状: 先生「家庭学習のコメント入れてかえすやつ、昔の（7月ぶん）はできてない」

  原因は2つ。どちらも返却APIが弾いているのではない。
    ① GET /api/teacher/homework が固定で LIMIT 100。日付ではなく「件数」で切っている。
       44人が毎日出すと約2登校日ぶん。2学期が始まって7月ぶんが押し出された。
       （この LIMIT 100 は 2026-07-20 時点のコードにも存在。我々が入れたものではない）
    ② 返却済みカードには、コメント欄も返却ボタンも描画していない。
       一度返すと UI から二度と触れない。

  この修正でやること
    H1 サーバ: /api/teacher/homework に ?unreturned=1 / ?from= / ?to= / ?month= を追加
    H2 画面  : 「🔴 未返却をぜんぶ表示」ボタンと 月しぼりこみ を追加
    H3 画面  : 返却済みカードに「✏️ コメントを直して再返却」を追加
               （コメント欄は今のコメントを入れた状態／「この直しを子どもに知らせる」は既定OFF）
    H4 サーバ: 返却APIに editOnly / notify を追加
               editOnly のときは teacher_comment と has_physical だけ更新し、
               returned_at は動かさない。ごほうびの処理には一切入らない。
               notify のときだけ、児童あてに messages を1通入れる。

  ★ reward_claimed は絶対に 0 に戻さない
     POST /api/homework/:id/claim は reward_claimed だけを見て
     reward_coins / bonus_coins を児童に渡す（台帳が無い）。
     0 に戻すと同じごほうびを二重に受け取れてしまう。
     だから「知らせる」はコイン系にはいっさい触れず、メッセージを1通送る方式にした。
"""
import io, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
src = io.open(TSX, encoding='utf-8').read()
orig = src
done = []

def fail(m):
    print('❌ 中止: ' + m); sys.exit(1)

def sub(tag, old, new, sentinel):
    """sentinel がすでにあれば適用ずみ扱い（冪等）"""
    global src
    if sentinel in src:
        print('⏭  %s は適用ずみ（スキップ）' % tag); return
    if src.count(old) != 1:
        fail('%s のアンカーが %d 箇所（1箇所のはず）' % (tag, src.count(old)))
    src = src.replace(old, new, 1)
    done.append(tag)

# ══════════════════════════════════════════════════════════
# H1 サーバ: 一覧に 未返却モード と 期間しぼりこみ を足す
# ══════════════════════════════════════════════════════════
H1_OLD = "  sql += ` ORDER BY hs.submitted_at DESC LIMIT 100`"
H1_NEW = """  // 📌 2026-09: 「昔の提出が返せない」対策。
  //   ここは日付ではなく件数（LIMIT 100）で切っていたため、2学期に入って
  //   新しい提出が積み上がると、7月ぶんが一覧から押し出されていた。
  //   ・?unreturned=1 … 未返却だけを、件数を広げて返す（先生が取りこぼしを拾うため）
  //   ・?from= / ?to= / ?month= … day_key（YYYY-MM-DD）での期間しぼりこみ
  //   ふだんの表示は今までどおり LIMIT 100 のまま（読み取り量を増やさない）。
  const onlyUnreturned = c.req.query('unreturned') === '1'
  let from = String(c.req.query('from') || '')
  let to   = String(c.req.query('to') || '')
  const month = String(c.req.query('month') || '')
  if (/^\\d{4}-\\d{2}$/.test(month)) { from = month + '-01'; to = month + '-31' }
  if (onlyUnreturned) sql += ` AND hs.returned_at IS NULL`
  if (/^\\d{4}-\\d{2}-\\d{2}$/.test(from)) { sql += ` AND hs.day_key >= ?`; binds.push(from) }
  if (/^\\d{4}-\\d{2}-\\d{2}$/.test(to))   { sql += ` AND hs.day_key <= ?`; binds.push(to) }
  const lim = (onlyUnreturned || from || to) ? 500 : 100
  sql += ` ORDER BY hs.submitted_at DESC LIMIT ` + lim"""
sub('H1 一覧に未返却モードと期間しぼりこみ', H1_OLD, H1_NEW, "const onlyUnreturned = c.req.query('unreturned')")

# ══════════════════════════════════════════════════════════
# H4 サーバ: 返却APIに editOnly / notify
# ══════════════════════════════════════════════════════════
H4_OLD = """  await c.env.DB.prepare(`
    UPDATE homework_submissions
    SET teacher_id=?, teacher_comment=?, has_physical=?, returned_at=?
    WHERE id=?
  `).bind(
    u.id,
    String(body.comment || '').slice(0, 500),
    body.hasPhysical ? 1 : 0,
    Date.now(),
    hwId
  ).run()
"""
H4_NEW = """  // 📌 2026-09: 返却済みのコメントを直せるようにした（editOnly）。
  //   ・returned_at は動かさない（「いつ返したか」を書き換えない／子どもの画面も静かなまま）
  //   ・ごほうびの処理には一切入らない（下の noReward 判定より前に return する）
  //   ・reward_claimed は絶対に 0 に戻さない。
  //     POST /api/homework/:id/claim は reward_claimed だけを見てごほうびを渡すので、
  //     戻すと同じごほうびを二重に受け取れてしまう。
  const editOnly = (body && body.editOnly === true)
  const comment = String(body.comment || '').slice(0, 500)
  if (editOnly) {
    const cur = await c.env.DB.prepare('SELECT user_id, day_key, returned_at FROM homework_submissions WHERE id=? LIMIT 1').bind(hwId).first<any>()
    if (!cur || !cur.returned_at) return jsonError(c, 400, 'not_returned_yet')
    await c.env.DB.prepare(`
      UPDATE homework_submissions SET teacher_comment=?, has_physical=? WHERE id=?
    `).bind(comment, body.hasPhysical ? 1 : 0, hwId).run()
    // 「この直しを子どもに知らせる」がONのときだけ、お知らせを1通だけ送る。
    //   コイン系には触れない（ぬか喜びさせない）。
    if (body && body.notify === true) {
      try {
        const cm = await c.env.DB.prepare('SELECT class_id FROM class_members WHERE user_id=? LIMIT 1').bind(cur.user_id).first<any>()
        if (cm?.class_id) {
          await c.env.DB.prepare(
            'INSERT INTO messages (id, class_id, sender_id, sender_role, recipient_id, body) VALUES (?,?,?,?,?,?)'
          ).bind(crypto.randomUUID(), cm.class_id, u.id, 'teacher',
                 cur.user_id,
                 String(cur.day_key || '') + ' の家庭学習に、先生がコメントを書きました。\\n' + comment).run()
        }
      } catch (e) { console.error('edit notify failed:', e) }
    }
    return c.json({ ok: true, edited: true })
  }

  await c.env.DB.prepare(`
    UPDATE homework_submissions
    SET teacher_id=?, teacher_comment=?, has_physical=?, returned_at=?
    WHERE id=?
  `).bind(
    u.id,
    comment,
    body.hasPhysical ? 1 : 0,
    Date.now(),
    hwId
  ).run()
"""
sub('H4 返却APIに editOnly / notify', H4_OLD, H4_NEW, 'const editOnly = (body && body.editOnly === true)')

# ══════════════════════════════════════════════════════════
# H2 画面: 「未返却をぜんぶ表示」と 月しぼりこみ
# ══════════════════════════════════════════════════════════
H2_OLD = """            <button onclick="loadHomework()" class="bg-slate-200 rounded px-3 py-1 text-sm">更新</button>"""
H2_NEW = """            <button onclick="loadHomework()" class="bg-slate-200 rounded px-3 py-1 text-sm">更新</button>
            <!-- 📌 2026-09: 一覧は新しい100件で打ち切られるため、古い提出に辿り着けなかった。
                 「未返却をぜんぶ」と「月しぼりこみ」を足して、7月ぶんにも届くようにする。 -->
            <button onclick="hwShowAllUnreturned()" id="hwAllUnreturnedBtn" class="bg-red-500 text-white rounded px-3 py-1 text-sm font-bold">🔴 未返却をぜんぶ表示</button>
            <input type="month" id="hwMonthFilter" class="border p-1 rounded text-sm bg-white" onchange="loadHomework()" title="この月の提出だけを表示します"/>
            <button onclick="hwClearFilters()" class="bg-slate-100 rounded px-2 py-1 text-xs">絞り込みを解除</button>"""
sub('H2 「未返却をぜんぶ表示」と月しぼりこみ', H2_OLD, H2_NEW, 'id="hwAllUnreturnedBtn"')

# ══════════════════════════════════════════════════════════
# H2b 画面: loadHomework がクエリを組み立てるところ
# ══════════════════════════════════════════════════════════
H2B_OLD = """        let qs = classId ? '?classId='+encodeURIComponent(classId) : '';"""
H2B_NEW = """        // 📌 2026-09: 未返却モード／月しぼりこみをサーバに渡す
        var _qp = [];
        if(classId) _qp.push('classId='+encodeURIComponent(classId));
        if(window._hwOnlyUnreturned) _qp.push('unreturned=1');
        var _mEl = document.getElementById('hwMonthFilter');
        if(_mEl && _mEl.value) _qp.push('month='+encodeURIComponent(_mEl.value));
        let qs = _qp.length ? ('?'+_qp.join('&')) : '';"""
sub('H2b loadHomework のクエリ組み立て', H2B_OLD, H2B_NEW, 'window._hwOnlyUnreturned')

# ══════════════════════════════════════════════════════════
# H2c 画面: 切り替え用の関数
# ══════════════════════════════════════════════════════════
H2C_OLD = """      async function returnHomeworkNoReward(id, btn){"""
H2C_NEW = """      // 📌 2026-09: 「🔴 未返却をぜんぶ表示」の ON/OFF
      window._hwOnlyUnreturned = false;
      function hwShowAllUnreturned(){
        window._hwOnlyUnreturned = !window._hwOnlyUnreturned;
        var b = document.getElementById('hwAllUnreturnedBtn');
        if(b){
          b.textContent = window._hwOnlyUnreturned ? '🔴 未返却だけ表示中（解除）' : '🔴 未返却をぜんぶ表示';
          b.className = window._hwOnlyUnreturned
            ? 'bg-red-700 text-white rounded px-3 py-1 text-sm font-bold'
            : 'bg-red-500 text-white rounded px-3 py-1 text-sm font-bold';
        }
        _hwDateFilter = '';
        loadHomework();
      }
      function hwClearFilters(){
        window._hwOnlyUnreturned = false;
        var m = document.getElementById('hwMonthFilter'); if(m) m.value = '';
        var b = document.getElementById('hwAllUnreturnedBtn');
        if(b){ b.textContent='🔴 未返却をぜんぶ表示'; b.className='bg-red-500 text-white rounded px-3 py-1 text-sm font-bold'; }
        _hwDateFilter = '';
        loadHomework();
      }

      // 📌 2026-09: 返却済みのコメントを直して再返却する
      function hwToggleEdit(id){
        var box = document.getElementById('hwEditBox_'+id);
        if(box) box.classList.toggle('hidden');
      }
      async function hwSaveEdit(id, btn){
        btn.disabled = true;
        var comment = (document.getElementById('hwEditComment_'+id)||{}).value || '';
        var hasPhysical = (document.getElementById('hwEditPhysical_'+id)||{}).checked || false;
        var notify = (document.getElementById('hwEditNotify_'+id)||{}).checked || false;
        try{
          await api('/api/teacher/homework/'+id+'/return',{method:'POST',headers:{'content-type':'application/json'},
            body:JSON.stringify({comment:comment, hasPhysical:hasPhysical, editOnly:true, notify:notify})});
          await loadHomework();
        }catch(e){
          btn.disabled=false;
          alert('エラー: '+String(e.message||e));
        }
      }

      async function returnHomeworkNoReward(id, btn){"""
sub('H2c 未返却トグルと再返却の関数', H2C_OLD, H2C_NEW, 'function hwShowAllUnreturned()')

# ══════════════════════════════════════════════════════════
# H3 画面: 返却済みカードに編集フォーム
# ══════════════════════════════════════════════════════════
H3_OLD = """          } else if(s.teacherComment) {
            const commentDiv = document.createElement('div');
            commentDiv.className='text-xs text-emerald-700 bg-emerald-50 rounded p-2 border border-emerald-200';
            commentDiv.textContent = '💬 ' + s.teacherComment;
            card.appendChild(commentDiv);
          }"""
H3_NEW = """          } else {
            // 📌 2026-09: 返却済みでも、コメントを直して再返却できるようにする。
            //   ・returned_at は動かさない（いつ返したかは変わらない）
            //   ・コインは増えない（サーバ側でごほうび処理に入らない）
            //   ・「この直しを子どもに知らせる」は既定OFF。
            //     コインが増えないのに「届きました！」だけ出ると、子どもが期待して落胆するため。
            const doneDiv = document.createElement('div');
            doneDiv.className='space-y-2 border-t pt-2';
            const __cmt = s.teacherComment || '';
            doneDiv.innerHTML =
              (__cmt
                ? '<div class="text-xs text-emerald-700 bg-emerald-50 rounded p-2 border border-emerald-200">💬 '+escH(__cmt)+'</div>'
                : '<div class="text-xs text-slate-400">コメントなしで返却しました</div>')
              + '<button class="bg-white border border-emerald-500 text-emerald-700 rounded px-3 py-1 text-xs font-bold" onclick="hwToggleEdit(&#39;'+escH(s.id)+'&#39;)">✏️ コメントを直して再返却</button>'
              + '<div id="hwEditBox_'+escH(s.id)+'" class="hidden space-y-2 bg-slate-50 rounded p-2 border">'
              +   '<div class="text-xs font-bold text-slate-600">先生コメント</div>'
              +   '<textarea class="w-full border rounded p-2 text-xs" rows="2" id="hwEditComment_'+escH(s.id)+'"></textarea>'
              +   '<label class="flex items-center gap-2 text-xs cursor-pointer"><input type="checkbox" id="hwEditPhysical_'+escH(s.id)+'"'+(s.hasPhysical?' checked':'')+'/> <span>成果物（ノートなど）も提出あり ⭐</span></label>'
              +   '<label class="flex items-center gap-2 text-xs cursor-pointer"><input type="checkbox" id="hwEditNotify_'+escH(s.id)+'"/> <span>この直しを子どもに知らせる</span></label>'
              +   '<p class="text-[10px] text-slate-400">直してもコインは増えません。知らせるにチェックを入れると、お知らせが1通だけ届きます。</p>'
              +   '<button class="bg-emerald-600 text-white rounded px-3 py-1 text-xs font-bold" onclick="hwSaveEdit(&#39;'+escH(s.id)+'&#39;, this)">保存する</button>'
              + '</div>';
            card.appendChild(doneDiv);
            // 値は innerHTML ではなく value で入れる（コメントに < や & があっても壊れないように）
            const __ta = doneDiv.querySelector('textarea');
            if(__ta) __ta.value = __cmt;
          }"""
# ⚠ ここの合言葉（sentinel）は、他の手順が先に入れてしまう文字列と
#   かぶらないものを選ぶこと。最初 'hwEditNotify_' にしていたら
#   H2c の hwSaveEdit が同じ文字列を持っていたため、H3 が「適用ずみ」と
#   誤判定されて丸ごと飛ばされた。下はカード側にしか出てこない文言。
sub('H3 返却済みカードに編集フォーム', H3_OLD, H3_NEW, 'コメントなしで返却しました')

# ══════════════════════════════════════════════════════════
# 検証
# ══════════════════════════════════════════════════════════
def used(name):
    for l in src.split('\n'):
        if name in l and not l.strip().startswith('//'):
            return True
    return False

# ★ reward_claimed を 0 に戻していないこと（二重受け取りの防止）
for l in src.split('\n'):
    ls = l.strip()
    if ls.startswith('//'): continue
    if re.search(r'reward_claimed\s*=\s*0', l):
        fail('reward_claimed を 0 に戻すコードがあります（ごほうびの二重受け取りになります）')
print('🔎 reward_claimed を 0 に戻すコードはありません')

# ★ editOnly の分岐が、ごほうび処理より前に return していること
a = src.index("app.post('/api/teacher/homework/:id/return'")
b = src.index('\n})\n', a)
blk = src[a:b]
if 'const editOnly' not in blk: fail('editOnly が返却APIの中にありません')
i_edit = blk.index('return c.json({ ok: true, edited: true })')
i_rew  = blk.index('const noReward')
if not (i_edit < i_rew):
    fail('editOnly の return が、ごほうび処理より後ろにあります')
if 'homework_rewards' in blk[:i_edit]:
    fail('editOnly の経路がごほうび台帳に触れています')
print('🔎 editOnly はごほうび処理に入る前に return しています')

# ★ 通常の返却の挙動が変わっていないこと
for must in ["SET teacher_id=?, teacher_comment=?, has_physical=?, returned_at=?",
             'const noReward = (body && body.noReward === true)',
             'INSERT INTO homework_rewards',
             "app.post('/api/homework/:id/claim'",
             'function returnHomework(id, btn, noReward)',
             'function bulkReturnNoComment()',
             'onclick="returnHomework(', 'id="hwList"', 'id="hwClassFilter"', 'id="hwStatusFilter"',
             'id="hwDateTabs"', 'id="hwSummaryBar"', 'id="hwUnsubmittedList"']:
    if must not in src: fail('★残すはずのものが失われました: %s' % must)
print('🔎 通常の返却・まとめて返却・ごほうび台帳・claim はそのまま残っています')

# ★ 新しい入口が全部そろっていること
for must in ['id="hwAllUnreturnedBtn"', 'id="hwMonthFilter"', 'function hwShowAllUnreturned()',
             'function hwClearFilters()', 'function hwToggleEdit(', 'async function hwSaveEdit(',
             'hwEditComment_', 'hwEditNotify_', "c.req.query('unreturned')", "c.req.query('month')",
             # ↓ カード側（H3）が本当に入ったか。ここを見ないと H3 の飛ばしに気づけない。
             '✏️ コメントを直して再返却', 'コメントなしで返却しました',
             'この直しを子どもに知らせる', 'id="hwEditBox_']:
    if must not in src: fail('新しい入口が足りません: %s' % must)
# 旧・返却済みの分岐が残っていないこと（H3が当たった証拠）
if '} else if(s.teacherComment) {' in src:
    fail('返却済みカードが古いまま（H3が当たっていません）')
print('🔎 未返却モード・月しぼりこみ・再返却フォームはすべて入りました')

# ★ 置換チェーンと <div> の釣り合い
def rc(t):
    a = t.index("app.get('/', async (c) => {"); b = t.index("app.get('/logout'", a)
    return t[a:b].count('.replace(')
if rc(src) != rc(orig): fail('置換チェーンの数が変わりました（%d → %d）' % (rc(orig), rc(src)))
print('🔎 置換チェーン: %d 件（変化なし）' % rc(src))

bal  = len(re.findall(r'<div\b', src))  - len(re.findall(r'</div>', src))
bal0 = len(re.findall(r'<div\b', orig)) - len(re.findall(r'</div>', orig))
if bal != bal0: fail('<div> の釣り合いが変わりました（%d → %d）' % (bal0, bal))
print('🔎 <div> の釣り合い: 変化なし')

# ★ 起動時に CREATE INDEX が復活していないこと（9/3の事故の再発防止）
g0 = src.index('let _adminChecked = false')
g1 = src.index('// -------------------- DB migration', g0)
for l in src[g0:g1].split('\n'):
    if 'CREATE INDEX' in l and not l.strip().startswith('//'):
        fail('起動時ミドルウェアに CREATE INDEX が復活しています')
print('🔎 起動時ミドルウェアに CREATE INDEX はありません')

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました（%d → %d 文字）' % (len(orig), len(src)))
else:
    print('… 変更なし')
print('---- 入れたもの ----')
for t in done: print(' ・' + t)
if not done: print(' （なし）')
