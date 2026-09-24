# -*- coding: utf-8 -*-
# __IMPORT_AUTO_V1__ / __IMPORT_CHECK_V1__  (2026-09-24)
#
#  取り込み口の統合。先生が「テストか／成果物か／ポートフォリオか」を選ぶのをやめる。
#
#  (1) 行き先は中身で決める（先生には何も聞かない）
#        点数 または 観点別（知技・思判表・主体）あり -> student_test_scores（成績・通知表）
#        どちらも無し                                 -> student_records（カルテの材料）
#      ※「◎○△があるか」では分かれない。成果物89件は全件に◎○△が入っており、
#        それで分けると通知表に成果物が流れ込む。実データ173件で検証ずみ。
#  (2) 種類（まとめ／振り返り／その他）も中身から決める。3択セレクトは廃止。
#        本文あり->まとめ／本文なし・振り返りあり->振り返り／どちらも無し->その他
#        既存89件すべてがこの規則に一致。
#  (3) 貼り付け欄は1つ。「=== [ID] 名前 ===」があればブロック形式、無ければ一覧形式。
#  (4) 取り込み口 4つ -> 2つ（ドリルパークは畳むだけ。消さない）
#  (5) 保存前の値の点検。満点超え／マイナス／0点／全員同じ点／二重取り込み／人数不足。
#      v188 (7e0ba7a) の名前照合と同じ作法：黄色で出し、チェックするまで保存しない。
#
#  児童の画面（配信チェーン）は1件も増やさない。増えていたら止まる。
import os
import sys

SRC = 'src/index.tsx'


def chain_count(t):
    i = t.index("app.get('/', async (c) => {")
    j = t.index("app.get('/logout'", i)
    return t[i:j].count('.replace(')


raw = (os.environ.get('CHAIN_BEFORE') or '').strip()
if not raw.isdigit():
    print('NG: CHAIN_BEFORE が数字でない（渡された値: %r）' % raw)
    sys.exit(1)
CHAIN_BEFORE = int(raw)

s = open(SRC, encoding='utf-8').read()
before = chain_count(s)
print('チェーン = %d' % before)
if before != CHAIN_BEFORE:
    print('NG: チェーンが %d 件。実測した %d と合わないので止めます。' % (before, CHAIN_BEFORE))
    sys.exit(1)

for marker in ['__IMPORT_AUTO_V1__', '__IMPORT_CHECK_V1__', 'function parseImport(']:
    if marker in s:
        print('すでに適用ずみ（%s）。何も書かずに終了します。' % marker)
        sys.exit(0)


def rep(old, new, tag):
    global s
    n = s.count(old)
    if n != 1:
        print('NG: アンカー「%s」が %d 件（1件でないので止めます）' % (tag, n))
        sys.exit(1)
    s = s.replace(old, new)
    print('  ok %s' % tag)


# ===== 取り込み口の作り直し（UI。行ではなくアンカーで位置を出す）=====
L = s.split('\n')
_st = None
for k in range(len(L)):
    if 'ドリルパークの取り込み' in L[k] and 'font-bold' in L[k]:
        _st = k - 1
        break
if _st is None:
    print('NG: ドリルパークのカードが見つかりません'); sys.exit(1)
_en = None
_drEnd = None
for k in range(_st, min(_st + 140, len(L))):
    if 'id="recDirStatus"' in L[k]:
        for m in range(k, min(k + 8, len(L))):
            # A=flexを閉じる / B=「mt-3 border-t」を閉じる / C=カード自体を閉じる
            # ・消す範囲は C まで（_en = m+1）。C を残すと閉じタグが1つ余る。
            # ・dr に入れるのは A,B まで（_drEnd = m）。C まで入れると二重に閉じる。
            if L[m].strip() == '</div>' and L[m - 1].strip() == '</div>' and L[m - 2].strip() == '</div>':
                _drEnd = m
                _en = m + 1
                break
        break
if _en is None:
    print('NG: 直接入力カードの終わりが見つかりません'); sys.exit(1)
dp = '\n'.join(L[_st + 1:_st + 10]).rstrip('\n')
if 'dpFile' not in dp:
    print('NG: ドリルパークの中身が想定と違います'); sys.exit(1)
_dirs = None
for k in range(_st, _en):
    if '児童をえらんで入力' in L[k]:
        _dirs = k
        break
if _dirs is None:
    print('NG: 直接入力の説明行が見つかりません'); sys.exit(1)
# 種類の3択セレクトを丸ごと落とす（<select ...> から対応する </select> まで）。
# 開始行だけ消すと </select> が孤児になり、HTML が壊れる。
_src = L[_dirs:_drEnd]
_ds = [i for i, x in enumerate(_src) if 'recDirType' in x and '<select' in x]
if len(_ds) != 1:
    print('NG: recDirType のセレクトが %d 件（1件でないので止めます）' % len(_ds)); sys.exit(1)
_a = _ds[0]
_b = None
for i in range(_a, min(_a + 10, len(_src))):
    if '</select>' in _src[i]:
        _b = i
        break
if _b is None:
    print('NG: recDirType の </select> が見つかりません'); sys.exit(1)
dr_lines = _src[:_a] + _src[_b + 1:]
dr = '\n'.join(dr_lines).rstrip('\n')
_ev = '<span class="text-xs text-slate-500">評価:</span>'
if dr.count(_ev) != 1:
    print('NG: 直接入力の「評価:」が1件ではありません'); sys.exit(1)
dr = dr.replace(_ev,
                '<span class="text-xs text-slate-500">点数:</span>\n'
                '                <input id="recDirScore" type="number" class="border rounded p-1 text-xs w-16 text-center" placeholder="—">\n'
                '                <span class="text-xs text-slate-400">/</span>\n'
                '                <input id="recDirMax" type="number" class="border rounded p-1 text-xs w-14 text-center" value="100">\n'
                '                <span class="text-xs text-slate-500 ml-2">評価:</span>')
start, end = _st, _en
new = '''          <details class="bg-white rounded-xl shadow p-4">
            <summary class="font-bold text-slate-700 cursor-pointer text-sm">📘 ドリルパークの取り込み（エクセル）<span class="ml-2 text-[10px] font-normal text-slate-400">ふだんは使いません</span></summary>
            <div class="mt-2">
''' + dp + '''
            </div>
          </details>
          <div class="bg-white rounded-xl shadow p-4">
            <div class="font-bold text-slate-700 mb-1">📥 取り込み（テスト・成果物・振り返り）</div>
            <div class="text-xs text-slate-500 mb-2">貼り付け欄は<b>1つ</b>です。テストでも成果物でも振り返りでも、同じ欄に貼ってください。<b>種類を選ぶ必要はありません。</b>点数があるものには点数を書く、それだけです。<br><span class="text-slate-400">点数か観点別（知技・思判表・主体）が入っていれば「成績」へ、入っていなければ「記録（カルテの材料）」へ、アプリが振り分けます。</span><br><b class="text-rose-600">保存の前にかならず一覧が出ます。おかしな値には印が付き、確認するまで保存されません。</b></div>
            <div class="flex items-center gap-2 flex-wrap mb-2 text-xs">
              <label class="text-slate-500">学年 <select id="tsGrade" class="border rounded p-1 bg-white"><option value="">自動</option><option>1</option><option>2</option><option>3</option><option>4</option><option>5</option><option>6</option></select></label>
              <label class="text-slate-500">教科 <select id="tsSubject" class="border rounded p-1 bg-white"><option value="">（教科をえらぶ）</option><option>国語</option><option>算数</option><option>理科</option><option>社会</option><option>英語</option></select></label>
              <input id="tsUnit" class="border rounded p-1" placeholder="単元(任意)" style="width:130px">
            </div>
            <div class="flex items-center gap-2 flex-wrap mb-2">
              <button onclick="copyTestPrompt()" class="bg-emerald-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:bg-emerald-700">📋 テストを読ませるプロンプト</button>
              <button onclick="copyRecordPrompt()" class="bg-emerald-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:bg-emerald-700">📋 成果物・振り返りを読ませるプロンプト</button>
              <span id="tsPromptStatus" class="text-xs text-emerald-600 font-bold"></span>
              <span id="recPromptStatus" class="text-xs text-emerald-600 font-bold"></span>
            </div>
            <textarea id="tsPaste" rows="8" class="w-full border rounded-lg p-2 text-xs" placeholder="外部AI（ChatGPT・Gemini・Claude）が書き出した結果を、そのままここに貼り付けてください。テストの一覧でも、児童ごとの成果物でも、どちらでも読み取ります。"></textarea>
            <div class="flex items-center gap-2 mt-2">
              <button onclick="parseImport()" class="bg-indigo-600 text-white rounded-lg px-4 py-1.5 text-xs font-bold hover:opacity-90">🔍 読み取り</button>
              <span id="tsParseStatus" class="text-xs text-slate-500"></span>
            </div>
            <div id="tsPreview" class="mt-3"></div>
            <div id="recPreview" class="mt-3"></div>
            <div class="mt-3 border-t border-slate-200 pt-3">
              <div class="font-bold text-slate-700 mb-1 text-sm">✍ 直接入力（1件ずつ手で追加）</div>
''' + dr + '''
          </div>'''

L[start:end] = new.split('\n')
s = '\n'.join(L)
print('  ok UI 取り込み口 4->2')


# ===== サーバ・クライアントの書き換え =====
# ---- p1 ----
# S1a: cur init — 点数・満点・観点別を持たせる
rep("cur={ idRaw:String(mk[1]||'').trim(), nameRaw:String(mk[2]||'').trim(), title:'', day:'', subject:'', unit:'', body:'', reflection:'', evalRank:'', evalComment:'' };",
    "cur={ idRaw:String(mk[1]||'').trim(), nameRaw:String(mk[2]||'').trim(), title:'', day:'', subject:'', unit:'', body:'', reflection:'', evalRank:'', evalComment:'', score:'', maxScore:'', evalKnowledge:'', evalThinking:'', evalAttitude:'' };",
    'S1a cur init')

# S1b: 点数・満点・観点別のキーを読む（評価コメント/評価より前に置く）
old="      else if(k.indexOf('評価コメント')>=0||k.indexOf('評価メモ')>=0){ cur.evalComment=v; sec='evalComment'; handled=true; }"
new=("      else if(k.indexOf('点数')>=0||k.indexOf('得点')>=0){ cur.score=_tsKeepNum(v); sec=null; handled=true; }\n"
     "      else if(k.indexOf('満点')>=0||k.indexOf('配点')>=0){ cur.maxScore=_tsKeepNum(v); sec=null; handled=true; }\n"
     "      else if(k.indexOf('知技')>=0||k.indexOf('知識')>=0){ cur.evalKnowledge=_recNormRank(v); sec=null; handled=true; }\n"
     "      else if(k.indexOf('思判表')>=0||k.indexOf('思考')>=0){ cur.evalThinking=_recNormRank(v); sec=null; handled=true; }\n"
     "      else if(k.indexOf('主体')>=0||k.indexOf('態度')>=0){ cur.evalAttitude=_recNormRank(v); sec=null; handled=true; }\n"
     +old)
rep(old,new,'S1b keys')

# ---- p2 ----
# S2a: 共通ヘルパ（行き先の自動判定・種類の自動判定）を _recParseText の直前に置く
anchor="function _recParseText(text){"
helper = (
"// ===== 取り込みの行き先・種類を、中身から自動で決める __IMPORT_AUTO_V1__ =====\n"
"//  ・点数 または 観点別（知技／思判表／主体）が入っていれば「成績」= student_test_scores\n"
"//    （通知表の画面は student_test_scores しか読まないため。◎○△だけでは分かれない：\n"
"//      成果物89件の全件に◎○△が入っており、分かれ目にならないことを実データで確認ずみ）\n"
"//  ・それ以外（本文・振り返り・◎○△だけ）は「記録」= student_records\n"
"//  ・先生には何も聞かない。点数欄に書いたかどうかだけで決まる。\n"
"function _impHasScore(r){ var v=(r&&r.score); if(v===''||v==null) return false; var n=parseInt(String(v),10); return !isNaN(n); }\n"
"function _impHasKanten(r){ return !!((r&&r.evalKnowledge)||(r&&r.evalThinking)||(r&&r.evalAttitude)); }\n"
"function _impDest(r){ return (_impHasScore(r)||_impHasKanten(r)) ? 'score' : 'record'; }\n"
"// 種類（まとめ／振り返り／その他）も中身から決める。先生の3択は廃止。\n"
"//  本文あり→まとめ／本文なし・振り返りあり→振り返り／どちらも無し→その他\n"
"//  既存89件すべてがこの規則に一致することを実データで確認ずみ。\n"
"function _impAutoType(r){ if(String((r&&r.body)||'').trim()) return 'report'; if(String((r&&r.reflection)||'').trim()) return 'reflect'; return 'other'; }\n"
)
rep(anchor, helper+anchor, 'S2a helpers')

# S2b: records/parse — 新しい列と dest/autoType/二重取り込みを返す
old="""    const mm = uid ? (roster as any[]).find((x: any) => x.id === uid) : null
    return { idRaw: bk.idRaw, nameRaw: bk.nameRaw, title: bk.title, day: bk.day, subject: bk.subject, unit: bk.unit, body: bk.body, reflection: bk.reflection, evalRank: bk.evalRank, evalComment: bk.evalComment, matchedUserId: uid, matchedName: mm ? mm.name : null }
  })
  return c.json({ ok: true, rows, roster: (roster as any[]).map((m: any) => ({ userId: m.id, name: m.name, loginId: m.loginId })) })"""
new="""    const mm = uid ? (roster as any[]).find((x: any) => x.id === uid) : null
    const dupKey = uid ? (uid + '|' + _recNorm(bk.title)) : ''
    return { idRaw: bk.idRaw, nameRaw: bk.nameRaw, title: bk.title, day: bk.day, subject: bk.subject, unit: bk.unit, body: bk.body, reflection: bk.reflection, evalRank: bk.evalRank, evalComment: bk.evalComment, score: bk.score, maxScore: bk.maxScore, evalKnowledge: bk.evalKnowledge, evalThinking: bk.evalThinking, evalAttitude: bk.evalAttitude, dest: _impDest(bk), autoType: _impAutoType(bk), dupOn: (dupKey && _recDup[dupKey]) ? _recDup[dupKey] : '', matchedUserId: uid, matchedName: mm ? mm.name : null }
  })
  return c.json({ ok: true, rows, roster: (roster as any[]).map((m: any) => ({ userId: m.id, name: m.name, loginId: m.loginId })) })"""
rep(old,new,'S2b parse return')

# S2c: records/parse — 二重取り込みの下調べ（直近60日・同じクラス・同じタイトル）
old2="""  const blocks = _recParseText(body.text)
  const rows = blocks.map((bk: any) => {
    const keyId = _recNorm(bk.idRaw); const keyNm = _recNorm(bk.nameRaw)"""
new2="""  // 📌 二重取り込みの下調べ。同じクラスの直近60日ぶんのタイトルだけを引く（LIMIT つき・軽い）。
  const _recDup: Record<string, string> = {}
  try {
    const _since = new Date(Date.now() - 60 * 86400000).toISOString().slice(0, 10)
    const _dr = await c.env.DB.prepare("SELECT sr.user_id as uid, sr.title as t, substr(sr.created_at,1,10) as d FROM student_records sr WHERE sr.user_id IN (SELECT user_id FROM class_members WHERE class_id=?) AND substr(sr.created_at,1,10) >= ? ORDER BY sr.id DESC LIMIT 400").bind(classId, _since).all<any>()
    for (const r of (((_dr && _dr.results) || []) as any[])) { const t = _recNorm(r.t); if (!t) continue; const k = String(r.uid) + '|' + t; if (!_recDup[k]) _recDup[k] = String(r.d || '') }
  } catch (e) {}
  const blocks = _recParseText(body.text)
  const rows = blocks.map((bk: any) => {
    const keyId = _recNorm(bk.idRaw); const keyNm = _recNorm(bk.nameRaw)"""
rep(old2,new2,'S2c dup lookup')

# ---- p3 ----
# S3a: records/save — 種類は先生に聞かず、中身から決める
old="""  const allowTypes = new Set(['report', 'reflect', 'other'])
  let rtype = String(body.type || 'report'); if (!allowTypes.has(rtype)) rtype = 'other'"""
new="""  // 📌 __IMPORT_AUTO_V1__ 種類（まとめ／振り返り／その他）は先生に聞かない。中身から決める。
  //    互換のため body.type も受けるが、行ごとの自動判定を優先する。
  const allowTypes = new Set(['report', 'reflect', 'other'])
  let rtypeFallback = String(body.type || '').trim(); if (!allowTypes.has(rtypeFallback)) rtypeFallback = ''"""
rep(old,new,'S3a rtype')

old2="""    const subj = String((it && it.subject) || '').slice(0, 40)
    const unit = String((it && it.unit) || '').slice(0, 80)
    const day = String((it && it.day) || '').slice(0, 40)
    await c.env.DB.prepare('INSERT INTO student_records (user_id, class_id, type, title, body, reflection, eval_rank, eval_comment, subject, unit, day_key, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(uid, classId, rtype, title, bodyTxt, reflection, evalRank, evalComment, subj, unit, day, u.id, nowIso).run()"""
new2="""    const subj = String((it && it.subject) || '').slice(0, 40)
    const unit = String((it && it.unit) || '').slice(0, 80)
    const day = String((it && it.day) || '').slice(0, 40)
    const rtype = _impAutoType({ body: bodyTxt, reflection }) || rtypeFallback || 'other'
    await c.env.DB.prepare('INSERT INTO student_records (user_id, class_id, type, title, body, reflection, eval_rank, eval_comment, subject, unit, day_key, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(uid, classId, rtype, title, bodyTxt, reflection, evalRank, evalComment, subj, unit, day, u.id, nowIso).run()"""
rep(old2,new2,'S3b rtype per row')

# S3c: test-scores/parse — 二重取り込みの下調べ＋値の点検用に既存テスト名を返す
old3="""  const parsed = _tsParseText(body.text)
  const rows = parsed.rows.map((r: any) => {"""
new3="""  // 📌 二重取り込みの下調べ。同じクラスで直近60日に取り込んだテスト名を集める（LIMIT つき）。
  const _tsDupNames: Record<string, string> = {}
  try {
    const _since = new Date(Date.now() - 60 * 86400000).toISOString().slice(0, 10)
    const _dr = await c.env.DB.prepare("SELECT sts.test_name as t, substr(sts.created_at,1,10) as d FROM student_test_scores sts WHERE sts.user_id IN (SELECT user_id FROM class_members WHERE class_id=?) AND substr(sts.created_at,1,10) >= ? ORDER BY sts.id DESC LIMIT 300").bind(classId, _since).all<any>()
    for (const r of (((_dr && _dr.results) || []) as any[])) { const t = _tsNorm(r.t); if (!t) continue; if (!_tsDupNames[t]) _tsDupNames[t] = String(r.d || '') }
  } catch (e) {}
  const parsed = _tsParseText(body.text)
  const rows = parsed.rows.map((r: any) => {"""
rep(old3,new3,'S3c ts dup lookup')

old4="""  return c.json({ ok: true, header: { testName: parsed.testName, testDate: parsed.testDate, subject: parsed.subject, maxScore: parsed.maxScore, grade: parsed.grade }, rows, roster:"""
new4="""  const _dupOn = _tsDupNames[_tsNorm(parsed.testName)] || ''
  return c.json({ ok: true, dupOn: _dupOn, rosterCount: (roster as any[]).length, header: { testName: parsed.testName, testDate: parsed.testDate, subject: parsed.subject, maxScore: parsed.maxScore, grade: parsed.grade }, rows, roster:"""
rep(old4,new4,'S3d ts parse return')

# ---- p5 ----
# C1: 直接入力 — 種類は自動、点数があれば成績側へ
old="""        var rtype=gv('recDirType')||'report';
        var row={userId:uid, title:title, body:body, reflection:refl, evalRank:er, evalComment:ec, subject:gv('recDirSubject'), unit:gv('recDirUnit'), day:gv('recDirDay')};
        if(st) st.textContent='保存中...';
        fetch('/api/teacher/records/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({classId:cid, type:rtype, rows:[row]})}).then(function(r){return r.json();}).then(function(res){"""
new="""        // 📌 __IMPORT_AUTO_V1__ 種類は聞かない。点数が入っていれば成績側へ、無ければ記録側へ。
        var _sc=gv('recDirScore'); var _mx=parseInt(gv('recDirMax'),10)||100;
        var _hasScore=!(_sc===''||_sc==null||isNaN(parseInt(_sc,10)));
        if(_hasScore){
          var _n=parseInt(_sc,10);
          if(_n<0||_n>_mx){ if(st) st.textContent='点数が満点('+_mx+')の範囲を外れています。確かめてください'; return; }
          if(st) st.textContent='保存中...';
          fetch('/api/teacher/test-scores/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({classId:cid, testName:(title||gv('recDirUnit')||'テスト'), testDate:gv('recDirDay'), subject:gv('recDirSubject'), maxScore:_mx, rows:[{userId:uid, score:_n, evalRank:er, evalKnowledge:er, evalThinking:'', evalAttitude:'', comment:ec}]})}).then(function(r){return r.json();}).then(function(res){
            if(res&&res.ok&&res.saved>0){ if(st) st.textContent='✓ 点数として保存しました（成績・通知表に反映されます）'; var ids=['recDirTitle','recDirBody','recDirReflection','recDirEvalC','recDirScore']; for(var k=0;k<ids.length;k++){ var e=document.getElementById(ids[k]); if(e) e.value=''; } }
            else { if(st) st.textContent='保存できませんでした（児童の割り当てを確認）'; }
          }).catch(function(e){ if(st) st.textContent='エラー: '+e.message; });
          return;
        }
        var row={userId:uid, title:title, body:body, reflection:refl, evalRank:er, evalComment:ec, subject:gv('recDirSubject'), unit:gv('recDirUnit'), day:gv('recDirDay')};
        if(st) st.textContent='保存中...';
        fetch('/api/teacher/records/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({classId:cid, rows:[row]})}).then(function(r){return r.json();}).then(function(res){"""
rep(old,new,'C1 direct entry')

# C2: 記録用プロンプト — 種類3択が無くなったので固定文言に。点数欄も案内する。
rep("""        var sel=document.getElementById('recType'); var t=sel?sel.value:'report';
        var label=_recTypeLabel(t);""",
    """        var label='成果物・振り返り';""",
    'C2 prompt label')
rep("""        L.push('評価コメント: （先生の評価コメントがあれば。なければ空欄）');""",
    """        L.push('評価コメント: （先生の評価コメントがあれば。なければ空欄）');
        L.push('点数: （テストの点数があれば数字だけ。成果物なら空欄のまま）');""",
    'C2b prompt score line')

# C3: parseRecords → parseImport（貼り付け欄は1つ。=== の有無で振り分ける）
old3="""      function parseRecords(){
        var ta=document.getElementById('recPaste'); var raw=ta?ta.value:'';
        var st=document.getElementById('recParseStatus');
        var sel=document.getElementById('laClassSelect'); var cid=sel?sel.value:'';"""
new3="""      // 📌 __IMPORT_AUTO_V1__ 入口は1つ。貼られた形を見て、こちらで振り分ける。
      //    「=== [ID] 名前 ===」の行があれば 児童ごとのブロック形式（成果物・振り返り）、
      //    無ければ 名簿の一覧形式（テスト）。先生はどちらを貼ってもよい。
      function parseImport(){
        var ta=document.getElementById('tsPaste'); var raw=ta?ta.value:'';
        var st=document.getElementById('tsParseStatus');
        var pv1=document.getElementById('tsPreview'); if(pv1) pv1.innerHTML='';
        var pv2=document.getElementById('recPreview'); if(pv2) pv2.innerHTML='';
        if(!raw||!raw.trim()){ if(st) st.textContent='AIの出力を貼り付けてください'; return; }
        if(/^\\s*===\\s*\\[[^\\]]*\\]/m.test(raw)){ parseRecords(); } else { parseTestScores(); }
      }
      function parseRecords(){
        var ta=document.getElementById('tsPaste'); var raw=ta?ta.value:'';
        var st=document.getElementById('tsParseStatus');
        var sel=document.getElementById('laClassSelect'); var cid=sel?sel.value:'';"""
rep(old3,new3,'C3 parseImport')

# ---- p6 ----
# V1: 値の点検ヘルパ（v188 の matchStatus と同じ作法：黄色＋チェックしないと保存しない）
anchor="      function _recEvalOpts(sel){"
helper = """      // ===== 取り込んだ値の点検 __IMPORT_CHECK_V1__ =====
      //  先生が点数をカルテに出さない理由は「読み取りミスがこわいから」。
      //  そこで、名前の突き合わせ（v188）と同じ作法を、値そのものにも広げる。
      //   ・おかしい値は黄色で出し、「確かめました」にチェックするまで保存しない
      //   ・検出する中身は実データ（テスト53件・成果物89件）を見て決めた。
      //     5の倍数でない点数などは、誤検知のほうが害が大きいので入れていない。
      function _impRowWarn(r, maxScore){
        var w=[];
        var v=(r&&r.score); var has=!(v===''||v==null||isNaN(parseInt(String(v),10)));
        if(has){
          var n=parseInt(String(v),10); var mx=parseInt(String(maxScore),10)||100;
          if(n>mx) w.push('満点'+mx+'点なのに'+n+'点になっています');
          else if(n<0) w.push('点数がマイナスです');
          else if(n===0) w.push('0点です。お休みでしたか？読み取れなかっただけではありませんか？');
        }
        if(r&&r.dupOn) w.push('同じ内容が '+r.dupOn+' に取り込みずみです');
        return w.join(' / ');
      }
      // 表ぜんたいの点検。行ごとではなく、上に1行だけ出す。
      function _impTableNote(d, maxScore){
        var notes=[]; var rows=(d&&d.rows)||[];
        var vals=[]; for(var i=0;i<rows.length;i++){ var v=rows[i].score; if(!(v===''||v==null||isNaN(parseInt(String(v),10)))) vals.push(parseInt(String(v),10)); }
        if(vals.length>=5){ var same=true; for(var j=1;j<vals.length;j++){ if(vals[j]!==vals[0]){ same=false; break; } }
          if(same) notes.push('⚠️ '+vals.length+'人ぜんぶが同じ'+vals[0]+'点です。読み取れているか確かめてください'); }
        if(d&&d.dupOn) notes.push('⚠️ 同じ名前のテストを '+d.dupOn+' に取り込みずみです。二重になっていませんか？');
        var rc=(d&&d.rosterCount)||0;
        if(rc && rows.length && rows.length<rc) notes.push('ℹ️ 名簿'+rc+'人のうち '+rows.length+'人ぶんを読み取りました（'+(rc-rows.length)+'人は空欄のままです）');
        return notes;
      }
      function _impNoteHtml(notes){
        if(!notes||!notes.length) return '';
        var h='<div class="bg-amber-50 border border-amber-300 rounded-lg p-2 mb-2 text-xs text-amber-800 space-y-0.5">';
        for(var i=0;i<notes.length;i++) h+='<div>'+escH(notes[i])+'</div>';
        return h+'</div>';
      }
"""
rep(anchor, helper+anchor, 'V1 helpers')

# V2: テスト側プレビュー — 表の上に点検、行ごとに黄色＋チェック
rep("""        h+='</div></div>';
        var unmatched=0;
        h+='<div class="max-h-72 overflow-y-auto"><table class="w-full text-xs">""",
    """        h+='</div></div>';
        h+=_impNoteHtml(_impTableNote(d, hd.maxScore||100));
        var unmatched=0; var _warnN=0;
        h+='<div class="max-h-72 overflow-y-auto"><table class="w-full text-xs">""",
    'V2a ts table note')

rep("""          h+='<td class="p-1 text-center"><input id="tsRow_'+i+'_score" type="number" class="border rounded p-1 w-16 text-center" value="'+escH(String(r.score==null?'':r.score))+'"><span class="text-slate-400"> / '+escH(String(hd.maxScore||100))+'</span></td>';""",
    """          var _vw=_impRowWarn(r, hd.maxScore||100); if(_vw) _warnN++;
          h+='<td class="p-1 text-center"><input id="tsRow_'+i+'_score" type="number" class="border rounded p-1 w-16 text-center'+(_vw?' bg-amber-100 border-amber-400':'')+'" value="'+escH(String(r.score==null?'':r.score))+'"><span class="text-slate-400"> / '+escH(String(hd.maxScore||100))+'</span>'+(_vw?('<div class="text-[10px] text-amber-700 mt-0.5 text-left">⚠️ '+escH(_vw)+'</div><label class="flex items-center gap-1 text-[10px] text-amber-700"><input type="checkbox" id="tsRow_'+i+'_okval">確かめました</label>'):'')+'</td>';""",
    'V2b ts row warn')

# V3: 保存時に、点検にひっかかった行はチェックが無ければ保存しない（v188 と同じ作法）
rep("""          var _hasScore=!(score===''||score==null);
          if(!_hasScore && !_ev){ skipped++; continue; }""",
    """          var _hasScore=!(score===''||score==null);
          if(!_hasScore && !_ev){ skipped++; continue; }
          // 📌 __IMPORT_CHECK_V1__ おかしな値は「確かめました」にチェックが無いと保存しない
          var _hd2=(d.header||{}); var _vw2=_impRowWarn({score:score, dupOn:(d.rows[i]&&d.rows[i].dupOn)||''}, (document.getElementById('tsHdrMax')||{}).value||_hd2.maxScore||100);
          if(_vw2){ var _ck=document.getElementById('tsRow_'+i+'_okval'); if(!_ck||!_ck.checked){ needCheck++; continue; } }""",
    'V3a ts save guard')

rep("""        var rows=[]; var skipped=0; var needConfirm=0;
        for(var i=0;i<d.rows.length;i++){
          var uid=gv('tsRow_'+i+'_user'); var score=gv('tsRow_'+i+'_score');""",
    """        var rows=[]; var skipped=0; var needConfirm=0; var needCheck=0;
        for(var i=0;i<d.rows.length;i++){
          var uid=gv('tsRow_'+i+'_user'); var score=gv('tsRow_'+i+'_score');""",
    'V3b ts needCheck var')

rep("""        if(!rows.length){ if(st) st.textContent='保存できる行がありません'+(needConfirm?('（要確認 '+needConfirm+'件は「この子で確定」にチェック）'):'（児童の割り当てと点数を確認）'); return; }""",
    """        if(!rows.length){ if(st) st.textContent='保存できる行がありません'+(needConfirm?('（要確認 '+needConfirm+'件は「この子で確定」にチェック）'):'')+(needCheck?('（要確認の値 '+needCheck+'件は「確かめました」にチェック）'):'')+(!needConfirm&&!needCheck?'（児童の割り当てと点数を確認）':''); return; }""",
    'V3c ts empty msg')

rep("""          if(res&&res.ok){ if(st) st.textContent='✓ '+res.saved+'人分を保存しました'+(skipped?('（未保存 '+skipped+'件）'):'')+(needConfirm?('（要確認 '+needConfirm+'件は候補にチェックで保存）'):'')+'。個人分析・カルテ・アナリティクスに反映され""",
    """          if(res&&res.ok){ if(st) st.textContent='✓ '+res.saved+'人分を保存しました'+(skipped?('（未保存 '+skipped+'件）'):'')+(needConfirm?('（要確認 '+needConfirm+'件は候補にチェックで保存）'):'')+(needCheck?('（要確認の値 '+needCheck+'件は「確かめました」にチェックで保存）'):'')+'。個人分析・カルテ・アナリティクスに反映され""",
    'V3d ts done msg')

# ---- p7 ----
# R1: 記録側プレビュー — 行き先バッジ＋点数欄＋二重取り込みの警告
rep("""          h+='<div class="flex items-center gap-1 mt-1"><span class="text-[10px] text-slate-500">評価:</span><select id="recRow_'+i+'_eval" class="border rounded p-1 text-xs">'+_recEvalOpts(r.evalRank)+'</select><input id="recRo""",
    """          h+='<div class="flex items-center gap-1 mt-1 flex-wrap"><span class="text-[10px] text-slate-500">点数:</span><input id="recRow_'+i+'_score" type="number" class="border rounded p-1 text-xs w-14 text-center'+(_vw?' bg-amber-100 border-amber-400':'')+'" placeholder="—" value="'+escH(String(r.score==null?'':r.score))+'"><span class="text-[10px] text-slate-400">入れると成績へ</span></div>';
          if(_vw){ h+='<div class="text-[10px] text-amber-700 mt-0.5">⚠️ '+escH(_vw)+'<label class="flex items-center gap-1 mt-0.5"><input type="checkbox" id="recRow_'+i+'_okval">確かめました</label></div>'; }
          h+='<div class="flex items-center gap-1 mt-1"><span class="text-[10px] text-slate-500">評価:</span><select id="recRow_'+i+'_eval" class="border rounded p-1 text-xs">'+_recEvalOpts(r.evalRank)+'</select><input id="recRo""",
    'R1a rec score+warn')

rep("""          var r=d.rows[i]; var ms=r.matchStatus||(r.matchedUserId?'auto':'none'); if(ms==='none') unmatched++;
          var _bg=(ms==='auto')?'bg-slate-50':(ms==='cand')?'bg-amber-50':'bg-red-50';""",
    """          var r=d.rows[i]; var ms=r.matchStatus||(r.matchedUserId?'auto':'none'); if(ms==='none') unmatched++;
          var _vw=_impRowWarn(r, 100); if(_vw) _warnN++;
          var _dest=(r.dest==='score')?'<span class="text-[9px] text-white bg-indigo-500 rounded px-1 ml-1">成績へ</span>':'<span class="text-[9px] text-white bg-slate-400 rounded px-1 ml-1">記録へ</span>';
          var _bg=(ms==='auto')?'bg-slate-50':(ms==='cand')?'bg-amber-50':'bg-red-50';""",
    'R1b rec dest badge')

rep("""        var unmatched=0; var h='';
        h+='<div class="space-y-2 max-h-96 overflow-y-auto">';""",
    """        var unmatched=0; var _warnN=0; var h='';
        h+=_impNoteHtml(_impTableNote(d, 100));
        h+='<div class="space-y-2 max-h-96 overflow-y-auto">';""",
    'R1c rec table note')

rep("""          h+='<span class="text-[10px] text-slate-400">読取: '+escH(r.idRaw||'')+' '+escH(r.nameRaw||'')+' '+_bd+'</span>';""",
    """          h+='<span class="text-[10px] text-slate-400">読取: '+escH(r.idRaw||'')+' '+escH(r.nameRaw||'')+' '+_bd+'</span>'+_dest;""",
    'R1d rec badge render')

# R2: saveRecords — 種類3択をやめ、点数/観点別が入った行は成績側へ回す
rep("""        var tsel=document.getElementById('recType'); var rtype=tsel?tsel.value:'report';
        var st=document.getElementById('recSaveStatus');
        var gv=function(id){ var e=document.getElementById(id); return e?e.value:''; };
        var rows=[]; var skipped=0; var needConfirm=0;""",
    """        var st=document.getElementById('recSaveStatus');
        var gv=function(id){ var e=document.getElementById(id); return e?e.value:''; };
        var rows=[]; var scoreRows=[]; var skipped=0; var needConfirm=0; var needCheck=0;""",
    'R2a rec save head')

rep("""          if((!title||!title.trim())&&(!bodyTxt||!bodyTxt.trim())&&(!refl||!refl.trim())&&!er&&(!ec||!ec.trim())){ skipped++; continue; }
          try{ _rememberAlias(cid, (d.rows[i]&&d.rows[i].nameRaw)||'', uid); }catch(_e){}
          rows.push({userId:uid, title:title, body:bodyTxt, reflection:refl, evalRank:er, evalComment:ec, subject:gv('recRow_'+i+'_subject'), unit:gv('recRow_'+i+'_unit'), day:gv('recRow_'+i+'_day')});
        }""",
    """          var _sc=gv('recRow_'+i+'_score');
          var _vw2=_impRowWarn({score:_sc, dupOn:(d.rows[i]&&d.rows[i].dupOn)||''}, 100);
          if(_vw2){ var _ck=document.getElementById('recRow_'+i+'_okval'); if(!_ck||!_ck.checked){ needCheck++; continue; } }
          if((!title||!title.trim())&&(!bodyTxt||!bodyTxt.trim())&&(!refl||!refl.trim())&&!er&&(!ec||!ec.trim())&&(_sc===''||_sc==null)){ skipped++; continue; }
          try{ _rememberAlias(cid, (d.rows[i]&&d.rows[i].nameRaw)||'', uid); }catch(_e){}
          // 📌 __IMPORT_AUTO_V1__ 点数か観点別が入っていれば成績側へ。先生には聞かない。
          var _r0=d.rows[i]||{};
          var _hasSc=!(_sc===''||_sc==null||isNaN(parseInt(_sc,10)));
          var _hasKan=!!(_r0.evalKnowledge||_r0.evalThinking||_r0.evalAttitude);
          if(_hasSc||_hasKan){
            scoreRows.push({userId:uid, _title:title, _subject:gv('recRow_'+i+'_subject'), _day:gv('recRow_'+i+'_day'),
              score:(_hasSc?parseInt(_sc,10):null), evalRank:(er||_r0.evalKnowledge||''),
              evalKnowledge:(_r0.evalKnowledge||er||''), evalThinking:(_r0.evalThinking||''), evalAttitude:(_r0.evalAttitude||''), comment:ec});
            continue;
          }
          rows.push({userId:uid, title:title, body:bodyTxt, reflection:refl, evalRank:er, evalComment:ec, subject:gv('recRow_'+i+'_subject'), unit:gv('recRow_'+i+'_unit'), day:gv('recRow_'+i+'_day')});
        }""",
    'R2b rec save split')

rep("""        if(!rows.length){ if(st) st.textContent='保存できる行がありません（児童の割り当てと内容を確認）'; return; }
        if(st) st.textContent='保存中...';
        fetch('/api/teacher/records/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({classId:cid, type:rtype, rows:rows})}).then(function(r){return r.json();}).then(function(res){""",
    """        if(!rows.length && !scoreRows.length){ if(st) st.textContent='保存できる行がありません'+(needConfirm?('（要確認 '+needConfirm+'件は「確定」にチェック）'):'')+(needCheck?('（要確認の値 '+needCheck+'件は「確かめました」にチェック）'):'')+(!needConfirm&&!needCheck?'（児童の割り当てと内容を確認）':''); return; }
        if(st) st.textContent='保存中...';
        // 点数・観点別が入っていた行は、そのまま成績側（通知表が読む表）へ保存する
        var _scDone=0;
        var _saveScores=function(){
          if(!scoreRows.length) return Promise.resolve(0);
          var _h=scoreRows[0];
          return fetch('/api/teacher/test-scores/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({classId:cid, testName:(_h._title||'取り込み'), testDate:(_h._day||''), subject:(_h._subject||''), maxScore:100, rows:scoreRows})}).then(function(r){return r.json();}).then(function(x){ _scDone=(x&&x.saved)||0; return _scDone; }).catch(function(){ return 0; });
        };
        _saveScores().then(function(){
        if(!rows.length){ if(st) st.textContent='✓ '+_scDone+'人分を成績として保存しました（通知表・分析に反映されます）'; return; }
        return fetch('/api/teacher/records/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({classId:cid, rows:rows})}).then(function(r){return r.json();}).then(function(res){""",
    'R2c rec save call')

rep("""          else { if(st) st.textContent='保存に失敗しました'; }
        }).catch(function(e){ if(st) st.textContent='エラー: '+e.message; });
      }
      function copyTestPrompt(){""",
    """          else { if(st) st.textContent='保存に失敗しました'; }
        });
        }).catch(function(e){ if(st) st.textContent='エラー: '+e.message; });
      }
      function copyTestPrompt(){""",
    'R2d rec save close')

rep("""          if(res&&res.ok){ if(st) st.textContent='✓ '+res.saved+'人分を保存しました'+(skipped?('（未保存 '+skipped+'件）'):'')+(needConfirm?('（要確認 '+needConfirm+'件は「確定」にチェックで保存）'):'')+'。個人分析の""",
    """          if(res&&res.ok){ if(st) st.textContent='✓ '+res.saved+'人分を記録として保存'+(_scDone?('／'+_scDone+'人分を成績として保存'):'')+'しました'+(skipped?('（未保存 '+skipped+'件）'):'')+(needConfirm?('（要確認 '+needConfirm+'件は「確定」にチェックで保存）'):'')+(needCheck?('（要確認の値 '+needCheck+'件は「確かめました」にチェックで保存）'):'')+'。個人分析の""",
    'R2e rec done msg')

# HTML のタグ均衡が崩れていないか（差し替えでいちばん壊れやすいのでここで止める）
import re as _re


def _bal(txt):
    _L = txt.split('\n')
    a = next(i for i, x in enumerate(_L) if 'id="anPane_tests"' in x)
    b = next(i for i, x in enumerate(_L) if 'サブタブ\u2465' in x)
    seg = '\n'.join(_L[a:b])
    return (len(_re.findall(r'<div\b', seg)) - len(_re.findall(r'</div>', seg)),
            len(_re.findall(r'<details\b', seg)) - len(_re.findall(r'</details>', seg)))


def _struct(txt):
    """サブタブ5 の HTML を実際に構文解析して、閉じ忘れ・孤児タグを見つける。
    正規表現の数合わせだけでは <select> の閉じ忘れを取りこぼしたので、パーサで見る。"""
    from html.parser import HTMLParser
    VOID = set(['input', 'br', 'img', 'hr', 'meta', 'link'])
    _L = txt.split('\n')
    a = next(i for i, x in enumerate(_L) if 'id="anPane_tests"' in x)
    b = next(i for i, x in enumerate(_L) if 'サブタブ\u2465' in x)

    class _P(HTMLParser):
        def __init__(self):
            HTMLParser.__init__(self); self.st = []; self.err = []

        def handle_starttag(self, t, attrs):
            if t not in VOID:
                self.st.append(t)

        def handle_endtag(self, t):
            if not self.st:
                self.err.append('余分な </%s>' % t); return
            if self.st[-1] != t:
                self.err.append('</%s> が来たが開いているのは <%s>' % (t, self.st[-1]))
            else:
                self.st.pop()

    q = _P(); q.feed('\n'.join(_L[a:b]))
    return (q.st, q.err)


_orig_text = open(SRC, encoding='utf-8').read()
_s0 = _struct(_orig_text)
_s1 = _struct(s)
print('タグ構造 原本=%s 差し替え後=%s' % (_s0, _s1))
if _s1 != _s0:
    print('NG: サブタブ\u2465 の HTML 構造が原本と違います。書かずに止めます。')
    sys.exit(1)

_b0 = _bal(_orig_text)
_b1 = _bal(s)
print('タグ均衡 原本=%s 差し替え後=%s' % (_b0, _b1))
if _b0 != _b1:
    print('NG: サブタブ\u2465 の div/details の開閉が合いません。書かずに止めます。')
    sys.exit(1)

after = chain_count(s)
if after != CHAIN_BEFORE:
    print('NG: チェーンが %d -> %d に変わりました。書かずに止めます。' % (CHAIN_BEFORE, after))
    sys.exit(1)
for must in ['__IMPORT_AUTO_V1__', '__IMPORT_CHECK_V1__', 'function parseImport(',
             '_impDest', '_impAutoType', '_impRowWarn', '_impTableNote',
             'recDirScore', 'tsRow_', 'recRow_']:
    if must not in s:
        print('NG: %s が入っていません' % must); sys.exit(1)
for gone in ["getElementById('recType')", "gv('recDirType')", "getElementById('recPaste')"]:
    if gone in s:
        print('NG: %s が残っています' % gone); sys.exit(1)
open(SRC, 'w', encoding='utf-8').write(s)
print('OK: 取り込み口を統合しました（チェーン %d のまま）' % after)
