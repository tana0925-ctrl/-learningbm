
// ==================== __TEACHER_RECOVERY_V1__ ====================
// 教師用ログイン復旧（一覧 / 絞り込み / 一括パスワード再発行 / 印刷）
// 設計上の約束:
//   - すべて requireTeacher の内側。対象は「自分が担任のクラス(classes.teacher_id = 自分)」の児童のみ。
//   - DDL は一切走らせない（新テーブル・新カラムなし＝マイグレーション不要）。
//   - state_json には絶対に触れない。
//   - UPDATE するのは password_hash / password_salt / password_updated_at / must_change_password のみ。
//   - 送られてきた studentId は必ず DB 側で担任クラス所属を再照合し、通らないものは捨てる。
//   - ポーリングなし（画面を開いた時と「再読み込み」を押した時だけ取得）。
//   - users.last_login_at / roster_no / secret_question が無い環境でも動くようフォールバックする。

const _TR_MAX_BULK = 10

async function _trUserCols(c: any): Promise<Record<string, boolean>> {
  const cols: Record<string, boolean> = {}
  try {
    const r = await c.env.DB.prepare(`SELECT name FROM pragma_table_info('users')`).all<any>()
    const rows = (r && r.results) ? r.results : []
    for (let i = 0; i < rows.length; i++) cols[String(rows[i].name)] = true
  } catch (_e) { /* 取れなければ最小構成で動く */ }
  return cols
}

// users に列が無い環境（migrations に last_login_at が無い等）でも落ちないように、
// 実在する列だけを SELECT する。DDL は一切走らせない。
async function _trSelectStudents(c: any, teacherId: string) {
  const cols = await _trUserCols(c)
  const hasLastLogin = !!cols['last_login_at']
  const hasRoster = !!cols['roster_no']
  const hasSecretCol = !!cols['secret_question']

  const sel: string[] = [
    'u.id as userId',
    'u.login_id as loginId',
    'u.name as name',
    'u.grade as grade',
    'u.class_name as className'
  ]
  sel.push(hasRoster ? 'u.roster_no as rosterNo' : 'NULL as rosterNo')
  sel.push(hasLastLogin ? 'u.last_login_at as lastLoginAt' : 'NULL as lastLoginAt')
  sel.push(hasSecretCol
    ? `CASE WHEN u.secret_question IS NOT NULL AND TRIM(u.secret_question) <> '' THEN 1 ELSE 0 END as hasSecret`
    : 'NULL as hasSecret')

  const order: string[] = ['u.grade', 'u.class_name']
  if (hasRoster) order.push('u.roster_no')
  order.push('u.login_id')

  const sql = `SELECT DISTINCT ${sel.join(', ')}
     FROM users u
     JOIN class_members cm ON cm.user_id = u.id
     JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
     WHERE u.role = 'student'
     ORDER BY ${order.join(', ')}`

  const r = await c.env.DB.prepare(sql).bind(teacherId).all<any>()
  return {
    rows: (r && r.results) ? r.results : [],
    hasLastLogin,
    hasRoster,
    hasSecretCol
  }
}

// 一覧取得（担任クラスのみ）
app.get('/api/teacher/recovery/students', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  let rows: any[] = []
  let hasLastLogin = false
  let hasSecretCol = false
  try {
    const r = await _trSelectStudents(c, u.id)
    rows = r.rows
    hasLastLogin = r.hasLastLogin
    hasSecretCol = r.hasSecretCol
  } catch (_e: any) {
    return jsonError(c, 500, 'db_error')
  }
  let map: Record<string, string> = {}
  let furi: Record<string, string> = {}
  try {
    const row = await c.env.DB.prepare(`SELECT value FROM admin_settings WHERE key='real_name_map' LIMIT 1`).first<any>()
    if (row && row.value) map = JSON.parse(row.value) || {}
  } catch (_e) { map = {} }
  try {
    const rf = await c.env.DB.prepare(`SELECT value FROM admin_settings WHERE key='real_furigana_map' LIMIT 1`).first<any>()
    if (rf && rf.value) furi = JSON.parse(rf.value) || {}
  } catch (_e) { furi = {} }
  const students = rows.map((r: any) => {
    const lid = String(r.loginId == null ? '' : r.loginId)
    return {
      userId: r.userId,
      loginId: lid,
      name: r.name || '',
      grade: (r.grade == null ? null : r.grade),
      className: r.className || '',
      rosterNo: (r.rosterNo == null ? null : r.rosterNo),
      lastLoginAt: r.lastLoginAt || null,
      hasSecret: !!r.hasSecret,
      realName: map[lid] || '',
      furigana: furi[lid] || '',
      wideId: /[^ -~]/.test(lid)
    }
  })
  return c.json({ ok: true, students, lastLoginAvailable: hasLastLogin, secretQuestionAvailable: hasSecretCol })
})

// 一括パスワード再発行（担任クラスの児童だけ／1回あたり最大 _TR_MAX_BULK 人）
app.post('/api/teacher/recovery/bulk-reset', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const body = await c.req.json().catch(() => null)
  if (!body || !Array.isArray(body.studentIds)) return jsonError(c, 400, 'studentIds_required')
  const seen: Record<string, boolean> = {}
  const ids: string[] = []
  for (let i = 0; i < body.studentIds.length; i++) {
    const s = String(body.studentIds[i] == null ? '' : body.studentIds[i]).trim()
    if (!s || seen[s]) continue
    seen[s] = true
    ids.push(s)
    if (ids.length >= _TR_MAX_BULK) break
  }
  if (!ids.length) return jsonError(c, 400, 'studentIds_empty')

  // 担任クラス所属かを DB 側で再照合（通らない id はここで落ちる）
  const ph = ids.map(() => '?').join(',')
  let owned: any[] = []
  try {
    const r = await c.env.DB.prepare(
      `SELECT DISTINCT u.id as userId, u.login_id as loginId, u.name as name
       FROM users u
       JOIN class_members cm ON cm.user_id = u.id
       JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
       WHERE u.role = 'student' AND u.id IN (${ph})`
    ).bind(u.id, ...ids).all<any>()
    owned = (r && r.results) ? r.results : []
  } catch (_e: any) {
    return jsonError(c, 500, 'db_error')
  }

  const results: any[] = []
  for (let i = 0; i < owned.length; i++) {
    const s = owned[i]
    const newPassword = genKidPassword()
    const salt = randomHex(16)
    const hash = await pbkdf2Hash(newPassword, salt)
    await c.env.DB.prepare(
      `UPDATE users SET password_hash=?, password_salt=?, password_updated_at=datetime('now'), must_change_password=0
       WHERE id=? AND role='student'`
    ).bind(hash, salt, s.userId).run()
    results.push({ userId: s.userId, loginId: String(s.loginId == null ? '' : s.loginId), name: s.name || '', newPassword })
  }
  const okMap: Record<string, boolean> = {}
  for (let i = 0; i < results.length; i++) okMap[results[i].userId] = true
  const skipped = ids.filter((x) => !okMap[x])
  return c.json({ ok: true, results, skipped })
})

// 教師用ログイン復旧 画面（担任クラスのみ。未ログイン/権限なしは /login へ）
app.get('/teacher-recovery', (c) => {
  return c.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ログイン復旧（先生用）</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body{font-family:"Hiragino Maru Gothic ProN","Hiragino Sans","Yu Gothic","Meiryo",sans-serif;}
  .mono{font-family:"SFMono-Regular",Consolas,"Courier New",monospace;letter-spacing:.06em;}
  .cards{display:grid;grid-template-columns:1fr 1fr;gap:0;}
  .rcard{border:1px dashed #94a3b8;box-sizing:border-box;padding:6mm;height:63mm;page-break-inside:avoid;break-inside:avoid;}
  @media print{
    @page{size:A4;margin:8mm;}
    body{background:#fff !important;}
    body *{visibility:hidden !important;}
    .print-now,.print-now *{visibility:visible !important;}
    .print-now{position:absolute !important;left:0;top:0;width:100%;margin:0 !important;padding:0 !important;box-shadow:none !important;border:0 !important;background:#fff !important;}
    .no-print{display:none !important;}
  }
</style>
</head>
<body class="min-h-screen bg-slate-50 p-4">
<div class="max-w-6xl mx-auto space-y-4">

  <div class="bg-white rounded-xl shadow p-4 flex items-center justify-between no-print">
    <div>
      <h1 class="text-xl font-bold">🆘 ログイン復旧（先生用）</h1>
      <p class="text-sm text-slate-500">担任クラスの児童だけが表示されます。パスワードは復元できないため「新しく作り直す」方式です。</p>
    </div>
    <div class="flex gap-2 items-center">
      <button id="reloadBtn" class="text-sm px-3 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold">↻ 再読み込み</button>
      <a href="/teacher" class="text-sm px-3 py-1 rounded bg-emerald-100 hover:bg-emerald-200 text-emerald-700 font-bold">← 教師ダッシュボード</a>
    </div>
  </div>

  <div id="err" class="hidden bg-red-50 border-2 border-red-300 text-red-800 rounded-xl p-4 font-bold no-print"></div>

  <div id="mainArea" class="space-y-4 no-print">
    <div class="bg-white rounded-xl shadow p-4">
      <h2 class="font-bold mb-2">① まず「入れていない子」をしぼりこむ</h2>
      <div class="flex flex-wrap gap-2 items-center text-sm">
        <span class="text-slate-500">この日から</span>
        <input id="cutoff" type="date" class="border rounded p-1.5 text-sm">
        <span class="text-slate-500">以降にログインしていない子</span>
        <button id="fNoLogin" class="bg-amber-500 hover:bg-amber-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold">この条件でえらぶ</button>
        <span class="mx-1 text-slate-300">|</span>
        <button id="pPreset1" class="bg-slate-100 hover:bg-slate-200 rounded px-2 py-1 text-xs font-bold">2学期(9/1)</button>
        <button id="pPreset2" class="bg-slate-100 hover:bg-slate-200 rounded px-2 py-1 text-xs font-bold">3学期(1/8)</button>
        <button id="pPreset3" class="bg-slate-100 hover:bg-slate-200 rounded px-2 py-1 text-xs font-bold">1学期(4/1)</button>
      </div>
      <div class="flex flex-wrap gap-2 items-center text-sm mt-3">
        <button id="fNever" class="bg-rose-100 hover:bg-rose-200 text-rose-700 rounded-lg px-3 py-1.5 text-xs font-bold">一度もログインしていない子</button>
        <button id="fNoSecret" class="bg-indigo-100 hover:bg-indigo-200 text-indigo-700 rounded-lg px-3 py-1.5 text-xs font-bold">ひみつのしつもん未登録の子</button>
        <button id="fWide" class="bg-fuchsia-100 hover:bg-fuchsia-200 text-fuchsia-700 rounded-lg px-3 py-1.5 text-xs font-bold">全角IDの子</button>
        <span class="mx-1 text-slate-300">|</span>
        <button id="fAll" class="bg-slate-100 hover:bg-slate-200 rounded px-2 py-1 text-xs font-bold">全員えらぶ</button>
        <button id="fNone" class="bg-slate-100 hover:bg-slate-200 rounded px-2 py-1 text-xs font-bold">選択をクリア</button>
      </div>
      <p id="lastLoginNote" class="hidden text-xs text-amber-700 font-bold mt-2">※ この環境では「最終ログイン日時」が取得できないため、日付での絞り込みは使えません。</p>
    </div>

    <div class="bg-white rounded-xl shadow p-4">
      <div class="flex items-center justify-between mb-2 flex-wrap gap-2">
        <h2 class="font-bold">② 児童一覧 <span id="cnt" class="text-sm font-normal text-slate-500"></span></h2>
        <div class="flex items-center gap-2">
          <span id="selCnt" class="text-sm font-bold text-emerald-700"></span>
          <button id="resetBtn" class="bg-slate-800 hover:bg-black text-white rounded-lg px-4 py-2 text-sm font-bold disabled:opacity-40" disabled>③ えらんだ子のパスワードを一括で作り直す</button>
        </div>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead><tr class="text-left text-slate-500 border-b">
            <th class="p-2 w-10"><input id="chkAll" type="checkbox"></th>
            <th class="p-2 w-12">番号</th>
            <th class="p-2">名前（ふりがな）</th>
            <th class="p-2">ログインID</th>
            <th class="p-2 w-24">ひみつの<br>しつもん</th>
            <th class="p-2 w-40">最終ログイン</th>
          </tr></thead>
          <tbody id="tbody"></tbody>
        </table>
      </div>
      <p id="empty" class="hidden text-sm text-slate-400 p-4">担任クラスの児童が見つかりませんでした。</p>
    </div>

    <div id="progress" class="hidden bg-white rounded-xl shadow p-4">
      <p class="font-bold text-slate-700">作り直しています… <span id="progTxt"></span></p>
      <div class="mt-2 h-2 rounded-full bg-slate-100 overflow-hidden"><div id="progBar" style="width:0%;height:100%;background:#10b981"></div></div>
    </div>
  </div>

  <div id="resultWrap" class="hidden space-y-4">
    <div class="bg-red-600 text-white rounded-xl p-5 shadow-lg no-print">
      <div class="text-lg font-black">⚠️ この画面を閉じると、新しいパスワードは二度と表示できません。</div>
      <div class="text-sm mt-1">先に印刷してください。（パスワードは暗号化して保存されるため、あとから取り出すことはできません。もう一度この画面で作り直すことはできます。）</div>
      <div class="mt-3 flex flex-wrap gap-2">
        <button id="printCards" class="bg-white text-red-700 rounded-lg px-4 py-2 text-sm font-black hover:bg-red-50">🖨 くばるカードを印刷（A4）</button>
        <button id="printList" class="bg-white text-red-700 rounded-lg px-4 py-2 text-sm font-black hover:bg-red-50">🖨 先生の手元用の一覧表を印刷</button>
        <button id="doneBtn" class="bg-red-800 text-white rounded-lg px-4 py-2 text-sm font-bold hover:bg-red-900">印刷しました（画面にもどる）</button>
      </div>
    </div>

    <div id="skipNote" class="hidden bg-amber-50 border-2 border-amber-300 text-amber-800 rounded-xl p-3 text-sm font-bold no-print"></div>

    <div id="cardsArea" class="bg-white rounded-xl shadow p-2 printable">
      <div id="cardsBox" class="cards"></div>
    </div>

    <div id="listArea" class="bg-white rounded-xl shadow p-4 printable">
      <h2 class="font-bold mb-2">先生の手元用 一覧表</h2>
      <table class="w-full text-sm border-collapse" id="listTable"></table>
    </div>
  </div>

</div>
<script>
(function(){
  var STUDENTS = [];
  var SEL = {};
  var RESULTS = [];
  var LAST_LOGIN_OK = true;
  var SECRET_OK = true;
  var CHUNK = 5;

  function $(id){ return document.getElementById(id); }
  function esc(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
  function pad(n){ return (n<10?'0':'')+n; }
  function jstDate(s){
    if(!s) return null;
    var d = new Date(String(s).replace(' ','T')+'Z');
    if(isNaN(d.getTime())) return null;
    return new Date(d.getTime()+9*3600000);
  }
  function fmtJst(s){
    var d = jstDate(s); if(!d) return '';
    return d.getUTCFullYear()+'/'+pad(d.getUTCMonth()+1)+'/'+pad(d.getUTCDate())+' '+pad(d.getUTCHours())+':'+pad(d.getUTCMinutes());
  }
  function ymdJst(s){
    var d = jstDate(s); if(!d) return null;
    return d.getUTCFullYear()+'-'+pad(d.getUTCMonth()+1)+'-'+pad(d.getUTCDate());
  }
  function nowJst(){ var n=new Date(); return new Date(n.getTime()+9*3600000); }
  function dispName(s){ return s.realName || s.name || s.loginId; }

  function defaultCutoff(){
    var n = nowJst(); var y = n.getUTCFullYear(); var m = n.getUTCMonth()+1;
    if(m >= 9) return y+'-09-01';
    if(m >= 4) return y+'-04-01';
    return y+'-01-08';
  }
  function presetYear(mm, dd){
    var n = nowJst(); var y = n.getUTCFullYear(); var m = n.getUTCMonth()+1;
    if(mm > m) y = y - 1;
    return y+'-'+pad(mm)+'-'+pad(dd);
  }

  function showErr(msg){ var e=$('err'); e.textContent=msg; e.classList.remove('hidden'); }

  function selCount(){ var n=0; for(var k in SEL){ if(SEL[k]) n++; } return n; }
  function refreshSel(){
    var n = selCount();
    $('selCnt').textContent = n ? (n+'人 選択中') : '';
    $('resetBtn').disabled = (n === 0);
    for(var i=0;i<STUDENTS.length;i++){
      var cb = $('cb_'+i);
      if(cb) cb.checked = !!SEL[STUDENTS[i].userId];
    }
  }

  function render(){
    var tb = $('tbody'); tb.innerHTML='';
    $('cnt').textContent = '（'+STUDENTS.length+'人）';
    if(!STUDENTS.length){ $('empty').classList.remove('hidden'); return; }
    $('empty').classList.add('hidden');
    var h = [];
    for(var i=0;i<STUDENTS.length;i++){
      var s = STUDENTS[i];
      var ll = s.lastLoginAt ? fmtJst(s.lastLoginAt) : '<span class="text-rose-600 font-bold">一度もなし</span>';
      if(!LAST_LOGIN_OK) ll = '<span class="text-slate-400">—</span>';
      var sq = SECRET_OK ? (s.hasSecret?'<span class="text-emerald-600 font-bold">○ 登録ずみ</span>':'<span class="text-slate-400">− 未登録</span>') : '<span class="text-slate-400">—</span>';
      h.push('<tr class="border-b hover:bg-emerald-50">');
      h.push('<td class="p-2"><input type="checkbox" id="cb_'+i+'" data-i="'+i+'" class="rowchk"></td>');
      h.push('<td class="p-2 text-slate-500">'+(s.rosterNo==null?'':esc(s.rosterNo))+'</td>');
      h.push('<td class="p-2"><span class="font-bold">'+esc(dispName(s))+'</span>'+(s.furigana?('<span class="text-xs text-slate-400 ml-1">'+esc(s.furigana)+'</span>'):'')+(s.name && s.realName && s.name!==s.realName?('<span class="text-xs text-slate-300 ml-1">('+esc(s.name)+')</span>'):'')+'</td>');
      h.push('<td class="p-2"><span class="mono font-bold">'+esc(s.loginId)+'</span>'+(s.wideId?'<span class="ml-2 text-[10px] bg-fuchsia-100 text-fuchsia-700 rounded-full px-2 py-0.5 font-bold">全角ID</span>':'')+'</td>');
      h.push('<td class="p-2">'+sq+'</td>');
      h.push('<td class="p-2 text-slate-600">'+ll+'</td>');
      h.push('</tr>');
    }
    tb.innerHTML = h.join('');
    var chks = document.querySelectorAll('.rowchk');
    for(var j=0;j<chks.length;j++){
      chks[j].onchange = function(){
        var idx = Number(this.getAttribute('data-i'));
        SEL[STUDENTS[idx].userId] = this.checked;
        refreshSel();
      };
    }
    refreshSel();
  }

  function selectBy(fn){
    SEL = {};
    for(var i=0;i<STUDENTS.length;i++){ if(fn(STUDENTS[i])) SEL[STUDENTS[i].userId]=true; }
    $('chkAll').checked = false;
    refreshSel();
  }

  function load(){
    fetch('/api/teacher/recovery/students', {headers:{'accept':'application/json'}}).then(function(r){
      if(r.status===401 || r.status===403){ location.href='/login'; return null; }
      return r.json();
    }).then(function(j){
      if(!j) return;
      if(!j.ok){ showErr('読み込みに失敗しました: '+(j.error||'')); return; }
      STUDENTS = j.students || [];
      LAST_LOGIN_OK = (j.lastLoginAvailable !== false);
      SECRET_OK = (j.secretQuestionAvailable !== false);
      if(!LAST_LOGIN_OK){
        $('lastLoginNote').classList.remove('hidden');
        $('fNoLogin').disabled=true; $('fNoLogin').classList.add('opacity-40');
        $('fNever').disabled=true; $('fNever').classList.add('opacity-40');
      }
      if(!SECRET_OK){ $('fNoSecret').disabled=true; $('fNoSecret').classList.add('opacity-40'); }
      SEL = {};
      render();
    }).catch(function(){ showErr('通信エラーが起きました。もう一度お試しください。'); });
  }

  function buildResultViews(){
    var ch = [];
    for(var i=0;i<RESULTS.length;i++){
      var r = RESULTS[i];
      ch.push('<div class="rcard">');
      ch.push('<div style="font-size:10px;color:#94a3b8">✂ - - - きりとって わたしてください - - -</div>');
      ch.push('<div style="font-size:20px;font-weight:800;margin-top:4mm">'+esc(r.dispName)+' さん</div>');
      ch.push('<div style="margin-top:5mm"><div style="font-size:11px;color:#64748b;font-weight:700">ログインID</div>');
      ch.push('<div class="mono" style="font-size:30px;font-weight:800;line-height:1.2">'+esc(r.loginId)+'</div>');
      if(r.wideId) ch.push('<div style="font-size:10px;color:#a21caf;font-weight:700">※ このIDは「全角」です。かなキーで全角にして入力してね</div>');
      ch.push('</div>');
      ch.push('<div style="margin-top:4mm"><div style="font-size:11px;color:#64748b;font-weight:700">あたらしいパスワード</div>');
      ch.push('<div class="mono" style="font-size:30px;font-weight:800;line-height:1.2;color:#b91c1c">'+esc(r.newPassword)+'</div></div>');
      ch.push('<div style="font-size:10px;color:#94a3b8;margin-top:3mm">入れたら、じぶんの好きなパスワードに変えてもOK</div>');
      ch.push('</div>');
    }
    while(ch.length && (RESULTS.length % 2) === 1){ ch.push('<div class="rcard" style="border-color:transparent"></div>'); break; }
    $('cardsBox').innerHTML = ch.join('');

    var lh = [];
    lh.push('<thead><tr><th style="border:1px solid #cbd5e1;padding:6px;text-align:left">番号</th><th style="border:1px solid #cbd5e1;padding:6px;text-align:left">名前</th><th style="border:1px solid #cbd5e1;padding:6px;text-align:left">ログインID</th><th style="border:1px solid #cbd5e1;padding:6px;text-align:left">あたらしいパスワード</th><th style="border:1px solid #cbd5e1;padding:6px;text-align:left">わたした✓</th></tr></thead><tbody>');
    for(var k=0;k<RESULTS.length;k++){
      var q = RESULTS[k];
      lh.push('<tr>');
      lh.push('<td style="border:1px solid #cbd5e1;padding:6px">'+(q.rosterNo==null?'':esc(q.rosterNo))+'</td>');
      lh.push('<td style="border:1px solid #cbd5e1;padding:6px">'+esc(q.dispName)+'</td>');
      lh.push('<td style="border:1px solid #cbd5e1;padding:6px" class="mono">'+esc(q.loginId)+(q.wideId?' (全角)':'')+'</td>');
      lh.push('<td style="border:1px solid #cbd5e1;padding:6px;font-weight:800" class="mono">'+esc(q.newPassword)+'</td>');
      lh.push('<td style="border:1px solid #cbd5e1;padding:6px;width:70px"></td>');
      lh.push('</tr>');
    }
    lh.push('</tbody>');
    $('listTable').innerHTML = lh.join('');
  }

  function doPrint(elId){
    var els = document.querySelectorAll('.printable');
    for(var i=0;i<els.length;i++) els[i].classList.remove('print-now');
    $(elId).classList.add('print-now');
    window.print();
    setTimeout(function(){ $(elId).classList.remove('print-now'); }, 800);
  }

  async function runReset(){
    var ids = [];
    for(var i=0;i<STUDENTS.length;i++){ if(SEL[STUDENTS[i].userId]) ids.push(STUDENTS[i].userId); }
    if(!ids.length) return;
    if(!confirm(ids.length+'人のパスワードを新しく作り直します。\\n\\n・今のパスワードは使えなくなります\\n・新しいパスワードはこのあと一度だけ表示されます（必ず印刷してください）\\n\\nすすめてよいですか？')) return;

    var byId = {};
    for(var m=0;m<STUDENTS.length;m++) byId[STUDENTS[m].userId]=STUDENTS[m];

    $('resetBtn').disabled = true;
    $('progress').classList.remove('hidden');
    RESULTS = [];
    var skipped = [];
    var done = 0;
    try{
      for(var p=0;p<ids.length;p+=CHUNK){
        var chunk = ids.slice(p, p+CHUNK);
        var r = await fetch('/api/teacher/recovery/bulk-reset', {
          method:'POST', headers:{'content-type':'application/json'},
          body: JSON.stringify({ studentIds: chunk })
        });
        if(r.status===401 || r.status===403){ showErr('権限がありません。ログインし直してください。'); $('progress').classList.add('hidden'); return; }
        var j = await r.json().catch(function(){ return null; });
        if(!r.ok || !j || !j.ok){ throw new Error((j && j.error) || ('HTTP '+r.status)); }
        for(var q=0;q<j.results.length;q++){
          var it = j.results[q];
          var src = byId[it.userId] || {};
          RESULTS.push({
            userId: it.userId,
            loginId: it.loginId,
            newPassword: it.newPassword,
            dispName: (src.realName || it.name || it.loginId),
            rosterNo: (src.rosterNo==null?null:src.rosterNo),
            wideId: !!src.wideId
          });
        }
        if(j.skipped && j.skipped.length){ for(var w=0;w<j.skipped.length;w++) skipped.push(j.skipped[w]); }
        done += chunk.length;
        $('progTxt').textContent = done+' / '+ids.length+' 人';
        $('progBar').style.width = Math.round(done/ids.length*100)+'%';
      }
    }catch(e){
      showErr('途中でエラーが起きました（'+(e && e.message ? e.message : '不明')+'）。ここまでに作り直せた分は下に表示します。必ず印刷してください。');
    }
    $('progress').classList.add('hidden');
    $('resetBtn').disabled = false;
    if(!RESULTS.length){ showErr('1人も作り直せませんでした。担任クラスの児童かどうかご確認ください。'); return; }
    RESULTS.sort(function(a,b){
      var x = (a.rosterNo==null?9999:a.rosterNo), y=(b.rosterNo==null?9999:b.rosterNo);
      if(x!==y) return x-y;
      return String(a.loginId).localeCompare(String(b.loginId));
    });
    buildResultViews();
    if(skipped.length){
      var sn = $('skipNote');
      sn.textContent = skipped.length+'人ぶんは担任クラスの児童として確認できなかったため、変更していません。';
      sn.classList.remove('hidden');
    }
    $('mainArea').classList.add('hidden');
    $('resultWrap').classList.remove('hidden');
    window.scrollTo(0,0);
    window.onbeforeunload = function(){ return '新しいパスワードはこの画面を閉じると二度と表示できません。印刷は終わりましたか？'; };
  }

  $('cutoff').value = defaultCutoff();
  $('pPreset1').onclick = function(){ $('cutoff').value = presetYear(9,1); };
  $('pPreset2').onclick = function(){ $('cutoff').value = presetYear(1,8); };
  $('pPreset3').onclick = function(){ $('cutoff').value = presetYear(4,1); };
  $('fNoLogin').onclick = function(){
    var cut = $('cutoff').value;
    if(!cut){ alert('日付を入れてください'); return; }
    selectBy(function(s){ var y = ymdJst(s.lastLoginAt); return (y === null) || (y < cut); });
  };
  $('fNever').onclick = function(){ selectBy(function(s){ return !s.lastLoginAt; }); };
  $('fNoSecret').onclick = function(){ selectBy(function(s){ return !s.hasSecret; }); };
  $('fWide').onclick = function(){ selectBy(function(s){ return !!s.wideId; }); };
  $('fAll').onclick = function(){ selectBy(function(){ return true; }); };
  $('fNone').onclick = function(){ selectBy(function(){ return false; }); };
  $('chkAll').onchange = function(){ var v=this.checked; selectBy(function(){ return v; }); $('chkAll').checked = v; };
  $('reloadBtn').onclick = function(){ load(); };
  $('resetBtn').onclick = function(){ runReset(); };
  $('printCards').onclick = function(){ doPrint('cardsArea'); };
  $('printList').onclick = function(){ doPrint('listArea'); };
  $('doneBtn').onclick = function(){
    if(!confirm('印刷は終わりましたか？　画面をもどすと、新しいパスワードは二度と表示できません。')) return;
    window.onbeforeunload = null;
    location.reload();
  };

  load();
})();
</script>
</body></html>`)
})

// ==================== /__TEACHER_RECOVERY_V1__ ====================

