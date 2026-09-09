// ===== ドリルパーク（外部ドリル教材）取り込みAPI __DRILLPARK_V1__ =====
// エクセルの解凍・読み取りはブラウザ側（/drillpark.js）でやり、ここには
// 「読み取り済みの行」だけが JSON で来る。既存のテスト結果取り込みと同じく
//   parse（照合して先生に見せる） → save（先生が確認したものだけ保存）
// の2段構え。
//
// 二重取り込みは row_key（エクセルの行の指紋）に張った UNIQUE で構造的に防ぐ。
// このファイルでは DDL を一切実行しない（テーブルは migrations/0029 で作る）。

function _dpStr(v: any, n: number): string { return String(v == null ? '' : v).slice(0, n) }
function _dpInt(v: any): number | null { const i = parseInt(String(v), 10); return isNaN(i) ? null : i }

// 氏名の正規化。ドリルパークは「伊藤　芽衣」と全角スペース区切りで出てくるが、
// admin_settings.real_name_map 側は「伊藤芽衣」なので、空白を落として突き合わせる。
function _dpNorm(s: any): string {
  let t = String(s == null ? '' : s)
  t = t.replace(/[Ａ-Ｚａ-ｚ０-９]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) - 65248))
  const KY: Record<string, string> = { '髙': '高', '﨑': '崎', '邊': '辺', '邉': '辺', '齊': '斉', '澤': '沢', '廣': '広', '濵': '浜', '眞': '真', '國': '国', '會': '会', '惠': '恵', '槇': '槙' }
  t = t.replace(/[髙﨑邊邉齊澤廣濵眞國會惠槇]/g, (ch) => KY[ch] || ch)
  let o = ''
  for (let i = 0; i < t.length; i++) { const c = t.charCodeAt(i); o += (c >= 0x30a1 && c <= 0x30f6) ? String.fromCharCode(c - 0x60) : t.charAt(i) }
  return o.replace(/[ 　・]/g, '').toLowerCase()
}

// エクセルの「その行」を一意に指す鍵。どの児童に割り当てたかには依存させない
// ＝ 割り当てを変えて取り込み直しても、同じ行は同じ鍵になり二重に入らない。
async function _dpRowKey(r: any): Promise<string> {
  const src = [
    _dpStr(r.doneOn, 20), _dpStr(r.startedAt, 12), _dpStr(r.classLabel, 40),
    (r.attendanceNo == null ? '' : String(r.attendanceNo)),
    _dpNorm(r.rawName), _dpStr(r.subject, 20), _dpStr(r.drillNo, 30), _dpStr(r.material, 200)
  ].join('|')
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('drillpark' + src))
  const b = new Uint8Array(buf)
  let hex = ''
  for (let i = 0; i < b.length; i++) hex += b[i].toString(16).padStart(2, '0')
  return hex
}

async function _dpClass(c: any, u: any, classId: string) {
  return u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first<any>()
}

// 名簿を1回だけ引く（出席番号つき）
async function _dpRoster(c: any, classId: string) {
  const r = await c.env.DB.prepare(
    'SELECT u.id as userId, u.login_id as loginId, u.name, u.roster_no as rosterNo FROM class_members cm JOIN users u ON u.id=cm.user_id WHERE cm.class_id=? ORDER BY (u.roster_no IS NULL), u.roster_no, u.name'
  ).bind(classId).all<any>()
  return (((r && r.results) || []) as any[])
}

app.post('/api/teacher/drillpark/parse', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid')
  const classId = _dpStr(body.classId, 80)
  const cls = await _dpClass(c, u, classId)
  if (!cls) return jsonError(c, 404, 'class_not_found')

  const roster = await _dpRoster(c, classId)

  // 名前の別名（ふりがな）も突き合わせに使う
  let nameMap: Record<string, string> = {}
  try {
    const row = await c.env.DB.prepare(`SELECT value FROM admin_settings WHERE key='real_name_map' LIMIT 1`).first<any>()
    if (row && row.value) { const j = JSON.parse(row.value); if (j && typeof j === 'object') nameMap = j }
  } catch { }

  const byName: Record<string, any[]> = {}
  const byNo: Record<string, any[]> = {}
  for (const m of roster) {
    const keys = [m.name, m.loginId, nameMap[m.loginId], nameMap[m.name]]
    for (const k of keys) { const nk = _dpNorm(k); if (!nk) continue; if (!byName[nk]) byName[nk] = []; if (byName[nk].indexOf(m) < 0) byName[nk].push(m) }
    if (m.rosterNo != null) { const rk = String(m.rosterNo); if (!byNo[rk]) byNo[rk] = []; byNo[rk].push(m) }
  }

  // 児童ごと（＝ファイルに出てくる22人ぶん）に照合する。行ごとではない。
  const students = Array.isArray(body.students) ? body.students : []
  const out = students.map((s: any) => {
    const rawName = _dpStr(s && s.rawName, 80)
    const no = (s && s.attendanceNo != null) ? String(_dpInt(s.attendanceNo)) : ''
    const nk = _dpNorm(rawName)
    const nHit = (byName[nk] && byName[nk].length === 1) ? byName[nk][0] : null
    const noHit = (no && byNo[no] && byNo[no].length === 1) ? byNo[no][0] : null
    let hit: any = null, status = 'none', note = ''
    if (nHit && noHit && nHit.userId === noHit.userId) { hit = nHit; status = 'auto' }
    else if (nHit && !noHit) { hit = nHit; status = 'auto' }
    else if (nHit && noHit) { hit = nHit; status = 'cand'; note = '名前は「' + (nHit.name || '') + '」、出席番号' + no + '番は「' + (noHit.name || '') + '」。食い違っています' }
    else if (noHit) { hit = noHit; status = 'cand'; note = '名前が名簿に無く、出席番号' + no + '番だけで当てています' }
    else if (byName[nk] && byName[nk].length > 1) { status = 'none'; note = '同じ名前の子が名簿に複数います' }
    return {
      key: _dpStr(s && s.key, 120), rawName, attendanceNo: (no === '' ? null : parseInt(no, 10)),
      sessions: _dpInt(s && s.sessions) || 0, totalQ: _dpInt(s && s.totalQ) || 0, correctQ: _dpInt(s && s.correctQ) || 0,
      matchedUserId: hit ? hit.userId : null, matchStatus: hit ? status : 'none',
      matchedName: hit ? (hit.name || hit.loginId || '') : null, note
    }
  })

  return c.json({
    ok: true, classId, className: cls.name || '',
    students: out,
    roster: roster.map((m: any) => ({ userId: m.userId, name: m.name, loginId: m.loginId, rosterNo: m.rosterNo }))
  })
})

app.post('/api/teacher/drillpark/save', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json().catch(() => null)
  if (!body || !Array.isArray(body.rows)) return jsonError(c, 400, 'invalid')
  const classId = _dpStr(body.classId, 80)
  const cls = await _dpClass(c, u, classId)
  if (!cls) return jsonError(c, 404, 'class_not_found')
  if (body.rows.length > 5000) return jsonError(c, 400, 'too_many_rows')

  // 自分のクラスの子にしか書かせない
  const mem = await c.env.DB.prepare('SELECT user_id as uid FROM class_members WHERE class_id=?').bind(classId).all<any>()
  const allowed = new Set((((mem && mem.results) || []) as any[]).map((r: any) => String(r.uid)))

  // 先生が画面で確定した「この子」の割り当て表
  const assign: Record<string, string> = {}
  for (const a of (Array.isArray(body.assignments) ? body.assignments : [])) {
    const k = _dpStr(a && a.key, 120), uid = _dpStr(a && a.userId, 80)
    if (k && uid && allowed.has(uid)) assign[k] = uid
  }

  const nowIso = new Date().toISOString()
  // 取り違えて保存したときに、この1回ぶんだけ取り消せるようにする目印
  const batchId = crypto.randomUUID()
  const stmt = c.env.DB.prepare(
    'INSERT INTO drill_sessions (row_key, user_id, class_id, source, done_on, started_at, subject, drill_no, material, use_type, drill_kind, answer_sec, total_q, correct_q, rate_pct, answers, import_batch, imported_at, imported_by)' +
    ' VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(row_key) DO NOTHING'
  )

  const binds: any[] = []
  let unassigned = 0, invalid = 0
  const seen = new Set<string>()
  let dupInFile = 0
  for (const r of body.rows) {
    const uid = assign[_dpStr(r && r.studentKey, 120)]
    if (!uid) { unassigned++; continue }
    const doneOn = _dpStr(r && r.doneOn, 10)
    if (!/^\d{4}-\d{2}-\d{2}$/.test(doneOn)) { invalid++; continue }
    const answers = _dpStr(r && r.answers, 120).replace(/[^01-]/g, '')
    const totalQ = Math.max(0, Math.min(99, _dpInt(r && r.totalQ) || 0))
    const correctQ = Math.max(0, Math.min(totalQ, _dpInt(r && r.correctQ) || 0))
    const key = await _dpRowKey(r)
    // 同じファイルの中に同じ行が2つあった場合もここで落とす（batch内はUNIQUEで弾けない）
    if (seen.has(key)) { dupInFile++; continue }
    seen.add(key)
    const sec = _dpInt(r && r.answerSec)
    const rate = _dpInt(r && r.ratePct)
    binds.push(stmt.bind(
      key, uid, classId, 'drillpark', doneOn, _dpStr(r && r.startedAt, 8),
      _dpStr(r && r.subject, 20), _dpStr(r && r.drillNo, 30), _dpStr(r && r.material, 200),
      _dpStr(r && r.useType, 20), _dpStr(r && r.drillKind, 30),
      (sec == null ? null : Math.max(0, Math.min(86400, sec))),
      totalQ, correctQ, (rate == null ? null : Math.max(0, Math.min(100, rate))),
      answers, batchId, nowIso, u.id
    ))
  }

  // まとめて書く（1行1往復にしない）
  let inserted = 0
  const CHUNK = 50
  for (let i = 0; i < binds.length; i += CHUNK) {
    const res = await c.env.DB.batch(binds.slice(i, i + CHUNK))
    for (const r of (res as any[])) { if (r && r.meta && r.meta.changes) inserted += r.meta.changes }
  }

  return c.json({
    ok: true,
    batchId,
    received: body.rows.length,
    inserted,
    skippedDuplicate: binds.length - inserted,
    skippedInFile: dupInFile,
    unassigned,
    invalid
  })
})

// 直近の取り込み（取り消しの入口）。画面を閉じたあとでも取り消せるように一覧で返す。
app.get('/api/teacher/drillpark/batches', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const classId = _dpStr(c.req.query('classId'), 80)
  const cls = await _dpClass(c, u, classId)
  if (!cls) return jsonError(c, 404, 'class_not_found')
  const r = await c.env.DB.prepare(
    "SELECT import_batch as batchId, COUNT(*) as rows, COUNT(DISTINCT user_id) as students," +
    " MIN(done_on) as firstDate, MAX(done_on) as lastDate, MAX(imported_at) as importedAt" +
    " FROM drill_sessions WHERE class_id=? AND import_batch IS NOT NULL" +
    " GROUP BY import_batch ORDER BY importedAt DESC LIMIT 10"
  ).bind(classId).all<any>()
  return c.json({ ok: true, batches: (((r && r.results) || []) as any[]) })
})

// 取り違えて保存したときの直し方は「その取り込みぶんを消してから入れ直す」。
// 同じ行は同じ row_key になるため、消さずに入れ直しても上書きされないため。
// 消せるのは自分のクラスの、ドリルパーク取り込みぶんだけ。
app.post('/api/teacher/drillpark/undo', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid')
  const classId = _dpStr(body.classId, 80)
  const batchId = _dpStr(body.batchId, 60)
  if (!batchId) return jsonError(c, 400, 'batch_required')
  const cls = await _dpClass(c, u, classId)
  if (!cls) return jsonError(c, 404, 'class_not_found')
  const res = await c.env.DB.prepare(
    "DELETE FROM drill_sessions WHERE import_batch=? AND class_id=? AND source='drillpark'"
  ).bind(batchId, classId).run()
  const deleted = (res && res.meta && res.meta.changes) || 0
  return c.json({ ok: true, deleted })
})

app.get('/drillpark.js', async (c) => {
  try {
    // @ts-ignore - Cloudflare Pages provides a static assets binding.
    const a = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/drillpark.js')))
    if (a && a.status === 200) return new Response(await a.text(), { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } })
  } catch { }
  return c.text('// drillpark.js not found', 404, { 'content-type': 'application/javascript; charset=utf-8' })
})

// ドリルパークのログを「先生が助言に使える形」にまとめる。
// 単元ごとの正答率より一段細かく、「どの教材の何問目でつまずいたか」まで出す。
function _dpAnalyze(rows: any[]) {
  if (!rows || !rows.length) return null
  const bySubject: Record<string, any> = {}
  const byMaterial: Record<string, any> = {}
  let totalQ = 0, correctQ = 0, sessions = 0, seconds = 0
  const days: Record<string, number> = {}
  const missed: any[] = []
  // 「前半は解けるが後半で崩れる」を見るための、問番号の位置ごとの正答率
  const pos = { early: { t: 0, c: 0 }, late: { t: 0, c: 0 } }

  for (const r of rows) {
    sessions++
    days[r.done_on] = (days[r.done_on] || 0) + 1
    // 秒のまま足す。1回ずつ分に丸めると、30秒未満の短いドリルが全部0分になって消える。
    seconds += (r.answer_sec || 0)
    totalQ += r.total_q || 0
    correctQ += r.correct_q || 0
    const sub = r.subject || 'その他'
    if (!bySubject[sub]) bySubject[sub] = { subject: sub, sessions: 0, total: 0, correct: 0 }
    bySubject[sub].sessions++; bySubject[sub].total += r.total_q || 0; bySubject[sub].correct += r.correct_q || 0
    const mk = sub + '／' + (r.material || '(教材名なし)')
    if (!byMaterial[mk]) byMaterial[mk] = { subject: sub, material: r.material || '', drillNo: r.drill_no || '', tries: 0, total: 0, correct: 0, sec: 0, lastDate: '' }
    const bm = byMaterial[mk]
    bm.tries++; bm.total += r.total_q || 0; bm.correct += r.correct_q || 0; bm.sec += (r.answer_sec || 0)
    if (String(r.done_on) > String(bm.lastDate)) bm.lastDate = r.done_on

    const a = String(r.answers || '')
    const wrong: number[] = []
    for (let i = 0; i < a.length; i++) {
      const ch = a.charAt(i)
      if (ch !== '0' && ch !== '1') continue
      const bucket = (i < 5) ? pos.early : pos.late
      bucket.t++; if (ch === '1') bucket.c++
      if (ch === '0') wrong.push(i + 1)
    }
    if (wrong.length) missed.push({ date: r.done_on, subject: sub, material: r.material || '', drillNo: r.drill_no || '', wrongQ: wrong, total: r.total_q || 0 })
  }

  const rate = (t: number, cc: number) => (t ? Math.round(cc / t * 100) : null)
  const subjects = Object.keys(bySubject).map((k) => { const v = bySubject[k]; v.rate = rate(v.total, v.correct); return v })
    .sort((a, b) => b.total - a.total)
  const materials = Object.keys(byMaterial).map((k) => { const v = byMaterial[k]; v.rate = rate(v.total, v.correct); return v })
    .sort((a, b) => (String(b.lastDate) > String(a.lastDate) ? 1 : -1))
  const weakMaterials = materials.filter((m) => m.total >= 4 && m.rate != null && m.rate < 70)
    .sort((a, b) => a.rate - b.rate).slice(0, 8)
  const strongMaterials = materials.filter((m) => m.total >= 4 && m.rate != null && m.rate >= 90)
    .sort((a, b) => b.total - a.total).slice(0, 8)
  const dayKeys = Object.keys(days).sort()

  return {
    overview: {
      sessions, totalQ, correctQ, ratePct: rate(totalQ, correctQ),
      dayCount: dayKeys.length, firstDate: dayKeys[0] || '', lastDate: dayKeys[dayKeys.length - 1] || '',
      seconds, minutes: Math.round(seconds / 60)
    },
    subjects,
    materials: materials.slice(0, 40),
    weakMaterials,
    strongMaterials,
    // 5問目までと6問目以降。差が大きければ「後半で集中が切れている」の材料になる。
    // ただし数問しか出ていないのに「後半0%」と出すと誤読のもとなので、
    // 20問に満たないうちは率を出さない（enough=false のときは使わないこと）。
    position: {
      early: (pos.early.t >= 20 ? rate(pos.early.t, pos.early.c) : null),
      late: (pos.late.t >= 20 ? rate(pos.late.t, pos.late.c) : null),
      earlyN: pos.early.t, lateN: pos.late.t,
      enough: (pos.early.t >= 20 && pos.late.t >= 20)
    },
    // 直近の誤答を「教材＋何問目」で。ここが一番具体的な助言の種になる
    recentMisses: missed.slice(0, 30)
  }
}
