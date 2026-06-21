import sys

def patch_file(path, edits):
    with open(path,'r',encoding='utf-8',newline='') as f:
        data=f.read()
    for old,new in edits:
        if new in data and old not in data:
            print('skip:',repr(old[:40])); continue
        if old not in data:
            print('ANCHOR NOT FOUND',path,repr(old[:70])); sys.exit(1)
        if data.count(old)!=1:
            print('NOT UNIQUE',data.count(old),repr(old[:70])); sys.exit(1)
        data=data.replace(old,new); print('ok',path,repr(old[:40]))
    with open(path,'w',encoding='utf-8',newline='') as f:
        f.write(data)

SRC_EDITS = [
    ('// ===== 授業メモAPI（クラス全体メモ＋児童ごとメモ・教師は自分のクラスのみ） =====',
     'app.post(\'/api/teacher/records/save\', async (c) => {\n  const u = c.get(\'user\')\n  if (!u || (u.role !== \'teacher\' && u.role !== \'admin\')) return jsonError(c, 403, \'forbidden\')\n  const body = await c.req.json().catch(() => null)\n  if (!body || !Array.isArray(body.rows)) return jsonError(c, 400, \'invalid\')\n  const classId = String(body.classId || \'\')\n  const cls = u.role === \'admin\'\n    ? await c.env.DB.prepare(\'SELECT id FROM classes WHERE id=? LIMIT 1\').bind(classId).first<any>()\n    : await c.env.DB.prepare(\'SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1\').bind(classId, u.id).first<any>()\n  if (!cls) return jsonError(c, 404, \'class_not_found\')\n  const mem = (((await c.env.DB.prepare(\'SELECT user_id as uid FROM class_members WHERE class_id=?\').bind(classId).all<any>()).results) || [])\n  const allowed = new Set((mem as any[]).map((r: any) => String(r.uid)))\n  try { await c.env.DB.prepare("CREATE TABLE IF NOT EXISTS student_records (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, class_id TEXT, type TEXT, title TEXT, body TEXT, subject TEXT, unit TEXT, day_key TEXT, created_by TEXT, created_at TEXT)").run() } catch {}\n  const allowTypes = new Set([\'report\', \'reflect\', \'other\'])\n  let rtype = String(body.type || \'report\'); if (!allowTypes.has(rtype)) rtype = \'other\'\n  const nowIso = new Date().toISOString()\n  let saved = 0\n  for (const it of body.rows) {\n    const uid = String((it && it.userId) || \'\')\n    if (!uid || !allowed.has(uid)) continue\n    const title = String((it && it.title) || \'\').slice(0, 200)\n    const bodyTxt = String((it && it.body) || \'\').slice(0, 8000)\n    if (!title && !bodyTxt) continue\n    const subj = String((it && it.subject) || \'\').slice(0, 40)\n    const unit = String((it && it.unit) || \'\').slice(0, 80)\n    const day = String((it && it.day) || \'\').slice(0, 40)\n    await c.env.DB.prepare(\'INSERT INTO student_records (user_id, class_id, type, title, body, subject, unit, day_key, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)\').bind(uid, classId, rtype, title, bodyTxt, subj, unit, day, u.id, nowIso).run()\n    saved++\n  }\n  return c.json({ ok: true, saved })\n})\n// ===== 授業メモAPI（クラス全体メモ＋児童ごとメモ・教師は自分のクラスのみ） ====='),
    ('  let teacherNotes: any[] = []',
     "  let records: any[] = []\n  try { const _rr = await c.env.DB.prepare(`SELECT id, type, title, body, subject, unit, day_key, created_at FROM student_records WHERE user_id=? ORDER BY (day_key IS NULL OR day_key=''), day_key DESC, id DESC`).bind(studentId).all<any>(); records = (((_rr && _rr.results) || []) as any[]).map((r: any) => ({ id: r.id, type: r.type, title: r.title, body: r.body, subject: r.subject, unit: r.unit, dayKey: r.day_key, createdAt: r.created_at })) } catch {}\n  let teacherNotes: any[] = []"),
    ('    testScores,\n    teacherNotes,',
     '    testScores,\n    records,\n    teacherNotes,'),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE P3_saveEp_query')
