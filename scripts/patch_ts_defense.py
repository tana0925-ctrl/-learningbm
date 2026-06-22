import sys

def patch_file(path, edits):
    with open(path,'r',encoding='utf-8',newline='') as f:
        data=f.read()
    for old,new in edits:
        if new in data and old not in data:
            print('skip'); continue
        if old not in data:
            print('ANCHOR NOT FOUND',repr(old[:60])); sys.exit(1)
        if data.count(old)!=1:
            print('NOT UNIQUE',data.count(old)); sys.exit(1)
        data=data.replace(old,new); print('ok',repr(old[:30]))
    with open(path,'w',encoding='utf-8',newline='') as f:
        f.write(data)

SRC_EDITS = [
    ("app.post('/api/teacher/student-ai-comments', async (c) => {",
     'app.post(\'/api/teacher/class-ai-summary\', async (c) => {\n  const u = c.get(\'user\')\n  if (!u || (u.role !== \'teacher\' && u.role !== \'admin\')) return jsonError(c, 403, \'forbidden\')\n  const body = await c.req.json().catch(() => null)\n  if (!body) return jsonError(c, 400, \'invalid\')\n  const classId = String(body.classId || \'\')\n  const cls = u.role === \'admin\'\n    ? await c.env.DB.prepare(\'SELECT id FROM classes WHERE id=? LIMIT 1\').bind(classId).first<any>()\n    : await c.env.DB.prepare(\'SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1\').bind(classId, u.id).first<any>()\n  if (!cls) return jsonError(c, 404, \'class_not_found\')\n  try { await c.env.DB.prepare(\'CREATE TABLE IF NOT EXISTS class_ai_summary (class_id TEXT PRIMARY KEY, overview TEXT, updated_at TEXT, updated_by TEXT)\').run() } catch {}\n  const overview = String(body.overview || \'\').slice(0, 20000)\n  await c.env.DB.prepare("INSERT INTO class_ai_summary (class_id, overview, updated_at, updated_by) VALUES (?,?,datetime(\'now\'),?) ON CONFLICT(class_id) DO UPDATE SET overview=excluded.overview, updated_at=datetime(\'now\'), updated_by=excluded.updated_by").bind(classId, overview, u.id).run()\n  return c.json({ ok: true })\n})\napp.get(\'/api/teacher/ai-summary\', async (c) => {\n  const u = c.get(\'user\')\n  if (!u || (u.role !== \'teacher\' && u.role !== \'admin\')) return jsonError(c, 403, \'forbidden\')\n  const classId = String(c.req.query(\'classId\') || \'\')\n  const cls = u.role === \'admin\'\n    ? await c.env.DB.prepare(\'SELECT id FROM classes WHERE id=? LIMIT 1\').bind(classId).first<any>()\n    : await c.env.DB.prepare(\'SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1\').bind(classId, u.id).first<any>()\n  if (!cls) return jsonError(c, 404, \'class_not_found\')\n  try { await c.env.DB.prepare(\'CREATE TABLE IF NOT EXISTS class_ai_summary (class_id TEXT PRIMARY KEY, overview TEXT, updated_at TEXT, updated_by TEXT)\').run() } catch {}\n  let overview = \'\', overviewUpdatedAt = \'\'\n  try { const o = await c.env.DB.prepare(\'SELECT overview, updated_at as updatedAt FROM class_ai_summary WHERE class_id=? LIMIT 1\').bind(classId).first<any>(); if (o) { overview = o.overview || \'\'; overviewUpdatedAt = o.updatedAt || \'\' } } catch {}\n  const rows = (((await c.env.DB.prepare("SELECT u.id as userId, u.login_id as loginId, u.name, sac.comment, sac.updated_at as updatedAt FROM class_members cm JOIN users u ON u.id=cm.user_id LEFT JOIN student_ai_comments sac ON sac.user_id=u.id WHERE cm.class_id=? ORDER BY (sac.updated_at IS NULL), sac.updated_at DESC").bind(classId).all<any>()).results) || [])\n  const comments = (rows as any[]).map((r: any) => ({ userId: r.userId, loginId: r.loginId, name: r.name, comment: r.comment || \'\', updatedAt: r.updatedAt || \'\' }))\n  return c.json({ ok: true, overview, overviewUpdatedAt, comments })\n})\napp.post(\'/api/teacher/student-ai-comments\', async (c) => {'),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE RA')
