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
        data=data.replace(old,new); print('ok',repr(old[:34]))
    with open(path,'w',encoding='utf-8',newline='') as f:
        f.write(data)

SRC_EDITS = [
    ('  try { await c.env.DB.prepare("CREATE TABLE IF NOT EXISTS student_records (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, class_id TEXT, type TEXT, title TEXT, body TEXT, subject TEXT, unit TEXT, day_key TEXT, created_by TEXT, created_at TEXT)").run() } catch {}',
     '  try { await c.env.DB.prepare("CREATE TABLE IF NOT EXISTS student_records (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, class_id TEXT, type TEXT, title TEXT, body TEXT, subject TEXT, unit TEXT, day_key TEXT, created_by TEXT, created_at TEXT)").run() } catch {}\n  try { await c.env.DB.prepare("ALTER TABLE student_records ADD COLUMN reflection TEXT").run() } catch {}\n  try { await c.env.DB.prepare("ALTER TABLE student_records ADD COLUMN eval_rank TEXT").run() } catch {}\n  try { await c.env.DB.prepare("ALTER TABLE student_records ADD COLUMN eval_comment TEXT").run() } catch {}'),
    ("    if (!title && !bodyTxt) continue\n    const subj = String((it && it.subject) || '').slice(0, 40)\n    const unit = String((it && it.unit) || '').slice(0, 80)\n    const day = String((it && it.day) || '').slice(0, 40)\n    await c.env.DB.prepare('INSERT INTO student_records (user_id, class_id, type, title, body, subject, unit, day_key, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(uid, classId, rtype, title, bodyTxt, subj, unit, day, u.id, nowIso).run()",
     "    const reflection = String((it && it.reflection) || '').slice(0, 8000)\n    const evalRankRaw = String((it && it.evalRank) || '').trim(); const _ranks = new Set(['◎','○','△']); const evalRank = _ranks.has(evalRankRaw) ? evalRankRaw : ''\n    const evalComment = String((it && it.evalComment) || '').slice(0, 2000)\n    if (!title && !bodyTxt && !reflection && !evalRank && !evalComment) continue\n    const subj = String((it && it.subject) || '').slice(0, 40)\n    const unit = String((it && it.unit) || '').slice(0, 80)\n    const day = String((it && it.day) || '').slice(0, 40)\n    await c.env.DB.prepare('INSERT INTO student_records (user_id, class_id, type, title, body, reflection, eval_rank, eval_comment, subject, unit, day_key, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(uid, classId, rtype, title, bodyTxt, reflection, evalRank, evalComment, subj, unit, day, u.id, nowIso).run()"),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE PA')
