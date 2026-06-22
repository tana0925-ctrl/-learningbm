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
    ('    return { idRaw: bk.idRaw, nameRaw: bk.nameRaw, title: bk.title, day: bk.day, subject: bk.subject, unit: bk.unit, body: bk.body, matchedUserId: uid, matchedName: mm ? mm.name : null }',
     '    return { idRaw: bk.idRaw, nameRaw: bk.nameRaw, title: bk.title, day: bk.day, subject: bk.subject, unit: bk.unit, body: bk.body, reflection: bk.reflection, evalRank: bk.evalRank, evalComment: bk.evalComment, matchedUserId: uid, matchedName: mm ? mm.name : null }'),
    ("  try { const _rr = await c.env.DB.prepare(`SELECT id, type, title, body, subject, unit, day_key, created_at FROM student_records WHERE user_id=? ORDER BY (day_key IS NULL OR day_key=''), day_key DESC, id DESC`).bind(studentId).all<any>(); records = (((_rr && _rr.results) || []) as any[]).map((r: any) => ({ id: r.id, type: r.type, title: r.title, body: r.body, subject: r.subject, unit: r.unit, dayKey: r.day_key, createdAt: r.created_at })) } catch {}",
     "  try { const _rr = await c.env.DB.prepare(`SELECT id, type, title, body, reflection, eval_rank, eval_comment, subject, unit, day_key, created_at FROM student_records WHERE user_id=? ORDER BY (day_key IS NULL OR day_key=''), day_key DESC, id DESC`).bind(studentId).all<any>(); records = (((_rr && _rr.results) || []) as any[]).map((r: any) => ({ id: r.id, type: r.type, title: r.title, body: r.body, reflection: r.reflection, evalRank: r.eval_rank, evalComment: r.eval_comment, subject: r.subject, unit: r.unit, dayKey: r.day_key, createdAt: r.created_at })) } catch {}"),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE PC')
