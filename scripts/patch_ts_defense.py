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
     "app.post('/api/teacher/records/parse', async (c) => {\n  const u = c.get('user')\n  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')\n  const body = await c.req.json().catch(() => null)\n  if (!body || typeof body.text !== 'string') return jsonError(c, 400, 'invalid')\n  const classId = String(body.classId || '')\n  const cls = u.role === 'admin'\n    ? await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()\n    : await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first<any>()\n  if (!cls) return jsonError(c, 404, 'class_not_found')\n  const roster = (((await c.env.DB.prepare('SELECT u.id, u.login_id as loginId, u.name FROM class_members cm JOIN users u ON u.id=cm.user_id WHERE cm.class_id=?').bind(classId).all<any>()).results) || [])\n  const idx: Record<string, string> = {}\n  for (const m of roster as any[]) { if (m.name) idx[_recNorm(m.name)] = m.id; if (m.loginId) idx[_recNorm(m.loginId)] = m.id }\n  const blocks = _recParseText(body.text)\n  const rows = blocks.map((bk: any) => {\n    const keyId = _recNorm(bk.idRaw); const keyNm = _recNorm(bk.nameRaw)\n    let uid: string | null = idx[keyId] || idx[keyNm] || null\n    if (!uid && keyNm) { for (const m of roster as any[]) { const nn = _recNorm(m.name); if (nn && (nn.indexOf(keyNm) >= 0 || keyNm.indexOf(nn) >= 0)) { uid = m.id; break } } }\n    const mm = uid ? (roster as any[]).find((x: any) => x.id === uid) : null\n    return { idRaw: bk.idRaw, nameRaw: bk.nameRaw, title: bk.title, day: bk.day, subject: bk.subject, unit: bk.unit, body: bk.body, matchedUserId: uid, matchedName: mm ? mm.name : null }\n  })\n  return c.json({ ok: true, rows, roster: (roster as any[]).map((m: any) => ({ userId: m.id, name: m.name, loginId: m.loginId })) })\n})\n// ===== 授業メモAPI（クラス全体メモ＋児童ごとメモ・教師は自分のクラスのみ） ====="),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE P2_parseEp')
