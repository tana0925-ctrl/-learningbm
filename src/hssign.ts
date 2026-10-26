// ==================== ✍️ HSSIGN_V1 サポーター（おうちの人）のサインを あとから足す（2026-10-26） ====================
//
// 💬 阪神マンとはじめる家庭学習で「あとでもらう」をえらんで先に提出した日に、
// その日の提出の「🏠サポーターから」（homework_submissions.parent_comment）へ サインを足すだけの道。
//   ・本人（児童）だけ・その日（サーバの学習日＝8:30区切り）の提出だけ。
//   ・サポーター欄が空のときだけ入る（シートで書いてもらった文や、先に入ったサインは上書きしない）。
//   ・コイン・かけら・返却・連続日数には一切さわらない（サインの有無でコインは変えない）。
//   ・DDL なし（既存の parent_comment 列だけを使う）。見るだけモードの書きこみは viewas.ts が手前で止める。

export const HSSIGN_MARK = 'HSSIGN_V1'

function clean(s: any, n: number): string {
  const a = Array.from(String(s == null ? '' : s).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').replace(/\r\n?/g, '\n').trim())
  return a.length > n ? a.slice(0, n).join('') : a.join('')
}

export function registerHsSign(app: any, deps: { jstStudyDayKey: (atMs?: number) => string }) {
  app.post('/api/homework/parent-sign', async (c: any) => {
    const u = c.get('user')
    if (!u) return c.json({ ok: false, error: 'login_required' }, 401)
    if (u.role !== 'student') return c.json({ ok: false, error: 'forbidden' }, 403)
    const body = await c.req.json().catch(() => null)
    if (!body) return c.json({ ok: false, error: 'invalid_json' }, 400)
    const dayKey = String(body.dayKey || '').slice(0, 10)
    if (dayKey !== deps.jstStudyDayKey()) return c.json({ ok: false, error: 'not_today' }, 400)
    const text = clean(body.text, 500)
    if (!text) return c.json({ ok: false, error: 'text_required' }, 400)

    const r = await c.env.DB.prepare(
      `UPDATE homework_submissions SET parent_comment=? WHERE user_id=? AND day_key=? AND (parent_comment IS NULL OR TRIM(parent_comment)='')`
    ).bind(text, u.id, dayKey).run()
    if (r && r.meta && Number(r.meta.changes) >= 1) return c.json({ ok: true, signed: true, parentComment: text })

    const row = await c.env.DB.prepare(
      `SELECT parent_comment AS pc FROM homework_submissions WHERE user_id=? AND day_key=? LIMIT 1`
    ).bind(u.id, dayKey).first()
    if (!row) return c.json({ ok: false, error: 'not_submitted' }, 404)
    return c.json({ ok: true, already: true, parentComment: String(row.pc || '') })
  })
}
