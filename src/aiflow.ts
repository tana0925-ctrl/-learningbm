// ==================== 🧵 AIFLOW_V1 AIの流れをアプリに残す（2026-10-27） ====================
//
// 先生のことば：「外部AIは一時チャットで使い捨てにしたい。前の流れはアプリが覚えておいて、次のコピーに入れてほしい」
//
// しくみ:
//   ・「今日のひと往復」で公開した返事は、もともと ai_review_drafts に status='published' で残っている。
//     ここでは新しい表を作らず、それを読むだけ（DDL なし）。
//   ・新しく [FLOW:児童ID] の欄を足す。AIが「この子の今週の変化（事実だけ・1〜2文）」を書き、
//     先生が④で確認して公開すると、ほかの返事と同じく ai_review_drafts に残る（kind='FLOW'・先生だけ）。
//   ・④で先生が書きかえてから公開した文は、公開のあとに本文を「公開した文」に合わせる（/final）。
//   ・次のコピーでは、直近4週ぶんを子どもごとに短くして「先週までの流れ」として入れる（public/ai-flow.js）。
//     名前は入れない（いまの仕組みどおり符号）。1人あたりの文字数に上限がある。
//
// ⚠️ 子どもの画面には何も足さない。読むのは /api/teacher/* だけ（先生・管理者・自分のクラス）。

export const AIFLOW_MARK = 'AIFLOW_V1'
const FLOW_KINDS = ['FLOW', 'KARTE', 'DAILY', 'PLAN', 'REFLECT', 'SUGGEST', 'WORK', 'WORKMEMO']   // PORTFOLIO_AI_V1 成果物の分析も流れに入れる

function jerr(c: any, status: number, error: string) { return c.json({ ok: false, error }, status) }
function short(s: any, n: number): string {
  const a = Array.from(String(s == null ? '' : s).replace(/\s+/g, ' ').trim())
  return a.length > n ? a.slice(0, n).join('') + '…' : a.join('')
}

export function registerAiFlow(app: any) {
  // 先生：クラスの「公開した返事」と「流れのメモ」を、直近 days 日ぶん（既定28日・最大42日）
  app.get('/api/teacher/ai-flow', async (c: any) => {
    const u = c.get('user')
    if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jerr(c, 403, 'forbidden')
    const classId = String(c.req.query('classId') || '')
    if (!classId) return jerr(c, 400, 'classId required')
    const own = u.role === 'admin'
      ? await c.env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(classId).first()
      : await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first()
    if (!own) return jerr(c, 404, 'class_not_found')
    const days = Math.max(7, Math.min(42, Number(c.req.query('days') || 28) | 0))
    let rows: any = { results: [] }
    try {
      rows = await c.env.DB.prepare(
        `SELECT d.kind AS kind, COALESCE(NULLIF(d.target_id,''), hs.user_id) AS uid, d.body AS body,
                d.published_at AS at, d.ref_key AS refKey
         FROM ai_review_drafts d
         LEFT JOIN homework_submissions hs ON d.kind='DAILY' AND hs.id=d.ref_key
         WHERE d.class_id=? AND d.status='published' AND d.published_at >= datetime('now', ?)
           AND d.kind IN (${FLOW_KINDS.map(() => '?').join(',')})
         ORDER BY d.published_at DESC LIMIT 800`
      ).bind(classId, '-' + days + ' days', ...FLOW_KINDS).all()
    } catch (_e) { rows = { results: [] } }
    const byUser: Record<string, any[]> = {}
    for (const r of ((rows && rows.results) || []) as any[]) {
      const uid = String(r.uid || '')
      if (!uid) continue
      const lim = (r.kind === 'FLOW' || r.kind === 'WORKMEMO') ? 160 : 90   // 本文は書き出しだけ（コピーが長くなりすぎないように）
      ;(byUser[uid] = byUser[uid] || []).push({ kind: String(r.kind), at: String(r.at || '').slice(0, 10), text: short(r.body, lim) })
    }
    return c.json({ ok: true, days, byUser })
  })

  // 先生：④で公開した文を「実際に公開した文」に合わせる（書きかえてから公開したとき用）
  app.post('/api/teacher/ai-flow/final', async (c: any) => {
    const u = c.get('user')
    if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jerr(c, 403, 'forbidden')
    const b = await c.req.json().catch(() => null)
    const items = (b && Array.isArray(b.items) ? b.items : []).slice(0, 400)
    let n = 0
    for (const it of items) {
      const id = String((it && it.id) || '')
      const body = String((it && it.body) || '').slice(0, 8000)
      if (!id || !body.trim()) continue
      try {
        const r = await c.env.DB.prepare(
          "UPDATE ai_review_drafts SET body=? WHERE id=? AND teacher_id=? AND status='published' AND body<>?" +
          (u.role === 'admin' ? '' : ' AND class_id IN (SELECT id FROM classes WHERE teacher_id=?)')
        ).bind(...(u.role === 'admin' ? [body, id, u.id, body] : [body, id, u.id, body, u.id])).run()
        if (r && r.meta && r.meta.changes) n += Number(r.meta.changes)
      } catch (_e) {}
    }
    return c.json({ ok: true, updated: n })
  })
}
