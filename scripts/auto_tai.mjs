// 🤖 AUTO_TAI_V1（2026-11-27）「今日のひと往復」を Claude のスケジュール実行で 回すための 道具
//   先生画面（/teacher）を ヘッドレスで ひらき、teacher-ai.js の 関数を そのまま 使う（ルール・取り込み・返却の しくみは 先生が 手で やるのと 同じ）。
//
//   node scripts/auto_tai.mjs prompt  <token> <classId> <out.txt>
//       → まだ返していない 家庭学習の 分だけ（DAILY・HSQ）の プロンプトを out.txt に 書く。書く ものが なければ "NONE" と 出す
//   node scripts/auto_tai.mjs publish <token> <classId> <answer.txt> [--dry]
//       → AIの 返事を 取りこんで 下書きに 入れ、DAILY・HSQ の 下書きだけ 公開（返却）する。
//         【ずる？】の ものは teacher-ai.js の きまりどおり 差し戻し／機械チェックだけの ものは 先生用に のこる。
//         --dry なら 取りこむだけで 公開しない
import { createRequire } from 'module'
const { chromium } = createRequire(import.meta.url)('playwright')
import fs from 'fs'

const BASE = process.env.LBM_BASE || 'https://learning-bm.pages.dev'
const [mode, token, classId, file, flag] = process.argv.slice(2)
if (!mode || !token || !classId || !file) { console.error('usage: auto_tai.mjs prompt|publish <token> <classId> <file> [--dry]'); process.exit(2) }

const b = await chromium.launch()
const ctx = await b.newContext({ extraHTTPHeaders: { 'x-lbm-auto': token } })
await ctx.addInitScript(() => {
  window.__clip = ''
  try { Object.defineProperty(navigator, 'clipboard', { value: { writeText: (t) => { window.__clip = String(t); return Promise.resolve() }, readText: () => Promise.resolve(window.__clip) }, configurable: true }) } catch (e) {}
  window.confirm = (m) => !/⚠/.test(String(m || ''))   // 名前もれなどの 警告が 出たら 公開しない
  window.alert = () => {}
  window.prompt = () => null
})
const p = await ctx.newPage()
const logs = []
p.on('console', (m) => { if (m.type() === 'error') logs.push(m.text().slice(0, 200)) })
await p.goto(BASE + '/teacher', { waitUntil: 'load' })
// teacher-ai.js と クラスの えらぶ欄が そろうまで まつ
for (let i = 0; i < 60; i++) {
  const ok = await p.evaluate((cid) => {
    const s = document.getElementById('analyticsClassFilter')
    if (!s || typeof window.taiCopyAll !== 'function') return false
    if (![...s.options].some((o) => o.value === cid)) return false
    s.value = cid; s.dispatchEvent(new Event('change', { bubbles: true }))
    return true
  }, classId)
  if (ok) { await p.waitForTimeout(2000); break }
  await p.waitForTimeout(500)
  if (i === 59) { console.error('teacher page not ready', logs); await b.close(); process.exit(3) }
}

if (mode === 'prompt') {
  const r = await p.evaluate(async () => {
    const set = (id, v) => { const e = document.getElementById(id); if (e) e.checked = v }
    set('taiOptDaily', true); ['taiOptKarte', 'taiOptClass', 'taiOptReport', 'taiOptPlan', 'taiOptReflect', 'taiOptSuggest', 'taiOptMinna'].forEach((id) => set(id, false))
    window.__taiForceRefresh = true
    try { if (window.AI_FLOW) window.AI_FLOW.enabled = () => false } catch (e) {}   // 🧵 流れ（FLOW）は 毎時間 作らない
    window.__clip = ''
    await window.taiCopyAll({})
    for (let i = 0; i < 240 && !window.__clip; i++) await new Promise((r) => setTimeout(r, 500))
    const t = window.__clip || ''
    return { text: t, blocks: (t.match(/=== \[(DAILY|HSQ):/g) || []).length }
  })
  if (!r.blocks) { console.log('NONE'); await b.close(); process.exit(0) }
  fs.writeFileSync(file, r.text)
  console.log('BLOCKS ' + r.blocks + ' CHARS ' + r.text.length)
} else if (mode === 'publish') {
  const raw = fs.readFileSync(file, 'utf8')
  const r = await p.evaluate(async ({ raw, dry }) => {
    const msgs = []
    const say = (m) => msgs.push(String(m))
    const cid0 = document.getElementById('analyticsClassFilter').value
    const d0 = await fetch('/api/teacher/ai-drafts?classId=' + encodeURIComponent(cid0), { credentials: 'include' }).then((r) => r.json()).catch(() => null)
    const before = {}; ((d0 && d0.drafts) || []).forEach((x) => { before[x.id] = 1 })   // この回で 入れた 下書きだけ 公開する（先生が 手で 作った 下書きには さわらない）
    await window.taiImport({ raw, say })
    await window.taiLoadDrafts()
    await new Promise((r) => setTimeout(r, 800))
    // DAILY・HSQ の 下書きだけ チェックして 公開（ほかは 先生が 見る）
    const cid = document.getElementById('analyticsClassFilter').value
    const d = await fetch('/api/teacher/ai-drafts?classId=' + encodeURIComponent(cid), { credentials: 'include' }).then((r) => r.json()).catch(() => null)
    const kindOf = {}; ((d && d.drafts) || []).forEach((x) => { kindOf[x.id] = x.kind })
    const els = document.querySelectorAll('.tai-chk')
    let n = 0, skipped = 0
    els.forEach((el) => {
      const kind = kindOf[el.getAttribute('data-id')] || ''
      const want = (kind === 'DAILY' || kind === 'HSQ') && !before[el.getAttribute('data-id')]
      // 名前もれ・NGワードの 警告が ついて 最初から チェックが 外れている ものは 公開しない（先生が 見る）
      const on = want && el.checked
      if (want && !el.checked) skipped++
      el.checked = on; if (on) n++
    })
    msgs.push('held_by_warning=' + skipped)
    if (dry) return { msgs, checked: n, published: false }
    if (n) await window.taiPublish()
    await new Promise((r) => setTimeout(r, 1500))
    const st = document.getElementById('taiPubStatus') || document.getElementById('taiStatus')
    return { msgs, checked: n, published: true, status: st ? st.textContent : '' }
  }, { raw, dry: flag === '--dry' })
  console.log(JSON.stringify(r))
} else {
  console.error('unknown mode'); await b.close(); process.exit(2)
}
await b.close()
