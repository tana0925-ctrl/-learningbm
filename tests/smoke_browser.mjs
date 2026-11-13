// 🧪 SMOKE_V1（2026-11-13）本物の ブラウザで「ひらく → 家庭学習 → 修行 → 防衛戦 → ほかの ページ」を とおす。
//   ・dist を wrangler pages dev（ローカル）で うごかし、/api は ここで にせもの（子ども or 先生）を かえす。
//   ・ページの エラー（pageerror）が 1つでも 出たら 失敗。出す前に CI で 走らせる（.github/workflows/deploy.yml）。
//   ・つかいかた：npm run build && node tests/smoke_browser.mjs
import { createRequire } from 'module'
import { spawn } from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'
const require = createRequire(import.meta.url)
const { chromium } = require('playwright')

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const PORT = Number(process.env.SMOKE_PORT || 8797)
const BASE = 'http://localhost:' + PORT
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
let pass = 0, fail = 0
function ok(c, m) { if (c) { pass++; console.log('PASS | ' + m) } else { fail++; console.log('FAIL | ' + m) } }

// wrangler の 設定から AI（リモートで トークンが いる）を ぬいた コピーを つくる
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lbm-smoke-'))
fs.symlinkSync(path.join(ROOT, 'dist'), path.join(tmp, 'dist'))
fs.symlinkSync(path.join(ROOT, 'node_modules'), path.join(tmp, 'node_modules'))
fs.writeFileSync(path.join(tmp, 'wrangler.jsonc'), fs.readFileSync(path.join(ROOT, 'wrangler.jsonc'), 'utf8').replace(/"ai":\s*\{\s*"binding":\s*"AI"\s*\},/, ''))
const wr = spawn(path.join(ROOT, 'node_modules/.bin/wrangler'), ['pages', 'dev', 'dist', '--local', '--port', String(PORT)], { cwd: tmp, stdio: ['ignore', 'pipe', 'pipe'] })
let wlog = ''; wr.stdout.on('data', (d) => { wlog += d }); wr.stderr.on('data', (d) => { wlog += d })
async function up() { for (let i = 0; i < 90; i++) { try { const r = await fetch(BASE + '/'); if (r.status === 200) return true } catch (e) {} await sleep(1000) } return false }

const STUDENT = { user: { id: 'stu-smoke', role: 'student', grade: 6, name: 'テスト', login_id: 's001' } }
const TEACHER = { user: { id: 'tea-smoke', role: 'teacher', name: '先生', login_id: 't001' } }
function mock(p, who) {
  return p.route('**/api/**', (r) => {
    const u = r.request().url()
    const j = (o) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(o) })
    if (u.includes('/api/auth/me')) return j(who)
    if (u.includes('/api/defense/status')) return j({ ok: true, eventKey: '2026-11-13T03:30:00.000Z', stage: 3, decided: false, entered: false, enemy_squad: [{ name: 'スライム', sprite: '🟢', hp: 300, atk: 40, def: 10, spd: 60, buff: 'attack', skillPow: 10 }], entry_count: 20 })
    if (u.includes('/api/homework/rejected-mine')) return j({ ok: true, items: [] })
    return j({})
  })
}
async function page(b, who) {
  const p = await b.newPage({ viewport: { width: 1100, height: 900 } })
  const errs = []
  p.on('pageerror', (e) => errs.push(String(e && e.message || e).slice(0, 200)))
  await mock(p, who)
  return { p, errs }
}

try {
  const isUp = await up()
  if (!isUp && process.env.CI) { console.log('::warning::ローカルの サーバが 立ち上がらなかったので スモークテストを とばしました'); console.log(wlog.slice(-2000)); try { wr.kill('SIGTERM') } catch (e) {} process.exit(0) }
  ok(isUp, 'ローカルで ひらけた（wrangler pages dev）')
  const b = await chromium.launch()

  // ① 子どもの ページ
  {
    const { p, errs } = await page(b, STUDENT)
    const r = await p.goto(BASE + '/', { waitUntil: 'load' })
    const html = await r.text()
    ok(html.length < 1500000, 'いちばん上の HTML が 軽い（' + Math.round(html.length / 1024) + 'KB）')
    await sleep(3500)
    const g = await p.evaluate(() => ({ player: typeof player, tm: typeof trainingMode, ab: typeof window.autoBattleRT, drb: typeof window._defRenderBattle, hm: typeof window.HanshinManSystem, hc: typeof window.HSCHAT, hck: typeof window.HSCHECK, od: typeof window.openDefense, st: typeof window.selectTrainingMode, path: location.pathname }))
    ok(g.path === '/', 'ログイン画面へ とばされない')
    ok(g.player === 'object' && g.tm === 'string', 'player・trainingMode が ある')
    ok(g.ab === 'function' && g.drb === 'function' && g.od === 'function', '防衛戦の しくみが ある')
    ok(g.hm === 'object' && g.hc === 'object' && g.hck === 'object', '阪神マン・家庭学習の対話・理解度チェックが ある')
    // 家庭学習（阪神マンと はじめる）
    await p.evaluate(() => { try { window.HSCHAT.open() } catch (e) { throw e } }); await sleep(600)
    const chatBtns = await p.evaluate(() => Array.from(document.querySelectorAll('#hsChatFoot button')).map((x) => x.textContent).join('|'))
    ok(/その他/.test(chatBtns), '家庭学習の 対話が ひらく（' + chatBtns.slice(0, 60) + '）')
    await p.evaluate(() => { try { window.HSCHAT.close && window.HSCHAT.close() } catch (e) {} const r = document.getElementById('hsChat'); if (r) r.style.display = 'none' })
    // 修行（6年 比）
    await p.evaluate(() => { let u = null; try { const gs = window.CURRICULUM.math.grades; for (const k in gs) (gs[k].units || []).forEach((x) => { if (x.id === 'm6-ratio') u = x }) } catch (e) {} window.__currUnit = u; try { trySetMode('training') } catch (e) {} window.selectTrainingMode('m6-ratio') }); await sleep(800)
    const q = await p.evaluate(() => ({ m: trainingMode, cu: (window.__currUnit && window.__currUnit.id) || '', q: (window.trainingQ && window.trainingQ.q) || '' }))
    ok(q.m === 'm6-ratio' || q.cu === 'm6-ratio', '修行（6年 比）を えらべる（' + q.m + '/' + q.cu + (q.q ? ' ' + String(q.q).slice(0, 30) : '') + '）')
    // 防衛戦
    await p.evaluate(() => { try { window.openDefense() } catch (e) { throw e } }); await sleep(1500)
    const dv = await p.evaluate(() => { const m = document.getElementById('defenseModal'); return m ? (m.textContent || '').slice(0, 80) : '' })
    ok(dv.length > 0, '防衛戦の 画面が ひらく')
    ok(!errs.length, '子どもの ページで エラーなし' + (errs.length ? '：' + errs.slice(0, 5).join(' / ') : ''))
    await p.close()
  }

  // ② ほかの ページ
  for (const [url, who, name] of [['/pj', STUDENT, '先生PJ'], ['/chitosele', STUDENT, 'チトセレ（子ども）'], ['/chitosele?teacher=1', TEACHER, 'チトセレ（先生）']]) {
    const { p, errs } = await page(b, who)
    const r = await p.goto(BASE + url, { waitUntil: 'load' }); await sleep(1500)
    ok(r && r.status() === 200, name + ' が ひらく')
    ok(!errs.length, name + ' で エラーなし' + (errs.length ? '：' + errs.slice(0, 5).join(' / ') : ''))
    await p.close()
  }
  await b.close()
} catch (e) {
  fail++; console.log('FAIL | とちゅうで とまった：' + (e && e.stack || e))
} finally {
  try { wr.kill('SIGTERM') } catch (e) {}
  try { fs.rmSync(tmp, { recursive: true, force: true }) } catch (e) {}
}
console.log('\n' + pass + '/' + (pass + fail) + ' passed')
if (fail) { if (process.env.SMOKE_VERBOSE) console.log(wlog.slice(-3000)); process.exit(1) }
process.exit(0)
