// ==================== 🗓 CHITOSELE_V1 チトセレ（チトセレクトタイム）— 2026-11-11 ====================
//
// ブロックアワー（山吹小・大日向小の形を参考）。先生が 2週間ぶんの 時間割を わたし、そのうち「チトセレ」の コマで
// 子どもが 自分で 国語・社会・算数の 課題（学習ガイドの A〜F）を えらんで 計画 → やった・つづき を 記録する。
//   ・先生：時間割（ふつう／🌟チトセレ／👥みんなで）と 課題メニューを 決めて「子どもに出す」。みんなの計画を 一覧で 見る。
//   ・子ども：チトセレの コマに 課題を 入れる・✅できた／➡つづき を つける。みんなで やる コマは 見るだけ。
//   ・テーブルは 使うときに つくる（chitosele_cfg：クラスごと／chitosele_plan：子どもごと）。コインは 出さない。
//   ・見るだけモード（先生が子どもの画面を見る）の 書きこみは viewas.ts が 手前で 止める。

export const CHITOSELE_MARK = 'CHITOSELE_V1'

type Deps = { requireTeacher: (c: any) => any }

// 6年2組の 基本の 時間割（月〜金 × 1〜6時間目）。体育・音楽・書写・外国語・家庭は 基本 かえない。
const BASE_TT: string[][] = [
  ['道徳', '体育・図工', '算数', '外国語', '社会', ''],
  ['体育（館）', '国語', '家庭・総合', '家庭', '算数', '理科'],
  ['算数', '音楽・総合', '社会', '書写', '外国語', '委員会・クラブ'],
  ['国語', '算数', '社会', '音楽', '理科', ''],
  ['算数', '理科', '国語', '体育（外）', '図工', '総合・学活']
]
const SEL_SUBJ = ['国語', '社会', '算数']

// 学習ガイドの 課題（2026-11 の 3単元）。all=みんなで そろって やる（先生が コマを 決める）。done=もう おわった。
const DEFAULT_UNITS = [
  {
    id: 'koku', subj: '国語', name: '『鳥獣戯画』を読む', color: '#e11d48', hours: 5,
    tasks: [
      { k: 'A', t: '絵を読む', note: '第1時・みんなで（おわり）', all: 1, done: 1 },
      { k: 'B', t: '筆者の技を見ぬく', note: '教科書 p.156〜166・技の図鑑へ' },
      { k: 'C', t: '題材を決めて、構成を考える', note: '教科書 p.165〜167・写真や絵を1〜2枚' },
      { k: 'D', t: 'よさを伝える文章を書く', note: '教科書 p.168・技を2つ以上使う' },
      { k: 'E', t: '日本文化カフェ', note: '第5時・みんなで', all: 1 },
      { k: '✓', t: '自分の力で、理解チェック', note: 'できたら先生と確認', opt: 1 }
    ]
  },
  {
    id: 'sha', subj: '社会', name: '明治の国づくりを進めた人々', color: '#2563eb', hours: 7,
    tasks: [
      { k: '1', t: '問いづくり', note: '第1時・みんなで（おわり）', all: 1, done: 1 },
      { k: 'A', t: '若い武士たちが幕府をたおす', note: '教科書 p.104〜105' },
      { k: 'B', t: '大久保利通と明治新政府の改革', note: '教科書 p.106〜107' },
      { k: 'C', t: '新しい世の中の文化や生活', note: '教科書 p.108〜109' },
      { k: 'D', t: '板垣退助と自由民権運動', note: '教科書 p.110〜111' },
      { k: 'E', t: '伊藤博文と大日本帝国憲法', note: '教科書 p.112〜113' },
      { k: 'F', t: '吉田松陰への報告', note: '第7時・みんなで', all: 1 },
      { k: '★', t: 'チャレンジ（年表や本で調べよう）', note: 'よゆうがあれば', opt: 1 },
      { k: '✓', t: '自分の力で、理解チェック', note: 'できたら先生と確認', opt: 1 }
    ]
  },
  {
    id: 'san', subj: '算数', name: '図形の拡大と縮小', color: '#059669', hours: 9,
    tasks: [
      { k: '1', t: '導入', note: '第1時・みんなで（おわり）', all: 1, done: 1 },
      { k: 'A', t: '拡大図と縮図の意味', note: '教科書 p.142〜143・スキル21' },
      { k: 'B', t: '方眼を使ってかく', note: '教科書 p.144・スキル22①' },
      { k: 'C', t: '辺の長さや角を使ってかく', note: '教科書 p.145〜146・スキル22②' },
      { k: 'D', t: '1つの点を中心にしてかく', note: '教科書 p.147〜148・スキル22③④' },
      { k: 'E', t: '縮図の利用（縮尺）', note: '教科書 p.150〜151・スキル23①②③' },
      { k: 'F', t: '縮図で、測れない高さを求める', note: '教科書 p.153・スキル23④⑤' },
      { k: '✓', t: '理解チェック＋最後の確認', note: '教科書 p.152・スキル24', opt: 1 },
      { k: '8', t: '本番の測定と高さ調査カード', note: '第8時・みんなで', all: 1 },
      { k: '9', t: '答え合わせと振り返り', note: '第9時・みんなで', all: 1 }
    ]
  }
]

function jstToday(): string { return new Date(Date.now() + 9 * 3600000).toISOString().slice(0, 10) }
function addDay(dk: string, n: number): string { const d = new Date(dk + 'T00:00:00Z'); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10) }
function mondayOf(dk: string): string { const d = new Date(dk + 'T00:00:00Z'); const w = d.getUTCDay(); return addDay(dk, w === 0 ? -6 : 1 - w) }

// はじめの 時間割：きょうから先の 国語・社会・算数を 🌟チトセレに（先生が あとで なおす）
function defaultCfg(): any {
  const today = jstToday(), mon = mondayOf(today)
  const cells: any = {}
  for (let w = 0; w < 2; w++) for (let d = 0; d < 5; d++) {
    const dk = addDay(mon, w * 7 + d)
    for (let p = 0; p < 6; p++) {
      const t = BASE_TT[d][p]
      if (!t) continue
      const sel = SEL_SUBJ.indexOf(t) >= 0 && dk >= today
      cells[dk + '|' + (p + 1)] = sel ? { k: 's', t: '' } : { k: 'n', t }   // チトセレの コマに 教科は 入れない（子どもが 決める）
    }
  }
  return { v: 1, on: false, start: mon, weeks: 2, cells, units: JSON.parse(JSON.stringify(DEFAULT_UNITS)), msg: '' }
}

function cleanStr(s: any, n: number): string { return String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n) }

function cleanCfg(x: any): any {
  const out: any = { v: 1, on: !!(x && x.on), start: /^\d{4}-\d{2}-\d{2}$/.test(String(x && x.start)) ? String(x.start) : mondayOf(jstToday()), weeks: Math.max(1, Math.min(3, Number(x && x.weeks) || 2)), cells: {}, units: [], msg: cleanStr(x && x.msg, 300) }
  const cs = (x && x.cells) || {}
  Object.keys(cs).slice(0, 200).forEach((key) => {
    if (!/^\d{4}-\d{2}-\d{2}\|[1-7]$/.test(key)) return
    const v = cs[key] || {}
    const k = v.k === 's' || v.k === 'f' || v.k === 'x' ? v.k : 'n'   // x＝授業なし（5時間授業の日など）
    const cell: any = { k, t: k === 's' || k === 'x' ? '' : cleanStr(v.t, 40) }
    if (k === 'f') { cell.u = cleanStr(v.u, 10); cell.tk = cleanStr(v.tk, 4) }
    out.cells[key] = cell
  })
  const us = Array.isArray(x && x.units) ? x.units : []
  us.slice(0, 6).forEach((u: any) => {
    const id = cleanStr(u && u.id, 10).replace(/[^a-z0-9_-]/gi, '') || ('u' + out.units.length)
    out.units.push({
      id, subj: cleanStr(u.subj, 10), name: cleanStr(u.name, 40), color: /^#[0-9a-f]{6}$/i.test(String(u.color)) ? String(u.color) : '#64748b', hours: Math.max(0, Math.min(40, Number(u.hours) || 0)),
      tasks: (Array.isArray(u.tasks) ? u.tasks : []).slice(0, 16).map((t: any) => {
        const o: any = { k: cleanStr(t && t.k, 4), t: cleanStr(t && t.t, 40), note: cleanStr(t && t.note, 80) }
        if (t && t.all) o.all = 1; if (t && t.done) o.done = 1; if (t && t.opt) o.opt = 1
        return o
      }).filter((t: any) => t.k && t.t)
    })
  })
  return out
}

function cleanPlan(x: any, cfg: any): any {
  const out: any = { v: 2, s: {}, goal: cleanStr(x && x.goal, 200) }
  const s = (x && x.s) || {}
  const ok: any = {}
  ;(cfg.units || []).forEach((u: any) => (u.tasks || []).forEach((t: any) => { if (!t.all) ok[u.id + ':' + t.k] = 1 }))
  // 1コマに 課題を いくつでも（4つまで）＋ その他（自由に 書く）。課題ごとに ✅できた／➡つづき。
  const stOf = (x: any) => x === 'done' || x === 'cont' ? x : ''
  Object.keys(s).slice(0, 80).forEach((key) => {
    const c = cfg.cells && cfg.cells[key]
    if (!c || c.k !== 's') return
    const v = s[key] || {}
    let items: any[] = Array.isArray(v.items) ? v.items : (v.task ? [{ task: v.task, st: v.st }] : [])
    const seen: any = {}
    items = items.map((it: any) => ({ task: cleanStr(it && it.task, 20), st: stOf(it && it.st) }))
      .filter((it: any) => it.task && ok[it.task] && !seen[it.task] && (seen[it.task] = 1)).slice(0, 4)
    const other = cleanStr(v.other != null ? v.other : (v.task ? '' : v.memo), 120)
    const otherSt = other ? stOf(v.otherSt) : ''
    if (!items.length && !other) return
    out.s[key] = { items, other, otherSt }
  })
  return out
}

async function ensure(env: any) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS chitosele_cfg (class_id TEXT PRIMARY KEY, cfg TEXT NOT NULL, updated_at TEXT DEFAULT (datetime('now')))").run()
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS chitosele_plan (user_id TEXT NOT NULL, class_id TEXT NOT NULL, plan TEXT NOT NULL, updated_at TEXT DEFAULT (datetime('now')), PRIMARY KEY (user_id, class_id))").run()
}
async function loadCfg(env: any, cid: string): Promise<any | null> {
  const r: any = await env.DB.prepare('SELECT cfg FROM chitosele_cfg WHERE class_id=?').bind(cid).first()
  if (!r) return null
  try { return JSON.parse(String(r.cfg)) } catch (_e) { return null }
}
async function studentClass(env: any, uid: string): Promise<string> {
  const r: any = await env.DB.prepare('SELECT class_id AS cid FROM class_members WHERE user_id=? LIMIT 1').bind(uid).first()
  return String((r && r.cid) || '')
}
async function teacherOwns(env: any, u: any, cid: string): Promise<boolean> {
  const r: any = u.role === 'admin'
    ? await env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(cid).first()
    : await env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(cid, u.id).first()
  return !!r
}

export function registerChitosele(app: any, d: Deps) {
  // ── 子ども ──
  app.get('/api/chitosele/me', async (c: any) => {
    const u = c.get('user')
    if (!u) return c.json({ ok: false, error: 'login_required' }, 401)
    await ensure(c.env)
    const cid = await studentClass(c.env, u.id)
    if (!cid) return c.json({ ok: true, on: false })
    const cfg = await loadCfg(c.env, cid)
    if (!cfg || !cfg.on) return c.json({ ok: true, on: false })
    const r: any = await c.env.DB.prepare('SELECT plan FROM chitosele_plan WHERE user_id=? AND class_id=?').bind(u.id, cid).first()
    let plan: any = { v: 1, s: {}, goal: '' }
    try { if (r) plan = JSON.parse(String(r.plan)) } catch (_e) {}
    return c.json({ ok: true, on: true, today: jstToday(), cfg, plan })
  })
  app.put('/api/chitosele/me', async (c: any) => {
    const u = c.get('user')
    if (!u) return c.json({ ok: false, error: 'login_required' }, 401)
    if (u.role !== 'student') return c.json({ ok: false, error: 'student_only' }, 403)
    await ensure(c.env)
    const cid = await studentClass(c.env, u.id)
    const cfg = cid ? await loadCfg(c.env, cid) : null
    if (!cfg || !cfg.on) return c.json({ ok: false, error: 'off' }, 403)
    const body = await c.req.json().catch(() => null)
    const plan = cleanPlan(body && body.plan, cfg)
    await c.env.DB.prepare("INSERT INTO chitosele_plan (user_id, class_id, plan, updated_at) VALUES (?,?,?,datetime('now')) ON CONFLICT(user_id, class_id) DO UPDATE SET plan=excluded.plan, updated_at=datetime('now')").bind(u.id, cid, JSON.stringify(plan)).run()
    return c.json({ ok: true, plan })
  })

  // ── 先生 ──
  app.get('/api/teacher/chitosele/:cid', async (c: any) => {
    const u = d.requireTeacher(c)
    if (!u) return c.json({ ok: false, error: 'unauthorized' }, 401)
    const cid = String(c.req.param('cid'))
    if (!(await teacherOwns(c.env, u, cid))) return c.json({ ok: false, error: 'class_not_found' }, 404)
    await ensure(c.env)
    const saved = await loadCfg(c.env, cid)
    const cfg = saved || defaultCfg()
    const mem = await c.env.DB.prepare("SELECT u.id AS uid, u.login_id AS lid, u.name AS name, u.roster_no AS no FROM class_members cm JOIN users u ON u.id=cm.user_id WHERE cm.class_id=? AND u.role='student' ORDER BY (u.roster_no IS NULL), u.roster_no, u.login_id").bind(cid).all()
    const plans = await c.env.DB.prepare('SELECT user_id AS uid, plan, updated_at AS at FROM chitosele_plan WHERE class_id=?').bind(cid).all()
    let rn: any = {}
    try { const r: any = await c.env.DB.prepare("SELECT value FROM admin_settings WHERE key='real_name_map' LIMIT 1").first(); rn = r ? JSON.parse(String(r.value)) : {} } catch (_e) {}
    const pm: any = {}
    ;(((plans && plans.results) || []) as any[]).forEach((x: any) => { try { pm[x.uid] = { plan: JSON.parse(String(x.plan)), at: x.at } } catch (_e) {} })
    const kids = (((mem && mem.results) || []) as any[]).map((x: any) => ({ uid: x.uid, no: x.no, name: String(rn[x.lid] || x.name || x.lid || ''), plan: pm[x.uid] ? pm[x.uid].plan : null, at: pm[x.uid] ? pm[x.uid].at : '' }))
    return c.json({ ok: true, saved: !!saved, today: jstToday(), cfg, kids, base: BASE_TT })
  })
  app.put('/api/teacher/chitosele/:cid', async (c: any) => {
    const u = d.requireTeacher(c)
    if (!u) return c.json({ ok: false, error: 'unauthorized' }, 401)
    const cid = String(c.req.param('cid'))
    if (!(await teacherOwns(c.env, u, cid))) return c.json({ ok: false, error: 'class_not_found' }, 404)
    await ensure(c.env)
    const body = await c.req.json().catch(() => null)
    if (!body || !body.cfg) return c.json({ ok: false, error: 'invalid' }, 400)
    const cfg = cleanCfg(body.cfg)
    await c.env.DB.prepare("INSERT INTO chitosele_cfg (class_id, cfg, updated_at) VALUES (?,?,datetime('now')) ON CONFLICT(class_id) DO UPDATE SET cfg=excluded.cfg, updated_at=datetime('now')").bind(cid, JSON.stringify(cfg)).run()
    return c.json({ ok: true, cfg })
  })
  // クラスごとの ON/OFF（先生の画面の ボタン）。まだ 時間割を 保存していない クラスは、はじめの 形で つくって ON にする。
  app.get('/api/teacher/chitosele/:cid/on', async (c: any) => {
    const u = d.requireTeacher(c)
    if (!u) return c.json({ ok: false, error: 'unauthorized' }, 401)
    const cid = String(c.req.param('cid'))
    if (!(await teacherOwns(c.env, u, cid))) return c.json({ ok: false, error: 'class_not_found' }, 404)
    await ensure(c.env)
    const cfg = await loadCfg(c.env, cid)
    return c.json({ ok: true, on: !!(cfg && cfg.on), saved: !!cfg })
  })
  app.put('/api/teacher/chitosele/:cid/on', async (c: any) => {
    const u = d.requireTeacher(c)
    if (!u) return c.json({ ok: false, error: 'unauthorized' }, 401)
    const cid = String(c.req.param('cid'))
    if (!(await teacherOwns(c.env, u, cid))) return c.json({ ok: false, error: 'class_not_found' }, 404)
    await ensure(c.env)
    const body = await c.req.json().catch(() => null)
    const cfg = cleanCfg((await loadCfg(c.env, cid)) || defaultCfg())
    cfg.on = !!(body && body.on)
    await c.env.DB.prepare("INSERT INTO chitosele_cfg (class_id, cfg, updated_at) VALUES (?,?,datetime('now')) ON CONFLICT(class_id) DO UPDATE SET cfg=excluded.cfg, updated_at=datetime('now')").bind(cid, JSON.stringify(cfg)).run()
    return c.json({ ok: true, on: cfg.on })
  })
  // はじめの 形に もどす（時間割と 課題を つくりなおす。子どもの 計画は のこす）
  app.get('/api/teacher/chitosele-default', async (c: any) => {
    const u = d.requireTeacher(c)
    if (!u) return c.json({ ok: false, error: 'unauthorized' }, 401)
    return c.json({ ok: true, cfg: defaultCfg(), base: BASE_TT })
  })
}
