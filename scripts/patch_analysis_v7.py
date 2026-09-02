#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_analysis_v7.py --- 子どもの紙から提出率(%)を外す ＋ 児童アプリ内でカルテを見られるように（B-e）

  P1 印刷カルテから「家庭学習の提出（今年度）」パネル（％）を削除
  P2 印刷カルテから「月ごとの提出率(%)」グラフを削除（回数のグラフは残す）
     ※ 先生の画面（分析タブ）の提出率は触りません。傾向を見るのに必要なので残します。

  E1 GET  /api/student/my-karte      … 自分の分しか返さない。他人の userId は 403。
                                       先生が公開したものだけ。テストの点数・順位・比較は返さない。
  E2 POST /api/teacher/karte-share   … 先生の「公開」でカルテを子どもに見せる記録をつける。
                                       自分の担任クラスの児童だけ。
  E3 GET  /student-karte.js          … 児童画面用のスクリプトを配信するルート
  E4 児童画面(index.html)に <script src="/student-karte.js?v=1"> を注入（置換チェーンに1件追加）

public/index.html のファイル自体は書き換えません（配信時の置換で入れます）。
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')

src = io.open(TSX, encoding='utf-8').read()
orig = src
changes = []

def fail(msg):
    print('❌ 中止: ' + msg); sys.exit(1)

def rep(old, new, tag, sentinel=None):
    global src
    if sentinel is not None and sentinel in src:
        print('⏭  %s は適用済み（スキップ）' % tag); return
    n = src.count(old)
    if n == 0:
        if new and new in src:
            print('⏭  %s は適用済み（スキップ）' % tag); return
        fail('%s のアンカーが見つかりません' % tag)
    if n != 1:
        fail('%s のアンカーが %d 箇所（1箇所のはず）' % (tag, n))
    src = src.replace(old, new, 1)
    changes.append(tag)

def root_replace_count(text):
    a = text.index("app.get('/', async (c) => {")
    b = text.index("app.get('/logout'", a)
    return text[a:b].count('.replace(')

BEFORE_CHAIN = root_replace_count(orig)

# ---------------- P1: 提出率(%)パネルを削除 ----------------
SRX_OLD = (
    "/* 📌 2026-09 方針: ここには以前、先生のレビューを通さない自動の声かけ文が入っていた。 */ "
    "/*   低いと赤字で『正直に伝えると…』という文が、子どもに直接わたる形になっていた。 */ "
    "/*  → 数字だけ残し、かける言葉は先生がレビューして公開したコメント（🐯の欄）か手書きに任せる。 */ "
    "var _srx=(ov.submissionRate||{}); if(_srx.show){ "
    "var _trTxt=_srx.trend==='down'?'→ さいきんは すこし へっています':_srx.trend==='up'?'→ さいきんは ふえています':'→ ほぼ おなじくらいです'; "
    "var _box='<div class=\"sec\"><h2>📊 家庭学習の提出（今年度）</h2>'; "
    "_box+='<div style=\"display:flex;gap:14px;flex-wrap:wrap;align-items:center\">"
    "<div style=\"font-size:30px;font-weight:900;color:#475569\">'+(_srx.overall!=null?_srx.overall+'%':'-')+'</div>"
    "<div style=\"font-size:12px;color:#64748b;font-weight:700\">'+_trTxt+'"
    "<div style=\"font-size:10px;color:#94a3b8;font-weight:400\">直近約4週 '+(_srx.recent!=null?_srx.recent+'%':'-')+' / その前 '+(_srx.prev!=null?_srx.prev+'%':'-')+'</div></div></div>'; "
    "if(!d.aiComment){ _box+='<div style=\"margin-top:8px;border:2px dashed #cbd5e1;border-radius:10px;min-height:46px;padding:8px\">"
    "<div style=\"font-size:10px;color:#94a3b8;font-weight:700\">✏️ 先生から</div></div>'; } "
    "_box+='</div>'; H.push(_box); } "
)
SRX_NEW = (
    "/* 📌 2026-09 方針: 子どもに渡す紙から「提出率(%)」を外した（先生の判断）。 */ "
    "/*   ・％は子どもには抽象的で、下がったときに数字そのものが責めるように見えるため。 */ "
    "/*   ・かわりに一番上の「今週のようす」で『5日のうち○日』という実数だけを見せる。 */ "
    "/*   ・先生の画面（分析タブ）の提出率はそのまま残してあります。 */ "
)
rep(SRX_OLD, SRX_NEW, 'P1 紙から提出率(%)パネルを削除', sentinel='子どもに渡す紙から「提出率(%)」を外した')

# ---------------- P2: 月ごとの提出率(%)グラフを削除 ----------------
RATE_OLD = (
    "var _rItems=_mt.filter(function(m){return m.rate!=null;}).map(function(m){ return {label:String(m.month||'').slice(5), value:m.rate}; }); "
    "if(ov.submissionRate && ov.submissionRate.show && _rItems.length){ "
    "H.push('<div style=\"text-align:center\"><div style=\"font-size:11px;font-weight:700;color:#475569;margin-bottom:2px\">月ごとの提出率(%)</div>'+_kBars(_rItems)+'</div>'); } "
)
RATE_NEW = "/* 📌 2026-09: 月ごとの提出率(%)グラフも紙からは外した（回数のグラフは残す）。 */ "
rep(RATE_OLD, RATE_NEW, 'P2 紙から月ごとの提出率(%)グラフを削除', sentinel='月ごとの提出率(%)グラフも紙からは外した')

# ---------------- E1/E2: 児童向けカルテAPI ----------------
API_ANCHOR = "app.get('/api/teacher/risk-scores', async (c) => {"

API_NEW = """// ===== 📒 わたしのカルテ（子ども向け・B-e） =====
//  ・自分の分しか返さない。userId を渡してきても、自分以外なら 403。
//  ・先生が「公開」したもの（student_karte_shared に記録があるもの）だけ返す。
//  ・テストの点数・得点率・順位・ほかの子との比較は一切返さない。
//  ・パーセントも返さない（実数だけ）。文章は本人が書いたものと、先生が公開したものだけ。
//  ・learning_results は読まない（読み取りはごく少量）。
async function ensureKarteShareTable(env: any) {
  try { await env.DB.prepare('CREATE TABLE IF NOT EXISTS student_karte_shared (user_id TEXT PRIMARY KEY, class_id TEXT, shared_at TEXT, shared_by TEXT)').run() } catch (e) {}
}

app.get('/api/student/my-karte', async (c) => {
  const u = requireStudent(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  // 他人の分を見ようとしたら 403（MIしらべの /api/mi/my と同じ作法）
  const asked = String(c.req.query('userId') || c.req.query('studentId') || '')
  if (asked && asked !== String(u.id)) return jsonError(c, 403, 'forbidden')

  await ensureKarteShareTable(c.env)
  let shared: any = null
  try { shared = await c.env.DB.prepare('SELECT user_id FROM student_karte_shared WHERE user_id=? LIMIT 1').bind(u.id).first<any>() } catch (e) {}
  if (!shared) return c.json({ ok: true, published: false })

  let teacherMessage = ''
  try {
    const r = await c.env.DB.prepare('SELECT comment FROM student_ai_comments WHERE user_id=? LIMIT 1').bind(u.id).first<any>()
    teacherMessage = (r && r.comment) ? String(r.comment) : ''
  } catch (e) {}

  // 今週（日本時間の月〜金）
  const jst = new Date(Date.now() + 9 * 3600000)
  const wd = (jst.getUTCDay() + 6) % 7
  const monMs = jst.getTime() - wd * 86400000
  const ymd = (ms: number) => new Date(ms).toISOString().slice(0, 10)
  const dayKeys: string[] = []
  for (let i = 0; i < 5; i++) dayKeys.push(ymd(monMs + i * 86400000))
  const nowUtc = new Date()
  const wdU = nowUtc.getUTCDay() === 0 ? 6 : nowUtc.getUTCDay() - 1
  const monUtc = ymd(nowUtc.getTime() - wdU * 86400000)

  let subs: any[] = []
  try {
    const r = await c.env.DB.prepare('SELECT day_key, minutes, end_weather, weather_reason FROM homework_submissions WHERE user_id=? AND day_key >= ? AND day_key <= ?')
      .bind(u.id, dayKeys[0], dayKeys[4]).all<any>()
    subs = (((r && r.results) || []) as any[])
  } catch (e) {}
  const byDay: Record<string, any> = {}
  for (const s of subs) byDay[String(s.day_key)] = s

  const DOWJA = ['月', '火', '水', '木', '金']
  const days: any[] = []
  const voices: string[] = []
  let done = 0, minutes = 0
  for (let i = 0; i < 5; i++) {
    const s = byDay[dayKeys[i]]
    if (s) {
      done++
      minutes += Number(s.minutes || 0)
      if (s.weather_reason) voices.push(DOWJA[i] + ' ' + String(s.weather_reason).slice(0, 200))
      days.push({ weather: String(s.end_weather || '') })
    } else {
      days.push(null)
    }
  }

  let reflection: any = null
  try {
    const r = await c.env.DB.prepare('SELECT good_point, improve_point, next_action FROM structured_reflections WHERE user_id=? AND week_key IN (?, ?) ORDER BY week_key DESC LIMIT 1')
      .bind(u.id, dayKeys[0], monUtc).first<any>()
    if (r) reflection = {
      goodPoint: String(r.good_point || '').slice(0, 300),
      improvePoint: String(r.improve_point || '').slice(0, 300),
      nextAction: String(r.next_action || '').slice(0, 100),
    }
  } catch (e) {}

  return c.json({ ok: true, published: true, week: { days, done, minutes, voices }, reflection, teacherMessage })
})

// 先生：カルテを子どもの画面に出す（公開）。自分の担任クラスの児童だけ。
app.post('/api/teacher/karte-share', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json<any>().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid')
  const classId = String(body.classId || '')
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')

  const wanted = Array.isArray(body.studentIds) ? body.studentIds.map((x: any) => String(x)).slice(0, 300) : []
  if (!wanted.length) return c.json({ ok: true, saved: 0 })
  // そのクラスに在籍している子だけに絞る（別クラスの子を公開できないように）
  const memberRows = (((await c.env.DB.prepare('SELECT user_id FROM class_members WHERE class_id=?').bind(classId).all<any>()).results) || [])
  const members: Record<string, boolean> = {}
  for (const m of memberRows) members[String(m.user_id)] = true
  const ids = wanted.filter((x: string) => members[x])

  await ensureKarteShareTable(c.env)
  let saved = 0
  for (const sid of ids) {
    try {
      await c.env.DB.prepare("INSERT INTO student_karte_shared (user_id, class_id, shared_at, shared_by) VALUES (?,?,datetime('now'),?) ON CONFLICT(user_id) DO UPDATE SET class_id=excluded.class_id, shared_at=datetime('now'), shared_by=excluded.shared_by")
        .bind(sid, classId, u.id).run()
      saved++
    } catch (e) {}
  }
  return c.json({ ok: true, saved })
})

app.get('/api/teacher/risk-scores', async (c) => {"""
rep(API_ANCHOR, API_NEW, 'E1/E2 児童向けカルテAPIと公開APIを追加', sentinel="app.get('/api/student/my-karte'")

# ---------------- E3: /student-karte.js の配信ルート ----------------
ROUTE_OLD = "let _rootHtmlCache: string | null = null"
ROUTE_NEW = """app.get('/student-karte.js', async (c) => { try { const a = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/student-karte.js'))); if (a && a.status === 200) return new Response(await a.text(), { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } }); } catch (e) {} return c.text('not found', 404) })

let _rootHtmlCache: string | null = null"""
rep(ROUTE_OLD, ROUTE_NEW, 'E3 /student-karte.js の配信ルートを追加', sentinel="app.get('/student-karte.js'")

# ---------------- E4: 児童画面にスクリプトタグを注入 ----------------
MI_ANCHOR = '      // 🧭 MIしらべ の入口を「ステータス」画面の中へ。既存の「復習チャレンジ」カードと同じ作法。\n'
MI_NEW = (
    '      // 📒 わたしのカルテ（子ども向け）のスクリプトを読み込む\n'
    '      t = t.replace(\'<script src="/typeshoot.js"></script></body>\', '
    '\'<script src="/typeshoot.js"></script><script src="/student-karte.js?v=1"></script></body>\')\n'
    + MI_ANCHOR
)
rep(MI_ANCHOR, MI_NEW, 'E4 児童画面に /student-karte.js の script タグを注入',
    sentinel='student-karte.js?v=1')

# ---------------- P3: teacher-ai.js のキャッシュ更新 ----------------
rep('<script src="/teacher-ai.js?v=4"></script>', '<script src="/teacher-ai.js?v=5"></script>',
    'P3 teacher-ai.js のキャッシュ更新 (v5)', sentinel='/teacher-ai.js?v=5')

# ---------------- 検証 ----------------
after_chain = root_replace_count(src)
added = 1 if any(t.startswith('E4 ') for t in changes) else 0
if after_chain != BEFORE_CHAIN + added:
    fail('置換チェーンの数が想定外です（適用前 %d / 適用後 %d、+%d のはず）' % (BEFORE_CHAIN, after_chain, added))
if src.count('student-karte.js?v=1') != 1:
    fail('スクリプトタグの注入が %d 箇所（1箇所のはず）' % src.count('student-karte.js?v=1'))
print('🔎 置換チェーン: %d 件 → %d 件（スクリプトタグ注入ぶん +%d）' % (BEFORE_CHAIN, after_chain, added))

for must in ["app.get('/api/student/my-karte'", "app.post('/api/teacher/karte-share'",
             "app.get('/student-karte.js'", 'student-karte.js?v=1',
             'student_karte_shared', 'function _buildKarteHtml',
             '📅 今週のようす（', '<h2>🌟 今年度の積み上げ</h2>',
             "if (asked && asked !== String(u.id)) return jsonError(c, 403, 'forbidden')",
             'const u = requireStudent(c)', '/teacher-ai.js?v=5']:
    if must not in src: fail('必須の要素が失われました: %s' % must)

# 紙のカルテに提出率(%)が残っていないこと
i = src.index('function _buildKarteHtml')
j = src.index('function downloadKartePdf')
karte = src[i:j]
karte_nc = karte
for cm in ['子どもに渡すカルテにはテストの点数・得点率を載せない（先生の指示）',
           '子どもに渡す紙から「提出率(%)」を外した（先生の判断）。',
           '％は子どもには抽象的で、下がったときに数字そのものが責めるように見えるため。',
           'かわりに一番上の「今週のようす」で『5日のうち○日』という実数だけを見せる。',
           '先生の画面（分析タブ）の提出率はそのまま残してあります。',
           '月ごとの提出率(%)グラフも紙からは外した（回数のグラフは残す）。']:
    karte_nc = karte_nc.replace(cm, '')
for bad in ['提出率', 'submissionRate', 'テストの記録', '得点率', 'testScores']:
    if bad in karte_nc: fail('紙のカルテに残ってはいけないものがあります: %s' % bad)
print('🔎 紙のカルテに 提出率(%) / テストの点数 は入っていません')

# 先生の画面側の提出率は残っていること
if 'submissionRate' not in src: fail('先生の画面の提出率まで消えています')
print('🔎 先生の画面の提出率は残っています')

# 児童APIが learning_results を読んでいないこと
a2 = src.index("app.get('/api/student/my-karte'")
b2 = src.index("app.post('/api/teacher/karte-share'")
if 'learning_results' in src[a2:b2]:
    fail('児童向けカルテAPIが learning_results を読んでいます（重い）')
print('🔎 児童向けカルテAPIは learning_results を読みません')

for pat, want in [("app.get('/api/student/my-karte'", 1), ("app.post('/api/teacher/karte-share'", 1),
                  ("app.get('/student-karte.js'", 1), ('student-karte.js?v=1', 1),
                  ("app.get('/api/teacher/risk-scores'", 1)]:
    if src.count(pat) != want:
        fail('検証失敗: %r が %d 箇所（%d のはず）' % (pat, src.count(pat), want))

# ---------------- T1/T2: public/teacher-ai.js（先生の公開ボタン側） ----------------
TAI = os.path.join(ROOT, 'public', 'teacher-ai.js')
tai = io.open(TAI, encoding='utf-8').read()
tai_orig = tai

T1_OLD = "    KARTE:     { ja: '個人カルテ',       to: 'paper',   badge: '印刷して渡す' },"
T1_NEW = "    KARTE:     { ja: '個人カルテ',       to: 'kid',     badge: '子どもの画面に出る／印刷もできる' },"

T2_OLD = """    // --- 個人カルテ ---
    if (byKind.KARTE) {
      var r2 = await postJson('/api/teacher/student-ai-comments', {
        comments: byKind.KARTE.map(function (x) { return { studentId: x.targetId, comment: x.body }; })
      });
      if (r2 && r2.ok) { byKind.KARTE.forEach(function (x) { okIds.push(x.id); }); msgs.push('カルテ' + r2.saved + '人'); }
    }"""
T2_NEW = """    // --- 個人カルテ ---
    if (byKind.KARTE) {
      var r2 = await postJson('/api/teacher/student-ai-comments', {
        comments: byKind.KARTE.map(function (x) { return { studentId: x.targetId, comment: x.body }; })
      });
      if (r2 && r2.ok) {
        byKind.KARTE.forEach(function (x) { okIds.push(x.id); });
        msgs.push('カルテ' + r2.saved + '人');
        // 📒 2026-09: 公開したカルテを、その子のアプリ画面にも出す。
        //   ここで記録した子だけが /api/student/my-karte で自分のカルテを見られる。
        //   （先生が公開していない子には何も出ない）
        try {
          await postJson('/api/teacher/karte-share', {
            classId: cid,
            studentIds: byKind.KARTE.map(function (x) { return x.targetId; })
          });
        } catch (e) {}
      }
    }"""

if T1_NEW in tai:
    print('⏭  T1 カルテのバッジを「子どもの画面に出る」に は適用済み（スキップ）')
else:
    if tai.count(T1_OLD) != 1: fail('T1 のアンカーが %d 箇所（1箇所のはず）' % tai.count(T1_OLD))
    tai = tai.replace(T1_OLD, T1_NEW, 1); changes.append('T1 カルテのバッジを「子どもの画面に出る」に')

if '/api/teacher/karte-share' in tai:
    print('⏭  T2 公開時にカルテを子どもの画面へ は適用済み（スキップ）')
else:
    if tai.count(T2_OLD) != 1: fail('T2 のアンカーが %d 箇所（1箇所のはず）' % tai.count(T2_OLD))
    tai = tai.replace(T2_OLD, T2_NEW, 1); changes.append('T2 公開時にカルテを子どもの画面へ')

for must in ['/api/teacher/karte-share', '子どもの画面に出る／印刷もできる',
             'function taiPublish', 'function taiCopyAll', 'function taiCopyFresh']:
    if must not in tai: fail('teacher-ai.js の必須要素が失われました: %s' % must)
if tai.count("'/api/teacher/karte-share'") != 1:
    fail('teacher-ai.js の karte-share 呼び出しが %d 箇所（1箇所のはず）' % tai.count("'/api/teacher/karte-share'"))
if "badge: '印刷して渡す'" in tai:
    fail('古いバッジが残っています')
print('🔎 teacher-ai.js: 公開ボタンからカルテを子どもの画面に出す配線を確認')

if tai != tai_orig:
    io.open(TAI, 'w', encoding='utf-8', newline='').write(tai)
    print('✅ public/teacher-ai.js を更新しました')

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました')
else:
    print('… src/index.tsx は変更なし')
print('---- 適用した項目 ----')
for c in changes: print(' ・' + c)
if not changes: print(' （なし）')
