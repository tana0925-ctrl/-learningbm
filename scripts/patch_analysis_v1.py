#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_analysis_v1.py  ---  分析タブ 作り直し 第1段階

やること（すべて「必ず1回だけ一致」を確認してから適用。合わなければ中止）
  src/index.tsx
    T1 AI下書きレビュー用API（ai-drafts 3本）を追加
    T2 分析タブの最上部に「今日のひと往復」パネルを追加
    T3 古いAIパネル4つを <details>「以前の画面（そのうち無くなります）」に畳んで下へ移動
    T4 サブタブ④のラベルを「AI分析・個人」→「AIの結果」に
    T5 「🤖 最新のAI分析（保存済み…）」→「📄 いま子どもに届いている文（保存ずみ）」
    T6 「🔍 要因分析（何をすると伸びる？）」→ AI誤認しない見出しに
    T7 個人カルテパネルに「児童一覧を表示」ボタン（古いAIボタンに依存しないように）
    T8 /api/homework/analyze-photo の自動AI分析を停止
    T9 教師ダッシュボードに <script src="/teacher-ai.js"> を追加
    T10「📷 成果物（AI分析）：」→「📷 成果物メモ（過去の自動分析）：」
  public/index.html （バイナリ読み書き・CRLF維持）
    H1 写真提出の「🔍分析中...」表示を「📤送信中...」に
    H2 「(分析スキップ)」「(分析エラー)」の文言を送信状態の文言に
    H3 児童ステータス「学習の分析」の説明を「計算で出している」と明示
    H4 児童「先生（AI）からの計画アドバイス」→「先生からの計画アドバイス」
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
HTML = os.path.join(ROOT, 'public', 'index.html')

changes = []
def fail(msg):
    print('❌ 中止: ' + msg)
    sys.exit(1)

def rep(text, old, new, tag, expect=1, sentinel=None):
    if sentinel is not None and sentinel in text:
        print('⏭  %s は適用済み（スキップ）' % tag)
        return text
    n = text.count(old)
    if n == 0:
        if new in text:
            print('⏭  %s は適用済み（スキップ）' % tag)
            return text
        fail('%s のアンカーが見つかりません' % tag)
    if n != expect:
        fail('%s のアンカーが %d 箇所ありました（%d 箇所のはず）' % (tag, n, expect))
    changes.append(tag)
    return text.replace(old, new, expect)

# ===================================================================
# src/index.tsx
# ===================================================================
src = io.open(TSX, encoding='utf-8').read()
orig_src = src

# ---------------- T1: AI下書きレビュー用API ----------------
ANCHOR_API = '// ===== テスト結果の取り込みAPI（外部AIの出力を貼り付け→パース→保存・集計値は再利用可能） ====='

NEW_API = r'''// ===== 外部AIの貼り戻しを「下書き」として預かるAPI =====
//  子どもに届く前に、先生が必ず目を通せるようにするための置き場。
//  ここに入っているだけでは誰にも届かない。公開は既存APIをそのまま使う。
async function ensureAiDraftTable(env: any) {
  try {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS ai_review_drafts (
      id TEXT PRIMARY KEY,
      teacher_id TEXT NOT NULL,
      class_id TEXT NOT NULL,
      week_key TEXT,
      kind TEXT NOT NULL,
      target_id TEXT,
      target_name TEXT,
      ref_key TEXT,
      body TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'draft',
      created_at TEXT,
      published_at TEXT
    )`).run()
  } catch {}
  try { await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_ai_drafts_class ON ai_review_drafts (class_id, status)').run() } catch {}
}
async function aiDraftOwnsClass(c: any, u: any, classId: string) {
  return u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first<any>()
}
const AI_DRAFT_KINDS = ['DAILY', 'KARTE', 'PLAN', 'REFLECT', 'SUGGEST', 'CLASS', 'WEEKREPORT']

app.post('/api/teacher/ai-drafts', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json<any>().catch(() => null)
  if (!body || !Array.isArray(body.items)) return jsonError(c, 400, 'invalid')
  const classId = String(body.classId || '')
  if (!classId) return jsonError(c, 400, 'classId required')
  if (!(await aiDraftOwnsClass(c, u, classId))) return jsonError(c, 404, 'class_not_found')
  await ensureAiDraftTable(c.env)
  const weekKey = String(body.weekKey || '').slice(0, 12)
  if (body.replace) {
    try { await c.env.DB.prepare("DELETE FROM ai_review_drafts WHERE class_id=? AND teacher_id=? AND status='draft'").bind(classId, u.id).run() } catch {}
  }
  let saved = 0
  for (const it of body.items) {
    const kind = String((it && it.kind) || '').toUpperCase()
    if (AI_DRAFT_KINDS.indexOf(kind) < 0) continue
    const text = String((it && it.body) || '').slice(0, 8000)
    if (!text.trim()) continue
    const targetId = String((it && it.targetId) || '')
    // 児童宛ての下書きは、そのクラスの児童かどうかを必ず確かめる
    if (targetId) {
      const own = await c.env.DB.prepare('SELECT 1 FROM class_members WHERE class_id=? AND user_id=? LIMIT 1').bind(classId, targetId).first<any>()
      if (!own) continue
    }
    const id = 'aid_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 9)
    await c.env.DB.prepare(
      "INSERT INTO ai_review_drafts (id, teacher_id, class_id, week_key, kind, target_id, target_name, ref_key, body, status, created_at) VALUES (?,?,?,?,?,?,?,?,?,'draft',datetime('now'))"
    ).bind(id, u.id, classId, weekKey, kind, targetId, String((it && it.targetName) || '').slice(0, 60), String((it && it.refKey) || '').slice(0, 60), text).run()
    saved++
  }
  return c.json({ ok: true, saved })
})

app.get('/api/teacher/ai-drafts', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const classId = String(c.req.query('classId') || '')
  if (!classId) return jsonError(c, 400, 'classId required')
  if (!(await aiDraftOwnsClass(c, u, classId))) return jsonError(c, 404, 'class_not_found')
  await ensureAiDraftTable(c.env)
  let rows: any = { results: [] }
  try {
    rows = await c.env.DB.prepare(
      "SELECT id, kind, target_id as targetId, target_name as targetName, ref_key as refKey, body, status, created_at as createdAt, published_at as publishedAt FROM ai_review_drafts WHERE class_id=? AND teacher_id=? AND status<>'discarded' ORDER BY (status='draft') DESC, kind, created_at DESC LIMIT 400"
    ).bind(classId, u.id).all<any>()
  } catch {}
  const drafts = (((rows && rows.results) || []) as any[])
  // 家庭学習コメントには、どの日の提出かを添えて先生が見分けられるようにする
  for (const d of drafts) {
    if (d.kind === 'DAILY' && d.refKey) {
      try {
        const hw = await c.env.DB.prepare('SELECT hs.day_key as dayKey, u2.name, u2.login_id as loginId FROM homework_submissions hs JOIN users u2 ON u2.id=hs.user_id WHERE hs.id=? LIMIT 1').bind(d.refKey).first<any>()
        if (hw) { d.refLabel = hw.dayKey || ''; if (!d.targetName) d.targetName = hw.name || hw.loginId || '' }
      } catch {}
    }
  }
  return c.json({ ok: true, drafts })
})

app.post('/api/teacher/ai-drafts/mark', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json<any>().catch(() => null)
  if (!body || !Array.isArray(body.ids)) return jsonError(c, 400, 'invalid')
  const status = String(body.status || '')
  if (status !== 'published' && status !== 'discarded' && status !== 'draft') return jsonError(c, 400, 'bad_status')
  await ensureAiDraftTable(c.env)
  let n = 0
  for (const rawId of body.ids) {
    const id = String(rawId || '')
    if (!id) continue
    const r = await c.env.DB.prepare(
      "UPDATE ai_review_drafts SET status=?, published_at=CASE WHEN ?='published' THEN datetime('now') ELSE published_at END WHERE id=? AND teacher_id=?"
    ).bind(status, status, id, u.id).run()
    if (r && r.meta && r.meta.changes) n += r.meta.changes
  }
  return c.json({ ok: true, updated: n })
})

'''
src = rep(src, ANCHOR_API, NEW_API + ANCHOR_API, 'T1 ai-drafts API', sentinel="app.post('/api/teacher/ai-drafts'")

# ---------------- T2: 「今日のひと往復」パネル ----------------
ANCHOR_SEL = ('<!-- 共通クラス選択 -->\n'
              '        <div class="bg-white rounded-xl shadow p-3 flex gap-2 items-center flex-wrap">\n'
              '          <span class="text-sm font-bold text-slate-600">クラス:</span>\n'
              '          <select id="analyticsClassFilter" class="border p-2 rounded text-sm bg-white"></select>\n'
              '        </div>\n')

CHK = ('<label class="flex items-center gap-1"><input type="checkbox" id="%s"%s class="accent-indigo-600"> %s</label>')
ROUNDTRIP = '''
        <!-- ★ 今日のひと往復（分析タブのメインの導線） -->
        <div class="bg-white rounded-xl shadow border-2 border-indigo-400 p-4 space-y-3">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div class="font-black text-base text-indigo-800">📋 今日のひと往復</div>
            <span class="text-xs text-slate-500">コピー → 外部AIに貼る → 貼り戻す → 確認して公開</span>
          </div>

          <div class="border border-slate-200 rounded-lg p-3">
            <div class="font-bold text-sm text-slate-700 mb-2"><span class="bg-indigo-500 text-white rounded-full px-2 py-0.5 text-xs mr-1">1</span>今回ふくめるもの</div>
            <div class="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-700 mb-2">
              ''' + CHK % ('taiOptDaily', ' checked', '家庭学習コメント（毎日）') + '''
              ''' + CHK % ('taiOptKarte', '', '個人カルテ') + '''
              ''' + CHK % ('taiOptClass', '', 'クラス所見') + '''
              ''' + CHK % ('taiOptReport', '', '週報') + '''
              ''' + CHK % ('taiOptPlan', '', '計画アドバイス') + '''
              ''' + CHK % ('taiOptReflect', '', '週の振り返りの返却') + '''
              ''' + CHK % ('taiOptSuggest', '', 'おすすめ計画') + '''
            </div>
            <button onclick="taiCopyAll()" class="bg-emerald-600 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:bg-emerald-700">📋 まとめてコピー</button>
            <span id="taiStatus" class="text-xs font-bold text-indigo-700 ml-2"></span>
          </div>

          <div class="border border-slate-200 rounded-lg p-3">
            <div class="font-bold text-sm text-slate-700 mb-2"><span class="bg-indigo-500 text-white rounded-full px-2 py-0.5 text-xs mr-1">2</span>ChatGPT / Gemini / Claude に貼る　<span class="bg-indigo-500 text-white rounded-full px-2 py-0.5 text-xs mr-1">3</span>返ってきた文をここに貼る</div>
            <textarea id="taiPaste" rows="4" class="w-full border border-slate-300 rounded-lg p-2 text-xs" placeholder="AIの返事をぜんぶ貼り付け（=== [ ... ] === の目印ごとに自動でふり分けます）"></textarea>
            <button onclick="taiImport()" class="mt-2 bg-indigo-600 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:bg-indigo-700">🔍 下書きに取り込む</button>
          </div>

          <div class="border-2 border-rose-300 bg-rose-50 rounded-lg p-3">
            <div class="flex items-center justify-between flex-wrap gap-2 mb-1">
              <div class="font-bold text-sm text-rose-800"><span class="bg-rose-500 text-white rounded-full px-2 py-0.5 text-xs mr-1">4</span>先生が確認して公開</div>
              <div class="flex items-center gap-2">
                <span id="taiPubCount" class="text-xs font-bold text-rose-700"></span>
                <button onclick="taiLoadDrafts()" class="bg-white border border-rose-300 text-rose-700 rounded px-2 py-1 text-xs font-bold hover:bg-rose-100">🔄 更新</button>
              </div>
            </div>
            <p class="text-xs text-rose-700 mb-2">公開ボタンを押すまで、子どもには何も届きません。</p>
            <div id="taiDraftList" class="space-y-2"><p class="text-xs text-slate-400">クラスを選んでください</p></div>
            <div class="flex items-center gap-2 flex-wrap mt-2">
              <button onclick="taiPublish()" class="bg-rose-600 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:bg-rose-700">✅ チェックした分を公開</button>
              <button onclick="taiDiscard()" class="bg-slate-200 text-slate-700 rounded-lg px-3 py-2 text-xs font-bold hover:bg-slate-300">🗑 下書きを消す</button>
              <span id="taiPubStatus" class="text-xs font-bold text-rose-700"></span>
            </div>
          </div>
        </div>
'''
src = rep(src, ANCHOR_SEL, ANCHOR_SEL + ROUNDTRIP, 'T2 今日のひと往復パネル', sentinel='id="taiDraftList"')

# ---------------- T3: 古いAIパネルを畳んで下へ ----------------
A1 = '<div class="bg-gradient-to-br from-violet-50 to-fuchsia-50 border border-violet-300 rounded-xl p-4 space-y-2">'
A2 = '<!-- AIクラス分析 -->'
A3 = '<!-- 通知表（先生用・観点別◎○△） -->'
A4 = '<!-- 全員分まとめAI分析 -->'
A5 = '<!-- 提出ヒートマップ -->'
A6 = '<!-- サブタブ⑤: テスト結果の取り込み -->'
DETAILS_MARK = '以前の画面（そのうち無くなります）'

if DETAILS_MARK in src:
    print('⏭  T3 古いパネルの移動は適用済み（スキップ）')
else:
    for a in (A1, A2, A3, A4, A5, A6):
        if src.count(a) != 1:
            fail('T3 のアンカー %r が %d 箇所（1箇所のはず）' % (a[:40], src.count(a)))
    i1, i2, i3 = src.index(A1), src.index(A2), src.index(A3)
    i4, i5, i6 = src.index(A4), src.index(A5), src.index(A6)
    if not (i1 < i2 < i3 < i4 < i5 < i6):
        fail('T3 のアンカーの並び順が想定と違います')
    cutA = src[i1:i2]   # 🤖 AI分析（まとめて）— ワンストップ
    cutB = src[i2:i3]   # 🤖 AIクラス分析 ＋ 📋 週報レポート
    cutC = src[i4:i5]   # 🤖 全員分のAI分析（一括）
    rest = src[:i1] + src[i3:i4] + src[i5:]

    details = (
        '<details class="bg-slate-50 border border-slate-300 rounded-xl">\n'
        '            <summary class="cursor-pointer p-3 text-sm font-bold text-slate-500 select-none">🗂 ' + DETAILS_MARK + '（ふだんは開かなくて大丈夫です）</summary>\n'
        '            <div class="p-3 pt-0 space-y-3">\n'
        '            ' + cutA.rstrip() + '\n\n            ' + cutB.rstrip() + '\n\n            ' + cutC.rstrip() + '\n'
        '            </div>\n'
        '          </details>\n'
    )
    # ヒートマップの直後（= anPane_ai を閉じる </div> の直前）に差し込む
    h5 = rest.index(A5); h6 = rest.index(A6)
    seg = rest[h5:h6]
    k = seg.rfind('</div>')
    if k < 0:
        fail('T3 の挿入位置（anPane_ai の閉じタグ）が見つかりません')
    new_seg = seg[:k] + details + '          ' + seg[k:]
    src = rest[:h5] + new_seg + rest[h6:]
    changes.append('T3 古いAIパネルを畳んで下へ移動')

# ---------------- T4〜T7: ラベルまわり ----------------
src = rep(src,
  '<span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">4</span> AI分析・個人',
  '<span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">4</span> AIの結果',
  'T4 サブタブ④ラベル')

src = rep(src,
  '<div class="font-bold text-sm text-sky-800">🤖 最新のAI分析（保存済み・いつでも表示）</div>',
  '<div class="font-bold text-sm text-sky-800">📄 いま子どもに届いている文（AIが書き、先生が公開したもの）</div>',
  'T5 保存済みAI分析の見出し')

src = rep(src,
  '<h3 class="font-bold text-slate-700">🔍 要因分析（何をすると伸びる？）</h3>',
  '<h3 class="font-bold text-slate-700">🔍 何をすると伸びる？</h3><span class="text-[10px] bg-slate-100 text-slate-500 rounded px-1.5 py-0.5 font-bold">計算で表示・AIではありません</span>',
  'T6 要因分析の見出し')

src = rep(src,
  '''<p class="text-xs text-amber-600">児童の名前をクリックすると、AIによる個人分析が表示されます。</p>
            <div id="karteStudentList" class="flex flex-wrap gap-2">
              <p class="text-xs text-slate-400">クラスを選んで「AIで分析」または「週報を生成」を押すと、ここに児童一覧が表示されます</p>
            </div>''',
  '''<p class="text-xs text-amber-600">名前をクリックすると、その子の記録をまとめた画面が開きます。<button onclick="taiLoadRoster()" class="ml-1 bg-amber-500 text-white rounded px-2 py-0.5 text-[11px] font-bold hover:bg-amber-600">🔄 児童一覧を表示</button></p>
            <div id="karteStudentList" class="flex flex-wrap gap-2">
              <p class="text-xs text-slate-400">「児童一覧を表示」を押してください</p>
            </div>''',
  'T7 個人カルテに児童一覧ボタン')

# ---------------- T8: 児童写真の自動AI分析を停止 ----------------
AI_START = "    try {\n      let binary = ''\n"
AI_END   = "    } catch (e: any) {\n      console.error('AI photo analysis error:', e)\n      analysisText = ''\n    }\n"
STOP_NOTE = "    // 🚫 2026-09 方針変更: 児童が出した写真の自動AI分析は行いません。\n"

if STOP_NOTE in src:
    print('⏭  T8 写真の自動AI分析停止は適用済み（スキップ）')
else:
    if src.count(AI_START) != 1: fail('T8 の開始アンカーが %d 箇所' % src.count(AI_START))
    if src.count(AI_END) != 1:   fail('T8 の終了アンカーが %d 箇所' % src.count(AI_END))
    a = src.index(AI_START); b = src.index(AI_END) + len(AI_END)
    if b <= a: fail('T8 のアンカーの並び順が想定と違います')
    removed = src[a:b]
    if 'callGemini' not in removed or 'gemma' not in removed:
        fail('T8 で取り除こうとした範囲に想定のAI呼び出しが含まれていません')
    src = src[:a] + (
        STOP_NOTE +
        "    //    提出直後の反応はアプリ側（写真ボーナス）で返します。\n"
        "    //    中身のあるコメントは、先生が外部AIの下書きを確認して公開したものだけが届きます。\n"
        "    //    （教師ダッシュボード 分析タブ →「今日のひと往復」→ ④先生が確認して公開）\n"
        "    analysisText = ''\n"
    ) + src[b:]
    changes.append('T8 写真の自動AI分析を停止')

# ---------------- T9: teacher-ai.js を読み込む ----------------
TAIL = "        await renderClasses();\n      })();\n    </script>"
src = rep(src, TAIL, TAIL + '\n    <script src="/teacher-ai.js?v=1"></script>', 'T9 teacher-ai.js の読み込み', sentinel='/teacher-ai.js')

# ---------------- T10: 写真メモのラベル ----------------
src = rep(src, '📷 成果物（AI分析）：', '📷 成果物メモ（2026年8月までの自動分析）：', 'T10 写真メモのラベル')

# ===================================================================
# public/index.html （バイナリ・CRLF維持）
# ===================================================================
raw = open(HTML, 'rb').read()
orig_raw = raw

def brep(data, old, new, tag, expect=1):
    o = old.encode('utf-8'); n = new.encode('utf-8')
    cnt = data.count(o)
    if cnt == 0:
        if n in data:
            print('⏭  %s は適用済み（スキップ）' % tag)
            return data
        fail('%s のアンカーが見つかりません' % tag)
    if cnt != expect:
        fail('%s のアンカーが %d 箇所（%d 箇所のはず）' % (tag, cnt, expect))
    changes.append(tag)
    return data.replace(o, n, expect)

raw = brep(raw, "statusEl.textContent += ' 🔍分析中...';",
                "statusEl.textContent += ' 📤送信中...';", 'H1 写真の送信中表示')
raw = brep(raw, "statusEl.textContent = file.name.slice(0,20) + ' ✅';",
                "statusEl.textContent = file.name.slice(0,20) + ' ✅ 先生に送ったよ';", 'H2a 送信完了表示')
raw = brep(raw, "statusEl.textContent = file.name.slice(0,20) + ' (分析スキップ)';",
                "statusEl.textContent = file.name.slice(0,20) + ' ⚠️ 送れませんでした';", 'H2b 送信失敗表示')
raw = brep(raw, "statusEl.textContent = file.name.slice(0,20) + ' (分析エラー)';",
                "statusEl.textContent = file.name.slice(0,20) + ' ⚠️ 送れませんでした';", 'H2c 送信エラー表示')
raw = brep(raw, '<div class="text-xs text-gray-500">修行の記録から自動で作るよ</div>',
                '<div class="text-xs text-gray-500">きろくを計算して出しているよ（AIではないよ）</div>', 'H3 学習の分析の説明')
raw = brep(raw, '\\uD83D\\uDCCB 先生（AI）からの計画アドバイス',
                '\\uD83D\\uDCCB 先生からの計画アドバイス', 'H4 計画アドバイスの見出し')

# ===================================================================
# 書き出し（適用前後の確認つき）
# ===================================================================
def root_replace_count(text):
    a = text.index("app.get('/', async (c) => {")
    b = text.index("app.get('/logout'", a)
    return text[a:b].count('.replace(')

before_n = root_replace_count(orig_src)
after_n  = root_replace_count(src)
if before_n != after_n:
    fail('本番HTMLの置換チェーンの数が %d → %d に変わりました' % (before_n, after_n))
print('🔎 置換チェーン: %d 件（適用前後で同数）' % after_n)

if src != orig_src:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました')
else:
    print('… src/index.tsx は変更なし')

if raw != orig_raw:
    open(HTML, 'wb').write(raw)
    print('✅ public/index.html を更新しました（CRLFのままバイナリ書き込み）')
else:
    print('… public/index.html は変更なし')

print('---- 適用した項目 ----')
for c in changes:
    print(' ・' + c)
if not changes:
    print(' （なし）')
