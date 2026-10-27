# -*- coding: utf-8 -*-
# PORTFOLIO_V1 ＋ AIFLOW_V1 を src/index.tsx と public/teacher-ai.js に「目印つきで」重ねる。
#   ・何回流しても同じ結果（すでに入っていれば何もしない）。
#   ・目印が見つからなければ止まる（最新の main で形が変わっていたら、手で確かめる）。
#   ・src/index.tsx の app.get('/') の .replace() の対象行には触らない。
#   使い方: python3 scripts/patch_portfolio_aiflow_v1.py
import io, sys, re

def load(p):
    with io.open(p, 'r', encoding='utf-8', newline='') as f:
        return f.read()

def save(p, s):
    with io.open(p, 'w', encoding='utf-8', newline='') as f:
        f.write(s)

def put(s, anchor, new, where, mark, count=1):
    if mark in s:
        return s, False
    n = s.count(anchor)
    if n != count:
        sys.exit('アンカーが %d 個（期待 %d）: %r' % (n, count, anchor[:80]))
    if where == 'after':
        return s.replace(anchor, anchor + new, 1), True
    if where == 'before':
        return s.replace(anchor, new + anchor, 1), True
    if where == 'replace':
        return s.replace(anchor, new, 1), True
    raise ValueError(where)

changed = []

# ───────────── src/index.tsx ─────────────
P = 'src/index.tsx'
s = load(P)
s, c = put(s, "import { registerHsSign } from './hssign'\n",
           "// PORTFOLIO_V1 📸 成果物ポートフォリオ（先生だけ）。中身は src/portfolio.ts。\nimport { registerPortfolio, pfFromHomework, pfWorkNoteFor } from './portfolio'\n// AIFLOW_V1 🧵 今日のひと往復に「先週までの流れ」。中身は src/aiflow.ts。\nimport { registerAiFlow } from './aiflow'\n",
           'after', "from './portfolio'"); changed += ['import'] if c else []
s, c = put(s, "type Bindings = {\n  DB: D1Database\n  SESSION_SECRET: string\n  ADMIN_LOGIN_ID?: string\n  ADMIN_PASSWORD?: string\n  AI: any\n",
           "  PF?: any     // PORTFOLIO_V1 R2（写真の置き場・あれば優先）\n  PFDB?: any   // PORTFOLIO_V1 写真専用の D1（R2 が無いあいだの置き場）\n",
           'after', 'PORTFOLIO_V1 R2（写真の置き場'); changed += ['bindings'] if c else []
s, c = put(s, "registerHsSign(app, { jstStudyDayKey })    // HSSIGN_V1\n",
           "registerPortfolio(app, { getCookie })    // PORTFOLIO_V1\nregisterAiFlow(app)    // AIFLOW_V1\n",
           'after', 'registerPortfolio(app'); changed += ['register'] if c else []
s, c = put(s, "const AI_DRAFT_KINDS = ['DAILY', 'KARTE', 'PLAN', 'REFLECT', 'SUGGEST', 'CLASS', 'WEEKREPORT']",
           "const AI_DRAFT_KINDS = ['DAILY', 'KARTE', 'PLAN', 'REFLECT', 'SUGGEST', 'CLASS', 'WEEKREPORT', 'FLOW', 'WORK', 'WORKMEMO']   // AIFLOW_V1 FLOW＝流れのメモ（先生だけ）／PORTFOLIO_AI_V1 WORK＝成果物へのひとこと（カルテ📓）・WORKMEMO＝成果物の分析メモ（先生だけ）",
           'replace', "'FLOW', 'WORK', 'WORKMEMO']"); changed += ['kinds'] if c else []
s, c = put(s, "    } catch (dbErr: any) {\n      console.error('D1 photo save error:', dbErr?.message || dbErr)\n    }\n",
           "    // 📸 PORTFOLIO_V1 成果物ポートフォリオにも入れる（先生だけが見る。子どもの画面には出ない。設定で止められる）\n"
           "    if (savedToV2 || photoIdx === 0) {\n"
           "      try {\n"
           "        const _pf = pfFromHomework(c.env, u.id, dayKey, photoIdx, imageBytes, mimeType)\n"
           "        let _ec: any = null\n"
           "        try { _ec = (c as any).executionCtx } catch (_e) { _ec = null }\n"
           "        if (_ec && typeof _ec.waitUntil === 'function') _ec.waitUntil(_pf); else await _pf\n"
           "      } catch (_e) {}\n"
           "    }\n",
           'after', 'PORTFOLIO_V1 成果物ポートフォリオにも入れる'); changed += ['hw-hook'] if c else []
s, c = put(s, "// 写真を取得（先生 or 本人のみ）\napp.get('/api/photo/:userId/:dayKey', async (c) => {\n  const u = c.get('user')\n  if (!u) return jsonError(c, 403, 'forbidden')\n  const targetUserId = c.req.param('userId')\n  const dayKey = c.req.param('dayKey')\n\n  // 本人 or 先生のみ\n  if (u.role === 'student' && u.id !== targetUserId) return jsonError(c, 403, 'forbidden')\n",
           "// 写真を取得（先生・管理者のみ）\napp.get('/api/photo/:userId/:dayKey', async (c) => {\n  const u = c.get('user')\n  if (!u) return jsonError(c, 403, 'forbidden')\n  const targetUserId = c.req.param('userId')\n  const dayKey = c.req.param('dayKey')\n\n  // 📸 PORTFOLIO_V1 写真は先生・管理者だけ（子どもの画面・見るだけモードには出さない。子どもの画面はこの道を使っていない）\n  if (u.role !== 'teacher' && u.role !== 'admin') return jsonError(c, 403, 'forbidden')\n",
           'replace', '写真は先生・管理者だけ（子どもの画面'); changed += ['photo-guard'] if c else []
s, c = put(s, "    headers.set('Content-Type', row.mime_type || 'image/jpeg')\n    headers.set('Cache-Control', 'private, max-age=3600')\n",
           "    // 📸 PORTFOLIO_V1 画像としてだけ返す（画像でない中身を、ページとして開かせない）\n"
           "    headers.set('Content-Type', /^image\\/(jpeg|png|webp|gif)$/i.test(String(row.mime_type || '')) ? String(row.mime_type) : 'image/jpeg')\n"
           "    headers.set('Cache-Control', 'private, max-age=3600')\n"
           "    headers.set('X-Content-Type-Options', 'nosniff')\n"
           "    headers.set('Content-Security-Policy', \"default-src 'none'; sandbox\")\n",
           'replace', '画像としてだけ返す（画像でない中身を'); changed += ['photo-headers'] if c else []
# 📓 my-karte の返事に work を足す（返す項目が増えていても動くよう、行の終わりだけを見る）
if 'pfWorkNoteFor(c.env' not in s:
    m = re.search(r"\n(  return c\.json\(\{ ok: true, published: true, week: \{ days, done, minutes, voices \}[^\n]*?) \}\)\n", s)
    if not m: sys.exit('my-karte の return が見つかりません')
    line = m.group(1)
    s = s[:m.start()] + "\n  // 📓 PORTFOLIO_AI_V1 先生が公開した「ノート・作品へのひとこと」（文だけ。写真は出さない）\n  let work: any = null\n  try { work = await pfWorkNoteFor(c.env, String(u.id)) } catch (_e) { work = null }\n" + line + ", work })\n" + s[m.end():]
    changed.append('my-karte')
TB = "app.get('/teibako.js', async (c) => {"
i = s.find(TB)
if i < 0: sys.exit('teibako.js の道が見つかりません')
j = s.find('\n', i)
route_line = s[i:j]
if "app.get('/portfolio.js'" not in s:
    add = ''
    for fn, mk in (('portfolio.js', 'PORTFOLIO_V1'), ('ai-flow.js', 'AIFLOW_V1')):
        ln = route_line.replace("'/teibako.js'", "'/" + fn + "'").replace("https://assets/teibako.js", "https://assets/" + fn)
        k = ln.rfind('//')
        ln = (ln[:k] if k > 0 else ln + '   ') + '// ' + mk
        add += '\n' + ln
    s = s[:j] + add + s[j:]
    changed.append('routes')
s, c = put(s, '<a href="/teacher-mi" class="text-sm px-3 py-1 rounded bg-indigo-100 hover:bg-indigo-200 text-indigo-700 font-bold transition">🧭 MIしらべ</a>\n',
           '          <button onclick="PF_OPEN()" title="ノート・作品・家庭学習の写真（先生だけ）" class="text-sm px-3 py-1 rounded bg-amber-100 hover:bg-amber-200 text-amber-800 font-bold transition">📸 成果物</button><!-- PORTFOLIO_V1 -->\n',
           'after', 'PF_OPEN()'); changed += ['button'] if c else []
if '/ai-flow.js?v=' not in s:
    m = re.search(r'\n[ \t]*<script src="/teibako\.js\?v=\d+"></script>[^\n]*\n', s)
    if not m: sys.exit('teibako.js の読み込みタグが見つかりません')
    s = s[:m.end()] + '    <script src="/ai-flow.js?v=1"></script><!-- AIFLOW_V1 🧵 先週までの流れ -->\n    <script src="/portfolio.js?v=1"></script><!-- PORTFOLIO_V1 📸 成果物 -->\n' + s[m.end():]
    changed.append('scripts')
save(P, s)

# ───────────── public/teacher-ai.js ─────────────
P = 'public/teacher-ai.js'
t = load(P)
t, c = put(t, "var TAI_KINDS = ['DAILY', 'KARTE', 'PLAN', 'REFLECT', 'SUGGEST', 'CLASS', 'WEEKREPORT'];",
           "var TAI_KINDS = ['DAILY', 'KARTE', 'PLAN', 'REFLECT', 'SUGGEST', 'CLASS', 'WEEKREPORT', 'FLOW', 'WORK', 'WORKMEMO'];   /* AIFLOW_V1 ／ PORTFOLIO_AI_V1 */",
           'replace', "'FLOW', 'WORK', 'WORKMEMO'];"); changed += ['t-kinds'] if c else []
t, c = put(t, "    WEEKREPORT:{ ja: '週報',             to: 'teacher', badge: '先生だけ' }",
           ",\n    FLOW:      { ja: '流れのメモ',       to: 'teacher', badge: '先生だけ（次のコピーの「先週までの流れ」に入る）' },   /* AIFLOW_V1 */"
           "\n    WORK:      { ja: '📓 成果物へのひとこと', to: 'kid', badge: '子どもの画面と紙のカルテ（📓）に出る' },   /* PORTFOLIO_AI_V1 */"
           "\n    WORKMEMO:  { ja: '成果物の分析メモ', to: 'teacher', badge: '先生だけ（次のコピーの「先週までの流れ」に入る）' }   /* PORTFOLIO_AI_V1 */",
           'after', "FLOW:      { ja: '流れのメモ'"); changed += ['t-kindja'] if c else []
t, c = put(t, "var flags = ['daily', 'karte', 'classOv', 'report', 'plan', 'reflect', 'suggest']",
           "var flags = ['daily', 'karte', 'classOv', 'report', 'plan', 'reflect', 'suggest', 'flowCtx', 'flow']   /* AIFLOW_V1 */",
           'replace', "'suggest', 'flowCtx', 'flow']"); changed += ['t-cache'] if c else []
t, c = put(t, "    // MINNA_FURI_V1 ⭐みんなのふりかえり候補（中身は teibako.js の window.MINNA_PICK）\n",
           "    // AIFLOW_V1 🧵 先週までの流れ（中身は ai-flow.js の window.AI_FLOW）。入らなかった分だけのコピーでは使わない\n"
           "    want.flowCtx = !!window.AI_FLOW && window.AI_FLOW.enabled() && !(opts.onlyKinds && opts.onlyKinds.length) && !opts.retryMode;\n"
           "    want.flow = !!want.flowCtx && !oneKind && !oneId;\n",
           'before', 'want.flowCtx = !!window.AI_FLOW'); changed += ['t-want'] if c else []
t, c = put(t, "    TAI_NG_RULE_LINES.forEach(function (x) { out.push(x); });   /* NGWORD_V1 */\n",
           "    try { if (want.flowCtx) window.AI_FLOW.ruleLines(want.flow).forEach(function (x) { out.push(x); }); } catch (e) {}   /* AIFLOW_V1 */\n",
           'after', 'window.AI_FLOW.ruleLines('); changed += ['t-rules'] if c else []
t, c = put(t, "    for (var i = 0; i < roster.length; i++) {\n      var st = roster[i];\n      var nm = anonUid(st.userId);",
           "    if (want.flowCtx) { say('前の流れを読んでいます...'); try { await window.AI_FLOW.prefetch(cid); } catch (e) {} }   /* AIFLOW_V1 */\n",
           'before', 'window.AI_FLOW.prefetch('); changed += ['t-prefetch'] if c else []
t, c = put(t, "      // ---- 書いてほしい欄（目印） ----\n",
           "      try { if (want.flowCtx) window.AI_FLOW.linesFor(st.userId, want).forEach(function (x) { out.push(x); }); } catch (e) {}   /* AIFLOW_V1 */\n",
           'before', 'window.AI_FLOW.linesFor('); changed += ['t-lines'] if c else []
t, c = put(t, "      if (want.suggest) { out.push('=== [SUGGEST:' + sid + '] ' + nm + ' ==='); out.push(''); }\n",
           "      if (want.flow) { out.push('=== [FLOW:' + sid + '] ' + nm + ' ==='); out.push(''); }   /* AIFLOW_V1 */\n",
           'after', "'=== [FLOW:'"); changed += ['t-marker'] if c else []
t, c = put(t, "    if (okIds.length) {\n      await postJson('/api/teacher/ai-drafts/mark', { ids: okIds, status: 'published' });\n    }\n",
           "    // --- AIFLOW_V1 流れのメモ（先生だけ。公開すると次のコピーの「先週までの流れ」に入る） ---\n"
           "    if (byKind.FLOW) { byKind.FLOW.forEach(function (x) { okIds.push(x.id); }); msgs.push('流れのメモ' + byKind.FLOW.length + '人'); }\n"
           "    // --- PORTFOLIO_AI_V1 成果物の分析（📓ひとこと＝子どものカルテに出る／分析メモ＝先生だけ） ---\n"
           "    if (byKind.WORKMEMO) { byKind.WORKMEMO.forEach(function (x) { okIds.push(x.id); }); msgs.push('成果物の分析メモ' + byKind.WORKMEMO.length + '人'); }\n"
           "    if (byKind.WORK) {\n"
           "      byKind.WORK.forEach(function (x) { okIds.push(x.id); }); msgs.push('📓成果物へのひとこと' + byKind.WORK.length + '人');\n"
           "      try { await postJson('/api/teacher/karte-share', { classId: cid, studentIds: byKind.WORK.map(function (x) { return x.targetId; }) }); } catch (e) {}\n"
           "    }\n",
           'before', 'if (byKind.FLOW)'); changed += ['t-pubflow'] if c else []
t, c = put(t, "    if (okIds.length) {\n      await postJson('/api/teacher/ai-drafts/mark', { ids: okIds, status: 'published' });\n    }\n",
           "    try { if (okIds.length && window.AI_FLOW) await window.AI_FLOW.saveFinal(picks, okIds); } catch (e) {}   /* AIFLOW_V1 公開した文に合わせる */\n",
           'after', 'window.AI_FLOW.saveFinal('); changed += ['t-final'] if c else []
t, c = put(t, "  var say2 = appendMode ? sayOne : say;\n  var cid = classId();\n  var ta = $(appendMode ? 'taiOnePaste' : 'taiPaste');\n  var raw = ta ? ta.value : '';\n",
           "  var say2 = (typeof opts.say === 'function') ? opts.say : (appendMode ? sayOne : say);   /* PORTFOLIO_AI_V1 成果物の分析の取り込みからも使う */\n"
           "  var cid = opts.classId || classId();\n"
           "  var ta = (typeof opts.raw === 'string') ? null : $(appendMode ? 'taiOnePaste' : 'taiPaste');\n"
           "  var raw = (typeof opts.raw === 'string') ? opts.raw : (ta ? ta.value : '');\n",
           'replace', '成果物の分析の取り込みからも使う'); changed += ['t-import'] if c else []
# 子ども：わたしのカルテに 📓
P2 = 'public/student-karte.js'
k = load(P2)
k, c = put(k, "    /* KARTE_HANSHIN_V2 (2026-10-05) 注記（※〜）は出さない（先生の指示）。\n",
           "    /* PORTFOLIO_AI_V1 📓 ノート・作品から（先生が読んで公開した文だけ。写真は出さない） */\n"
           "    if (d.work && d.work.text) {\n"
           "      h += '<div class=\"mt-3 rounded-xl bg-white border border-sky-200 p-3\">'\n"
           "         + '<div class=\"text-xs font-bold text-sky-700\">📓 ノート・作品から</div>'\n"
           "         + '<div class=\"text-sm text-gray-800\" style=\"white-space:pre-wrap\">' + esc(d.work.text) + '</div></div>';\n"
           "    }\n",
           'before', 'PORTFOLIO_AI_V1 📓 ノート・作品から'); changed += ['k-work'] if c else []
save(P2, k)
save(P, t)
print('changed:', ', '.join(changed) if changed else '(なし・すでに入っている)')
