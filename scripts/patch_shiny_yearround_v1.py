#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_shiny_yearround_v1.py --- 色違い（シャイニー）の通年化と、お知らせの作り直し

やること（src/index.tsx のみを書き換える。public/index.html は触らない）:

 1) 通年化
    置換チェーンに1件追加し、出現判定から isSummerFestSeason() の縛りを外す。
    SHINY_RATE(=0.01) と対象条件（uncapturable / isBoss / isGymLeader / isWarBoss を除外）は無変更。
    見た目（shiny-mon の hue-rotate と ✨バッジ）も無変更。

 2) 通知を「遭遇時」から「捕獲時」へ
    これまでは finishInitPvE()（バトル開始時＝ボールを投げる前）で報告APIを叩いていた。
    そのため、逃げられた子も「見つけた」として記録されていた。
    （実際 2026-07-22 の第1号は、遭遇しただけで捕獲ログが無い）
    → 遭遇時の報告呼び出しを外し、捕獲成立の直後に送る。
    ※ 出現抽選そのものは遭遇時のまま。ここを捕獲時に動かすと、
      バトル中に色違いの姿が見えなくなり「色違いを見つけて捕まえる」体験が壊れるため。

 3) 発見のたびのお知らせ（通年で見える場所）
    サーバ側に捕獲ログ（admin_settings の 'shiny_catch_log'、最新20件）を追加。
    第1号キー 'summer26_shiny_first' は一切変更しない（舟橋さんの記録はそのまま残る）。
    /shiny-news.js を新設し、野生バトルの地方選択画面(#screen-map-select)に
    「はじめて見つけた人」と「つかまえた人（最新5件）」を表示する。夏フェス画面の外なので通年で見える。

安全策:
 - アンカーはすべて「ちょうど1箇所」であることを確認してから置換する
 - 冪等: 目印 SENTINEL があれば何もしない（目印と検証条件は別の文字列にしてある）
 - 置換チェーンの件数を適用前後で照合（50 → 53 を期待）
 - public/index.html を実際に読み、アンカーが存在することを確認する（読むだけ）
 - DDL は流さない（既存の admin_settings テーブルだけを使う）
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
HTML = os.path.join(ROOT, 'public', 'index.html')

# 冪等の目印（※検証条件にはこの文字列を使わないこと）
SENTINEL = '/* SHINY_YEARROUND_V1 */'

src = io.open(TSX, encoding='utf-8').read()


def fail(msg):
    print('❌ 中止: ' + msg)
    sys.exit(1)


def must_be_one(text, needle, label):
    n = text.count(needle)
    if n != 1:
        fail('%s が %d 箇所（1箇所のはず）' % (label, n))
    return n


def root_replace_count(text):
    a = text.index("app.get('/', async (c) => {")
    b = text.index("app.get('/logout'", a)
    return text[a:b].count('.replace(')


def tsq(s):
    """Python文字列を TypeScript のシングルクォート文字列リテラルにする"""
    out = s.replace('\\', '\\\\').replace("'", "\\'")
    out = out.replace('\r', '').replace('\n', '\\n')
    return "'" + out + "'"


# ------------------------------------------------------------------
# 冪等チェック
# ------------------------------------------------------------------
if SENTINEL in src:
    print('⏭  すでに適用済み（目印あり）。何もしません')
    print('🔎 置換チェーン: %d 件' % root_replace_count(src))
    sys.exit(0)

BEFORE = root_replace_count(src)
print('🔎 適用前の置換チェーン: %d 件' % BEFORE)

# ------------------------------------------------------------------
# public/index.html 側のアンカー（読むだけ。書き換えない）
# ------------------------------------------------------------------
HTML_A_OLD = (
    "                    if (_shCap && typeof isSummerFestSeason === 'function' "
    "&& isSummerFestSeason() && Math.random() < SHINY_RATE) {\n"
    "                        battle.enemyShiny = true;\n"
    "                        _sh0.shiny = true;\n"
    "                        try { if (window._sf26ReportShiny) window._sf26ReportShiny(_shm); } catch(e) {}\n"
    "                    }"
)
HTML_A_NEW = (
    "                    if (_shCap && Math.random() < SHINY_RATE) {\n"
    "                        battle.enemyShiny = true;\n"
    "                        _sh0.shiny = true;\n"
    "                    }"
)

HTML_B_OLD = (
    "// ✨ 色違いを永続保存（state_json の player.monsters と box に shiny:true）\n"
    "                    try { if (battle.enemyShiny) { "
    "if (!player.monsters[enemy.id]) player.monsters[enemy.id] = "
    "{ level: captureLvl, exp: 0, nextExp: calculateNextExp(captureLvl) }; "
    "player.monsters[enemy.id].shiny = true; "
    "if (typeof boxEntry === 'object' && boxEntry) boxEntry.shiny = true; } } catch(e){}"
)
HTML_B_NEW = (
    HTML_B_OLD
    + "\n                    try { if (battle.enemyShiny && window._shinyCaught) "
      "window._shinyCaught(enemy.name); } catch(e){}"
)

if not os.path.exists(HTML):
    fail('public/index.html が見つかりません')
html = io.open(HTML, encoding='utf-8', errors='replace').read()
must_be_one(html, HTML_A_OLD, 'public/index.html の 出現判定ブロック')
must_be_one(html, HTML_B_OLD, 'public/index.html の 色違い永続保存ブロック')
must_be_one(html, '</body>', 'public/index.html の </body>')
print('🔎 public/index.html の3つのアンカーは、いずれもちょうど1箇所')

# ------------------------------------------------------------------
# (1)(2)(3) 置換チェーンに3件追加
# ------------------------------------------------------------------
CHAIN_TAIL = "\n      _rootHtmlCache = t\n    }\n    return c.html(_rootHtmlCache)"
must_be_one(src, CHAIN_TAIL, '置換チェーンの末尾')

ADD = (
    SENTINEL
    + '.replace(' + tsq(HTML_A_OLD) + ', ' + tsq(HTML_A_NEW) + ')'
    + '.replace(' + tsq(HTML_B_OLD) + ', ' + tsq(HTML_B_NEW) + ')'
    + '.replace(\'</body>\', \'<script src="/shiny-news.js?v=1"></script></body>\')'
)
src = src.replace(CHAIN_TAIL, ADD + CHAIN_TAIL, 1)
print('✅ 置換チェーンに3件追加（通年化 / 捕獲時通知 / お知らせスクリプトの読み込み）')

# ------------------------------------------------------------------
# (4) サーバ側: 捕獲ログの記録と、お知らせAPI、/shiny-news.js
# ------------------------------------------------------------------
OLD_POST_TAIL = (
    "  let first: any = null\n"
    "  try {\n"
    "    const cur = await c.env.DB.prepare(`SELECT value FROM admin_settings "
    "WHERE key='summer26_shiny_first' LIMIT 1`).first<any>()\n"
    "    first = cur?.value ? JSON.parse(cur.value) : null\n"
    "  } catch (e) {}\n"
    "  return c.json({ ok: true, first, isFirstDiscoverer: !!(first && first.userId === u.id) })\n"
    "})"
)
NEW_POST_TAIL = (
    "  // 捕獲したときだけ記録する（古い端末は captured を送らないので自然に除外）\n"
    "  if (body && body.captured) {\n"
    "    try {\n"
    "      const cur0 = await c.env.DB.prepare(`SELECT value FROM admin_settings "
    "WHERE key='shiny_catch_log' LIMIT 1`).first<any>()\n"
    "      let arr: any[] = []\n"
    "      try { arr = cur0?.value ? JSON.parse(cur0.value) : [] } catch (e2) { arr = [] }\n"
    "      if (!Array.isArray(arr)) arr = []\n"
    "      arr.unshift({ userId: u.id, name: finderName, monsterName, at: new Date().toISOString() })\n"
    "      arr = arr.slice(0, 20)\n"
    "      await c.env.DB.prepare(`INSERT INTO admin_settings (key, value, updated_at) "
    "VALUES ('shiny_catch_log', ?, datetime('now')) "
    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`)"
    ".bind(JSON.stringify(arr)).run()\n"
    "    } catch (e) {}\n"
    "  }\n"
    "  const nw = await shinyNewsData(c)\n"
    "  return c.json({ ok: true, first: nw.first, recent: nw.recent, "
    "isFirstDiscoverer: !!(nw.first && nw.first.userId === u.id) })\n"
    "})"
)
must_be_one(src, OLD_POST_TAIL, '/api/summer/shiny-found の末尾')
src = src.replace(OLD_POST_TAIL, NEW_POST_TAIL, 1)
print('✅ /api/summer/shiny-found に捕獲ログの記録を追加（第1号キーは無変更）')

SHINY_JS = (
    "(function(){\n"
    "  var last = null;\n"
    "  function esc(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }\n"
    "  window._shinyCaught = function(monName){\n"
    "    try {\n"
    "      fetch('/api/summer/shiny-found', { method:'POST', headers:{'content-type':'application/json'}, "
    "credentials:'same-origin', body: JSON.stringify({ monsterName: monName || '', captured: true }) })\n"
    "        .then(function(r){ return r.json(); })\n"
    "        .then(function(j){\n"
    "          try { render(j); } catch(e) {}\n"
    "          var msg = '✨ 色違いだ！ ' + (monName || 'モンスター') + ' を つかまえた！';\n"
    "          if (j && j.isFirstDiscoverer) { msg += '  — きみは、いちばん最初に色違いを見つけた人です！'; }\n"
    "          setTimeout(function(){ try { alert(msg); } catch(e) {} }, 1800);\n"
    "        })\n"
    "        .catch(function(){});\n"
    "    } catch(e) {}\n"
    "  };\n"
    "  function slot(){\n"
    "    var host = document.getElementById('screen-map-select');\n"
    "    if (!host) return null;\n"
    "    var el = document.getElementById('shinyNewsBox');\n"
    "    if (!el) {\n"
    "      el = document.createElement('div');\n"
    "      el.id = 'shinyNewsBox';\n"
    "      el.style.margin = '0 0 12px';\n"
    "      var t = document.getElementById('pveSelectTitle');\n"
    "      if (t && t.parentNode === host) { host.insertBefore(el, t.nextSibling); }\n"
    "      else { host.insertBefore(el, host.firstChild); }\n"
    "    }\n"
    "    return el;\n"
    "  }\n"
    "  function render(d){\n"
    "    if (d && (d.first !== undefined || d.recent !== undefined)) last = d;\n"
    "    var el = slot(); if (!el || !last) return;\n"
    "    var f = last.first, r = last.recent || [];\n"
    "    if (!f && (!r || !r.length)) { el.innerHTML = ''; return; }\n"
    "    var h = '';\n"
    "    if (r && r.length) {\n"
    "      h += '<div style=\"font-size:12px;color:#334155;margin-top:3px;\">つかまえた人：</div>';\n"
    "      for (var i = 0; i < r.length && i < 5; i++) {\n"
    "        h += '<div style=\"font-size:12px;color:#334155;\">・' + esc(r[i].name) + ' さん … ' + esc(r[i].monsterName || '?') + '</div>';\n"
    "      }\n"
    "    }\n"
    "    if (f) {\n"
    "      h += '<div style=\"font-size:11px;color:#7c3aed;margin-top:5px;\">はじめて見つけた人：' + esc(f.name) + ' さん（' + esc(f.monsterName || '?') + '）</div>';\n"
    "    }\n"
    "    el.innerHTML = '<div style=\"background:#fdf4ff;border:2px solid #e879f9;border-radius:14px;padding:8px 12px;\">'\n"
    "      + '<div style=\"font-weight:900;color:#a21caf;font-size:13px;\">✨ 色違いのきろく ✨</div>' + h + '</div>';\n"
    "  }\n"
    "  function load(){\n"
    "    try {\n"
    "      fetch('/api/shiny/news', { credentials:'same-origin' })\n"
    "        .then(function(r){ return r.json(); })\n"
    "        .then(render)\n"
    "        .catch(function(){});\n"
    "    } catch(e) {}\n"
    "  }\n"
    "  try {\n"
    "    setTimeout(load, 4000);\n"
    "    setInterval(load, 300000);\n"
    "    setInterval(function(){ try { if (last) render(); } catch(e) {} }, 3000);\n"
    "  } catch(e) {}\n"
    "})();"
)

NEW_BLOCK = (
    "// ✨ 色違いのお知らせ（通年）— 第1号キー summer26_shiny_first は読むだけで変更しない\n"
    "async function shinyNewsData(c: any) {\n"
    "  let first: any = null\n"
    "  let recent: any[] = []\n"
    "  try {\n"
    "    const a = await c.env.DB.prepare(`SELECT value FROM admin_settings "
    "WHERE key='summer26_shiny_first' LIMIT 1`).first<any>()\n"
    "    first = a?.value ? JSON.parse(a.value) : null\n"
    "  } catch (e) {}\n"
    "  try {\n"
    "    const b = await c.env.DB.prepare(`SELECT value FROM admin_settings "
    "WHERE key='shiny_catch_log' LIMIT 1`).first<any>()\n"
    "    const arr = b?.value ? JSON.parse(b.value) : []\n"
    "    if (Array.isArray(arr)) recent = arr.slice(0, 5)\n"
    "  } catch (e) {}\n"
    "  return { first, recent }\n"
    "}\n"
    "\n"
    "app.get('/api/shiny/news', async (c) => {\n"
    "  const u = requireStudent(c)\n"
    "  if (!u) return c.json({ first: null, recent: [] })\n"
    "  return c.json(await shinyNewsData(c))\n"
    "})\n"
    "\n"
    "const SHINY_NEWS_JS = `" + SHINY_JS + "`\n"
    "\n"
    "app.get('/shiny-news.js', (c) => {\n"
    "  return new Response(SHINY_NEWS_JS, { headers: { 'content-type': "
    "'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } })\n"
    "})\n"
    "\n"
)

EGG_ANCHOR = "app.get('/egg2p.js', (c) => {"
must_be_one(src, EGG_ANCHOR, "app.get('/egg2p.js') の目印")
src = src.replace(EGG_ANCHOR, NEW_BLOCK + EGG_ANCHOR, 1)
print('✅ /api/shiny/news と /shiny-news.js を追加')

# ------------------------------------------------------------------
# 検証（※ SENTINEL は使わない）
# ------------------------------------------------------------------
if '`' in SHINY_JS or '${' in SHINY_JS:
    fail('クライアントJSにバッククォートまたは ${ が混ざっています')

after = root_replace_count(src)
if after != BEFORE + 3:
    fail('置換チェーンの数が想定と違います（%d → %d、期待は %d）' % (BEFORE, after, BEFORE + 3))
print('🔎 適用後の置換チェーン: %d 件（+3）' % after)

must_be_one(src, 'shiny-news.js?v=1', 'お知らせスクリプトの読み込みタグ')
must_be_one(src, "app.get('/shiny-news.js'", '/shiny-news.js のルート')
must_be_one(src, "app.get('/api/shiny/news'", '/api/shiny/news のルート')
must_be_one(src, 'async function shinyNewsData', 'shinyNewsData の定義')
must_be_one(src, 'const SHINY_NEWS_JS', 'SHINY_NEWS_JS の定義')
if src.count('shiny_catch_log') != 3:
    fail('shiny_catch_log が %d 箇所（3箇所のはず）' % src.count('shiny_catch_log'))
must_be_one(src, 'window._shinyCaught = function', '_shinyCaught の定義')

# 第1号キーを壊していないこと
if src.count("INSERT INTO admin_settings (key, value) VALUES ('summer26_shiny_first', ?)") != 1:
    fail('第1号キーの記録処理が変わっています')
print('🔎 第1号キー summer26_shiny_first の記録処理は無変更（舟橋さんの記録はそのまま）')

# 確率と対象条件を変えていないこと
if html.count('const SHINY_RATE = 0.01;') != 1:
    fail('public/index.html の出現率の定義が想定と違います（1%のはず）')
if src.count('SHINY_RATE') != 2:
    fail('src/index.tsx の SHINY_RATE が %d 箇所（置換前後の2箇所のはず）' % src.count('SHINY_RATE'))
print('🔎 出現率は無変更（public/index.html の const SHINY_RATE = 0.01; に手を触れていない）')

# チェーンを実際に回して結果を確かめる
sim = html
sim = sim.replace(HTML_A_OLD, HTML_A_NEW, 1)
sim = sim.replace(HTML_B_OLD, HTML_B_NEW, 1)
sim = sim.replace('</body>', '<script src="/shiny-news.js?v=1"></script></body>', 1)
if 'isSummerFestSeason() && Math.random() < SHINY_RATE' in sim:
    fail('通年化に失敗（期間判定が残っています）')
if sim.count('window._shinyCaught(enemy.name)') != 1:
    fail('捕獲時の通知呼び出しが %d 箇所（1箇所のはず）' % sim.count('window._shinyCaught(enemy.name)'))
if sim.count('_sf26ReportShiny(_shm)') != 0:
    fail('遭遇時の報告呼び出しが残っています')
if sim.count('/shiny-news.js?v=1') != 1:
    fail('お知らせスクリプトのタグが %d 個（1個のはず）' % sim.count('/shiny-news.js?v=1'))
if sim.count('Math.random() < SHINY_RATE') != 1:
    fail('出現判定が %d 箇所（1箇所のはず）' % sim.count('Math.random() < SHINY_RATE'))
print('🔎 チェーンを実際に回して確認: 通年化OK / 捕獲時通知1件 / 遭遇時通知0件 / タグ1件')

io.open(TSX, 'w', encoding='utf-8').write(src)
print('🎉 完了: src/index.tsx を更新しました')
