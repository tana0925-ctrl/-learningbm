# -*- coding: utf-8 -*-
"""
QRHUNT_V1 — 既存「ひみつのQR」を、校内でさがすQRに作り替える。

src/index.tsx への当てぶん。中身の本体は src/qrhunt.tsx に閉じてある（src/mi.tsx にならった）。

  P1 /login に next（ログイン後の戻り先）を足す   ← このイベントの前提。実測で壊れていた
  P2 src/qrhunt.tsx を配線する（import と registerQrHunt の2行）
  P3 先生のミッションタブの中に「ひみつのQR」セクション＋JSを足す（新タブは作らない）
  P4 /api/student/class-mission のレスポンスに qrHunt を相乗りさせる（API本数を増やさない）
  P5 /qrhunt.js /qrgen.js の配信ルート
  P6 児童HTMLに qrhunt.js を読み込ませる
  P7 死んでいた QR 一式の撤去（jsQR CDN / ショップの画像アップロード口 / 空振りする初期化）

※ public/index.html（6.3MB）は手で編集しない。P6/P7 は既存のやり方どおり
  `/` ハンドラ内の t.replace() チェーンで行う。
※ 冪等ではない。当てる前に git status がきれいなことを確認すること。
"""
import io, os, sys, json

SRC = 'src/index.tsx'

# ── チェーン件数の数え方は既存パッチ（patch_karte_fix_v2.py）と同一 ──
def chain_count(t):
    i = t.index("app.get('/', async (c) => {")
    j = t.index("app.get('/logout'", i)
    return t[i:j].count('.replace(')

# この patch がチェーンに足す本数（内訳を書いておく。合わなければ止まる）。
#   +1 qrhunt.js の <script> 追記
#   +1 jsQR の CDN タグを撤去
#   +1 ショップの「ひみつのQR」セクションを撤去
#   +1 setupQrFileUpload の初期化（1つめ）を撤去
#   +1 setupCharRestoreQrFileUpload の初期化（1つめ）を撤去
#   +1 初期化（2つめ・書式ちがい）を撤去
#   +1 setupQrFileUpload 関数の本体を撤去
#   +1 setupCharRestoreQrFileUpload 関数の本体を撤去
CHAIN_DELTA = 8

s = io.open(SRC, encoding='utf-8').read()
orig_len = len(s)

if 'QRHUNT_V1' in s:
    print('NG: すでに当たっています（QRHUNT_V1 が src/index.tsx にある）')
    sys.exit(1)

# CHAIN_BEFORE は「流す直前に実測した値」。合わなければ1バイトも書かずに止まる。
_raw = (os.environ.get('CHAIN_BEFORE') or '').strip()
if _raw:
    if not _raw.isdigit():
        print('NG: CHAIN_BEFORE が数字でない（渡された値: %r）' % _raw); sys.exit(1)
    _before = chain_count(s)
    print('チェーン = %d （実測して渡された値 = %s）' % (_before, _raw))
    if _before != int(_raw):
        print('NG: チェーンが %d 件。渡された %s と合わないので止めます。' % (_before, _raw)); sys.exit(1)
else:
    _before = chain_count(s)
    print('チェーン = %d （CHAIN_BEFORE 未指定なのでガードなし）' % _before)

def sub(name, old, new, count=1):
    global s
    n = s.count(old)
    if n != count:
        print('  !! %-26s 見つかった数=%d (期待=%d) → 中止' % (name, n, count))
        sys.exit(1)
    s = s.replace(old, new, count)
    print('  ok %s' % name)


# ── P1  /login に next ────────────────────────────────────────
# いまは成功後 location.href='/' 固定で、QRのURLが失われる（2026-09-24 実測）。
# ⚠️ オープンリダイレクト対策：同一オリジンの相対パスだけ通す。
sub('P1 login next',
"""        const me = await fetch('/api/auth/me').then(r=>r.json()).catch(()=>({}));
        if(me.user && me.user.role === 'teacher') { location.href = '/teacher'; }
        else { location.href = '/'; }""",
"""        const me = await fetch('/api/auth/me').then(r=>r.json()).catch(()=>({}));
        // QRHUNT_V1: 読んだQRのURLに戻す。これが無いとQRの中身が消える。
        // ⚠️ ?next=https://わるいサイト を通すと踏み台にされるので、
        //    「/ で始まり // で始まらない」相対パスだけ許可する。
        var _next = '';
        try { _next = new URLSearchParams(location.search).get('next') || ''; } catch(e) {}
        // ⚠️ 正規表現やバックスラッシュを書くと、この HTML が TS の
        //    テンプレートリテラルの中にあるせいで エスケープが1段食われ、
        //    配信時に構文エラーになる（実際に一度なった）。
        //    だからバックスラッシュを一切書かずに判定する。
        //      ・「/」で始まる（相対パス）
        //      ・「//」で始まらない（//evil.com は外部サイト）
        //      ・バックスラッシュを含まない（ブラウザが / に正規化して //evil.com になる）
        var _bs = String.fromCharCode(92);
        var _safeNext = '';
        if (_next.length > 1 && _next.charAt(0) === '/' && _next.charAt(1) !== '/' && _next.indexOf(_bs) < 0) {
          _safeNext = _next;
        }
        if(_safeNext) { location.href = _safeNext; }
        else if(me.user && me.user.role === 'teacher') { location.href = '/teacher'; }
        else { location.href = '/'; }""")


# ── P2  配線 ────────────────────────────────────────────────
sub('P2 import',
"""import { defStageEnemies } from './def_stage'""",
"""import { defStageEnemies } from './def_stage'
// QRHUNT_V1 既存「ひみつのQR」の作り替え。中身は src/qrhunt.tsx に閉じている。
import { registerQrHunt, qrHuntCard } from './qrhunt'""")

sub('P2 register',
"""registerMi(app)""",
"""registerMi(app)
registerQrHunt(app)   // QRHUNT_V1""")


# ── P4  class-mission に相乗り ─────────────────────────────────
# 児童側の API を1本も増やさないため。ホームはすでにこれを叩いている。
sub('P4 ride-along',
"""  if (!m) return c.json({ ok: true, mission: null })
  const progress = (_preProgress != null) ? _preProgress""",
"""  // QRHUNT_V1: ここに相乗りさせる（新しいAPI呼び出しを増やさない）
  const _qrCard = await qrHuntCard(c, cm.class_id, u.id)
  if (!m) return c.json({ ok: true, mission: null, qrHunt: _qrCard })
  const progress = (_preProgress != null) ? _preProgress""")

sub('P4 ride-along main',
"""  return c.json({ ok: true, mission: { ...m, progress, achieved: progress >= m.goalCorrect, claimed: !!claimed } })""",
"""  return c.json({ ok: true, mission: { ...m, progress, achieved: progress >= m.goalCorrect, claimed: !!claimed }, qrHunt: _qrCard })""")


# ── P5  配信ルート ──────────────────────────────────────────
A5 = """app.get('/teacher-progress.js', async (c) => {"""
sub('P5 asset routes', A5,
"""// QRHUNT_V1 児童側（カメラで読むので読み取りライブラリは無い）
app.get('/qrhunt.js', async (c) => { try { const a = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/qrhunt.js'))); if (a && a.status === 200) return new Response(await a.text(), { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } }); } catch (e) {} return c.text('not found', 404) })
// QRHUNT_V1 先生の印刷ページ専用。外部CDNを使わないために同梱している
app.get('/qrgen.js', async (c) => { try { const a = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/qrgen.js'))); if (a && a.status === 200) return new Response(await a.text(), { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=3600' } }); } catch (e) {} return c.text('not found', 404) })
""" + A5)


# ── P6 / P7  児童HTML（t.replace チェーンに追加）──────────────────
A6 = """      t = t.replace('</body>', '<script src="/g8xmath.js?v=1"></script><script src="/g8xeng.js?v=1"></script><script src="/g8xsci.js?v=1"></script><script src="/g8xsoc.js?v=1"></script><script src="/g8xjp.js?v=1"></script></body>')"""

sub('P6/P7 html', A6, A6 + """
      // ── QRHUNT_V1 ─────────────────────────────────────────────
      t = t.replace('</body>', '<script src="/qrhunt.js?v=1"></script></body>')

      // 死んでいた「ひみつのQR」一式の撤去。消してよいと判断した根拠（2026-09-24 実測）:
      //   ・発行UI（teacherQrGenBox / secretQrGenerateBtn / secretQrCoinAmount / secretQrValidMin）は
      //     HTML に1つも存在しない ＝ 先生は1枚も作れない状態だった
      //   ・D1 の progress 26行中、使った形跡は1アカウントのみ。nonce を復号すると
      //     2025-12-18 14:10〜14:20 の5回だけで、以後9か月ゼロ
      //   ・キャラ復元QR（BMCHAR3）も発行側が児童用パッチで無効化ずみ、読み取り側の要素も不在。
      //     代わりに「バックアップコード／ファイル」が生きている（player 全体を戻せる上位互換）
      //   残っていたのは読み取り口だけ。カメラで読む方式に一本化するので、ここで外す。
      t = t.replace('<script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js"></script>',
                    '<!-- QRHUNT_V1: jsQR 撤去。QRは iPad のカメラが読むのでライブラリ不要（外部CDN依存も1本減る） -->')
      t = t.replace(QRHUNT_OLD_SHOP_SECTION,
                    '<!-- QRHUNT_V1: ショップの「画像をアップロード」口は撤去。カメラで読む方式に一本化した -->')
      t = t.replace("try{ setupQrFileUpload('shop-qr-file-input', 'shop-qr-canvas'); }catch(e){ console.warn('QR file upload init skipped', e); }",
                    "/* QRHUNT_V1: 撤去ずみ */")
      t = t.replace("try{ setupCharRestoreQrFileUpload('char-restore-qr-file-input', 'char-restore-qr-canvas'); }catch(e){ console.warn('Char restore QR file upload init skipped', e); }",
                    "/* QRHUNT_V1: 撤去ずみ（要素は元から存在しなかった）*/")
      // 初期化はもう1か所あった（書式がちがうので上の replace では落ちない）。関数の本体ごと外す。
      // 呼ぶ人も、呼ばれる先の要素も、もう無い。
      t = t.replace(QRHUNT_DEAD_INIT2, '                /* QRHUNT_V1: 撤去ずみ */\\n')
      t = t.replace(QRHUNT_DEAD_FN_SHOP, '/* QRHUNT_V1: setupQrFileUpload 撤去ずみ */')
      t = t.replace(QRHUNT_DEAD_FN_CHARRESTORE, '/* QRHUNT_V1: setupCharRestoreQrFileUpload 撤去ずみ。\\n   ⚠️ キャラ復元QR（BMCHAR3）は、作る側も読む側も画面が丸ごと無い状態だった。\\n   代替は「💾 バックアップ」（ファイル／コードから復元）だが、これは\\n   あらかじめ自分でバックアップを取っていた子しか救えない。\\n   先生が発行して子どもを後追いで復旧させる手段は、いま無い。別便で作り直す候補。 */')""")


# 撤去する実物（public/index.html から一字一句そのまま抜いたもの。ここに埋め込んである）
OLD_SECTION = "<!-- ひみつのQR セクション -->\n<div class=\"mt-4 border-t-2 border-dashed border-gray-300 pt-4 pb-8\" id=\"secretQrSection\">\n<!-- タイトルをひみつのQRに統一 -->\n<h3 class=\"text-center text-sm font-bold text-gray-500 mb-2\">🔒 ひみつのQR</h3>\n  <!-- File Upload for QR Reading -->\n<div class=\"pt-2 w-full max-w-[240px]\">\n<p class=\"text-xs font-bold text-gray-600 mb-2 text-center\">QRコードを読み取る</p>\n<label class=\"flex items-center justify-center w-full bg-white/50 border-2 border-dashed border-gray-400 rounded-lg p-3 cursor-pointer hover:bg-white transition\">\n<div class=\"text-center\">\n<span class=\"text-2xl block\">📁</span>\n<span class=\"text-xs font-bold text-gray-600\">画像をアップロード</span>\n</div>\n<input accept=\"image/*\" class=\"hidden\" id=\"shop-qr-file-input\" type=\"file\"/>\n</label>\n</div>\n<canvas id=\"shop-qr-canvas\" style=\"display:none;\"></canvas>\n<!-- secretQrOutput removed -->\n</div>\n"

DEAD = {
  "QRHUNT_DEAD_INIT2": "            // Secret coin QR (shop)\n                if (typeof setupQrFileUpload === 'function') {\n                    setupQrFileUpload('shop-qr-file-input','shop-qr-canvas');\n                }\n                // Character restore QR\n                if (typeof setupCharRestoreQrFileUpload === 'function') {\n                    setupCharRestoreQrFileUpload('char-restore-qr-file-input','char-restore-qr-canvas');\n                }\n",
  "QRHUNT_DEAD_FN_SHOP": "function setupQrFileUpload(fileInputId, canvasId) {\n            const fileInput = document.getElementById(fileInputId);\n            const canvas = document.getElementById(canvasId);\n\n            if (!fileInput || !canvas) {\n                console.warn(`setupQrFileUpload: Missing elements ${fileInputId} or ${canvasId}`);\n                return;\n            }\n\n            const ctx = canvas.getContext('2d');\n\n            fileInput.addEventListener('change', (e) => {\n                const file = e.target.files[0];\n                if (!file) return;\n\n                const reader = new FileReader();\n                reader.onload = (event) => {\n                    const img = new Image();\n                    img.onload = () => {\n                        // キャンバスに描画して解析\n                        canvas.width = img.width;\n                        canvas.height = img.height;\n                        ctx.drawImage(img, 0, 0);\n\n                        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);\n                        // jsQRが存在するか確認\n                        if (typeof jsQR === 'function') {\n                            const code = jsQR(imageData.data, canvas.width, canvas.height, {\n                                inversionAttempts: \"dontInvert\",\n                            });\n\n                            if (code && code.data) {\n                                console.log('QR Code detected from file:', code.data);\n                                // 成功\n                                onSecretQrDecoded(code.data);\n                                // 入力をクリア (同じファイルを再度選べるように)\n                                fileInput.value = '';\n                            } else {\n                                alert(\"画像からQRコードを読み取れませんでした。\");\n                            }\n                        } else {\n                            console.error('jsQR library not found!');\n                            alert(\"QRコード読み取りライブラリが読み込まれていません。\");\n                        }\n                    };\n                    img.onerror = () => {\n                        alert(\"画像の読み込みに失敗しました。\");\n                    };\n                    img.src = event.target.result;\n                };\n                reader.readAsDataURL(file);\n            });\n        }",
  "QRHUNT_DEAD_FN_CHARRESTORE": "function setupCharRestoreQrFileUpload(fileInputId, canvasId) {\n            const fileInput = document.getElementById(fileInputId);\n            const canvas = document.getElementById(canvasId);\n            if (!fileInput || !canvas) {\n                console.warn(`setupCharRestoreQrFileUpload: Missing elements ${fileInputId} or ${canvasId}`);\n                return;\n            }\n            const ctx = canvas.getContext('2d');\n            fileInput.addEventListener('change', (e) => {\n                const file = e.target.files && e.target.files[0];\n                if (!file) return;\n\n                const reader = new FileReader();\n                reader.onload = (event) => {\n                    const img = new Image();\n                    img.onload = () => {\n                        canvas.width = img.width;\n                        canvas.height = img.height;\n                        ctx.drawImage(img, 0, 0);\n                        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);\n                        if (typeof jsQR === 'function') {\n                            const code = jsQR(imageData.data, canvas.width, canvas.height, { inversionAttempts: \"dontInvert\" });\n                            if (code && code.data) {\n                                console.log('Char restore QR detected:', code.data);\n                                onCharRestoreQrDecoded(code.data);\n                                fileInput.value = '';\n                            } else {\n                                alert(\"画像からQRコードを読み取れませんでした。\");\n                            }\n                        } else {\n                            alert(\"QRコード読み取りライブラリが読み込まれていません。\");\n                        }\n                    };\n                    img.onerror = () => alert(\"画像の読み込みに失敗しました。\");\n                    img.src = event.target.result;\n                };\n                reader.onerror = () => alert(\"ファイルの読み込みに失敗しました。\");\n                reader.readAsDataURL(file);\n            });\n        }",
}

DEAD_CONSTS = '\n'.join(
  '// QRHUNT_V1 撤去する死んだコード（public/index.html の実物と一字一句同じ）\nconst %s = %s' % (k, json.dumps(v, ensure_ascii=False))
  for k, v in DEAD.items())
sub('P7 const',
"""app.get('/', async (c) => {
  try {
    if (!_rootHtmlCache) {""",
DEAD_CONSTS + """

// QRHUNT_V1 撤去する旧「ひみつのQR」セクション（public/index.html の実物と一字一句同じ）
const QRHUNT_OLD_SHOP_SECTION = """ + json.dumps(OLD_SECTION, ensure_ascii=False) + """

app.get('/', async (c) => {
  try {
    if (!_rootHtmlCache) {""")


# ── P3  先生のミッションタブ ───────────────────────────────────
sub('P3 pane',
"""        <div class="bg-white rounded-xl shadow p-4">
          <h3 class="font-bold mb-3">ミッション一覧・進捗</h3>
          <div id="cmList"></div>
        </div>
      </div>

      <!-- 連絡帳タブ -->""",
"""        <div class="bg-white rounded-xl shadow p-4">
          <h3 class="font-bold mb-3">ミッション一覧・進捗</h3>
          <div id="cmList"></div>
        </div>

        <!-- QRHUNT_V1: 校内でさがすQR。既存の「ひみつのQR」の作り替え。
             新しいタブは作らない。クラスは上の cmClassFilter を使い回す（選ぶ場所を増やさない）。 -->
        <div class="bg-white rounded-xl shadow p-4">
          <h3 class="font-bold mb-1">🔒 ひみつのQR（校内でさがす）</h3>
          <p class="text-xs text-slate-500 mb-3">
            先生がQRを校内にはり、子どもが iPad の<b>カメラでうつす</b>と ひとこと がもらえます。1人1枚1回だけ。<br>
            アプリの中に読み取り画面はありません（カメラが標準で読みます）。ひとことは<b>空欄のままでも動きます</b>。
          </p>
          <div id="qrHuntBox" class="text-sm text-slate-400">よみこみ中…</div>
        </div>
      </div>

      <!-- 連絡帳タブ -->""")

sub('P3 switchTab',
"""        if(tab === 'missions') loadClassMissions();""",
"""        if(tab === 'missions') { loadClassMissions(); loadQrHunts(); }""")

sub('P3 js',
"""      function switchTab(tab){""",
"""      /* ===== QRHUNT_V1 先生側 ===== */
      function qrEsc(x){ return String(x==null?'':x).replace(/[&<>"']/g, function(ch){
        return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]; }); }

      async function loadQrHunts(){
        var box = document.getElementById('qrHuntBox'); if(!box) return;
        var sel = document.getElementById('cmClassFilter');
        var classId = sel ? sel.value : '';
        if(!classId){ box.innerHTML = '<span class="text-slate-400">クラスをえらんでください</span>'; return; }
        try{
          var j = await fetch('/api/teacher/qr-hunts?classId=' + encodeURIComponent(classId)).then(function(r){return r.json();});
          var hs = (j && j.hunts) || [];
          var html = '';
          if(!hs.length){
            html += '<p class="text-slate-500 mb-2">まだありません。</p>';
          }
          hs.forEach(function(h){
            var st = {open:'📗 開催中', before:'⏳ これから', after:'🌙 おわり', closed_now:'🕒 いまは時間外'}[h.state] || '';
            html += '<div class="border rounded-lg p-3 mb-3">'
              + '<div class="flex items-center justify-between gap-2 flex-wrap">'
              +   '<div class="font-bold">' + qrEsc(h.title) + ' <span class="text-xs font-normal text-slate-500">' + st + '</span></div>'
              +   '<div class="text-xs text-slate-500">' + qrEsc(String(h.start_at).slice(0,10)) + ' 〜 ' + qrEsc(String(h.end_at).slice(0,10))
              +     (h.open_from ? '　' + qrEsc(h.open_from) + '〜' + qrEsc(h.open_to) + ' のみ' : '') + '</div>'
              + '</div>'
              + '<div class="mt-2 space-y-1">';
            (h.spots||[]).forEach(function(sp){
              html += '<div class="flex items-center gap-2 flex-wrap text-xs">'
                +  '<span class="font-black w-6 text-center">' + sp.sort_no + '</span>'
                +  '<input class="border rounded px-2 py-1 flex-1 min-w-[140px]" placeholder="どこに貼ったか（先生用メモ）" value="' + qrEsc(sp.label) + '" id="qrl_' + sp.token + '"/>'
                +  '<input class="border rounded px-2 py-1 flex-[2] min-w-[180px]" placeholder="ひとこと（空欄でもOK）" value="' + qrEsc(sp.reward_text) + '" id="qrt_' + sp.token + '"/>'
                +  '<input class="border rounded px-2 py-1 w-20" type="number" min="0" placeholder="キャラ番号" value="' + (sp.reward_monster_id||'') + '" id="qrm_' + sp.token + '" title="図鑑の番号。わからなければ空欄で"/>'
                +  '<button class="bg-slate-200 rounded px-2 py-1 font-bold" onclick="saveQrSpot(\\'' + sp.token + '\\')">保存</button>'
                + '</div>';
            });
            html += '</div>'
              + '<div class="mt-3 flex gap-2 flex-wrap">'
              +   '<a class="bg-amber-500 text-white rounded px-3 py-1 text-xs font-bold" target="_blank" href="/teacher/qr-print?hunt=' + encodeURIComponent(h.id) + '">🖨 印刷する</a>'
              +   '<button class="bg-slate-200 rounded px-3 py-1 text-xs font-bold" onclick="showQrFinds(\\'' + h.id + '\\')">👀 だれが何まい</button>'
              + '</div>'
              + '<div class="mt-2 text-xs" id="qrf_' + h.id + '"></div>'
              + '</div>';
          });
          html += '<div class="border-t pt-3 mt-2 space-y-2">'
            + '<div class="font-bold text-sm">あたらしく作る</div>'
            + '<input id="qrNewTitle" class="w-full border p-2 rounded text-sm" placeholder="なまえ（例：秋のひみつのQR）"/>'
            + '<div class="flex gap-2 flex-wrap">'
            +   '<div class="flex-1 min-w-[110px]"><label class="text-xs font-bold text-gray-600">まい数</label><input id="qrNewCount" type="number" min="1" max="60" value="6" class="w-full border p-2 rounded text-sm"/></div>'
            +   '<div class="flex-1 min-w-[130px]"><label class="text-xs font-bold text-gray-600">はじまり</label><input id="qrNewStart" type="date" class="w-full border p-2 rounded text-sm"/></div>'
            +   '<div class="flex-1 min-w-[130px]"><label class="text-xs font-bold text-gray-600">おわり</label><input id="qrNewEnd" type="date" class="w-full border p-2 rounded text-sm"/></div>'
            + '</div>'
            + '<div class="flex gap-2 flex-wrap items-end">'
            +   '<div class="flex-1 min-w-[110px]"><label class="text-xs font-bold text-gray-600">よめる時間（から）</label><input id="qrNewFrom" type="time" class="w-full border p-2 rounded text-sm"/></div>'
            +   '<div class="flex-1 min-w-[110px]"><label class="text-xs font-bold text-gray-600">（まで）</label><input id="qrNewTo" type="time" class="w-full border p-2 rounded text-sm"/></div>'
            +   '<div class="flex-1 min-w-[180px] text-xs text-slate-500 pb-2">空欄なら終日。中休み・昼休みだけにすると、写真を持ち帰っても使えなくなります。</div>'
            + '</div>'
            + '<button class="bg-amber-600 hover:bg-amber-700 text-white rounded px-4 py-2 font-bold text-sm" onclick="createQrHunt()">🔒 作る</button>'
            + '<p id="qrNewMsg" class="text-sm"></p>'
            + '</div>';
          box.innerHTML = html;
        }catch(e){ box.innerHTML = '<span class="text-red-600">よみこみに失敗しました</span>'; }
      }

      async function createQrHunt(){
        var sel = document.getElementById('cmClassFilter');
        var msg = document.getElementById('qrNewMsg');
        var classId = sel ? sel.value : '';
        if(!classId){ msg.textContent = 'クラスをえらんでください'; return; }
        var body = {
          classId: classId,
          title: document.getElementById('qrNewTitle').value || 'ひみつのQR',
          count: Number(document.getElementById('qrNewCount').value) || 6,
          startAt: document.getElementById('qrNewStart').value || undefined,
          endAt: document.getElementById('qrNewEnd').value || undefined,
          openFrom: document.getElementById('qrNewFrom').value || undefined,
          openTo: document.getElementById('qrNewTo').value || undefined
        };
        msg.textContent = '作っています…';
        try{
          var r = await fetch('/api/teacher/qr-hunt', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(body)});
          var j = await r.json();
          if(!r.ok){ msg.textContent = 'しっぱい：' + (j.error||''); return; }
          msg.textContent = '';
          loadQrHunts();
        }catch(e){ msg.textContent = 'しっぱいしました'; }
      }

      async function saveQrSpot(token){
        var label = (document.getElementById('qrl_' + token)||{}).value || '';
        var text  = (document.getElementById('qrt_' + token)||{}).value || '';
        var mon   = Number((document.getElementById('qrm_' + token)||{}).value || 0);
        var body = { label: label, text: text, kind: mon > 0 ? 'monster' : 'word', monsterId: mon > 0 ? mon : null, coins: 0 };
        try{
          await fetch('/api/teacher/qr-spot/' + encodeURIComponent(token), {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(body)});
          var b = document.getElementById('qrt_' + token);
          if(b){ b.style.background = '#dcfce7'; setTimeout(function(){ b.style.background=''; }, 900); }
        }catch(e){ alert('保存できませんでした'); }
      }

      async function showQrFinds(huntId){
        var box = document.getElementById('qrf_' + huntId); if(!box) return;
        box.textContent = 'よみこみ中…';
        try{
          var j = await fetch('/api/teacher/qr-hunt/' + encodeURIComponent(huntId) + '/finds').then(function(r){return r.json();});
          var rows = (j && j.rows) || [];
          if(!rows.length){ box.textContent = 'まだだれも見つけていません'; return; }
          var html = '<table class="w-full text-xs"><tr class="text-slate-500"><th class="text-left">なまえ</th><th>みつけた</th><th class="text-right">さいご</th></tr>';
          rows.forEach(function(r){
            html += '<tr><td>' + qrEsc(r.name||r.loginId) + '</td><td class="text-center font-bold">' + r.found + ' / ' + j.total + '</td>'
                 +  '<td class="text-right text-slate-400">' + qrEsc(r.lastAt||'-') + '</td></tr>';
          });
          html += '</table><p class="text-slate-400 mt-1">※ 短い時間に全員がそろっていたら、写真が回った可能性があります。記録するだけで、罰は作っていません。</p>';
          box.innerHTML = html;
        }catch(e){ box.textContent = 'よみこみに失敗しました'; }
      }

      function switchTab(tab){""")

_after = chain_count(s)
print('\n適用後のチェーン = %d （%d + %d を期待）' % (_after, _before, CHAIN_DELTA))
if _after != _before + CHAIN_DELTA:
    print('NG: チェーンの増分が想定外（%d -> %d）。書き込まずに止めます。' % (_before, _after))
    sys.exit(1)

io.open(SRC, 'w', encoding='utf-8').write(s)
print('完了: %d → %d bytes' % (orig_len, len(s)))
