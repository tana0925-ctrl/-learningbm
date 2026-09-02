#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_cleanup_s1.py --- 準備（B5の移設）＋ 第1段階（死んでいるコードの削除）

  M1〜M6  B5「1人ずつの計画コピー／貼り付け」を、新しい「今日のひと往復」の④の中へ移設。
          旧版は先生のレビューを通さずに直接公開していたが、移設版は下書きに追加するので
          必ず④の公開ボタンを通る。
  D1      /api/student/dashboard（呼び出し元ゼロの死んだAPI）を削除。
          ※ 中で使う generateFeedback() は /api/teacher/auto-feedback がまだ使うので残す。
             （第4段階で auto-feedback を消したときに一緒に消す）
  D2      public/index.html の「2つ目の hsPhotoClear」（旧・単一写真版）を削除。
          あとから定義されたこちらが上書きしていたため、複数枚版が効いていなかった。
          残す1つ目に、旧要素の後始末も足しておく。

GitHub の Secrets には触りません。
"""
import io, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
TAI  = os.path.join(ROOT, 'public', 'teacher-ai.js')
HTML = os.path.join(ROOT, 'public', 'index.html')

src = io.open(TSX, encoding='utf-8').read();  src0 = src
tai = io.open(TAI, encoding='utf-8').read();  tai0 = tai
html_bytes = open(HTML, 'rb').read();         html0 = html_bytes
changes = []

def fail(msg):
    print('❌ 中止: ' + msg); sys.exit(1)

def rep_in(text, old, new, tag, sentinel=None):
    if sentinel is not None and sentinel in text:
        print('⏭  %s は適用済み（スキップ）' % tag); return text
    n = text.count(old)
    if n == 0:
        if new and new in text:
            print('⏭  %s は適用済み（スキップ）' % tag); return text
        fail('%s のアンカーが見つかりません' % tag)
    if n != 1:
        fail('%s のアンカーが %d 箇所（1箇所のはず）' % (tag, n))
    changes.append(tag)
    return text.replace(old, new, 1)

def root_replace_count(text):
    a = text.index("app.get('/', async (c) => {")
    b = text.index("app.get('/logout'", a)
    return text[a:b].count('.replace(')

BEFORE_CHAIN = root_replace_count(src0)

# ============================================================ M1: 1人だけ作り直す欄（HTML）
ONE_ANCHOR = """              <span id="taiPrintStatus" class="text-xs text-rose-700"></span>
            </div>
          </div>"""
ONE_HTML = """              <span id="taiPrintStatus" class="text-xs text-rose-700"></span>
            </div>
            <details class="mt-2 pt-2 border-t border-rose-200" ontoggle="if(this.open){try{taiOneOpen()}catch(e){}}">
              <summary class="text-xs text-rose-700 cursor-pointer">🔁 1人だけ作り直す</summary>
              <div class="mt-2 p-2 rounded-lg bg-white border border-rose-200 space-y-2">
                <p class="text-xs text-slate-500">1人ぶんだけ気に入らないときに。作り直した文も、上の「公開」を通ります。</p>
                <div class="flex items-center gap-2 flex-wrap">
                  <select id="taiOneStu" class="text-xs border border-slate-300 rounded px-2 py-1"><option value="">児童をえらぶ</option></select>
                  <select id="taiOneKind" class="text-xs border border-slate-300 rounded px-2 py-1">
                    <option value="DAILY">家庭学習コメント</option>
                    <option value="KARTE">個人カルテ</option>
                    <option value="PLAN">計画アドバイス</option>
                    <option value="REFLECT">振り返りの返却</option>
                    <option value="SUGGEST">おすすめ計画</option>
                  </select>
                  <button onclick="taiOneCopy()" class="bg-emerald-600 text-white rounded px-3 py-1 text-xs font-bold hover:bg-emerald-700">① コピー</button>
                </div>
                <textarea id="taiOnePaste" rows="3" class="w-full border border-slate-300 rounded p-2 text-xs" placeholder="AIの返事をここに貼る"></textarea>
                <div class="flex items-center gap-2 flex-wrap">
                  <button onclick="taiOneImport()" class="bg-indigo-600 text-white rounded px-3 py-1 text-xs font-bold hover:bg-indigo-700">② 下書きに追加</button>
                  <span id="taiOneStatus" class="text-xs text-slate-500"></span>
                </div>
              </div>
            </details>
          </div>"""
src = rep_in(src, ONE_ANCHOR, ONE_HTML, 'M1 「1人だけ作り直す」欄を④に追加', sentinel='taiOneStu')

# ============================================================ M2: teacher-ai.js のキャッシュ更新
src = rep_in(src, '<script src="/teacher-ai.js?v=5"></script>', '<script src="/teacher-ai.js?v=6"></script>',
             'M2 teacher-ai.js のキャッシュ更新 (v6)', sentinel='/teacher-ai.js?v=6')

# ============================================================ D1: 死んだAPIを削除
D1_START = '// 生徒：自分の学習ダッシュボード（成長の見える化）\napp.get(\'/api/student/dashboard\', async (c) => {'
i = src.find(D1_START)
if i < 0:
    if '2026-09: /api/student/dashboard は削除' in src:
        print('⏭  D1 /api/student/dashboard の削除 は適用済み（スキップ）')
    else:
        fail('D1 の開始アンカーが見つかりません')
else:
    D1_END = '    feedback,\n  })\n})\n\n'
    j = src.find(D1_END, i)
    if j < 0: fail('D1 の終了アンカーが見つかりません')
    j += len(D1_END)
    block = src[i:j]
    if block.count("app.get('") != 1 or block.count("app.post('") != 0:
        fail('D1 の範囲がずれています（中に別のAPIが入っています）')
    NOTE = ('// 🗑 2026-09: /api/student/dashboard は削除しました。\n'
            '//   定義だけあって、画面からもスクリプトからも一度も呼ばれていませんでした（確認ずみ）。\n'
            '//   この中で使っていた generateFeedback() は /api/teacher/auto-feedback がまだ使うので残しています。\n\n')
    src = src[:i] + NOTE + src[j:]
    changes.append('D1 死んだAPI /api/student/dashboard を削除（%d文字）' % len(block))

# ============================================================ M3〜M6: teacher-ai.js（1人だけモード）
tai = rep_in(tai,
    "  function sayPub(msg) { var e = $('taiPubStatus'); if (e) e.textContent = msg || ''; }",
    "  function sayPub(msg) { var e = $('taiPubStatus'); if (e) e.textContent = msg || ''; }\n"
    "  function sayOne(msg) { var e = $('taiOneStatus'); if (e) e.textContent = msg || ''; }",
    'M3 sayOne を追加', sentinel='function sayOne(')

OLD_HEAD = """  async function taiCopyAll() {
    var cid = classId();
    if (!cid) { say('先にクラスを選んでください'); return; }

    var want = {
      daily:   opt('taiOptDaily'),
      karte:   opt('taiOptKarte'),
      classOv: opt('taiOptClass'),
      report:  opt('taiOptReport'),
      plan:    opt('taiOptPlan'),
      reflect: opt('taiOptReflect'),
      suggest: opt('taiOptSuggest')
    };"""
NEW_HEAD = """  //  opts.onlyStudentId / opts.onlyKind をつけて呼ぶと「1人だけ・1種類だけ」作り直せる
  //  （旧「1人ずつの計画コピー」の置きかえ。データの作り方は全員ぶんとまったく同じ）
  async function taiCopyAll(opts) {
    opts = opts || {};
    var oneId = String(opts.onlyStudentId || '');
    var oneKind = String(opts.onlyKind || '');
    var cid = classId();
    if (!cid) { say('先にクラスを選んでください'); return; }

    var want = oneKind ? {
      daily:   oneKind === 'DAILY',
      karte:   oneKind === 'KARTE',
      classOv: false,
      report:  false,
      plan:    oneKind === 'PLAN',
      reflect: oneKind === 'REFLECT',
      suggest: oneKind === 'SUGGEST'
    } : {
      daily:   opt('taiOptDaily'),
      karte:   opt('taiOptKarte'),
      classOv: opt('taiOptClass'),
      report:  opt('taiOptReport'),
      plan:    opt('taiOptPlan'),
      reflect: opt('taiOptReflect'),
      suggest: opt('taiOptSuggest')
    };"""
tai = rep_in(tai, OLD_HEAD, NEW_HEAD, 'M4 taiCopyAll に「1人だけ」モードを追加', sentinel='opts.onlyStudentId')

tai = rep_in(tai,
    "    var _ckey = cacheKeyOf(cid, want);\n    if (!window.__taiForceRefresh) {",
    "    var _ckey = cacheKeyOf(cid, want);\n    if (!oneId && !window.__taiForceRefresh) {",
    'M4b 1人だけのときはキャッシュを使わない')

tai = rep_in(tai,
    "    if (!roster.length) { say('名簿が取得できませんでした'); window.__taiBusy = false; return; }",
    "    if (!roster.length) { say('名簿が取得できませんでした'); window.__taiBusy = false; return; }\n"
    "    if (oneId) {\n"
    "      roster = roster.filter(function (r) { return String(r.userId) === oneId; });\n"
    "      if (!roster.length) { sayOne('その児童が名簿に見つかりません'); window.__taiBusy = false; return; }\n"
    "    }",
    'M4c 1人だけに名簿をしぼる', sentinel='roster = roster.filter(function (r) { return String(r.userId) === oneId; });')

tai = rep_in(tai,
    "    window.__taiLast = { chars: _txt.length, blocks: _blocks, cached: false };\n"
    "    cacheSet(_ckey, _txt, _blocks);\n"
    "    window.__taiBusy = false;\n"
    "    copyText(_txt);\n"
    "  }",
    "    window.__taiLast = { chars: _txt.length, blocks: _blocks, cached: false };\n"
    "    if (!oneId) cacheSet(_ckey, _txt, _blocks);\n"
    "    window.__taiBusy = false;\n"
    "    copyText(_txt);\n"
    "    if (oneId) sayOne('✓ この子のぶんをコピーしました。AIに貼って、返事を下の欄へ');\n"
    "  }",
    'M4d 1人だけのときはキャッシュに入れない')

OLD_IMP = """  async function taiImport() {
    var cid = classId();
    var ta = $('taiPaste');
    var raw = ta ? ta.value : '';
    if (!cid) { say('先にクラスを選んでください'); return; }
    if (!raw || !raw.trim()) { say('AIの返事を貼り付けてください'); return; }

    say('読み取り中...');"""
NEW_IMP = """  //  opts.append=true のときは、いまある下書きを消さずに追加する（1人だけ作り直すとき）
  async function taiImport(opts) {
    opts = opts || {};
    var appendMode = !!opts.append;
    var say2 = appendMode ? sayOne : say;
    var cid = classId();
    var ta = $(appendMode ? 'taiOnePaste' : 'taiPaste');
    var raw = ta ? ta.value : '';
    if (!cid) { say2('先にクラスを選んでください'); return; }
    if (!raw || !raw.trim()) { say2('AIの返事を貼り付けてください'); return; }

    say2('読み取り中...');"""
tai = rep_in(tai, OLD_IMP, NEW_IMP, 'M5 taiImport に「追加」モードを追加', sentinel='var appendMode =')

OLD_SAVE = """    if (!items.length) {
      say('目印（=== [ ... ] === ）が見つかりませんでした（' + blocks.length + 'ブロック検出）');
      return;
    }

    var res = await postJson('/api/teacher/ai-drafts', {
      classId: cid, weekKey: weekKey(), replace: true, items: items
    });
    if (!res || !res.ok) { say('下書きの保存に失敗しました'); return; }
    say('✓ ' + res.saved + '件を下書きに取り込みました。下の「④ 先生が確認して公開」を見てください' +
        (unmatched.length ? '（名前が一致しなかったもの: ' + unmatched.slice(0, 5).join(', ') + '）' : ''));"""
NEW_SAVE = """    if (!items.length) {
      say2('目印（=== [ ... ] === ）が見つかりませんでした（' + blocks.length + 'ブロック検出）');
      return;
    }

    var res = await postJson('/api/teacher/ai-drafts', {
      classId: cid, weekKey: weekKey(), replace: !appendMode, items: items
    });
    if (!res || !res.ok) { say2('下書きの保存に失敗しました'); return; }
    say2('✓ ' + res.saved + '件を下書きに' + (appendMode ? '追加' : '取り込み') + 'ました。下の「④ 先生が確認して公開」を見てください' +
        (unmatched.length ? '（名前が一致しなかったもの: ' + unmatched.slice(0, 5).join(', ') + '）' : ''));"""
tai = rep_in(tai, OLD_SAVE, NEW_SAVE, 'M5b 追加モードでは既存の下書きを消さない')

OLD_ROSTER = """        }), cid);
      }
    } catch (e) {}
  }"""
NEW_ROSTER = """        }), cid);
      }
    } catch (e) {}
    try { taiOneFill(roster); } catch (e) {}
  }

  // --- 🔁 1人だけ作り直す（旧「1人ずつの計画コピー」の置きかえ） ---
  function taiOneEsc(s) {
    return String(s == null ? '' : s).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;');
  }
  function taiOneFill(roster) {
    var sel = $('taiOneStu');
    if (!sel) return;
    var cur = sel.value;
    var h = '<option value="">児童をえらぶ</option>';
    (roster || []).forEach(function (r) {
      h += '<option value="' + taiOneEsc(r.userId) + '">' + taiOneEsc(nameOf(r.loginId, r.name)) + '</option>';
    });
    sel.innerHTML = h;
    if (cur) { try { sel.value = cur; } catch (e) {} }
  }
  async function taiOneOpen() { try { await taiLoadRoster(); } catch (e) {} }
  async function taiOneCopy() {
    var sel = $('taiOneStu'), kd = $('taiOneKind');
    var sid = sel ? sel.value : '';
    if (!sid) { sayOne('児童をえらんでください'); return; }
    sayOne('この子のぶんを作っています…');
    await taiCopyAll({ onlyStudentId: sid, onlyKind: (kd ? kd.value : 'DAILY') });
  }
  async function taiOneImport() { await taiImport({ append: true }); }"""
tai = rep_in(tai, OLD_ROSTER, NEW_ROSTER, 'M6 1人だけ作り直すための関数を追加', sentinel='function taiOneFill(')

tai = rep_in(tai,
    "  window.taiCopyFresh = taiCopyFresh;",
    "  window.taiCopyFresh = taiCopyFresh;\n"
    "  window.taiOneOpen = taiOneOpen;\n"
    "  window.taiOneCopy = taiOneCopy;\n"
    "  window.taiOneImport = taiOneImport;",
    'M6b 1人だけ作り直すを画面から呼べるようにする', sentinel='window.taiOneCopy')

# ============================================================ D2: public/index.html
OLD2 = ("function hsPhotoClear() {\n"
        "  const input = document.getElementById('hsPhotoInput');\n"
        "  const statusEl = document.getElementById('hsPhotoStatus');\n"
        "  const previewEl = document.getElementById('hsPhotoPreview');\n"
        "  const analysisEl = document.getElementById('hsPhotoAnalysis');\n"
        "  if (input) input.value = '';\n"
        "  if (statusEl) statusEl.textContent = '';\n"
        "  if (previewEl) previewEl.style.display = 'none';\n"
        "  if (analysisEl) { analysisEl.style.display = 'none'; analysisEl.textContent = ''; }\n"
        "  window._hsPhotoAnalysisResult = '';\n"
        "}").encode('utf-8')
NEW2 = ("/* 🗑 2026-09: 旧・単一写真版の hsPhotoClear は削除しました。\n"
        "   あとから定義されたこちらが上の複数枚版を上書きしてしまい、\n"
        "   提出したあとも写真が残る状態になっていました。 */").encode('utf-8')

OLD1 = ("function hsPhotoClear() {\n"
        "  _hsPhotoFiles = [];\n"
        "  _hsPhotoAnalysisResult = '';\n"
        "  var input = document.getElementById('hsPhotoInput');\n"
        "  if (input) input.value = '';\n"
        "  var list = document.getElementById('hsPhotoPreviewList');\n"
        "  if (list) list.innerHTML = '';\n"
        "  var statusEl = document.getElementById('hsPhotoStatus');\n"
        "  if (statusEl) statusEl.textContent = '';\n"
        "}").encode('utf-8')
NEW1 = ("function hsPhotoClear() {\n"
        "  _hsPhotoFiles = [];\n"
        "  _hsPhotoAnalysisResult = '';\n"
        "  var input = document.getElementById('hsPhotoInput');\n"
        "  if (input) input.value = '';\n"
        "  var list = document.getElementById('hsPhotoPreviewList');\n"
        "  if (list) list.innerHTML = '';\n"
        "  var statusEl = document.getElementById('hsPhotoStatus');\n"
        "  if (statusEl) statusEl.textContent = '';\n"
        "  var previewEl = document.getElementById('hsPhotoPreview');\n"
        "  if (previewEl) previewEl.style.display = 'none';\n"
        "  var analysisEl = document.getElementById('hsPhotoAnalysis');\n"
        "  if (analysisEl) { analysisEl.style.display = 'none'; analysisEl.textContent = ''; }\n"
        "  try { window._hsPhotoAnalysisResult = ''; } catch (e) {}\n"
        "}").encode('utf-8')

if NEW2 in html_bytes:
    print('⏭  D2 旧 hsPhotoClear の削除 は適用済み（スキップ）')
else:
    if html_bytes.count(OLD2) != 1: fail('D2 の削除対象が %d 箇所（1箇所のはず）' % html_bytes.count(OLD2))
    if html_bytes.count(OLD1) != 1: fail('D2 の残す方が %d 箇所（1箇所のはず）' % html_bytes.count(OLD1))
    crlf_before = html_bytes.count(b'\r\n')
    html_bytes = html_bytes.replace(OLD2, NEW2, 1)
    html_bytes = html_bytes.replace(OLD1, NEW1, 1)
    if html_bytes.count(b'function hsPhotoClear()') != 1:
        fail('hsPhotoClear が %d 個（1個のはず）' % html_bytes.count(b'function hsPhotoClear()'))
    if html_bytes.count(b'\r\n') != crlf_before:
        fail('改行コード(CRLF)の数が変わりました %d → %d' % (crlf_before, html_bytes.count(b'\r\n')))
    changes.append('D2 旧 hsPhotoClear を削除し、残す方に後始末を追加')

# ============================================================ 検証
if root_replace_count(src) != BEFORE_CHAIN:
    fail('置換チェーンの数が変わりました（%d → %d）' % (BEFORE_CHAIN, root_replace_count(src)))
print('🔎 置換チェーン: %d 件（変化なし）' % root_replace_count(src))

# 消してはいけないものが残っていること
for must in ['function _buildKarteHtml', 'function downloadAllKartes', 'function updateKarteStudentList',
             '_lastStudentSummaries', 'async function showStudentKarte', 'function generateFeedback',
             "app.get('/api/teacher/auto-feedback'", "app.get('/api/student/my-karte'",
             '/teacher-ai.js?v=6', 'taiOneStu', 'taiOneKind', 'taiOnePaste']:
    if must not in src: fail('残すはずのものが失われました: %s' % must)
if "app.get('/api/student/dashboard'" in src:
    fail('D1 が消えていません')
print('🔎 印刷ボタンが使う関数・showStudentKarte・generateFeedback はすべて残っています')

for must in ['function sayOne(', 'opts.onlyStudentId', 'var appendMode =', 'function taiOneFill(',
             'window.taiOneCopy', 'async function taiCopyAll(opts)', 'async function taiImport(opts)',
             "replace: !appendMode", '/api/teacher/karte-share']:
    if must not in tai: fail('teacher-ai.js の必須要素が足りません: %s' % must)
if "replace: true, items: items" in tai:
    fail('taiImport がまだ replace: true 固定です')
print('🔎 teacher-ai.js: 1人だけ作り直すモードの配線を確認')

_h = html_bytes.decode('utf-8')
for must in ['cannot_trade_special', 'genElectric6', 'uncapturable', '_hash',
             'hsPhotosSelected', '_hsPhotoFiles', 'hsPhotoPreviewList']:
    if must not in _h: fail('index.html の大事な目印が失われました: %s' % must)
print('🔎 index.html の保護マーカーは無事です')

if src != src0:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src);  print('✅ src/index.tsx を更新しました')
if tai != tai0:
    io.open(TAI, 'w', encoding='utf-8', newline='').write(tai);  print('✅ public/teacher-ai.js を更新しました')
if html_bytes != html0:
    open(HTML, 'wb').write(html_bytes)
    print('✅ public/index.html を更新しました（%d → %d バイト）' % (len(html0), len(html_bytes)))
print('---- 適用した項目 ----')
for c in changes: print(' ・' + c)
if not changes: print(' （なし）')
