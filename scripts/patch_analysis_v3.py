#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_analysis_v3.py --- 子どもに配るカルテ 第1歩（a・b）＋既定チェックの見直し

  W1 「個人カルテ」を既定でONにする（家庭学習コメントと合わせて2つがONの状態）
  W2 「今日のひと往復」④の下に「📄 全員分のカルテを印刷（A4・1人1枚）」を置く
  W3 印刷カルテ（_buildKarteHtml）から「📝 テストの記録」セクションを外す
      … 先生の方針「カルテにテストの点数は入れない」を紙の方にも効かせる
  W4 teacher-ai.js のキャッシュを v=3 に
  public/index.html は触りません。
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
        if new in src:
            print('⏭  %s は適用済み（スキップ）' % tag); return
        fail('%s のアンカーが見つかりません' % tag)
    if n != 1:
        fail('%s のアンカーが %d 箇所（1箇所のはず）' % (tag, n))
    src = src.replace(old, new, 1)
    changes.append(tag)

# ---------------- W1: 個人カルテを既定ON ----------------
rep('<label class="flex items-center gap-1"><input type="checkbox" id="taiOptKarte" class="accent-indigo-600"> 個人カルテ</label>',
    '<label class="flex items-center gap-1"><input type="checkbox" id="taiOptKarte" checked class="accent-indigo-600"> 個人カルテ</label>',
    'W1 個人カルテを既定ON',
    sentinel='id="taiOptKarte" checked')

# ---------------- W2: 印刷ボタン ----------------
ANCHOR_PUB = """              <span id="taiPubStatus" class="text-xs font-bold text-rose-700"></span>
            </div>"""
NEW_PRINT = """              <span id="taiPubStatus" class="text-xs font-bold text-rose-700"></span>
            </div>
            <div class="flex items-center gap-2 flex-wrap mt-2 pt-2 border-t border-rose-200">
              <span class="text-xs text-rose-800 font-bold">公開したあと →</span>
              <button onclick="taiPrintKartes()" class="bg-white border border-rose-300 text-rose-700 rounded-lg px-3 py-2 text-xs font-bold hover:bg-rose-100">📄 全員分のカルテを印刷（A4・1人1枚）</button>
              <span id="taiPrintStatus" class="text-xs text-rose-700"></span>
            </div>"""
rep(ANCHOR_PUB, NEW_PRINT, 'W2 カルテ印刷ボタンを④の下に追加', sentinel='taiPrintKartes()')

# ---------------- W3: 印刷カルテからテストの記録を外す ----------------
TEST_SEC = ("""var tsc=(d.testScores||[]); if(tsc.length){ H.push('<div class="sec"><h2>📝 テストの記録</h2><ul>'); """
            """for(var ti=0;ti<tsc.length;ti++){ var tt=tsc[ti]; var tp=(tt.pct==null)?'':('（'+tt.pct+'%）'); """
            """H.push('<li>'+esc(tt.testDate||'')+' '+esc(tt.subject||'')+' '+esc(tt.testName||'')+' … '+(tt.score==null?'-':tt.score)+'/'+(tt.maxScore||100)+'点'+tp+"""
            """(tt.comment?' <span style="color:#0369a1">💬'+esc(tt.comment)+'</span>':'')+'</li>'); } H.push('</ul></div>'); } """)
NOTE = "/* 2026-09 方針: 子どもに渡すカルテにはテストの点数・得点率を載せない（先生の指示） */ "
rep(TEST_SEC, NOTE, 'W3 印刷カルテからテストの記録を削除',
    sentinel='子どもに渡すカルテにはテストの点数')

# ---------------- W4: キャッシュ更新 ----------------
rep('<script src="/teacher-ai.js?v=2"></script>',
    '<script src="/teacher-ai.js?v=3"></script>',
    'W4 teacher-ai.js のキャッシュ更新', sentinel='/teacher-ai.js?v=3')

# ---------------- 検証 ----------------
def root_replace_count(text):
    a = text.index("app.get('/', async (c) => {")
    b = text.index("app.get('/logout'", a)
    return text[a:b].count('.replace(')

if root_replace_count(orig) != root_replace_count(src):
    fail('本番HTMLの置換チェーンの数が変わりました')
print('🔎 置換チェーン: %d 件（適用前後で同数）' % root_replace_count(src))

for must in ['function _buildKarteHtml(', 'function downloadAllKartes(', 'id="taiDraftList"',
             "app.get('/api/teacher/risk-scores'", '/teacher-ai.js']:
    if must not in src: fail('必須の要素が失われました: %s' % must)
# 印刷カルテの他セクションが残っているか
for must in ['🌟 がんばりの記録', '🌱 これから もっと のびるところ', '🐯 阪神マンからのアドバイス', '@page{size:A4']:
    if must not in src: fail('印刷カルテの要素が失われました: %s' % must)
if 'テストの記録</h2>' in src: fail('印刷カルテにテストの記録が残っています')

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました')
else:
    print('… 変更なし')
print('---- 適用した項目 ----')
for c in changes: print(' ・' + c)
if not changes: print(' （なし）')
