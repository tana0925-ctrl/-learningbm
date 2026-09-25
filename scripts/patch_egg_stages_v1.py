# -*- coding: utf-8 -*-
"""
patch_egg_stages_v1.py — タマゴバトル ステージ11〜15 を開通し、難易度を整える
2026-09-25  EGGSTAGE_V1   (チェーン 132 -> 137)

なにをするか（src/index.tsx の app.get('/') のチェーンに .replace() を5本足すだけ）:

  R1  STAGES に ステージ11〜15 を「末尾に」足す（迷路の壁の形＋名前）
        ⚠️ 記録(player.eggStageClears)は配列の並び順の番号で保存されている。
           途中に差し込むと全員の進捗がズレる。だから必ず末尾。
        敵・ボス・報酬キャラ(1411〜1415)は すでに用意されているので、
        STAGES に足すだけで自動的にひもづく。新しいIDは1つも作らない。

  R2  敵レベル  [3,5,8, ...,24, 28,32,38,44,52]
              → [2,4,6, ...,24, 26,29,33,38,44]
        ・ステージ1〜3 を易しく（0クリアが25人中11人いる）
        ・ステージ11〜15 の伸びを ゆるめる

  R3  敵リーダーHP  235 + i*42
              → (i<=2 ? 210 : 235) + min(i,10)*42
        ・ステージ1〜3 の切片を 210 に
        ・ステージ4〜10 は 今と完全に同じ（進行中の子の体感を変えない）
        ・ステージ11〜15 は 655 で頭打ち（もとは 655〜823）

  R4  敵のタマゴ上限  12+2+i*2  →  min(32, 12+2+i*2)
        ・ステージ10 までは今と同じ（14〜32）
        ・ステージ11〜15 は 32 で頭打ち（もとは 34〜42。味方は12固定なので3.5倍差だった）

  R5  妨害コアを ステージ11〜15 では「1週目から」出す
        ・1週目 ステージ11〜13 は 2個 / 14〜15 は 3個
        ・2週目のルールは いままでどおり（1〜4:1個 / 5〜7:2個 / 8以降:3個）
        ・数字を上げるかわりに「仕掛け」で難しくするのが狙い

⚠️ public/index.html は 1バイトも変えない（ワークフロー側でも確認している）
⚠️ progress（児童のデータ）には 触らない
⚠️ テンプレートリテラルの中の onclick で 1段だけの \\' を使わない（2026-09-25の事故の原因）
   → このパッチは onclick を1つも作らないが、念のため最後に全体を点検する
"""
import io
import json
import os
import re
import shutil
import sys

TSX = 'src/index.tsx'
HTML = 'public/index.html'
SELF_COPY = 'scripts/patch_egg_stages_v1.py'
TAG = 'EGGSTAGE_V1'

CHAIN_ADDS = 5
CHAIN_EXPECT_BEFORE = int((os.environ.get('CHAIN_BEFORE') or '132').strip())
CHAIN_EXPECT_AFTER = CHAIN_EXPECT_BEFORE + CHAIN_ADDS

# ───────────────────────────────────────────────────────────
# ステージ11〜15 の壁（キャンバス 960x520 / 自陣(80,440) / 敵陣(870,70)）
# 半径7・9 の円で自陣から敵陣まで到達できることを手元のBFSで確認済み。
# 歩ける面積は 81〜85%（既存10面は 72.8〜90.2%）。
# ───────────────────────────────────────────────────────────
NEW_STAGES = [
    (u"\U0001F3A8 \u5C71\u306E\u30A2\u30FC\u30C8\u5DE5\u623F", [
        (180, 60, 10, 200), (180, 60, 240, 10), (180, 360, 10, 100),
        (300, 160, 10, 200), (420, 60, 10, 140), (420, 260, 10, 200),
        (540, 160, 10, 200), (660, 60, 10, 140), (660, 260, 10, 200),
        (780, 160, 10, 200), (300, 250, 120, 10), (540, 250, 120, 10),
    ]),
    (u"\U0001F977 \u304B\u3052\u306E\u795E\u793E", [
        (150, 100, 220, 10), (150, 100, 10, 120), (360, 100, 10, 120),
        (150, 300, 220, 10), (150, 300, 10, 120), (360, 300, 10, 120),
        (590, 100, 220, 10), (590, 100, 10, 120), (800, 100, 10, 120),
        (590, 300, 220, 10), (590, 300, 10, 120), (800, 300, 10, 120),
        (470, 0, 10, 120), (470, 400, 10, 120),
    ]),
    (u"\U0001F468\u200D\U0001F680 \u30B9\u30DA\u30FC\u30B9\u57FA\u5730", [
        (240, 120, 480, 10), (240, 390, 480, 10),
        (240, 120, 10, 110), (240, 290, 10, 110),
        (710, 120, 10, 110), (710, 290, 10, 110),
        (360, 210, 240, 10), (360, 300, 240, 10),
        (360, 210, 10, 40), (590, 260, 10, 50),
        (100, 250, 10, 200), (850, 70, 10, 200),
    ]),
    (u"\U0001F995 \u304D\u3087\u3046\u308A\u3085\u3046\u6E13\u8C37", [
        (0, 150, 280, 10), (360, 150, 600, 10),
        (0, 290, 120, 10), (200, 290, 600, 10), (880, 290, 80, 10),
        (120, 400, 600, 10), (800, 400, 160, 10),
        (280, 60, 10, 100), (640, 160, 10, 130),
        (360, 300, 10, 100), (760, 300, 10, 100),
    ]),
    (u"\U0001F31F \u30BF\u30DE\u30B4\u795E\u6BBF", [
        (120, 80, 10, 360), (830, 80, 10, 360),
        (120, 80, 250, 10), (470, 80, 370, 10),
        (120, 430, 370, 10), (590, 430, 250, 10),
        (300, 190, 360, 10), (300, 330, 360, 10),
        (300, 190, 10, 60), (300, 290, 10, 50),
        (650, 190, 10, 60), (650, 290, 10, 50),
        (470, 240, 10, 40),
    ]),
]


def build_stage_text():
    out = []
    for name, walls in NEW_STAGES:
        out.append(u'    { name:"%s", walls:[\n' % name)
        for (x, y, w, h) in walls:
            out.append(u'      {x:%d,y:%d,w:%d,h:%d},\n' % (x, y, w, h))
        out.append(u'    ]},\n')
    return u''.join(out)


# ───────────────────────────────────────────────────────────
# 置きかえる5本（a=目印 / b=置きかえ後）
# どれも ' も \ も ` も ${ も含まない。TS の文字列は '...' で囲む。
# ───────────────────────────────────────────────────────────
A1 = u'      {x:470,y:220,w:10,h:80},\n    ]},\n  ]'
B1 = u'      {x:470,y:220,w:10,h:80},\n    ]},\n' + build_stage_text() + u'  ]'

A2 = u'const EGG_STAGE_ENEMY_LV_FIXED = [3, 5, 8, 11, 14, 16, 18, 20, 22, 24, 28, 32, 38, 44, 52]'
B2 = u'const EGG_STAGE_ENEMY_LV_FIXED = [2, 4, 6, 11, 14, 16, 18, 20, 22, 24, 26, 29, 33, 38, 44]'

A3 = u'const enemyBaseHP = 235 + (this.stageIndex||0)*42;'
B3 = u'const enemyBaseHP = (((this.stageIndex||0) <= 2) ? 210 : 235) + Math.min((this.stageIndex||0), 10)*42;'

A4 = u'enemyRes: { eggs: 0, eggsMax: (DEFAULT_RES.eggsMax + 2 + (this.stageIndex||0)*2) },'
B4 = u'enemyRes: { eggs: 0, eggsMax: Math.min(32, (DEFAULT_RES.eggsMax + 2 + (this.stageIndex||0)*2)) },'

A5 = (u'      // spawn \u59A8\u5BB3\u30B3\u30A2\uFF082\u9031\u76EE\u306E\u307F\uFF09\n'
      u'      if(this.stageLoop===2){\n'
      u'        const si = (this.stageIndex||0); // 0-based\n'
      u'        let n = 1;\n'
      u'        if(si >= 4) n = 2;      // stage5-\n'
      u'        if(si >= 7) n = 3;      // stage8-')
B5 = (u'      // spawn \u59A8\u5BB3\u30B3\u30A2\uFF082\u9031\u76EE\u3001\u304A\u3088\u3073 \u30B9\u30C6\u30FC\u30B811\u4EE5\u964D\u306F1\u9031\u76EE\u304B\u3089\uFF09\n'
      u'      if(this.stageLoop===2 || (this.stageIndex||0) >= 10){\n'
      u'        const si = (this.stageIndex||0); // 0-based\n'
      u'        let n = 1;\n'
      u'        if(si >= 4) n = 2;      // stage5-\n'
      u'        if(si >= 7) n = 3;      // stage8-\n'
      u'        if(this.stageLoop !== 2) n = (si >= 13) ? 3 : 2;   // 1\u9031\u76EE: st11-13=2\u500B / st14-15=3\u500B')

PAIRS = [
    ('R1_STAGES', A1, B1),
    ('R2_ENEMY_LV', A2, B2),
    ('R3_BASE_HP', A3, B3),
    ('R4_EGG_CAP', A4, B4),
    ('R5_CORE_LOOP1', A5, B5),
]

INSERT_ANCHOR = u'\n    _rootHtmlCache = t\n    }\n'


def ts_str(s):
    """Python の文字列を TypeScript の '...' リテラルにする。"""
    out = s.replace(u'\\', u'\\\\').replace(u"'", u"\\'")
    out = out.replace(u'\r', u'\\r').replace(u'\n', u'\\n')
    assert u'`' not in out
    assert u'${' not in out
    return u"'" + out + u"'"


def chain_count(src):
    i = src.index(u"app.get('/', async (c) => {")
    j = src.index(u"app.get('/logout'")
    return src[i:j].count(u'.replace(')


def main():
    html = io.open(HTML, encoding='utf-8').read()
    src = io.open(TSX, encoding='utf-8').read()

    # ── 1) チェーン実測（流す前の値と合っているか） ──────────────
    before = chain_count(src)
    print('chain before = %d (expect %d)' % (before, CHAIN_EXPECT_BEFORE))
    if before != CHAIN_EXPECT_BEFORE:
        print('::error::chain mismatch. expected %d, got %d' % (CHAIN_EXPECT_BEFORE, before))
        sys.exit(1)

    # ── 2) 目印が public/index.html に ちょうど1つずつ あるか ────
    for tag, a, b in PAIRS:
        n = html.count(a)
        print('%-14s anchor in html = %d' % (tag, n))
        if n != 1:
            print('::error::%s anchor not unique in html (%d)' % (tag, n))
            sys.exit(1)
        if html.count(b) != 0:
            print('::error::%s already applied?' % tag)
            sys.exit(1)

    # ── 3) 置きかえたあとの HTML で ステージが15件になるか ───────
    after_html = html
    for tag, a, b in PAIRS:
        after_html = after_html.replace(a, b, 1)
    i = after_html.index(u'const STAGES = [')
    d = 0
    for k in range(after_html.index(u'[', i), len(after_html)):
        if after_html[k] == u'[':
            d += 1
        elif after_html[k] == u']':
            d -= 1
            if d == 0:
                break
    stage_names = re.findall(r'name:"([^"]+)"', after_html[i:k + 1])
    print('STAGES after = %d' % len(stage_names))
    if len(stage_names) != 15:
        print('::error::STAGES must be 15, got %d' % len(stage_names))
        sys.exit(1)
    # 既存10件の名前と順番が変わっていないこと（進捗の番号がズレないため）
    old_names = re.findall(r'name:"([^"]+)"', html[html.index(u'const STAGES = ['):])[:10]
    if stage_names[:10] != old_names:
        print('::error::existing stage order changed!')
        sys.exit(1)
    print('existing 10 stages unchanged and still first: OK')

    # ── 4) src/index.tsx に .replace() を5本 差しこむ ────────────
    if src.count(INSERT_ANCHOR) != 1:
        print('::error::insert anchor not unique')
        sys.exit(1)
    if TAG in src:
        print('::error::%s already present' % TAG)
        sys.exit(1)

    block = [u'\n']
    block.append(u'      // \u2550\u2550\u2550\u2550\u2550\u2550 %s \u30BF\u30DE\u30B4\u30D0\u30C8\u30EB \u30B9\u30C6\u30FC\u30B811\u301C15 \u3092\u958B\u901A\uFF0B\u96E3\u6613\u5EA6\u8ABF\u6574 \u2550\u2550\u2550\u2550\u2550\u2550\n' % TAG)
    block.append(u'      // \u4E2D\u8EAB\u306F scripts/patch_egg_stages_v1.py\u3002public/index.html \u306F \u624B\u3067 \u66F8\u304D\u304B\u3048\u306A\u3044\u3002\n')
    block.append(u'      // \u2757 STAGES \u3078\u306E\u8FFD\u52A0\u306F\u5FC5\u305A\u672B\u5C3E\uFF08\u8A18\u9332\u304C\u4E26\u3073\u9806\u306E\u756A\u53F7\u3067\u4FDD\u5B58\u3055\u308C\u3066\u3044\u308B\u305F\u3081\uFF09\u3002\n')
    block.append(u'      // \u7F6E\u304D\u304B\u3048\u6587\u5B57\u5217\u306F\u6A5F\u68B0\u751F\u6210\uFF08$ \u3084 \u30D0\u30C3\u30AF\u30B9\u30E9\u30C3\u30B7\u30E5\u3092\u58CA\u3055\u306A\u3044\u305F\u3081 () => b \u5F62\u5F0F\uFF09\u3002\n')
    for tag, a, b in PAIRS:
        block.append(u'      t = t.replace(%s, () => %s)   // %s %s\n' % (ts_str(a), ts_str(b), TAG, tag))
    new_src = src.replace(INSERT_ANCHOR, u''.join(block) + INSERT_ANCHOR, 1)

    after = chain_count(new_src)
    print('chain after = %d (expect %d)' % (after, CHAIN_EXPECT_AFTER))
    if after != CHAIN_EXPECT_AFTER:
        print('::error::chain after mismatch. expected %d, got %d' % (CHAIN_EXPECT_AFTER, after))
        sys.exit(1)

    # ── 5) 2026-09-25 \u306E\u4E8B\u6545\u306E\u518D\u767A\u9632\u6B62\u70B9\u691C ─────────────
    bad = re.findall(r'onclick="[^"]*?[^\\]\\\'[^"]*?"', new_src)
    bad = [x for x in bad if '\\\\\'' not in x]
    print('1\u6BB5\u3060\u3051\u306E \\\' \u3092\u4F7F\u3063\u3066\u3044\u308B onclick: %d' % len(bad))
    if bad:
        for x in bad[:5]:
            print('   ', x[:120])
        print('::error::\u5371\u306A\u3044 onclick \u304C\u3042\u308A\u307E\u3059')
        sys.exit(1)

    io.open(TSX, 'w', encoding='utf-8').write(new_src)
    print('patched %s (%d -> %d chars)' % (TSX, len(src), len(new_src)))

    # ── 6) 自分自身を scripts/ に残す（監査のため） ───────────────
    try:
        me = os.path.abspath(__file__)
        if not os.path.isdir('scripts'):
            os.makedirs('scripts')
        if os.path.abspath(SELF_COPY) != me:
            shutil.copyfile(me, SELF_COPY)
        print('kept a copy at %s' % SELF_COPY)
    except Exception as e:
        print('could not self-copy: %s' % e)

    # ── 7) 手元検証用に、ほどいた文字列を書き出す ─────────────────
    try:
        io.open('/tmp/egg_pairs.json', 'w', encoding='utf-8').write(
            json.dumps([{'tag': t_, 'a': a_, 'b': b_} for t_, a_, b_ in PAIRS], ensure_ascii=False))
        print('wrote /tmp/egg_pairs.json')
    except Exception:
        pass

    # ── 8) public/index.html は変えていないこと ───────────────────
    if io.open(HTML, encoding='utf-8').read() != html:
        print('::error::public/index.html changed')
        sys.exit(1)
    print('public/index.html untouched: OK')
    print('DONE %s' % TAG)


if __name__ == '__main__':
    main()
