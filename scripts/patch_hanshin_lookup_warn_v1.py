#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""阪神マン: アドバイス未登録時に単元IDをコンソールへ出す (+ 参照直前のマージ保証)

参照側のコードは src/index.tsx 本体ではなく public/index.html 側にあり、
src/index.tsx の app.get('/') が .replace() チェーンで加工して本番HTMLを作る。
よってこのパッチはチェーンに .replace() を1本だけ足す。

入れる内容:
  1. lookup 直前に window.__HANSHIN_ADV2_ENSURE() を呼び、参照時点でのマージ済みを保証
  2. rootNode が無いときに console.warn で trainingMode (単元ID) を出す

既存の .replace() 対象文字列には一切触れない。追加のみ。
"""

import re
import sys

PATH_TSX = 'src/index.tsx'
PATH_HTML = 'public/index.html'

# 冪等性の番兵。適用後検証の条件とは別物にしてある。
SENTINEL = '__HANSHIN_ADV2_LOOKUP_V1__'

# チェーン内の既存行。この直後に新しい .replace() を挿す。
ANCHOR_CHAIN = ('      t = t.replace("const HANSHIN_ADVICE_TREE = {", '
                '"const HANSHIN_ADVICE_TREE = window.HANSHIN_ADVICE_TREE = {")')

# public/index.html 側の差し替え対象（先頭16スペース）
ANCHOR_HTML = ' ' * 16 + 'const rootNode = HANSHIN_ADVICE_TREE[trainingMode];'

INSERT = r'''
      // __HANSHIN_ADV2_LOOKUP_V1__ 阪神マン: アドバイス参照の直前にマージを保証し、未登録なら単元IDをコンソールに出す
      t = t.replace(
        "                const rootNode = HANSHIN_ADVICE_TREE[trainingMode];",
        "                if (window.__HANSHIN_ADV2_ENSURE) { try { window.__HANSHIN_ADV2_ENSURE(); } catch (e) {} }\n" +
        "                const rootNode = HANSHIN_ADVICE_TREE[trainingMode];\n" +
        "                if (!rootNode) { try { console.warn('[阪神マン] アドバイス未登録 単元ID:', trainingMode); } catch (e) {} }"
      )'''


def fail(msg):
    print('[中止] ' + msg)
    sys.exit(1)


def main():
    with open(PATH_TSX, encoding='utf-8') as f:
        tsx = f.read()

    if SENTINEL in tsx:
        print('[スキップ] 既に適用済み (番兵 ' + SENTINEL + ' を検出)')
        return

    # --- アンカーの一意性 (src/index.tsx) ---
    n_chain = tsx.count(ANCHOR_CHAIN)
    if n_chain != 1:
        fail('チェーン挿入アンカーが %d 個。ちょうど1個であるべき' % n_chain)

    # --- 差し替え対象が public/index.html に一意に存在するか ---
    with open(PATH_HTML, encoding='utf-8') as f:
        html = f.read()
    n_html = html.count(ANCHOR_HTML)
    if n_html != 1:
        fail('public/index.html の lookup 行が %d 個。ちょうど1個であるべき' % n_html)

    rep_before = tsx.count('.replace(')
    chain_before = _chain_replace_count(tsx)

    i = tsx.index(ANCHOR_CHAIN) + len(ANCHOR_CHAIN)
    out = tsx[:i] + INSERT + tsx[i:]

    rep_after = out.count('.replace(')
    chain_after = _chain_replace_count(out)

    checks = [
        ('.replace() が1本増えていない', rep_after == rep_before + 1),
        ('チェーン内の .replace() が1本増えていない', chain_after == chain_before + 1),
        ('ENSURE 呼び出しが2箇所でない', out.count('__HANSHIN_ADV2_ENSURE') == 2),
        ('警告文が1箇所でない', out.count('アドバイス未登録 単元ID') == 1),
        ('挿入アンカーを壊した', out.count(ANCHOR_CHAIN) == 1),
        ('lookup 行の文字列が2箇所でない', out.count(ANCHOR_HTML) == 2),
        ('ファイルが縮んだ', len(out) > len(tsx)),
    ]
    ng = [name for name, ok in checks if not ok]
    if ng:
        fail('適用後検証に失敗: ' + ' / '.join(ng))

    with open(PATH_TSX, 'w', encoding='utf-8') as f:
        f.write(out)

    print('[完了] %s に .replace() を1本追加' % PATH_TSX)
    print('  .replace() 総数: %d -> %d' % (rep_before, rep_after))
    print("  app.get('/') チェーン内: %d -> %d" % (chain_before, chain_after))


def _chain_replace_count(text):
    """app.get('/') の本番HTML生成ハンドラ内の .replace( を数える。

    ハンドラの終わりは「次の app.<method>(」で区切る。固定幅で切ると
    チェーンが伸びたときに数え漏れ・数えすぎが起きるため。
    """
    start = -1
    for m in re.finditer(r"app\.get\(\s*['\"]/['\"]", text):
        if '_rootHtmlCache' in text[m.start():m.start() + 600]:
            start = m.start()
            break
    if start < 0:
        return -1
    end = len(text)
    for m in re.finditer(r"\bapp\.(?:get|post|put|delete|use|all)\(", text):
        if m.start() > start:
            end = m.start()
            break
    return text[start:end].count('.replace(')


main()
