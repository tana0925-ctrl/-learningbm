# -*- coding: utf-8 -*-
"""DEF2TRY_NOWCSS_V1

ためしバトルの わくの 中だけ、あたまの上の 「いま：〜」を
小学生が 読める 大きさに する。

さわるのは 2つだけ:
  public/defense2.js  … ためしバトル専用の みための きまりを 足す
  src/index.tsx       … よみこみの v を 1つ 上げる（チェーンの数は 変えない）

えらび方（CSS セレクタ）を #def2TryAnim に かぎっているので、
みんなで見る 本番の リプレイ（#def2Anim）の みためには あたらない。

めじるしが きっちり 1件 見つからなければ、ファイルには 1文字も 書かずに 止まる。
"""

import io
import sys

D2 = 'public/defense2.js'
IDX = 'src/index.tsx'

# 冪等性の番兵（すでに流したかを 見るだけの しるし）
MARK = 'DEF2TRY_NOWCSS_V1_MARK'

A_HOST = "      var host=document.getElementById('def2TryAnim');"
A_SHOW = '  function tbShow(rep, prog){'

V_OLD = '/defense2.js' + '?v' + '=7'
V_NEW = '/defense2.js' + '?v' + '=8'

CSS_MINE = (
    '#def2TryAnim .gc-now{'
    'font-size:12px !important;'
    'line-height:1.3 !important;'
    'opacity:1 !important;'
    'max-width:none !important;'
    'overflow:visible !important;'
    'text-overflow:clip !important;'
    'white-space:nowrap !important;'
    'padding:2px 7px !important;'
    'top:-19px !important;'
    'background:rgba(15,23,42,.95) !important;'
    'box-shadow:0 1px 4px rgba(0,0,0,.35) !important;'
    'z-index:9 !important;}'
)

CSS_FOE = (
    '#def2TryAnim [id^="gc-now-B-"]{'
    'font-size:9px !important;'
    'opacity:.5 !important;'
    'top:-15px !important;'
    'box-shadow:none !important;'
    'z-index:8 !important;}'
)

BLOCK = (
    '  /* ' + MARK + '\n'
    '     ためしバトルの わくの 中だけ、あたまの上の 「いま：」を 大きく する。\n'
    '     えらび方を #def2TryAnim に かぎっているので、\n'
    '     みんなで見る 本番の リプレイ（#def2Anim）には あたらない。\n'
    '     あいて（B）の ふきだしは 小さいままに して、\n'
    '     じぶんの モンスターの ほうが 先に 目に入るようにする。 */\n'
    '  function tbInjectNowCss(){\n'
    "    if(document.getElementById('def2TryNowCss')) return;\n"
    "    var st=document.createElement('style'); st.id='def2TryNowCss';\n"
    "    st.textContent='" + CSS_MINE + "'\n"
    "      +'" + CSS_FOE + "';\n"
    '    document.head.appendChild(st);\n'
    '  }\n'
    '\n'
)


def read(p):
    return io.open(p, encoding='utf-8', newline='').read()


def write(p, t):
    io.open(p, 'w', encoding='utf-8', newline='').write(t)


def main():
    d = read(D2)
    s = read(IDX)

    if MARK in d:
        print('すでに 入っています。なにも しません。')
        return 0

    for label, text, t in (
        ('ためしバトルの わく', A_HOST, d),
        ('ためしバトルの 出し口', A_SHOW, d),
        ('よみこみの v', V_OLD, s),
    ):
        c = t.count(text)
        if c != 1:
            print('NG: めじるし %s が %d 件（1件で ないので 止めます）' % (label, c))
            return 1

    if V_NEW in s:
        print('NG: あたらしい v が すでに あります')
        return 1
    if 'tbInjectNowCss' in d:
        print('NG: 名まえが ぶつかります')
        return 1
    if '#def2TryAnim .gc-now' in d:
        print('NG: みための きまりが すでに あります')
        return 1

    d2 = d.replace(A_SHOW, BLOCK + A_SHOW, 1)
    d2 = d2.replace(A_HOST, '      tbInjectNowCss();\n' + A_HOST, 1)
    s2 = s.replace(V_OLD, V_NEW, 1)

    if d2 == d or s2 == s:
        print('NG: 書きかえが おきませんでした')
        return 1
    if d2.count(MARK) != 1:
        print('NG: しるしの数が おかしい')
        return 1
    if d2.count('tbInjectNowCss') != 2:
        print('NG: 足した数が おかしい')
        return 1
    if d2.count('#def2Anim .gc-now{') != 1:
        print('NG: 本番の みためを こわしています')
        return 1
    if s2.count(V_NEW) != 1 or V_OLD in s2:
        print('NG: よみこみの v が おかしい')
        return 1

    write(D2, d2)
    write(IDX, s2)
    print('OK: ためしバトルの 「いま：」を 読める大きさに しました')
    return 0


if __name__ == '__main__':
    sys.exit(main())
