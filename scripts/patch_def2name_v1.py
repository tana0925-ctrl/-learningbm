# -*- coding: utf-8 -*-
"""DEF2NAME_V1  防衛戦の 名前の わくを ひろげる（第2便）

なぜ:
  第1便（DEF_DISPNAME_V1）で 防衛戦に 出す 名前が ログインIDから
  ゲーム内の 名前に かわった。ゲーム内の 名前は 12文字まで 入るのに、
  名前を 出す わくが せまくて「…」で 切れてしまう。

さわるのは 2つだけ:
  public/defense2.js … 名前の わくを ひろげる（2か所）
      ①ベスト3の はこ   flex:1 1 180px -> flex:1 1 220px
      ②貢献ゲージの名前  flex:0 0 84px  -> flex:0 0 120px
  src/index.tsx      … よみこみ番号 /defense2.js?v=21 -> ?v=22
      （これを わすれると 子どもの iPad が 古い ファイルを 見つづける）

さわらないもの:
  MVPの わく（def2HypeHtml の 主役カード）… 中央ぞろえの div で
      はばの しばりも 「…」も ないので 切れない。
  エントリー一覧 … inline-block の ふだで しばりが ないので 切れない。
  勝敗の けいさん・resolve・public/index.html は 1文字も さわらない。

チェーン: 167 -> 167（ふえも へりも しない）
めじるしが きっちり 1件 見つからなければ、ファイルには 1文字も 書かずに 止まる。
"""

import io
import sys

S = 'src/index.tsx'
D = 'public/defense2.js'

MARK = 'DEF2NAME_V1'

CHAIN_BEFORE = 167
CHAIN_AFTER = 167

AWARD_OLD = 'flex:1 1 180px;min-width:160px;'
AWARD_NEW = 'flex:1 1 220px;min-width:160px;'

GAUGE_OLD = 'flex:0 0 84px;'
GAUGE_NEW = 'flex:0 0 120px;'

TAIL = (
    "\n/* DEF2NAME_V1 名前の わくを ひろげた"
    "（ベスト3 180->220 / 貢献ゲージ 84->120）。"
    " 見た目だけ。勝敗の けいさんには さわっていない。 */\n"
)

VER_OLD = '/defense2.js?v=21'
VER_NEW = '/defense2.js?v=22'


def need_one(name, text, hay):
    n = hay.count(text)
    if n != 1:
        print('NG: めじるし %s が %d 件（1件で ないので 止めます）' % (name, n))
        return False
    return True


def chain_of(text):
    i = text.index("app.get('/', async (c) => {")
    j = text.index("app.get('/logout'", i)
    return text[i:j].count('.replace(')


def main():
    s = io.open(S, encoding='utf-8', newline='').read()
    d = io.open(D, encoding='utf-8', newline='').read()

    if MARK in d and VER_NEW in s:
        print('すでに 入っています。なにも しません。')
        return 0
    if (MARK in d) != (VER_NEW in s):
        print('NG: かたほうだけ 入っています（defense2.js=%s index.tsx=%s）。手で 見てください。'
              % (MARK in d, VER_NEW in s))
        return 1

    ok = True
    ok = need_one('ベスト3の はこ', AWARD_OLD, d) and ok
    ok = need_one('貢献ゲージの 名前らん', GAUGE_OLD, d) and ok
    ok = need_one('よみこみ番号 v21', VER_OLD, s) and ok

    if d.count(AWARD_NEW) != 0:
        print('NG: ベスト3の はこが すでに 220 に なっています')
        ok = False
    if d.count(GAUGE_NEW) != 0:
        print('NG: 貢献ゲージが すでに 120 に なっています')
        ok = False

    # 第1便（DEF_DISPNAME_V1）が 入っている ことが 前提。
    # 入っていないと 名前が ログインIDの ままなので、わくだけ ひろげても 意味がない。
    r = io.open('src/def_resolve.ts', encoding='utf-8', newline='').read()
    if '__DEF_DISPNAME_V1__' not in r:
        print('NG: 第1便（DEF_DISPNAME_V1）が src/def_resolve.ts に 入っていません。')
        ok = False
    if 'defDisplayName' not in s:
        print('NG: 第1便（defDisplayName）が src/index.tsx に 入っていません。')
        ok = False

    chain = chain_of(s)
    if chain != CHAIN_BEFORE:
        print('NG: チェーンが %d 件（流す前は %d 件の はず）。ほかの便と ぶつかっています。'
              % (chain, CHAIN_BEFORE))
        ok = False

    if not ok:
        print('中止しました。ファイルには 1文字も 書いていません。')
        return 1

    d2 = d.replace(AWARD_OLD, AWARD_NEW, 1).replace(GAUGE_OLD, GAUGE_NEW, 1) + TAIL
    s2 = s.replace(VER_OLD, VER_NEW, 1)

    if AWARD_OLD in d2 or GAUGE_OLD in d2:
        print('NG: 古い わくが まだ のこっています')
        return 1
    if d2.count(AWARD_NEW) != 1 or d2.count(GAUGE_NEW) != 1:
        print('NG: 書きかえの 数が 合いません')
        return 1
    if d2.count(MARK) != 1:
        print('NG: defense2.js の 番兵が %d 件（1件の はず）' % d2.count(MARK))
        return 1
    if s2.count(VER_NEW) != 1 or s2.count(VER_OLD) != 0:
        print('NG: よみこみ番号の 書きかえが おかしい')
        return 1

    chain2 = chain_of(s2)
    if chain2 != CHAIN_AFTER:
        print('NG: 流したあとの チェーンが %d 件（%d 件の はず）' % (chain2, CHAIN_AFTER))
        return 1

    # 長さの 見はり。見た目だけの 便なので 大きく ふえたら おかしい。
    if not (0 < len(d2) - len(d) < 400):
        print('NG: defense2.js の 長さの ふえかたが へん（%d 文字）' % (len(d2) - len(d)))
        return 1
    if len(s2) != len(s):
        print('NG: index.tsx の 長さが かわった（%d -> %d）' % (len(s), len(s2)))
        return 1

    io.open(D, 'w', encoding='utf-8', newline='').write(d2)
    io.open(S, 'w', encoding='utf-8', newline='').write(s2)
    print('OK: ベスト3 180->220 / 貢献ゲージ 84->120 / よみこみ番号 v21->v22')
    print('    チェーン %d -> %d' % (chain, chain2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
