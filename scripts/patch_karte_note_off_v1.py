# -*- coding: utf-8 -*-
"""
KARTE_HANSHIN_V2 (2026-10-05)

児童画面「わたしのカルテ」の阪神マンの欄の下にある注記を、丸ごと消す（先生の指示）。
  ・「※ 阪神マンのことばは、先生が読んでから わたしてくれたものだよ。」
  ・「※ 先生が読んで、わたしてくれたものだよ。」
  両方とも出さない。見出しの「阪神マンから」と虎の絵（ID:154）はそのまま残す。

直すもの:
  1) public/student-karte.js … 注記の1ブロックを削る（枠を閉じる h += '</div>'; は残す）
  2) src/index.tsx          … /student-karte.js?v=2 -> v=3
                               （既存の .replace( を書きかえるだけ。鎖は増やさない）

フェイルクローズ:
  ・CHAIN_BEFORE が実測と合わなければ、何も書かずに止まる
  ・置きかえ元が「ちょうど1回」見つからなければ止まる
  ・適用後に鎖の数が変わっていたら止まる
  ・見出し（阪神マンから／monSpriteHtml(154）が残っていなければ止まる
  ・public/index.html には一切さわらない
"""
import os
import sys

TSX = 'src/index.tsx'
SK = 'public/student-karte.js'


def die(msg):
    print('::error::' + msg)
    sys.exit(1)


def chain_count(s):
    a = s.index("app.get('/'")
    b = s.index("app.get('/logout'")
    if b <= a:
        die('app.get(\'/\') と app.get(\'/logout\') の並びがおかしい')
    return s[a:b].count('.replace(')


def replace_once(s, old, new, label):
    n = s.count(old)
    if n != 1:
        die('%s: 置きかえ元が %d 件（1件でないので中止）' % (label, n))
    return s.replace(old, new, 1)


def main():
    want = os.environ.get('CHAIN_BEFORE', '').strip()
    if not want.isdigit():
        die('CHAIN_BEFORE が数字で渡されていません: %r' % want)

    tsx = open(TSX, encoding='utf-8').read()
    before = chain_count(tsx)
    print('チェーン実測(前): %d / 指定: %s' % (before, want))
    if before != int(want):
        die('チェーン数が合いません（実測 %d / 指定 %s）。ほかの便が入っています。中止します。' % (before, want))

    sk = open(SK, encoding='utf-8').read()
    if 'KARTE_HANSHIN_V2' in sk:
        die('すでに適用済みです（KARTE_HANSHIN_V2 のマーカーがあります）')
    if '\r' in sk:
        die('public/student-karte.js に CR が入っています。中止します。')

    old_note = (
        "\n"
        "    /* KARTE_HANSHIN_V1 「先生が目を通している」ことは必ず伝える。\n"
        "       上が阪神マンになったので、文としてつながるように言い方だけ整えた。 */\n"
        "    h += '<div class=\"text-xs text-gray-500 mt-2\">'\n"
        "       + (d.teacherMessage\n"
        "          ? '※ 阪神マンのことばは、先生が読んでから わたしてくれたものだよ。'\n"
        "          : '※ 先生が読んで、わたしてくれたものだよ。')\n"
        "       + '</div>';\n"
        "    h += '</div>';\n"
    )
    new_note = (
        "\n"
        "    /* KARTE_HANSHIN_V2 (2026-10-05) 注記（※〜）は出さない（先生の指示）。\n"
        "       見出しの「阪神マンから」と虎の絵はそのまま。 */\n"
        "    h += '</div>';\n"
    )
    sk = replace_once(sk, old_note, new_note, '注記')

    # 見出しが残っていること（消しすぎの防止）
    for k in ['阪神マンから', 'monSpriteHtml(154']:
        if sk.count(k) < 1:
            die('見出しの %s が消えました。中止します。' % k)
    for k in ['※ 阪神マンのことばは', '※ 先生が読んで']:
        if k in sk:
            die('注記 %s が残っています。中止します。' % k)

    tsx2 = replace_once(tsx, "/student-karte.js?v=2", "/student-karte.js?v=3", 'student-karte.js の版数')

    after = chain_count(tsx2)
    print('チェーン実測(後): %d' % after)
    if after != before:
        die('チェーン数が %d -> %d に変わりました。中止します。' % (before, after))

    open(SK, 'w', encoding='utf-8', newline='').write(sk)
    open(TSX, 'w', encoding='utf-8', newline='').write(tsx2)
    print('OK: 注記を削除しました（鎖 %d のまま）' % after)


if __name__ == '__main__':
    main()
