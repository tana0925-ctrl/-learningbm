# -*- coding: utf-8 -*-
"""
KARTE_HANSHIN_V1 (2026-10-05)

児童画面「わたしのカルテ」の中の見出し「👩‍🏫 先生から」を「阪神マンから」に変える。

なぜ:
  この欄に出る文章は /api/student/my-karte の teacherMessage で、
  中身は student_ai_comments テーブルの comment 一本だけ。
  そこへ書き込むのは POST /api/teacher/student-ai-comments ただ一つで、
  送り元は teacher-ai.js の KARTE 種別の下書き（＝阪神マンが本人あてに書いた
  関西弁のひとこと。先生が読んで直してから「公開」する）。
  先生が手で書く別のコメント（家庭学習シートの「先生から」欄＝hsTeacherComment、
  メール、おへんじ、計画アドバイス）は、この欄には一切まざらない。
  紙のカルテではすでに「🐯 阪神マンからのアドバイス」と出ており、
  児童画面だけが「先生から」になっていて、誰のことばか伝わっていなかった。

直すもの:
  1) public/student-karte.js … 見出しと、下の注記の言い回し
  2) src/index.tsx          … /student-karte.js?v=1 -> v=2（古いJSを掴ませない）
                               既存の .replace( を書きかえるだけで、鎖は増やさない

フェイルクローズ:
  ・CHAIN_BEFORE（app.get('/') 〜 app.get('/logout') のあいだの .replace( の数）が
    実測と合わなければ、何も書かずに止まる
  ・置きかえ元の文字列が「ちょうど1回」見つからなければ止まる
  ・適用後に鎖の数が変わっていたら止まる
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
    if 'KARTE_HANSHIN_V1' in sk:
        die('すでに適用済みです（KARTE_HANSHIN_V1 のマーカーがあります）')
    if '\r' in sk:
        die('public/student-karte.js に CR が入っています。中止します。')

    # ---- 1) 冒頭の説明文 --------------------------------------------------
    sk = replace_once(
        sk,
        " *  ・文章は「その子自身が書いたことば」と「先生が読んで公開したメッセージ」だけ。\n",
        " *  ・文章は「その子自身が書いたことば」と「阪神マンのひとこと」だけ。\n"
        " *    阪神マンのひとことは、先生が読んで「公開」を押したものだけが出る（KARTE_HANSHIN_V1）。\n",
        '冒頭コメント')

    # ---- 2) 見出し --------------------------------------------------------
    old_head = (
        "    if (d.teacherMessage) {\n"
        "      h += '<div class=\"mt-3 rounded-xl bg-white border border-amber-200 p-3\">'\n"
        "         + '<div class=\"text-xs font-bold text-amber-700\">\U0001F469‍\U0001F3EB 先生から</div>'\n"
        "         + '<div class=\"text-sm text-gray-800\" style=\"white-space:pre-wrap\">' + esc(d.teacherMessage) + '</div></div>';\n"
        "    }\n"
    )
    new_head = (
        "    if (d.teacherMessage) {\n"
        "      /* KARTE_HANSHIN_V1 (2026-10-05)\n"
        "         ここに出る文章は阪神マン（関西弁の応援キャラ）が本人あてに書いたもの。\n"
        "         先生が読んで「公開」を押したものだけが届く。\n"
        "         紙のカルテの見出し「\U0001F42F 阪神マンからのアドバイス」と言い方をそろえた。\n"
        "         顔は図鑑の絵（ID:154 阪神マン）。絵が無い・読めないときは \U0001F42F にもどる。 */\n"
        "      var face = '\U0001F42F';\n"
        "      try {\n"
        "        if (typeof window.monSpriteHtml === 'function') face = window.monSpriteHtml(154, '\U0001F42F');\n"
        "      } catch (e) {}\n"
        "      h += '<div class=\"mt-3 rounded-xl bg-white border border-amber-200 p-3\">'\n"
        "         + '<div class=\"text-xs font-bold text-amber-700\" style=\"display:flex;align-items:center;gap:5px\">'\n"
        "         + '<span style=\"font-size:24px;line-height:1\">' + face + '</span><span>阪神マンから</span></div>'\n"
        "         + '<div class=\"text-sm text-gray-800\" style=\"white-space:pre-wrap\">' + esc(d.teacherMessage) + '</div></div>';\n"
        "    }\n"
    )
    sk = replace_once(sk, old_head, new_head, '見出し')

    # ---- 3) 下の注記 ------------------------------------------------------
    old_note = (
        "    h += '<div class=\"text-xs text-gray-500 mt-2\">※ 先生が読んで、わたしてくれたものだよ。</div>';\n"
    )
    new_note = (
        "    /* KARTE_HANSHIN_V1 「先生が目を通している」ことは必ず伝える。\n"
        "       上が阪神マンになったので、文としてつながるように言い方だけ整えた。 */\n"
        "    h += '<div class=\"text-xs text-gray-500 mt-2\">'\n"
        "       + (d.teacherMessage\n"
        "          ? '※ 阪神マンのことばは、先生が読んでから わたしてくれたものだよ。'\n"
        "          : '※ 先生が読んで、わたしてくれたものだよ。')\n"
        "       + '</div>';\n"
    )
    sk = replace_once(sk, old_note, new_note, '注記')

    # ---- 4) 版数 v=1 -> v=2（鎖は増やさない） -----------------------------
    tsx2 = replace_once(tsx, "/student-karte.js?v=1", "/student-karte.js?v=2", 'student-karte.js の版数')

    after = chain_count(tsx2)
    print('チェーン実測(後): %d' % after)
    if after != before:
        die('チェーン数が %d -> %d に変わりました。中止します。' % (before, after))

    open(SK, 'w', encoding='utf-8', newline='').write(sk)
    open(TSX, 'w', encoding='utf-8', newline='').write(tsx2)

    print('OK: public/student-karte.js と src/index.tsx を書きかえました（鎖 %d のまま）' % after)


if __name__ == '__main__':
    main()
