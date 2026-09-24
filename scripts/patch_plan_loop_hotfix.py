# -*- coding: utf-8 -*-
"""
patch_plan_loop_hotfix.py — 教師ダッシュボードが白紙になるのを直す（緊急）
2026-09-25  PLAN_LOOP_HOTFIX

何が起きたか：
  PLAN_LOOP_V1 で足した onclick を、テンプレートリテラルの中で \\' と1段だけ
  エスケープして書いた。ここは1段ぶん食われるので、配信されるJSでは

      onclick="planCommentEdit(''+escH(p.userId)+'',this)"

  となり、'...' の文字列がそこで閉じてしまって SyntaxError（Unexpected string）。
  教師ダッシュボードの本体スクリプト（33万文字）が丸ごと動かなくなっていた。
  → クラス一覧が空、計画も出ない、という状態。

直し方：
  エスケープの段数に左右されない HTML エンティティ &#39; に置きかえる。
  同じファイルの loadHomework も、もともとこの書き方（returnHomework(&#39;...）。

⚠ 再発防止：このスクリプトは、直したあとに
  「テンプレートリテラルの中の onclick で、1段だけの \\' を使っていないか」も点検する。
"""
import io
import re
import sys

TSX = 'src/index.tsx'

FIXES = [
    # 私が PLAN_LOOP_V1 で入れた2か所
    ("""onclick="planCommentEdit(\\''+escH(p.userId)+'\\',this)\"""",
     """onclick="planCommentEdit(&#39;'+escH(p.userId)+'&#39;,this)\""""),
    ("""onclick="savePlanComment(\\''+escH(p.userId)+'\\',this)\"""",
     """onclick="savePlanComment(&#39;'+escH(p.userId)+'&#39;,this)\""""),
    # QRHUNT_V1 が入れた2か所（同じ地雷。これが残っていると教師ダッシュボードは動かない）
    ("""onclick="saveQrSpot(\\'' + sp.token + '\\')\"""",
     """onclick="saveQrSpot(&#39;' + sp.token + '&#39;)\""""),
    ("""onclick="showQrFinds(\\'' + h.id + '\\')\"""",
     """onclick="showQrFinds(&#39;' + h.id + '&#39;)\""""),
]


def apply(s):
    for old, new in FIXES:
        n = s.count(old)
        assert n == 1, 'anchor not unique (%d): %s' % (n, old[:60])
        s = s.replace(old, new)
    return s


def main():
    src = io.open(TSX, encoding='utf-8').read()
    out = apply(src)
    if out == src:
        print('NO CHANGE'); sys.exit(1)
    io.open(TSX, 'w', encoding='utf-8').write(out)
    print('patched (%d -> %d)' % (len(src), len(out)))

    # 再発防止の点検：onclick= の中で 1段だけの \' を使っている所を洗う
    bad = re.findall(r'onclick="[^"]*?[^\\]\\\'[^"]*?"', out)
    bad = [b for b in bad if '\\\\\'' not in b]
    print('1段だけの \\\' を使っている onclick:', len(bad))
    for b in bad[:5]:
        print('   ', b[:120])
    if bad:
        print('::error::まだ危ない onclick が残っています')
        sys.exit(1)


if __name__ == '__main__':
    main()
