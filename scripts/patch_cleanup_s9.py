# -*- coding: utf-8 -*-
"""
patch_cleanup_s9.py — 教師ダッシュボードの片づけ 第2便のあと直し
2026-09-29  CLEANUP_S9

E-2 の「隠したクラスも表示する」チェックが効かなかったのを直す。
  本番で実際に押して確かめたところ、チェックを入れても 6年１組 が出てこなかった。
  原因：renderClassList() が wrap.innerHTML='' で中身を消したあとに
        チェックの状態を読んでいたため、読む時点でチェックそのものが
        消えており、いつも「隠す」と判断されていた。
  直し：チェックの状態を、消す前に読む。あわせて window に覚えておき、
        描き直しても選んだ状態が残るようにする。
  ※「隠す」こと自体は最初から効いている（6年１組は出ていない）。
    出し直せなかっただけ。データには一切さわっていない。

★配信チェーン（158件）は増減させない。
"""
import io
import sys

TSX = 'src/index.tsx'
ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"
CHAIN_WANT = 158


def die(msg):
    sys.stderr.write('NG: ' + msg + '\n')
    sys.exit(1)


def chain_count(s):
    i = s.index(ROOT_ANCHOR)
    j = s.index(END_ANCHOR, i)
    return s[i:j].count('.replace(')


def rep(s, old, new, label):
    n = s.count(old)
    if n != 1:
        die(u'あて先 %s が %d 件（1件のはず）' % (label, n))
    return s.replace(old, new)


OLD = (u"          const d = await api('/api/admin/classes');\n"
       u"          wrap.innerHTML='';\n"
       u"          /* 2026-09-29 整理(E-2): 「6年１組」(id bd8b4ede-…) は在籍1人・担任が別の先生で、\n"
       u"             この画面では使わないので既定で隠す。データは消していない。\n"
       u"             下のチェックを入れればいつでも出る。 */\n"
       u"          var _hideIds = ['bd8b4ede-0e2c-4f12-b76a-e28c0a62ce5a'];\n"
       u"          var _showAllEl = document.getElementById('admShowHiddenClasses');\n"
       u"          var _showAll = _showAllEl ? !!_showAllEl.checked : false;\n")

NEW = (u"          /* 2026-09-29 整理(E-2): 「6年１組」(id bd8b4ede-…) は在籍1人・担任が別の先生で、\n"
       u"             この画面では使わないので既定で隠す。データは消していない。\n"
       u"             下のチェックを入れればいつでも出る。\n"
       u"             ★2026-09-29 あと直し: チェックの状態は「中身を消す前」に読むこと。\n"
       u"               あとで読むと、読む時点でチェックごと消えていて いつも「隠す」になっていた。 */\n"
       u"          var _showAllEl = document.getElementById('admShowHiddenClasses');\n"
       u"          var _showAll = _showAllEl ? !!_showAllEl.checked : !!window._admShowHidden;\n"
       u"          window._admShowHidden = _showAll;\n"
       u"          var _hideIds = ['bd8b4ede-0e2c-4f12-b76a-e28c0a62ce5a'];\n"
       u"          const d = await api('/api/admin/classes');\n"
       u"          wrap.innerHTML='';\n")

CB_OLD = u"          if(_cb) _cb.onchange = ()=>{ renderClassList(); };\n"
CB_NEW = u"          if(_cb) _cb.onchange = ()=>{ window._admShowHidden = !!_cb.checked; renderClassList(); };\n"


def main():
    s = io.open(TSX, encoding='utf-8').read()
    n0 = chain_count(s)
    if n0 != CHAIN_WANT:
        die(u'チェーンが %d 件（%d 件のはず）。止めます。' % (n0, CHAIN_WANT))
    s = rep(s, OLD, NEW, 'E-2 チェックを読む順番')
    s = rep(s, CB_OLD, CB_NEW, 'E-2 チェックを覚える')
    n1 = chain_count(s)
    if n1 != n0:
        die(u'チェーンが %d 件になった' % n1)
    io.open(TSX, 'w', encoding='utf-8').write(s)
    print('PATCH OK / chain %d -> %d' % (n0, n1))


main()
