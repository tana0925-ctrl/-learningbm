# -*- coding: utf-8 -*-
# DEF_YOUTOO_V1 : まだ 出していない子の 画面に
#   「きみも たたかっているよ。プログラムを くむと、クラスが もっと つよくなる」と 出す。
#   せめない言い方にする（出していないことを わるいことに しない）。
#   つなぎ（root の HTML を 書きかえる ところ）に 1件だけ 足す。
#   public/index.html は 手で さわらない。ここでは あてはめ先が あることだけ 見る。
#
# 1回流しても 2回流しても 同じ形（番兵 __DEF_YOUTOO_V1__）。
# 一致しないときは 何も書かずに 失敗で終わる（fail-closed）。

import io
import sys

NL = chr(10)
BT = chr(96)

INDEX_PATH = 'src/index.tsx'
PUB_PATH = 'public/index.html'

SENTINEL = '__DEF_YOUTOO_V1__'

OLD_UI = ('if(d.my_entry && d.my_entry.monster){ var me=d.my_entry.monster; '
          + 'head+=' + chr(39) + '<div style="background:#ecfdf5;')

MSG = ('<div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:10px;padding:10px;margin-bottom:8px;">'
       + '<div style="font-weight:900;color:#1d4ed8;">🤝 きみも たたかっているよ</div>'
       + '<div style="font-size:13px;color:#334155;margin-top:3px;line-height:1.6;">'
       + 'クラスの みんなが 出るので、きみの いちばん上の モンスターも いっしょに たたかうよ。<br>'
       + 'プログラムを くむと、クラスは もっと つよくなる。</div></div>')

NEW_UI = ('if(!(d.my_entry && d.my_entry.monster)){ head+=' + chr(39) + MSG + chr(39) + '; } ' + OLD_UI)

CHAIN_ANCHOR = NL + '    _rootHtmlCache = t' + NL
CHAIN_ADD = (NL + '      // ' + SENTINEL + ' まだ 出していない子に「きみも たたかっているよ」と つたえる（せめない言い方で）'
             + NL + '      t = t.replace(' + BT + OLD_UI + BT + ', ' + BT + NEW_UI + BT + ')')


def read(path):
    return io.open(path, encoding='utf-8').read()


def write(path, text):
    io.open(path, 'w', encoding='utf-8', newline='').write(text)


def need_one(text, anchor, label):
    n = text.count(anchor)
    if n != 1:
        print('NG: %s のアンカーが %d 件（1 件でないので中止）' % (label, n))
        sys.exit(1)


def chain_count(text):
    i = text.index("app.get('/', async (c) => {")
    j = text.index("app.get('/logout'", i)
    return text[i:j].count('.replace(')


def main():
    s = read(INDEX_PATH)
    pub = read(PUB_PATH)

    if SENTINEL in s:
        print('すでに入っています（番兵 %s）。何もしません。' % SENTINEL)
        return

    need_one(pub, OLD_UI, '本番HTMLの 出陣ずみの ところ')
    need_one(s, CHAIN_ANCHOR, 'つなぎの おわり')
    if s.count(OLD_UI) != 0:
        print('NG: つなぎに すでに 同じ文字れつが ある')
        sys.exit(1)

    bt_before = s.count(BT)
    chain_before = chain_count(s)
    s2 = s.replace(CHAIN_ANCHOR, CHAIN_ADD + CHAIN_ANCHOR)
    chain_after = chain_count(s2)

    checks = [
        ('番兵', s2.count(SENTINEL), 1),
        ('見出しの ことば', s2.count('きみも たたかっているよ'), 1),
        ('さそいの ことば', s2.count('クラスは もっと つよくなる'), 1),
        ('ふえた 囲いの 数', s2.count(BT) - bt_before, 4),
        ('あてはめ先', s2.count(OLD_UI), 2),
    ]
    bad = 0
    for label, got, want in checks:
        if got != want:
            print('NG: %s が %d 件（%d 件の予定）' % (label, got, want))
            bad += 1
    if bad:
        sys.exit(1)

    if chain_after != chain_before + 1:
        print('NG: つなぎの数が %d から %d（ふえるのは 1 件だけの予定）' % (chain_before, chain_after))
        sys.exit(1)

    after = pub.replace(OLD_UI, NEW_UI)
    if after.count(MSG) != 1:
        print('NG: あてはめた あとの ことばが 1 件でない')
        sys.exit(1)
    if after.count(OLD_UI) != 1:
        print('NG: あてはめた あとの もとの ところが 1 件でない')
        sys.exit(1)

    write(INDEX_PATH, s2)
    print('OK: 入れました。つなぎの数は %d から %d。' % (chain_before, chain_after))


main()
