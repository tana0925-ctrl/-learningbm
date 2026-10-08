#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# CLASSES_TIDY_V1 : 教師ダッシュボード「⑥ クラス・名簿」の片づけ
#
# ■ 何が起きていたか（実測）
#   renderClasses() のクラス見出し行は
#       header.className = 'flex items-center justify-between mb-3'
#   という「横1行」です。ところがそこに、本来その下に置くはずの
#       khtBox       （🎫 カフート券   class="mt-3 pt-3 border-t ..."）
#       menusDivider （🗒 メニュー表示設定 class="mt-3 pt-3 border-t ..."）
#   の2つが header.appendChild() で押し込まれていました。
#   その結果、1行に4つのかたまりが並び、
#     ・クラス名のところが 72px まで潰れて「参加コー／ド:」と折れる
#     ・ボタンの箱が 423px になり、日本語は1文字ごとに改行できるので
#       ボタンが1文字ずつの縦書きになる（削除ボタンの実測幅 30px）
#   という見た目になっていました。
#   カードの幅を 2750px まで広げないと直らないので、画面幅の問題ではありません。
#
# ■ このパッチがすること（機能は1つも消しません。置き場所と見た目だけ）
#   (1) ボタンの箱を flex-wrap にする（横に入らなければ段を増やす）
#   (2) カフート券を見出し行から出す → カードの下に、折りたたみで置く
#   (3) メニュー表示設定を見出し行から出す → カードの下に、折りたたみで置く
#   (4) 削除をほかのボタンと並べない → いちばん下に、単独で置く
#       （押したときの確認ダイアログは もともと入っています。そのまま）
#   (5) 見出し行の中身を nowrap にする（縦書きにならない）
#   (6) カフート券の説明を 4行の「｜」区切りから 2行に分ける
#   (7) カフート券のボタンも nowrap にする
#   (8) 右下の浮きボタン「この子にいま届いているもの」を少し上げて、
#       「ひとこと」ボタンと重ならないようにする（public/teacher-preview.js）
#
# ■ 触る範囲
#   src/index.tsx と public/teacher-preview.js の2つだけ。
#   児童の画面（public/index.html）には1バイトも触りません。
#   D1 にも触りません。DDL も流しません。
#   チェーン件数は「流す直前に実測した値から変わっていないこと」の確認だけに使います。
#   （直すのは renderClasses で、チェーンの区間の外です）
#
#   前提が1つでも崩れたら、ファイルに書かずに exit 1（フェイルクローズ）。

import os
import sys

SRC = 'src/index.tsx'
TPV = 'public/teacher-preview.js'

SENTINEL = '__CLASSES_TIDY_V1__'

ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"

# ---------------------------------------------------------------- (1)
A1_OLD = "btnGroup.className='flex items-center gap-2';"
A1_NEW = ("btnGroup.className='flex flex-wrap items-center justify-end gap-2';"
          " /* " + SENTINEL + " 横に入らないときは段を増やす（縦書きにしない） */")

# ---------------------------------------------------------------- (2)
A2_OLD = "header.appendChild(khtBox);"
A2_NEW = ("/* " + SENTINEL + " カフート券は見出し行の中ではなく、カードの下に置く */")

# ---------------------------------------------------------------- (3)
A3_OLD = "header.appendChild(menusDivider);"
A3_NEW = ("/* " + SENTINEL + " メニュー表示設定も見出し行の中ではなく、カードの下に置く */")

# ---------------------------------------------------------------- (4)
A4_OLD = "btnGroup.appendChild(delBtn);"
A4_NEW = ("/* " + SENTINEL + " 削除はほかのボタンと並べない。いちばん下に単独で置く */")

# ---------------------------------------------------------------- (5)(2)(3)(4) の置きなおし本体
A5_OLD = "card.appendChild(header);"
A5_NEW = """card.appendChild(header);
            /* """ + SENTINEL + """ ここから：かたまりごとに置きなおす。機能は消さない。 */
            try {
              var _tdEls = header.querySelectorAll('button, select, span, a');
              for (var _ti = 0; _ti < _tdEls.length; _ti++) {
                _tdEls[_ti].style.whiteSpace = 'nowrap';
                _tdEls[_ti].style.flexShrink = '0';
              }
              title.className = 'flex flex-wrap items-baseline gap-x-2 gap-y-1';
              title.style.flexShrink = '0';
            } catch (e) {}
            setTimeout(function () {
              try {
                var _fold = function (sumText, keyText, el) {
                  var h = el.querySelector('div');
                  if (h && h.textContent && h.textContent.indexOf(keyText) >= 0) { h.remove(); }
                  el.className = '';
                  var d = document.createElement('details');
                  d.className = 'mt-3 pt-3 border-t border-slate-200';
                  var s = document.createElement('summary');
                  s.className = 'text-xs font-bold text-slate-600 cursor-pointer select-none';
                  s.textContent = sumText;
                  d.appendChild(s);
                  d.appendChild(el);
                  return d;
                };
                card.appendChild(_fold('🎫 カフート券', 'カフート券', khtBox));
                card.appendChild(_fold('🗒 メニュー表示設定', 'メニュー表示設定', menusDivider));
                var _foot = document.createElement('div');
                _foot.className = 'mt-4 pt-3 border-t border-slate-200 flex justify-end';
                delBtn.style.whiteSpace = 'nowrap';
                delBtn.style.flexShrink = '0';
                _foot.appendChild(delBtn);
                card.appendChild(_foot);
              } catch (e) {}
            }, 0);
            /* """ + SENTINEL + """ ここまで */"""

# ---------------------------------------------------------------- (6)
A6_OLD = "khtBody.textContent = s;"
A6_NEW = """khtBody.innerHTML = ''; /* """ + SENTINEL + """ 4行の「｜」区切りをやめて2行にする */
            var _kl1 = document.createElement('div');
            _kl1.textContent = (d.enabled ? 'ショップに出ています' : 'ショップに出ていません')
              + '　・　' + d.paid + ' / ' + d.need + ' 人'
              + ((d.needRaw === null) ? '（クラス全員＝児童' + d.size + '人）' : '（先生が ' + d.need + ' 人に下げています）')
              + ((typeof d.daysLeft === 'number') ? '　・　のこり ' + d.daysLeft + '日で自動返金' : '');
            var _kl2 = document.createElement('div');
            _kl2.textContent = '値段　500円…' + d.tier500 + '人／1500円…' + d.tier1500 + '人／3000円…' + d.tier3000 + '人';
            khtBody.appendChild(_kl1);
            khtBody.appendChild(_kl2);"""

# ---------------------------------------------------------------- (7)
A7_OLD = "b.className = 'text-xs px-2 py-1 rounded font-bold border ' + cls;"
A7_NEW = (A7_OLD + " b.style.whiteSpace = 'nowrap'; b.style.flexShrink = '0';"
          " /* " + SENTINEL + " */")

# ---------------------------------------------------------------- (8) 浮きボタンの重なり
T1_OLD = "btn.className = 'fixed bottom-4 right-4 z-[9998]"
T1_NEW = ("/* " + SENTINEL + " 「ひとこと」ボタンと重なるので少し上げる */\n    "
          "btn.className = 'fixed bottom-20 right-4 z-[9998]")

# src/index.tsx で消えてはいけない目印
KEEP_SRC = [
    'function renderClasses',
    "header.className='flex items-center justify-between mb-3'",
    "delBtn.textContent='削除'",
    'を削除しますか？',
    'kht-banner',
    'kht-body',
    'kht-ctrl',
    'kht-pending',
    '習ったところまで',
    'メニュー表示設定',
    'ランキング参加中',
    '家庭学習ON',
    '連絡帳ON',
    'シール交換けんON',
    'プログラム せいげんなし',
    'まだの子をみる',
    'みんなにコインを返す',
    '学校の休みを足す',
    'カフートをやった（リセット）',
    'cannot_trade_special',
    'genElectric6',
    'registerMi(app)',
    'registerQrHunt(app)',
    'OCTGACHA_V1',
    '__WORLD_V3__',
    'WARMIX',
    '_hash',
]

KEEP_TPV = [
    'tspOpenBtn',
    'この子にいま届いているもの',
    'tspOverlay',
    '読み取り専用',
]


def die(msg):
    sys.stderr.write('FAIL: %s\n' % msg)
    sys.exit(1)


def chain_count(s):
    i = s.index(ROOT_ANCHOR)
    j = s.index(END_ANCHOR, i)
    return s[i:j].count('.replace(')


def want_chain():
    v = (os.environ.get('CHAIN_BEFORE') or '').strip()
    if not v.isdigit():
        die('CHAIN_BEFORE が数字で渡されていない: %r' % v)
    return int(v)


def main():
    expect_chain = want_chain()

    with open(SRC, encoding='utf-8', newline='') as fp:
        s = fp.read()
    with open(TPV, encoding='utf-8', newline='') as fp:
        t = fp.read()

    if SENTINEL in s and SENTINEL in t:
        print('SKIP: 番兵 %s があるので何もしない' % SENTINEL)
        return
    if SENTINEL in s or SENTINEL in t:
        die('番兵が片方のファイルにだけある（中途半端な状態）')

    # --- フェイルクローズ: 前提 -------------------------------------
    if '\r' in s:
        die('src/index.tsx に CR がある（LFのはず）')
    if '\r' in t:
        die('public/teacher-preview.js に CR がある（LFのはず）')

    n_chain = chain_count(s)
    if n_chain != expect_chain:
        die('チェーンが %d件（実測で渡された想定は %d件）' % (n_chain, expect_chain))

    pairs_src = [('(1)', A1_OLD), ('(2)', A2_OLD), ('(3)', A3_OLD), ('(4)', A4_OLD),
                 ('(5)', A5_OLD), ('(6)', A6_OLD), ('(7)', A7_OLD)]
    for name, a in pairs_src:
        n = s.count(a)
        if n != 1:
            die('%s の足場が %d件（想定 1件）: %r' % (name, n, a[:60]))

    if t.count(T1_OLD) != 1:
        die('(8) の足場が %d件（想定 1件）' % t.count(T1_OLD))
    if t.count('bottom-20') != 0:
        die('(8) すでに bottom-20 がある（想定外）')

    keep0 = {}
    for k in KEEP_SRC:
        n = s.count(k)
        if n < 1:
            die('src の目印が無い: %s' % k)
        keep0[k] = n
    keept0 = {}
    for k in KEEP_TPV:
        n = t.count(k)
        if n < 1:
            die('teacher-preview.js の目印が無い: %s' % k)
        keept0[k] = n

    n_script_src = s.count('<script')
    n_backtick = s.count('`')

    # --- 当てる -----------------------------------------------------
    s2 = s
    for name, old, new in [('(1)', A1_OLD, A1_NEW), ('(2)', A2_OLD, A2_NEW),
                           ('(3)', A3_OLD, A3_NEW), ('(4)', A4_OLD, A4_NEW),
                           ('(5)', A5_OLD, A5_NEW), ('(6)', A6_OLD, A6_NEW),
                           ('(7)', A7_OLD, A7_NEW)]:
        before = s2
        s2 = s2.replace(old, new, 1)
        if s2 == before:
            die('%s の置換に失敗した' % name)

    t2 = t.replace(T1_OLD, T1_NEW, 1)
    if t2 == t:
        die('(8) の置換に失敗した')

    # --- 当てたあとの確認 -------------------------------------------
    if s2.count(SENTINEL) != 8:
        die('src の番兵が %d件（想定 8件）' % s2.count(SENTINEL))
    if t2.count(SENTINEL) != 1:
        die('teacher-preview.js の番兵が %d件（想定 1件）' % t2.count(SENTINEL))

    if s2.count('`') != n_backtick:
        die('バッククォートの数が変わった（%d -> %d）' % (n_backtick, s2.count('`')))
    if '${' in A5_NEW or '${' in A6_NEW or '${' in A1_NEW or '${' in A7_NEW:
        die('入れた文に ${ が混ざっている（テンプレートリテラルの中なので禁止）')
    if s2.count('<script') != n_script_src:
        die('script タグの数が変わった')

    if s2.count('header.appendChild(khtBox);') != 0:
        die('(2) の古い行が残っている')
    if s2.count('header.appendChild(menusDivider);') != 0:
        die('(3) の古い行が残っている')
    if s2.count('btnGroup.appendChild(delBtn);') != 0:
        die('(4) の古い行が残っている')
    if s2.count('header.appendChild(btnGroup);') != 1:
        die('ボタンの箱を見出し行に付ける行が %d件（想定 1件）'
            % s2.count('header.appendChild(btnGroup);'))
    if s2.count("_foot.appendChild(delBtn);") != 1:
        die('削除を下に置く行が %d件（想定 1件）' % s2.count("_foot.appendChild(delBtn);"))
    if s2.count('flex flex-wrap items-center justify-end gap-2') != 1:
        die('(1) の本体が %d件（想定 1件）'
            % s2.count('flex flex-wrap items-center justify-end gap-2'))
    if s2.count("khtBody.appendChild(_kl2);") != 1:
        die('(6) の本体が %d件（想定 1件）' % s2.count("khtBody.appendChild(_kl2);"))

    if t2.count("fixed bottom-20 right-4 z-[9998]") != 1:
        die('(8) の本体が %d件（想定 1件）' % t2.count("fixed bottom-20 right-4 z-[9998]"))
    if t2.count('bottom-4') != 0:
        die('(8) 古い bottom-4 が %d件 残っている' % t2.count('bottom-4'))

    if chain_count(s2) != n_chain:
        die('チェーンが %d -> %d に変わった' % (n_chain, chain_count(s2)))

    # 目印は「減っていないこと」を見る。
    # (5) で '🗒 メニュー表示設定' という見出しを1つ足すので、増える目印はある。
    for k in KEEP_SRC:
        if s2.count(k) < keep0[k]:
            die('src の目印が減った: %s (%d -> %d)' % (k, keep0[k], s2.count(k)))
    for k in KEEP_TPV:
        if t2.count(k) < keept0[k]:
            die('teacher-preview.js の目印が減った: %s (%d -> %d)'
                % (k, keept0[k], t2.count(k)))

    if '\r' in s2 or '\r' in t2:
        die('CR が入った')

    with open(SRC, 'w', encoding='utf-8', newline='') as fp:
        fp.write(s2)
    with open(TPV, 'w', encoding='utf-8', newline='') as fp:
        fp.write(t2)

    print('OK: src %d -> %d / tpv %d -> %d / chain %d（据え置き）'
          % (len(s), len(s2), len(t), len(t2), n_chain))


if __name__ == '__main__':
    main()
