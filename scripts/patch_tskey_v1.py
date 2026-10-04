# -*- coding: utf-8 -*-
"""TSKEY_V1  タイプシュートで スペースが きかない のを 直す

先生のことば:
  「タイプシュート。やはり攻撃と防御の切り替わりがスペースでできなかった」
  「タイプシュートバグってるという噂もある」

しらべて わかったこと（ブラウザで 実測）:
  タマゴ2人対戦（index.tsx の EGG2P_JS）が、キーを うけとる ところで
      ev.stopPropagation()
  を よんでいた。これは「スペース・e・f・矢印キーを ほかの だれにも わたさない」
  という いみ。しかも この うけとり口は window に capture で ついていて、
  「やめる」を おさずに おわった ときなどに ページに のこる。

  のこったまま タイプシュートを はじめると こうなる:
      スペース … とどかない → こうげき⇄ぼうぎょが きりかわらない
      e と f   … とどかない → 「ねこ」「えいご」「ふじさん」が 打てない
  キーを 1つずつ 送って かぞえた 実測:
      a○ b○ e× f× n○ o○ スペース× 矢印× k○

  タイプシュート側を いくら 直しても、キーが そこまで とどいていなかった。
  まえの なおし（ともだち対戦の 見えない入力欄）が きかなかったのは このため。

  もう1つ、タイプシュート側にも 本物の バグが ある:
      こうげき⇄ぼうぎょを かえても「打ちかけの 文字」が 消えない。
      のこった 打ちかけは どの ことばにも あてはまらないので、
      そのあと 何を 打っても 画面が うごかなくなる。
      （Backspace を 何回か おせば 直るが、子どもは それを 知らない）

直すこと:
  1) src/index.tsx の EGG2P_JS
       ev.stopPropagation() を やめる（ev.preventDefault() は のこす。
       これが ないと ページが スクロールしてしまう）
       おわった あと（alive=false）は なにも しない ガードを つける
       → タマゴ対戦の あそびかたは 1つも かわらない
  2) public/typeshoot.js
       こうげき⇄ぼうぎょを きりかえた ときに 打ちかけの 文字を 消す
       ぼうぎょで あてはまらない 文字を 打ったら 打ちかけを 消す
          （ともだち対戦は もともと こう なっている。同じに そろえる）
       「もういちど」に 🎫1まい と 書く（おすと チケットが 1まい へるため）
  3) よみこみ番号（古いものが のこらないように）
       /egg2p.js?v=1  ->  ?v=2
       /typeshoot.js  ->  /typeshoot.js?v=2
       （typeshoot の タグは public/index.html に ある。
         public/index.html は 手で 書きかえず、index.tsx に さしかえを 1つ 足す）

さわるのは 2つだけ:
  src/index.tsx
  public/typeshoot.js
public/index.html には 1文字も 書かない。
めじるしが きっちり 1件 見つからなければ、ファイルには 1文字も 書かずに 止まる。

チェーン: 158 -> 159（typeshoot の よみこみ番号の さしかえを 1つ 足すため）
"""

import io
import sys

S = 'src/index.tsx'
T = 'public/typeshoot.js'

MARK = 'TSKEY_V1'

CHAIN_BEFORE = 158
CHAIN_AFTER = 159

# ---------------------------------------------------------------- src/index.tsx
# (1) タマゴ対戦の キーの うけとり口
ONKD_OLD = (
    "function onKd(ev){ var k=ev.key; "
    "if(k===' '||k==='f'||k==='F'||k==='e'||k==='E'||k.indexOf('Arrow')===0)"
    "{ keys[k]=true; ev.preventDefault(); ev.stopPropagation(); } }"
)
ONKD_NEW = (
    "function onKd(ev){ "
    "/* TSKEY_V1 おわった あとは なにも しない。stopPropagation は しない"
    " （すると タイプシュートに スペース・e・f が とどかなくなる）。 */ "
    "if(!alive) return; var k=ev.key; if(!k) return; "
    "if(k===' '||k==='f'||k==='F'||k==='e'||k==='E'||k.indexOf('Arrow')===0)"
    "{ keys[k]=true; ev.preventDefault(); } }"
)

ONKU_OLD = "function onKu(ev){ keys[ev.key]=false; }"
ONKU_NEW = "function onKu(ev){ if(!alive) return; /* TSKEY_V1 */ keys[ev.key]=false; }"

# (2) よみこみ番号
EGG_V_OLD = '/egg2p.js?v=1'
EGG_V_NEW = '/egg2p.js?v=2'

VER_ANCHOR = "t = t.replace('</body>', '<script src=\"/egg2p.js"
VER_ADD = (
    "t = t.replace('<script src=\"/typeshoot.js\"></script>', "
    "'<script src=\"/typeshoot.js?v=2\"></script>'); /* TSKEY_V1_VER */ "
)

# ------------------------------------------------------------ public/typeshoot.js
TS_SET_OLD = "function setMode(m) {\n    S.mode = m;\n"
TS_SET_NEW = (
    "function setMode(m) {\n    S.mode = m;\n"
    "    S.typed = ''; renderTyped(); "
    "/* TSKEY_V1 こうげき⇄ぼうぎょを かえたら 打ちかけの 文字を 消す */\n"
)

TS_VSET_OLD = "function vSetMode(m) {\n    V.mode = m;\n"
TS_VSET_NEW = (
    "function vSetMode(m) {\n    V.mode = m;\n"
    "    V.typed = ''; vRenderTyped(); /* TSKEY_V1 */\n"
)

TS_DEF_OLD = (
    "          S.combo = 0; if (el('tsCombo')) el('tsCombo').textContent = '';\n"
    "          var tw2 = el('tsTyped');"
)
TS_DEF_NEW = (
    "          S.combo = 0; if (el('tsCombo')) el('tsCombo').textContent = '';\n"
    "          S.typed = ''; renderTyped(); "
    "/* TSKEY_V1 あてはまらない ときは 打ちかけを 消す（ともだち対戦と 同じ） */\n"
    "          var tw2 = el('tsTyped');"
)

TS_RETRY_OLD = ">もういちど</button>"
TS_RETRY_NEW = ">もういちど（🎫1まい）</button>"


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
    t = io.open(T, encoding='utf-8', newline='').read()

    # 冪等性（もう 流したか）
    done_s = MARK in s
    done_t = MARK in t
    if done_s and done_t:
        print('すでに 入っています。なにも しません。')
        return 0
    if done_s != done_t:
        print('NG: かたほうだけ 入っています（index.tsx=%s typeshoot.js=%s）。手で 見てください。'
              % (done_s, done_t))
        return 1

    ok = True
    ok = need_one('タマゴ対戦の キーうけとり口', ONKD_OLD, s) and ok
    ok = need_one('タマゴ対戦の キーはなし口', ONKU_OLD, s) and ok
    ok = need_one('タマゴ対戦の よみこみ番号 v1', EGG_V_OLD, s) and ok
    ok = need_one('さしこみ場所（script タグの ならび）', VER_ANCHOR, s) and ok

    ok = need_one('こうげき⇄ぼうぎょの きりかえ', TS_SET_OLD, t) and ok
    ok = need_one('ともだち対戦の きりかえ', TS_VSET_OLD, t) and ok
    ok = need_one('ぼうぎょで あてはまらない とき', TS_DEF_OLD, t) and ok
    ok = need_one('もういちど ボタン', TS_RETRY_OLD, t) and ok

    if s.count(EGG_V_NEW) != 0:
        print('NG: /egg2p.js?v=2 が もう あります'); ok = False
    if s.count('/typeshoot.js?v=') != 0:
        print('NG: /typeshoot.js の よみこみ番号が もう あります'); ok = False

    chain = chain_of(s)
    if chain != CHAIN_BEFORE:
        print('NG: チェーンが %d 件（流す前は %d 件の はず）。ほかの便と ぶつかっています。'
              % (chain, CHAIN_BEFORE))
        ok = False

    if not ok:
        print('中止しました。ファイルには 1文字も 書いていません。')
        return 1

    s2 = s.replace(ONKD_OLD, ONKD_NEW, 1)
    s2 = s2.replace(ONKU_OLD, ONKU_NEW, 1)
    s2 = s2.replace(EGG_V_OLD, EGG_V_NEW, 1)
    s2 = s2.replace(VER_ANCHOR, VER_ADD + VER_ANCHOR, 1)

    t2 = t.replace(TS_SET_OLD, TS_SET_NEW, 1)
    t2 = t2.replace(TS_VSET_OLD, TS_VSET_NEW, 1)
    t2 = t2.replace(TS_DEF_OLD, TS_DEF_NEW, 1)
    t2 = t2.replace(TS_RETRY_OLD, TS_RETRY_NEW, 1)

    # --- 流したあとの たしかめ（1つでも だめなら 書かない） ---
    if s2 == s or t2 == t:
        print('NG: なにも かわりませんでした'); return 1
    if ONKD_OLD in s2:
        print('NG: 古い うけとり口（stopPropagation つき）が まだ のこっています'); return 1
    if ONKU_OLD in s2:
        print('NG: 古い キーはなし口が まだ のこっています'); return 1
    if s2.count('/egg2p.js?v=2') != 1:
        print('NG: タマゴの よみこみ番号が %d 件' % s2.count('/egg2p.js?v=2')); return 1
    if s2.count('/typeshoot.js?v=2') != 1:
        print('NG: タイプシュートの よみこみ番号が %d 件' % s2.count('/typeshoot.js?v=2')); return 1
    if s2.count(MARK) != 3:
        print('NG: index.tsx の 番兵が %d 件（3件の はず）' % s2.count(MARK)); return 1
    if t2.count(MARK) != 3:
        print('NG: typeshoot.js の 番兵が %d 件（3件の はず）' % t2.count(MARK)); return 1
    if t2.count(TS_RETRY_NEW) != 1:
        print('NG: もういちど ボタンの 書きかえが %d 件' % t2.count(TS_RETRY_NEW)); return 1

    chain2 = chain_of(s2)
    if chain2 != CHAIN_AFTER:
        print('NG: 流したあとの チェーンが %d 件（%d + 1 = %d の はず）'
              % (chain2, CHAIN_BEFORE, CHAIN_AFTER))
        return 1

    io.open(S, 'w', encoding='utf-8', newline='').write(s2)
    io.open(T, 'w', encoding='utf-8', newline='').write(t2)
    print('OK: 入れました。チェーン %d -> %d' % (chain, chain2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
