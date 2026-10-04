# -*- coding: utf-8 -*-
"""TSPAUSE_V1  ほかのアプリを見て もどると ことばが ドサッと 降ってくる のを 直す

症状:
  タイプシュートの とちゅうで ほかの アプリや べつの タブを 見て もどると、
  見ていない あいだに 出るはずだった ことばが まとめて 落ちてくる。

なぜ:
  えが うごく しくみ（requestAnimationFrame）は 画面を 見ていない あいだ 止まる。
  ところが「ことばを 出す」タイマー（setInterval）は 止まらない。
  だから ことばだけ たまっていく。

直しかた:
  ことばを 出す ところで、画面を 見ていない あいだは 何も 出さない。
      if (document.hidden) return;
  タイマーを 止めたり つけ直したり しないので、こわれにくい。

  ※ ともだち対戦は さわらない。あいては あそび つづけているので、
    こちらで 止めると つじつまが 合わなくなる。

さわるのは 2つだけ:
  public/typeshoot.js … ことばを 出す ところに 1行 足す
  src/index.tsx       … よみこみ番号 /typeshoot.js?v=2 -> ?v=3

チェーン: 159 -> 159（ふえも へりも しない）
めじるしが きっちり 1件 見つからなければ、ファイルには 1文字も 書かずに 止まる。
"""

import io
import sys

S = 'src/index.tsx'
T = 'public/typeshoot.js'

MARK = 'TSPAUSE_V1'

CHAIN_BEFORE = 159
CHAIN_AFTER = 159

CPU_OLD = (
    "function cpuFire() { if (!S.open || S.ended || !S.ready) return; "
    "spawnEnemyWord(); rotateEnemy(); }"
)
CPU_NEW = (
    "function cpuFire() { if (!S.open || S.ended || !S.ready) return; "
    "if (document.hidden) return; "
    "/* TSPAUSE_V1 ほかの アプリを 見ている あいだは ことばを 出さない"
    "（もどった ときに ドサッと 降ってこないように） */ "
    "spawnEnemyWord(); rotateEnemy(); }"
)

VER_OLD = '/typeshoot.js?v=2'
VER_NEW = '/typeshoot.js?v=3'


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

    if MARK in t and VER_NEW in s:
        print('すでに 入っています。なにも しません。')
        return 0
    if (MARK in t) != (VER_NEW in s):
        print('NG: かたほうだけ 入っています（typeshoot.js=%s index.tsx=%s）。手で 見てください。'
              % (MARK in t, VER_NEW in s))
        return 1

    ok = True
    ok = need_one('ことばを 出す ところ', CPU_OLD, t) and ok
    ok = need_one('よみこみ番号 v2', VER_OLD, s) and ok

    # 第1便（TSKEY_V1）が 入っている ことが 前提
    if t.count('TSKEY_V1') != 3:
        print('NG: 第1便（TSKEY_V1）が typeshoot.js に %d 件（3件の はず）。先に 第1便を 流してください。'
              % t.count('TSKEY_V1'))
        ok = False
    if s.count('TSKEY_V1') != 3:
        print('NG: 第1便（TSKEY_V1）が index.tsx に %d 件（3件の はず）' % s.count('TSKEY_V1'))
        ok = False

    chain = chain_of(s)
    if chain != CHAIN_BEFORE:
        print('NG: チェーンが %d 件（流す前は %d 件の はず）。ほかの便と ぶつかっています。'
              % (chain, CHAIN_BEFORE))
        ok = False

    if not ok:
        print('中止しました。ファイルには 1文字も 書いていません。')
        return 1

    t2 = t.replace(CPU_OLD, CPU_NEW, 1)
    s2 = s.replace(VER_OLD, VER_NEW, 1)

    if t2 == t or s2 == s:
        print('NG: なにも かわりませんでした'); return 1
    if CPU_OLD in t2:
        print('NG: 古い ことばを 出す ところが まだ のこっています'); return 1
    if t2.count(MARK) != 1:
        print('NG: typeshoot.js の 番兵が %d 件（1件の はず）' % t2.count(MARK)); return 1
    if s2.count(VER_NEW) != 1 or s2.count(VER_OLD) != 0:
        print('NG: よみこみ番号の 書きかえが おかしい（v3=%d v2=%d）'
              % (s2.count(VER_NEW), s2.count(VER_OLD))); return 1

    chain2 = chain_of(s2)
    if chain2 != CHAIN_AFTER:
        print('NG: 流したあとの チェーンが %d 件（%d の はず）' % (chain2, CHAIN_AFTER))
        return 1

    io.open(S, 'w', encoding='utf-8', newline='').write(s2)
    io.open(T, 'w', encoding='utf-8', newline='').write(t2)
    print('OK: 入れました。チェーン %d -> %d' % (chain, chain2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
