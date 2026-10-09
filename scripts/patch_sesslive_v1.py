#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# SESSLIVE_V1 : セッションを使うたびに延ばす ＋ 403のときの文言を直す
#
# 《なぜ》
#   2026-10-08、犬飼翔太さん（NGY）が家庭学習を出せなかった。
#   10-07 22:36 を最後に、10-08 は提出だけでなく「認証が要る書き込み」が
#   1件も無く（learning_results / photo_bonus_rewards いずれもゼロ）、
#   10-09 08:48 にログインし直した跡だけが残っていた。
#   セッションは署名Cookieだけで、30日たつと切れる。延長されない。
#   タブを開いたままの iPad だと、切れた瞬間から API が 403 になる。
#   そのとき子どもに出るのは「ネットワークエラー」だけで、原因が分からない。
#
# 《直すこと》
#   (1) src/index.tsx の認証ミドルウェアで、発行から1日以上たっていたら
#       同じ中身・同じ秘密鍵で Cookie を打ち直す（スライド式）。
#       → 使っている子は切れなくなる。
#   (2) public/index.html の hsSubmitAndExport の catch で、403 のときだけ
#       「もう一度ログインしてね」と出し、ログイン画面へ送る。
#       → 子どもが自分で直せる。
#
# 《絶対に変えないこと》
#   ・makeSession / readSession / SESSION_SECRET の署名の仕組み
#     （ここを変えると全員がログアウトされる）
#   ・SESSION_MAX_AGE の 30日という値そのもの
#   ・cookie の属性（httpOnly / secure / sameSite / path / maxAge）
#     ログイン時 (554〜560行) と同じものをそのまま使う。
#   ・配信チェーン（app.get('/') と app.get('/logout') のあいだの .replace( の数）
#     足場に触らない。数が変わったら書かずに止まる。
#   ・D1 には一切触らない。
#
# 前提が1つでも崩れたら、ファイルに書かずに exit 1（フェイルクローズ）。

import os
import re
import sys

HTML = 'public/index.html'
SRC = 'src/index.tsx'

SENTINEL = '__SESSLIVE_V1__'

ROOT_ANCHOR = "app.get('/'"
END_ANCHOR = "app.get('/logout'"

# ── (1) サーバ：ミドルウェアで Cookie を打ち直す ───────────────────────────
SRV_OLD = """  c.set('user', {
    id: sess.id,
    role: sess.role,
    loginId: sess.loginId,
    isActive: !!sess.isActive,
  })

  return next()
})"""

SRV_NEW = """  c.set('user', {
    id: sess.id,
    role: sess.role,
    loginId: sess.loginId,
    isActive: !!sess.isActive,
  })

  /* """ + SENTINEL + """ 使っているあいだはセッションを延ばす（スライド式）。
     署名のしかたも秘密鍵も Cookie の属性も、ログイン時とまったく同じ。
     打ち直しに失敗しても、いまの Cookie はそのまま残す（何もしないだけ）。
     1日に1回しか打ち直さないので、Set-Cookie が毎回つくことはない。 */
  try {
    const _ageSec = sess.iat ? (Math.floor(Date.now() / 1000) - sess.iat) : null
    if (_ageSec !== null && _ageSec > 24 * 60 * 60) {
      const _fresh = await makeSession(secret, {
        id: sess.id,
        role: sess.role,
        loginId: sess.loginId,
        isActive: !!sess.isActive,
        iat: Math.floor(Date.now() / 1000),
      })
      if (_fresh) {
        setCookie(c, 'session', _fresh, {
          httpOnly: true,
          secure: true,
          sameSite: 'Lax',
          path: '/',
          maxAge: 60 * 60 * 24 * 30,
        })
      }
    }
  } catch (e) { /* 延ばせなくても、いまのセッションは生きたまま */ }

  return next()
})"""

# ── (2) 児童画面：403 のときだけ文言を変えてログインへ送る ─────────────────
CLI_OLD = (
    "      console.warn('[homework] DB submit failed:', e);\n"
    "      alert('⚠️ ネットワークエラーで"
    "提出できませんでした。\\n"
    "時間をおいて再提出してください。');"
)

CLI_NEW = (
    "      console.warn('[homework] DB submit failed:', e);\n"
    "      /* " + SENTINEL + " 403（ログインが切れている）"
    "と、それ以外の通信失敗を分ける。\n"
    "         403 のときは子どもが自分で直せる"
    "よう、ログイン画面へ送る。 */\n"
    "      if (e && e.status === 403) {\n"
    "        alert('⚠️ ログインの有効期限が"
    "切れていました。\\nもう一度 ログイン"
    "してね。\\n書いたことは消えていま"
    "せん。');\n"
    "        try { location.href = '/login'; } catch (_e) {}\n"
    "        if (btn) { btn.disabled = false; btn.textContent = '\U0001f4e4 先生に提出'; }\n"
    "        return;\n"
    "      }\n"
    "      alert('⚠️ ネットワークエラーで"
    "提出できませんでした。\\n"
    "時間をおいて再提出してください。');"
)


def die(msg):
    print('::error::' + msg)
    sys.exit(1)


def chain_count(src):
    a = src.find(ROOT_ANCHOR)
    b = src.find(END_ANCHOR)
    if a < 0 or b < 0 or b <= a:
        die('配信チェーンの足場（app.get(\'/\') / app.get(\'/logout\')）が見つかりません。')
    return len(re.findall(r'\.replace\(', src[a:b]))


def main():
    for f in (HTML, SRC):
        if not os.path.exists(f):
            die(f + ' がありません。')

    src = open(SRC, encoding='utf-8').read()
    html = open(HTML, encoding='utf-8').read()

    # 鎖を数える。渡された数と合わなければ、1バイトも書かずに止まる。
    chain = chain_count(src)
    want = os.environ.get('CHAIN_BEFORE', '')
    print('チェーン件数: %d' % chain)
    if not want:
        die('CHAIN_BEFORE が渡されていません。')
    if str(chain) != str(want).strip():
        die('チェーン件数が %d で、渡された %s と合いません。中止します。' % (chain, want))

    # 冪等：2回目は何もしない
    done_src = SENTINEL in src
    done_html = SENTINEL in html
    if done_src and done_html:
        print('すでに当たっています。何もしません。')
        # 当たっているときも、鎖が動いていないことだけ見ておく
        if chain_count(src) != chain:
            die('チェーン件数が動きました。')
        return

    if done_src != done_html:
        die('片側だけ当たっています（src=%s html=%s）。手で確かめてください。' % (done_src, done_html))

    # ── 足場の実測 ───────────────────────────────────────────────
    if src.count(SRV_OLD) != 1:
        die('src/index.tsx の足場（認証ミドルウェアの c.set(\'user\')）が %d 件です（1件のはず）。'
            % src.count(SRV_OLD))
    if html.count(CLI_OLD) != 1:
        die('public/index.html の足場（提出失敗の alert）が %d 件です（1件のはず）。'
            % html.count(CLI_OLD))
    # 足場が配信チェーンの中にいないこと（足場を崩さないため）
    a, b = src.find(ROOT_ANCHOR), src.find(END_ANCHOR)
    if a < src.find(SRV_OLD) < b:
        die('src の足場が配信チェーンの中にあります。中止します。')
    if CLI_OLD in src:
        die('児童画面の足場が src/index.tsx にもあります（配信チェーンの足場かもしれません）。中止します。')
    # makeSession / setCookie が使える場所であること
    if 'async function makeSession' not in src:
        die('makeSession が見つかりません。')
    if "import { getCookie, setCookie, deleteCookie } from 'hono/cookie'" not in src:
        die('setCookie の import が見つかりません。')
    # 署名の仕組みには触っていないことを、あとで差分で確かめるために控える
    before_make = src[src.find('async function makeSession'):src.find('async function makeSession') + 600]

    # ── 当てる ───────────────────────────────────────────────────
    src2 = src.replace(SRV_OLD, SRV_NEW, 1)
    html2 = html.replace(CLI_OLD, CLI_NEW, 1)

    if src2 == src or html2 == html:
        die('置きかえが起きませんでした。')

    # 鎖が動いていないこと
    if chain_count(src2) != chain:
        die('当てたあとでチェーン件数が %d -> %d に動きました。中止します。'
            % (chain, chain_count(src2)))
    # 署名の仕組みが動いていないこと
    if src2[src2.find('async function makeSession'):src2.find('async function makeSession') + 600] != before_make:
        die('makeSession が変わっています。中止します。')
    if src2.count('const SESSION_MAX_AGE = 30 * 24 * 60 * 60') != 1:
        die('SESSION_MAX_AGE の行が変わっています。中止します。')
    # 番兵が1つずつ入ったこと
    if src2.count(SENTINEL) != 1 or html2.count(SENTINEL) != 1:
        die('番兵の数がおかしいです（src=%d html=%d）。'
            % (src2.count(SENTINEL), html2.count(SENTINEL)))

    open(SRC, 'w', encoding='utf-8', newline='').write(src2)
    open(HTML, 'w', encoding='utf-8', newline='').write(html2)
    print('当てました。src %d -> %d バイト / html %d -> %d バイト'
          % (len(src), len(src2), len(html), len(html2)))
    print('チェーン件数は %d のまま。' % chain)


if __name__ == '__main__':
    main()
