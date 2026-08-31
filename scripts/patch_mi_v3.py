#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MIしらべ v3 パッチ（先生の指示3件）

  1. 特典コインの金額を 100 → 1000 に変更
     金額は src/mi.tsx の MI_REWARD_COINS 1か所だけが真実の源。
     画面の文言はすべてサーバーが返した値を表示しており、直書きはゼロ。
  2. 回答のたびに画面が先頭に戻る不具合の修正（実機報告）
     原因: 回答ハンドラが renderQuestions() を呼び、app.innerHTML の総入れ替えと
           window.scrollTo(0,0) が毎回走っていた。
     修正: 回答時は「触った問題の選択肢」と「進み具合」だけを描き直す部分更新にする。
           先頭に戻すのはページを送った/戻したときだけ（意図した動きなので残す）。
  3. 先生用に「特典コインの受け取り状況」を追加（読み取り専用）
     mi_rewards.coins に受け取り時点の金額が残るので、金額変更の前後で
     誰がいくら受け取ったかを先生が確認できる。この画面から配ることはできない。

対象ファイル: src/mi.tsx / public/mi.js / public/teacher-mi.js
public/index.html と src/index.tsx はどちらも変更しない（.replace() チェーンにも触れない）。
"""
import base64
import gzip
import io
import json
import re
import sys

EDITS_B64 = "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"

TSX = 'src/index.tsx'
HTML = 'public/index.html'
ROOT_BLOCK_RE = re.compile(r"app\.get\('/', async \(c\) => \{.*?_rootHtmlCache = t", re.S)
EXPECT_COINS = 1000


def load(p):
    with io.open(p, encoding='utf-8', newline='') as f:
        return f.read()


def main():
    edits = json.loads(gzip.decompress(base64.b64decode(EDITS_B64)).decode('utf-8'))

    before_tsx = load(TSX)
    before_html = load(HTML)
    m = ROOT_BLOCK_RE.search(before_tsx)
    if not m:
        sys.exit("FATAL: app.get('/') のブロックが見つかりません。中止します。")
    print("app.get('/') 内の .replace( = %d 件（このパッチでは触らない）" % m.group(0).count('.replace('))

    if 'MI_REWARD_COINS = %d' % EXPECT_COINS in load('src/mi.tsx'):
        print('  [skip] すでに適用済みです。')
        return

    bucket = {}
    for e in edits:
        bucket.setdefault(e['file'], []).append(e)
    results = {}
    for path, es in bucket.items():
        cur = load(path)
        for i, e in enumerate(es):
            n = cur.count(e['old'])
            if n != 1:
                sys.exit('FATAL: %s の編集 %d/%d のアンカーが %d 件（1件であるべき）。中止します。\n---\n%s\n---'
                         % (path, i + 1, len(es), n, e['old'][:300]))
            cur = cur.replace(e['old'], e['new'])
        results[path] = cur
        print('  %s: %d 箇所を編集' % (path, len(es)))

    mi = results['src/mi.tsx']
    mijs = results['public/mi.js']

    # ---- 確認1: 金額の定義が1か所だけ・想定どおりか ----
    defs = re.findall(r'^export const MI_REWARD_COINS = (\d+)$', mi, re.M)
    if defs != [str(EXPECT_COINS)]:
        sys.exit('FATAL: MI_REWARD_COINS の定義が %s。中止します。' % defs)
    print('MI_REWARD_COINS = %s（定義は1か所だけ）' % defs[0])

    # ---- 確認2: 金額を画面文言に直書きしていないか ----
    bad = []
    for path, text in list(results.items()):
        for mm in re.finditer(r'(\d+)\s*コイン', text):
            bad.append('%s: %s' % (path, mm.group(0)))
    if bad:
        sys.exit('FATAL: 金額を直書きしている箇所があります: %s' % bad)
    print('画面文言への金額の直書き: 0 件')

    # ---- 確認3: 月1回の制約と二重付与防止が健在か ----
    for label, key in [('mi_rewards の PRIMARY KEY', 'PRIMARY KEY (user_id, month_key)'),
                       ('JSTの月キー', 'miJstMonthKey'),
                       ('サーバー側の付与処理', 'miGrantMonthlyReward'),
                       ('枠の先取り確保', 'INSERT INTO mi_rewards'),
                       ('失敗時の枠の解放', 'DELETE FROM mi_rewards WHERE user_id=? AND month_key=?'),
                       ('progress への加算台帳', '_miCoinsApplied')]:
        if key not in mi:
            sys.exit('FATAL: %s が見つかりません。中止します。' % label)
    print('月1回の制約・二重付与防止: すべて健在')

    # ---- 確認4: スクロール修正 ----
    #      回答ハンドラの中から renderQuestions() の呼び出しが消え、部分更新になっていること。
    i = mijs.index('function bindOpts(')
    seg = mijs[i:mijs.index('function renderQuestions(', i)]
    if 'renderQuestions()' in seg:
        sys.exit('FATAL: 回答時にまだ全体再描画をしています。中止します。')
    for key in ('optsHtml(qi)', 'paintProgress()'):
        if key not in seg:
            sys.exit('FATAL: 部分更新の処理(%s)が見つかりません。中止します。' % key)
    n_scroll = len(re.findall(r'window\.scrollTo\(0, 0\)', mijs))
    if n_scroll != 4:
        sys.exit('FATAL: scrollTo の箇所が %d 件（ページ送り/やめる/結果/最初の画面へ の4件であるべき）。中止します。' % n_scroll)
    print('スクロール修正: 回答時は部分更新・scrollTo は画面切替の4か所のみ')

    # ---- 確認5: 先生用の受け取り状況が読み取り専用か ----
    i = mi.index("app.get('/api/teacher/mi/class/:classId/rewards'")
    seg = mi[i:mi.index('})', mi.index('return c.json', i))]
    for kw in ('INSERT', 'UPDATE', 'DELETE', 'DROP'):
        if kw in seg.upper():
            sys.exit('FATAL: 先生用の受け取り状況に書き込みSQL(%s)。中止します。' % kw)
    print('先生用の受け取り状況: 読み取り専用')

    for path, text in results.items():
        with io.open(path, 'w', encoding='utf-8', newline='') as f:
            f.write(text)

    if load(TSX) != before_tsx:
        sys.exit('FATAL: src/index.tsx が変更されました。中止します。')
    if load(HTML) != before_html:
        sys.exit('FATAL: public/index.html が変更されました。中止します。')
    print('src/index.tsx と public/index.html: 変更なし')
    print('✅ 特典 %d コイン / スクロール修正 / 先生用の受け取り状況 を適用しました。' % EXPECT_COINS)


if __name__ == '__main__':
    main()
