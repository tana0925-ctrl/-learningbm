#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MIしらべ v4 パッチ

  1. 結果のグラフをレーダーチャートに（8軸・各16点満点）
     - 外部ライブラリを増やさず SVG を自前描画
     - 目盛りは 4/8/12/16 の同心8角形。各頂点に領域名と「12/16」を残す
     - 塗りは1色。前回の記録があれば薄い破線で重ねる
     - 幅に応じて wide / narrow の2レイアウト。極端に狭いときは棒グラフにフォールバック
     - 棒グラフとの手動切り替えボタンも用意
  2. 「やってみたい 勉強の しかた」を結果画面に追加
     - 8領域×3個の工夫カタログ（児童向け／先生向けの2文言）
     - 上位3領域から2つずつ＋最下位領域から1つ を提案
     - 「あなたはこうしなさい」ではなく「こんなやり方も試せるよ」
     - 本人が1〜3個えらんで保存でき、次に受けたとき振り返れる（mi_picks）
  3. 先生の個人詳細に読み解きと手だてを追加
     - 「本人はこう感じている」「こういう手が合うかもしれない」という書き方
     - 本人が選んだ工夫も表示（声かけ・グループ編成の参考）

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

    if 'MI_TIPS' in load('src/mi.tsx'):
        print('  [skip] すでに適用済みです。')
        return

    bucket = {}
    for e in edits:
        bucket.setdefault(e['file'], []).append(e)
    results = {}
    for path, es in bucket.items():
        cur = load(path)
        for i, e in enumerate(es):
            key = e.get('anchor', e.get('old'))
            n = cur.count(key)
            if n != 1:
                sys.exit('FATAL: %s の編集 %d/%d のアンカーが %d 件（1件であるべき）。中止します。\n---\n%s\n---'
                         % (path, i + 1, len(es), n, key[:300]))
            if 'anchor' in e:
                cur = cur.replace(key, key + e['insert']) if e['where'] == 'after' else cur.replace(key, e['insert'] + key)
            else:
                cur = cur.replace(e['old'], e['new'])
        results[path] = cur
        print('  %s: %d 箇所を編集' % (path, len(es)))

    mi = results['src/mi.tsx']
    mijs = results['public/mi.js']
    tjs = results['public/teacher-mi.js']

    # ---- 確認1: 工夫カタログが8領域そろっているか ----
    keys = re.findall(r"key: '([a-z]+\d)'", mi)
    doms = re.findall(r"^  ([a-z]+): \[$", mi, re.M)
    if len(set(keys)) != len(keys):
        sys.exit('FATAL: 工夫のキーが重複しています。中止します。')
    if len(keys) < 16 or len(doms) < 8:
        sys.exit('FATAL: 工夫カタログが足りません（キー %d 個 / 領域 %d 個）。中止します。' % (len(keys), len(doms)))
    print('学び方の工夫カタログ: %d 領域 / %d 個' % (len(doms), len(keys)))

    # ---- 確認2: 断定・タイプ分けの言い回しが混ざっていないか ----
    ng = []
    for label, text in (('児童画面', mijs), ('先生画面', tjs)):
        for w in ('タイプです', '型です', 'あなたは視覚', 'に向いている', 'と決まります'):
            if w in text:
                ng.append('%s: %s' % (label, w))
        # 「しなさい」は否定形（「〜しなさい」では ありません）としてだけ許す
        pos = text.find('しなさい')
        while pos >= 0:
            if '」では ありません' not in text[pos:pos + 20]:
                ng.append('%s: しなさい（否定形ではない）' % label)
            pos = text.find('しなさい', pos + 1)
    if ng:
        sys.exit('FATAL: 断定的な言い回しが含まれています: %s' % ng)
    for need, label in (('こんな やり方も 試せるよ', '児童画面の提案文'),
                        ('まだ あまり やって いない だけ', '低い領域のフォロー文')):
        if need not in mijs:
            sys.exit('FATAL: %s が見つかりません。中止します。' % label)
    for need, label in (('かもしれません', '先生画面の非断定表現'),
                        ('決めつけず', '先生画面の注意書き')):
        if need not in tjs:
            sys.exit('FATAL: %s が見つかりません。中止します。' % label)
    print('言い回しの確認: タイプ分け・断定なし / 提案形になっている')

    # ---- 確認3: レーダーの要素 ----
    for need, label in (('RD_WIDE', '広い幅むけレイアウト'), ('RD_NARROW', '狭い幅むけレイアウト'),
                        ('function radarSvg', 'レーダー描画'), ("return 'bar'", '棒グラフへのフォールバック'),
                        ('stroke-dasharray', '前回の重ね描き'), ("'/' + MAX", '頂点の n/16 表示')):
        if need not in mijs:
            sys.exit('FATAL: レーダーの %s が見つかりません。中止します。' % label)
    if mijs.count('fill="#6366f1"') != 1:
        sys.exit('FATAL: レーダーの塗りが1色ではありません。中止します。')
    print('レーダー: 2レイアウト＋棒グラフへのフォールバック / 塗りは1色 / 前回の重ね描きあり')

    # ---- 確認4: 回答時のスクロール維持（v3の修正）が壊れていないか ----
    i = mijs.index('function bindOpts(')
    seg = mijs[i:mijs.index('function renderQuestions(', i)]
    if 'renderQuestions()' in seg:
        sys.exit('FATAL: 回答時に全体再描画が復活しています。中止します。')
    if len(re.findall(r'window\.scrollTo\(0, 0\)', mijs)) != 4:
        sys.exit('FATAL: scrollTo の箇所が想定と違います。中止します。')
    print('スクロール維持（v3の修正）: 健在')

    # ---- 確認5: 特典まわり（v3）が壊れていないか ----
    for need in ('MI_REWARD_COINS = 1000', 'PRIMARY KEY (user_id, month_key)', 'miGrantMonthlyReward', '_miCoinsApplied'):
        if need not in mi:
            sys.exit('FATAL: 特典まわりの %s が失われています。中止します。' % need)
    if 'PRIMARY KEY (user_id, result_id)' not in mi:
        sys.exit('FATAL: mi_picks の主キーがありません。中止します。')
    print('特典まわり（v3）: 健在 / mi_picks は (user_id, result_id) で一意')

    # ---- 確認6: 選択の保存はサーバーが検証しているか ----
    i = mi.index("app.put('/api/mi/picks'")
    seg = mi[i:mi.index('  })', i)]
    for need, label in ('miSanitizePicks', 'カタログ照合'), ('SELECT 1 as ok FROM mi_results WHERE id=? AND user_id=?', '本人確認'):
        if need not in seg:
            sys.exit('FATAL: picks 保存の %s がありません。中止します。' % label)
    print('やってみたいことの保存: 本人確認＋カタログ照合あり')

    for path, text in results.items():
        with io.open(path, 'w', encoding='utf-8', newline='') as f:
            f.write(text)

    if load(TSX) != before_tsx:
        sys.exit('FATAL: src/index.tsx が変更されました。中止します。')
    if load(HTML) != before_html:
        sys.exit('FATAL: public/index.html が変更されました。中止します。')
    print('src/index.tsx と public/index.html: 変更なし')
    print('✅ レーダーチャート / 学び方の工夫 / 先生の読み解き を適用しました。')


if __name__ == '__main__':
    main()
