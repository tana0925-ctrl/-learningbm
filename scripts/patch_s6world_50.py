# scripts/patch_s6world_50.py
# 小6社会「世界の国々」を 7問 → 50問 に作り直す。
#
# なぜここからか:
#   D1 の記録では、この単元だけで 33,093 回解かれている（6年生の全解答の22%）。
#   ところが問題は 7 パターンしかなく、正答率 99.7%。1問あたり約4,700回。
#   さらに測ると「正解がいちばん長い選択肢」である割合が 86% で、
#   内容を知らなくても長いものを選べば当たる状態だった。
#
# もとの7問の問題点:
#   1. すべて国際機関（国連・ユネスコ・SDGs・ODA）の話で、
#      単元の前半にあたる「我が国とつながりが深い国の人々の生活」が1問も無かった。
#   2. 誤答が「戦争を推進すること」「北極圏」「一つの国が支配する」のように
#      明らかに答えでないものばかりで、消去法で解けた。
#   3. 「日本の貿易の相手国として最も多いのは？」は年によって変わる。→ 削除した。
#
# 扱う範囲（この範囲の外は出さない）:
#   小6社会(3)「グローバル化する世界と日本の役割」
#     ア(ア) 我が国と経済や文化などの面でつながりが深い国の人々の生活
#     ア(イ) 国際連合の働きと我が国の国際協力
#   取り上げる国: アメリカ・中国・韓国・ブラジル・サウジアラビア
#
# 内訳: 米6 / 中6 / 韓5 / ブラジル5 / サウジ5 / 国連10 / 国際協力7 / 世界の姿6
#
# 問題の作り方の方針:
#   - 誤答は同じ分野の実在する語から作る（国連機関には別の国連機関を、
#     首都には別の都市を置く）
#   - 正解だけが長くならないよう、1問ごとに長さをそろえた
#   - カッコは使わない（_pickBank が表示時にカッコを除去するため、
#     除去後に2つの選択肢が同じ文字列になる事故を防ぐ）
#   - 数値・統計・順位は原則作らない。数値を含むのは「SDGsは17の目標」の1問だけ
#
# 検証（sentinel と検証条件は分けてある）:
#   - sentinel(__S6WORLD_50__) は「src/index.tsx に入れたか」の冪等判定にだけ使う
#   - 正しさの判定は目印を見ない。チェーンを走らせて genWorld6 を取り出し、
#     60000回生成して基準を数える（下の verify_world6）
#   - アンカーは変換後のHTML内で1個であること
#   - .replace() チェーン 適用前49 / 適用後50
#   - 非破壊検証（挿入した分を取り除くと元ファイルと完全一致）
import sys, json, hashlib

SRC = 'src/index.tsx'
HTML = 'public/index.html'

SENTINEL = '__S6WORLD_50__'
CHAIN_BEFORE = 49
CHAIN_AFTER = 50
TAIL_ANCHOR = '      _rootHtmlCache = t'

ANCHOR = "function genWorld6(){return _pickBank(_SS.world6);}"

# 時事語（これを含む問題は作らない）
BANNED = ['最も多い', 'いちばん多い', '最大の輸出', '現在の', '最新の', '何か国', '第何位', '世界一']

BANK = r'''
[
 {
  "q": "🌍 アメリカ合衆国の首都はどこ？",
  "correct": "ワシントンD.C.",
  "wrongs": [
   "ニューオーリンズ",
   "サンフランシスコ",
   "フィラデルフィア"
  ]
 },
 {
  "q": "🌍 アメリカ合衆国で\nおもに使われている言語は？",
  "correct": "英語",
  "wrongs": [
   "スペイン語",
   "フランス語",
   "ドイツ語"
  ]
 },
 {
  "q": "🌍 アメリカの農業の特色は？",
  "correct": "広い農地で大型機械を使って行う",
  "wrongs": [
   "せまい農地で手作業を中心に行う",
   "水田が耕地の大部分をしめる",
   "山の斜面のだんだん畑が中心"
  ]
 },
 {
  "q": "🌍 日本がアメリカから\n多く輸入している農産物は？",
  "correct": "とうもろこしや大豆",
  "wrongs": [
   "さとうきびやバナナ",
   "コーヒー豆やカカオ豆",
   "オリーブやぶどう"
  ]
 },
 {
  "q": "🌍 アメリカの小学校で\nよく見られるようすは？",
  "correct": "スクールバスで通学する子が多い",
  "wrongs": [
   "決められた制服を着て通学する子が多い",
   "そうじの時間が毎日ある",
   "給食当番が配ぜんを行う"
  ]
 },
 {
  "q": "🌍 さまざまな民族が\nともに暮らすアメリカの社会を何という？",
  "correct": "多民族社会",
  "wrongs": [
   "単一民族社会",
   "鎖国した社会",
   "農村中心の社会"
  ]
 },
 {
  "q": "🌍 中国の首都はどこ？",
  "correct": "ペキン",
  "wrongs": [
   "シャンハイ",
   "ホンコン",
   "ソウル"
  ]
 },
 {
  "q": "🌍 中国でおもに使われている文字は？",
  "correct": "漢字",
  "wrongs": [
   "ハングル",
   "アルファベット",
   "アラビア文字"
  ]
 },
 {
  "q": "🌍 中国から日本に\n多く輸入されているものは？",
  "correct": "衣類や機械類",
  "wrongs": [
   "原油や天然ガス",
   "鉄鉱石や石炭",
   "小麦や牛肉"
  ]
 },
 {
  "q": "🌍 中国の代表的な料理として\n知られているものは？",
  "correct": "ぎょうざやチャーハン",
  "wrongs": [
   "キムチやビビンバ",
   "タコスやトルティーヤ",
   "ナンやカレー"
  ]
 },
 {
  "q": "🌍 中国で古くからの暦にもとづいて\n祝われる正月を何という？",
  "correct": "春節",
  "wrongs": [
   "七夕",
   "感謝祭",
   "イースター"
  ]
 },
 {
  "q": "🌍 中国は日本から見て\nどの方角にある？",
  "correct": "西",
  "wrongs": [
   "東",
   "南",
   "北"
  ]
 },
 {
  "q": "🌍 大韓民国の首都はどこ？",
  "correct": "ソウル",
  "wrongs": [
   "ペキン",
   "ハノイ",
   "マニラ"
  ]
 },
 {
  "q": "🌍 韓国で使われている文字は？",
  "correct": "ハングル",
  "wrongs": [
   "アルファベット",
   "アラビア文字",
   "キリル文字"
  ]
 },
 {
  "q": "🌍 韓国の食事でよく使われ\n日本とちがうところは？",
  "correct": "金属のはしとスプーンを使う",
  "wrongs": [
   "木のはしだけを使って食べる",
   "ナイフとフォークを使って食べる",
   "手を使って直接食べる"
  ]
 },
 {
  "q": "🌍 韓国の代表的な\nつけもの料理は？",
  "correct": "キムチ",
  "wrongs": [
   "ぬかづけ",
   "ザワークラウト",
   "ピクルス"
  ]
 },
 {
  "q": "🌍 韓国は日本から見て\nどこにある？",
  "correct": "西どなりの朝鮮半島にある",
  "wrongs": [
   "東どなりの太平洋上にある",
   "南のはるか遠くの島にある",
   "北の広い大陸の内陸にある"
  ]
 },
 {
  "q": "🌍 ブラジルでおもに\n使われている言語は？",
  "correct": "ポルトガル語",
  "wrongs": [
   "スペイン語",
   "イタリア語",
   "フランス語"
  ]
 },
 {
  "q": "🌍 ブラジルに広がる\n世界最大の熱帯雨林は？",
  "correct": "アマゾン",
  "wrongs": [
   "サハラ",
   "ゴビ",
   "ヒマラヤ"
  ]
 },
 {
  "q": "🌍 ブラジルで毎年行われる\n有名な祭りは？",
  "correct": "カーニバル",
  "wrongs": [
   "ハロウィン",
   "オクトーバーフェスト",
   "ホーリー"
  ]
 },
 {
  "q": "🌍 日本からブラジルへ移り住んだ人や\nその子孫を何という？",
  "correct": "日系人",
  "wrongs": [
   "帰国子女",
   "留学生",
   "旅行者"
  ]
 },
 {
  "q": "🌍 ブラジルから日本に\n多く輸入されている農産物は？",
  "correct": "コーヒー豆",
  "wrongs": [
   "オリーブ",
   "ぶどう",
   "なつめやし"
  ]
 },
 {
  "q": "🌍 サウジアラビアの人々が\n多く信仰している宗教は？",
  "correct": "イスラム教",
  "wrongs": [
   "キリスト教",
   "仏教",
   "ヒンドゥー教"
  ]
 },
 {
  "q": "🌍 日本がサウジアラビアから\n多く輸入しているものは？",
  "correct": "石油",
  "wrongs": [
   "石炭",
   "鉄鉱石",
   "木材"
  ]
 },
 {
  "q": "🌍 イスラム教の人々が\n礼拝を行う建物を何という？",
  "correct": "モスク",
  "wrongs": [
   "仏教寺院",
   "キリスト教会",
   "神社"
  ]
 },
 {
  "q": "🌍 イスラム教で食べることが\n禁じられている肉は？",
  "correct": "ぶた肉",
  "wrongs": [
   "牛肉",
   "とり肉",
   "ひつじ肉"
  ]
 },
 {
  "q": "🌍 サウジアラビアの国土の\n多くをしめる地形は？",
  "correct": "砂漠",
  "wrongs": [
   "森林",
   "氷河",
   "湿地"
  ]
 },
 {
  "q": "🌍 国際連合の本部がある\n都市はどこ？",
  "correct": "ニューヨーク",
  "wrongs": [
   "アムステルダム",
   "ブエノスアイレス",
   "ヨハネスブルク"
  ]
 },
 {
  "q": "🌍 国際連合がつくられた\nいちばんの目的は？",
  "correct": "世界の平和と安全を守ること",
  "wrongs": [
   "貿易の利益を大きくすること",
   "強い国の力をさらに高めること",
   "各国の軍隊を強くすること"
  ]
 },
 {
  "q": "🌍 世界の子どもの命と健康を守る\n活動をしている国連の機関は？",
  "correct": "ユニセフ",
  "wrongs": [
   "ユネスコ",
   "WTO",
   "IOC"
  ]
 },
 {
  "q": "🌍 教育・科学・文化を通じて\n平和をつくる国連の機関は？",
  "correct": "ユネスコ",
  "wrongs": [
   "ユニセフ",
   "WTO",
   "IOC"
  ]
 },
 {
  "q": "🌍 世界遺産の登録を\n行っている国連の機関は？",
  "correct": "ユネスコ",
  "wrongs": [
   "ユニセフ",
   "WHO",
   "IOC"
  ]
 },
 {
  "q": "🌍 世界の人々の健康を守る\n活動をしている国連の機関は？",
  "correct": "WHO",
  "wrongs": [
   "ユニセフ",
   "ユネスコ",
   "IOC"
  ]
 },
 {
  "q": "🌍 加盟国のすべてが参加して\n話し合う国連の場を何という？",
  "correct": "総会",
  "wrongs": [
   "安全保障理事会",
   "事務局",
   "国際司法裁判所"
  ]
 },
 {
  "q": "🌍 世界の平和と安全に\nおもな責任をもつ国連の機関は？",
  "correct": "安全保障理事会",
  "wrongs": [
   "国際司法裁判所",
   "国連教育科学文化機関",
   "国連児童基金"
  ]
 },
 {
  "q": "🌍 2030年までに世界で達成しようと\n国連が決めた目標を何という？",
  "correct": "SDGs",
  "wrongs": [
   "ODA",
   "NGO",
   "GDP"
  ]
 },
 {
  "q": "🌍 SDGsは、いくつの目標から\nできている？",
  "correct": "17",
  "wrongs": [
   "7",
   "27",
   "47"
  ]
 },
 {
  "q": "🌍 日本の政府が発展途上国を助けるために\n行っている援助を何という？",
  "correct": "ODA",
  "wrongs": [
   "NGO",
   "WHO",
   "GDP"
  ]
 },
 {
  "q": "🌍 政府ではなく民間の人々がつくり\n国際協力を行う団体を何という？",
  "correct": "NGO",
  "wrongs": [
   "ODA",
   "GDP",
   "IOC"
  ]
 },
 {
  "q": "🌍 発展途上国へ行き\n技術や知識を伝える日本の人たちは？",
  "correct": "青年海外協力隊",
  "wrongs": [
   "日本赤十字社",
   "国際交流基金",
   "日本オリンピック委員会"
  ]
 },
 {
  "q": "🌍 戦争や紛争のために自分の国を\nはなれた人々を何という？",
  "correct": "難民",
  "wrongs": [
   "移民",
   "留学生",
   "旅行者"
  ]
 },
 {
  "q": "🌍 国際協力で大切な\n考え方として正しいのは？",
  "correct": "たがいの文化を尊重し合うこと",
  "wrongs": [
   "自分の国のやり方に合わせさせること",
   "ゆたかな国だけで決めること",
   "他の国と関わりを持たないこと"
  ]
 },
 {
  "q": "🌍 日本が国際連合に\n加盟したのはいつごろ？",
  "correct": "第二次世界大戦が終わったあと",
  "wrongs": [
   "第一次世界大戦が始まるより前",
   "江戸時代が終わるころ",
   "明治時代が始まったころ"
  ]
 },
 {
  "q": "🌍 日本が国際社会で果たしている\n役割として正しいのは？",
  "correct": "平和の実現に向けた協力や支援",
  "wrongs": [
   "他の国の政治を支配すること",
   "武力によって紛争を解決すること",
   "貿易をやめて孤立すること"
  ]
 },
 {
  "q": "🌍 世界でいちばん面積が\n大きい大陸は？",
  "correct": "ユーラシア大陸",
  "wrongs": [
   "アフリカ大陸",
   "北アメリカ大陸",
   "南アメリカ大陸"
  ]
 },
 {
  "q": "🌍 世界でいちばん面積が\n大きい海は？",
  "correct": "太平洋",
  "wrongs": [
   "大西洋",
   "インド洋",
   "北極海"
  ]
 },
 {
  "q": "🌍 地球全体の気温が\n高くなっていく問題を何という？",
  "correct": "地球温暖化",
  "wrongs": [
   "オゾン層の破壊",
   "海洋プラスチック汚染",
   "酸性雨の増加"
  ]
 },
 {
  "q": "🌍 森林が減り土地があれて\n広がっていく問題を何という？",
  "correct": "砂漠化",
  "wrongs": [
   "オゾン層の破壊",
   "海洋プラスチック汚染",
   "酸性雨の増加"
  ]
 },
 {
  "q": "🌍 温室効果ガスを減らすために\n大切な取り組みは？",
  "correct": "再生可能エネルギーを増やすこと",
  "wrongs": [
   "石炭や石油をもっと燃やすこと",
   "森林を切りひらいて広げること",
   "電気を使う量をふやし続けること"
  ]
 },
 {
  "q": "🌍 世界の国々が協力して\n環境問題に取り組む理由は？",
  "correct": "一つの国だけでは解決できないから",
  "wrongs": [
   "一部の大きな国だけが困っているから",
   "決まりを作ることが目的だから",
   "他の国の産業を止めたいから"
  ]
 }
]
'''


def js_str(s):
    return "'" + s.replace('\\', '\\\\').replace("'", "\\'").replace('\n', '\\n') + "'"


def build_fn():
    bank = json.loads(BANK)
    items = ','.join(
        '{q:' + js_str(p['q']) +
        ',correct:' + js_str(p['correct']) +
        ',wrongs:[' + ','.join(js_str(w) for w in p['wrongs']) + ']}'
        for p in bank
    )
    return 'function genWorld6(){return _pickBank([' + items + ']);}'


def build_insert():
    comment = (
        '      // 🌍 小6社会「世界の国々」: 7問しかないのに33,093回解かれ、正答率99.7%。\n'
        '      //    しかも正解が最長である割合が86%で、内容を知らなくても選べた。\n'
        '      //    指導要領の構成に合わせて50問に作り直す。範囲はつながりの深い5か国と\n'
        '      //    国際連合・国際協力。数値や順位は作らない。' + SENTINEL + '\n'
    )
    return comment + '      t = t.replace(' + json.dumps(ANCHOR, ensure_ascii=False) + \
        ', ' + json.dumps(build_fn(), ensure_ascii=False) + ')\n'


def chain_count(src_text):
    i = src_text.index("app.get('/', async (c) => {")
    j = src_text.index("app.get('/logout'")
    return src_text[i:j].count('.replace(')


def check_bank():
    """書き込む前に、問題そのものを検査する。ここで落ちたら何も書かない。"""
    import re as _re
    bank = json.loads(BANK)
    errs = []
    if len(bank) != 50:
        errs.append('問題数が %d（50であること）' % len(bank))

    def strip(x):
        return _re.sub(r'（[^）]*）', '', _re.sub(r'\([^)]*\)', '', x)).strip()

    seen = set()
    for i, p in enumerate(bank, 1):
        tag = 'Q%d' % i
        if p['q'] in seen:
            errs.append(tag + ' 問題文が重複')
        seen.add(p['q'])
        if len(p['wrongs']) != 3:
            errs.append(tag + ' 誤答が3つでない')
        opts = [p['correct']] + p['wrongs']
        disp = [strip(o) for o in opts]
        if len(set(disp)) < 4:
            errs.append(tag + ' 表示上の選択肢が重複: ' + ' / '.join(disp))
        if any(not o for o in disp):
            errs.append(tag + ' 空の選択肢')
        if p['correct'] in p['wrongs']:
            errs.append(tag + ' 正解が誤答にも入っている')
        if any(('（' in o) or ('(' in o) for o in opts):
            errs.append(tag + ' 選択肢にカッコがある')
        c = len(strip(p['correct']))
        w = sorted(len(strip(x)) for x in p['wrongs'])
        if w[1] > 0 and c / w[1] >= 1.5:
            errs.append(tag + ' 長さ比 %.2f（1.5未満であること）' % (c / w[1]))
        blob = p['q'] + p['correct'] + ''.join(p['wrongs'])
        for b in BANNED:
            if b in blob:
                errs.append(tag + ' 時事語「' + b + '」を含む')
    return errs


def main():
    errs = check_bank()
    if errs:
        print('FAIL: 問題の検査で %d 件' % len(errs), file=sys.stderr)
        for e in errs:
            print('  ' + e, file=sys.stderr)
        sys.exit(1)
    print('OK  : 問題の事前検査 50問すべて合格', file=sys.stderr)

    with open(HTML, 'rb') as f:
        html = f.read().decode('utf-8')
    with open(SRC, 'rb') as f:
        src_bytes = f.read()
    src = src_bytes.decode('utf-8')

    if html.count(ANCHOR) != 1:
        print('FAIL: アンカーが public/index.html 内に %d 個（1個であること）'
              % html.count(ANCHOR), file=sys.stderr)
        sys.exit(1)

    insert = build_insert()

    if SENTINEL in src:
        n = chain_count(src)
        if n != CHAIN_AFTER:
            print('NG: 既に適用済みだがチェーンが %d 件（%d 件であること）'
                  % (n, CHAIN_AFTER), file=sys.stderr)
            sys.exit(1)
        print('SKIP: 既に適用済み（チェーン %d 件）' % n, file=sys.stderr)
        return

    before = chain_count(src)
    if before != CHAIN_BEFORE:
        print('FAIL: チェーンが %d 件。想定は %d 件。他の変更が入っている可能性があるので中止する。'
              % (before, CHAIN_BEFORE), file=sys.stderr)
        sys.exit(1)

    if src.count(TAIL_ANCHOR) != 1:
        print('FAIL: 挿入位置が %d 個（1個であること）' % src.count(TAIL_ANCHOR), file=sys.stderr)
        sys.exit(1)

    out = src.replace(TAIL_ANCHOR, insert + TAIL_ANCHOR, 1)

    after = chain_count(out)
    if after != CHAIN_AFTER:
        print('FAIL: 適用後のチェーンが %d 件' % after, file=sys.stderr)
        sys.exit(1)

    if out.replace(insert, '', 1) != src:
        print('FAIL: 非破壊検証に失敗（挿入以外の場所が変わっている）', file=sys.stderr)
        sys.exit(1)

    with open(SRC, 'wb') as f:
        f.write(out.encode('utf-8'))

    print('OK  : 世界の国々を50問に差し替え（チェーン %d → %d 件）' % (before, after), file=sys.stderr)
    print('      src/index.tsx sha256 %s -> %s'
          % (hashlib.sha256(src_bytes).hexdigest()[:12],
             hashlib.sha256(out.encode('utf-8')).hexdigest()[:12]), file=sys.stderr)


def verify_world6(built_html, trials=60000):
    """変換後のHTMLから genWorld6 を取り出して実行し、基準を数える。目印は見ない。"""
    import re, subprocess, tempfile, os
    m = re.search(r'function genWorld6\(\)\{', built_html)
    if not m:
        return False, 'NG: 変換後のHTMLに genWorld6 が無い'
    i = m.start()
    d = 0
    k = built_html.index('{', i)
    while k < len(built_html):
        if built_html[k] == '{':
            d += 1
        elif built_html[k] == '}':
            d -= 1
            if d == 0:
                break
        k += 1
    fn = built_html[i:k + 1]

    js = r"""
const _ri=(a,b)=>Math.floor(Math.random()*(b-a+1))+a;
const _strip=s=>(s||'').replace(/（[^）]*）/g,'').replace(/\([^)]*\)/g,'').trim();
function _pickBank(bank){
  const p=bank[_ri(0,bank.length-1)];
  const o=[p.correct,...p.wrongs].sort(()=>Math.random()-0.5);
  return {q:p.q, ans:o.indexOf(p.correct), options:o.map(_strip), inputType:'mcq'};
}
__FN__
const N=__N__;
const qs=new Set(); let dup=0,noans=0,longest=0,badn=0,empty=0;
const per={};
for(let i=0;i<N;i++){
  const p=genWorld6(); qs.add(p.q);
  const o=p.options;
  if(o.length!==4) badn++;
  if(new Set(o).size<4) dup++;
  if(p.ans<0||p.ans>=o.length){ noans++; continue; }
  if(o.some(x=>!x)) empty++;
  const a=o[p.ans], w=o.filter((x,j)=>j!==p.ans);
  if(a.length>Math.max(...w.map(x=>x.length))) longest++;
  const med=w.map(x=>x.length).sort((x,y)=>x-y)[1];
  per[p.q]=per[p.q]||{ratio: med>0? a.length/med : 1};
}
const over=Object.entries(per).filter(function(e){return e[1].ratio>=1.5;})
  .map(function(e){return e[0].split('\n').join(' ');});
console.log(JSON.stringify({patterns:qs.size, dup:dup, noans:noans, badn:badn, empty:empty,
  longestPct: Math.round(1000*longest/N)/10, over:over}));
""".replace('__FN__', fn).replace('__N__', str(trials))

    fd, path = tempfile.mkstemp(suffix='.js')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(js)
        r = subprocess.run(['node', path], capture_output=True, text=True)
        if r.returncode != 0:
            return False, 'NG: 検証スクリプトが失敗\n' + r.stdout + r.stderr
        v = json.loads(r.stdout.strip().splitlines()[-1])
        ok = True
        lines = ['パターン数 %d / 選択肢重複 %d / 正解なし %d / 選択肢数おかしい %d / 空 %d / 正解が最長 %s%%'
                 % (v['patterns'], v['dup'], v['noans'], v['badn'], v['empty'], v['longestPct'])]
        if v['patterns'] != 50:
            ok = False
            lines.append('NG: 50パターンでない')
        if v['dup'] or v['noans'] or v['badn'] or v['empty']:
            ok = False
            lines.append('NG: 選択肢に不備')
        if v['longestPct'] >= 80:
            ok = False
            lines.append('NG: 正解がほぼ常に最長（消去法で当たる）')
        if v['over']:
            ok = False
            lines.append('NG: 長さ比1.5以上の問題 %d 問' % len(v['over']))
            lines += ['   ' + q for q in v['over']]
        else:
            lines.append('長さ比1.5以上の問題: 0問')
        return ok, '\n'.join(lines)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


if __name__ == '__main__':
    main()
