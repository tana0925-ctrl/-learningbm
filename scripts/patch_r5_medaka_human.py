# scripts/patch_r5_medaka_human.py
# 小5理科「メダカのたんじょう」「人のたんじょう」の生成関数が存在せず、
# 単元を選ぶと理科ではない問題が出て、しかも答えられない状態になっていたのを直す。
#
# 何が起きているか:
#   CURRICULUM には次の2単元がある。
#     {id:'r5-medaka', gen:'genMedaka5', input:'mcq'}
#     {id:'r5-human',  gen:'genHuman5',  input:'mcq'}
#   ところが genMedaka5 / genHuman5 はどこにも定義されていない。
#   public/index.html にも無く、src/index.tsx の .replace() チェーンにも無い。
#   （小6理科の genPlant6 / genElectric6 / genEnvironment6 はチェーンで注入済みだが、
#     この2つだけ取り残されていた。）
#
#   その結果:
#     1. _genTrainQ_curriculum が window['genMedaka5'] を見つけられず、
#        generateDecimalProblem() にフォールバックする
#        → 理科の単元なのに「0.15 × 10 = ?」のような小数の計算問題が出る
#     2. 単元の input が 'mcq' なので trainSubmit() が先頭で
#        `if (... || _isNewCurrMCQ_submit) return;` により何もせず返る
#        → 答えを入れて OK を押しても、正解にも不正解にもならない
#
#   D1 の記録はこの見立てと合っている。r5-medaka は5件・r5-human は3件だけで、
#   すべて2026年4月上旬、すべて不正解、それ以降ゼロ。行き止まりに当たって
#   子どもがその単元を見捨てた形。
#
# 直し方:
#   小6理科3単元と同じ作法で、src/index.tsx の .replace() チェーンに
#   genMedaka5 / genHuman5 を注入する（public/index.html は直接編集しない）。
#   挿入位置はチェーンの最後。他セッションがチェーンの途中を編集しても衝突しない。
#
# 問題の作り方:
#   誤答は「もっともらしいが間違い」にしてある。同じ単元の中で本当に出てくる語
#   （たいばん・へそのお・ようすい など）を誤答に使い、正解だけが長い／形式が違う
#   といった手がかりが出ないようにした。カッコは使わない（_pickBank が表示時に
#   カッコを取り除くため、取り除いた結果2つの選択肢が同じ文字列になる事故を避ける）。
#
# 検証（sentinel と検証条件は分けてある）:
#   - sentinel(__R5_MEDAKA_HUMAN__) は「src/index.tsx に入れたか」の冪等判定にだけ使う
#   - 正しさの判定は目印を見ない。チェーンを実際に走らせて2つの関数を取り出し、
#     各5000回生成して次を数える:
#       * 6パターン出ること
#       * 選択肢が4つで、表示上の重複が0件
#       * 正解が必ず選択肢の中にあること
#       * 正解が常に最長になっていないこと（消去法で当たらないこと）
#   - アンカーは変換後のHTML内で1個であること
#   - .replace() チェーン 適用前48 / 適用後49（どちらもズレたら中止）
#     ※ 比の修正(patch_ratio6_gcd.py)を先に流しておくこと
#   - 非破壊検証（挿入した分を取り除くと元ファイルと完全一致）
import sys, json, hashlib

SRC = 'src/index.tsx'
HTML = 'public/index.html'

SENTINEL = '__R5_MEDAKA_HUMAN__'

CHAIN_BEFORE = 48
CHAIN_AFTER = 49

TAIL_ANCHOR = '      _rootHtmlCache = t'

# 小5理科の並びの中。ほかの .replace() が触っていない一意な行。
ANCHOR = 'function genFlowWater5(){return _pickBank(_SB5ext.fw5);}'

MEDAKA = [
    {
        'q': 'メダカのおすとめすを見分けるとき、注目するひれはどれ？',
        'correct': 'せびれとしりびれ',
        'wrongs': ['おびれとむなびれ', 'はらびれとおびれ', 'むなびれとせびれ'],
    },
    {
        'q': '受精卵とは、どのようなものですか？',
        'correct': 'めすがうんだ卵とおすの精子が結びついたもの',
        'wrongs': ['めすがうんだばかりで精子と結びつく前の卵',
                   'おすが出した精子だけがたくさん集まったもの',
                   '卵からかえったばかりの小さな子メダカ'],
    },
    {
        'q': 'メダカのたまごは、かえるまでにおよそどれくらいかかりますか？',
        'correct': '約2週間',
        'wrongs': ['約2日', '約2か月', '約半年'],
    },
    {
        'q': 'たまごの中のようすを大きくして観察するときに使う道具は？',
        'correct': 'かいぼうけんび鏡',
        'wrongs': ['ほう位じしん', 'メスシリンダー', '記録温度計'],
    },
    {
        'q': 'たまごからかえったばかりの子メダカが、2〜3日えさを食べなくてもよいのはなぜ？',
        'correct': 'はらのふくろに養分が入っているから',
        'wrongs': ['水の中の養分を体から吸うから',
                   '親メダカが口うつしで養分をやるから',
                   '日光を受けて自分で養分を作るから'],
    },
    {
        'q': 'メダカを飼うとき、水そうはどこに置くとよいですか？',
        'correct': '日光が直接当たらない明るいところ',
        'wrongs': ['一日中日光が強く当たるところ',
                   '光がまったく入らない暗いところ',
                   'だんぼうのふき出し口のすぐ近く'],
    },
]

HUMAN = [
    {
        'q': '女性の卵と男性の精子が結びつくことを何といいますか？',
        'correct': '受精',
        'wrongs': ['発芽', '成長', '分裂'],
    },
    {
        'q': '受精卵が育っていく、母親の体の中の場所はどこ？',
        'correct': '子宮',
        'wrongs': ['たいばん', 'へそのお', 'ようすい'],
    },
    {
        'q': '母親からの養分や酸素が子どもに送られる通り道は？',
        'correct': 'へそのお',
        'wrongs': ['ようすい', '子宮のかべ', 'はいのくだ'],
    },
    {
        'q': '子宮の中で子どもをつつみ、外からのしょうげきをやわらげているものは？',
        'correct': 'ようすい',
        'wrongs': ['へそのお', 'たいばん', '子宮口'],
    },
    {
        'q': '人の子どもが母親の子宮の中で育つ期間は、およそどれくらい？',
        'correct': '約38週',
        'wrongs': ['約20週', '約50週', '約8週'],
    },
    {
        'q': '生まれたばかりの赤ちゃんの体重は、およそどれくらい？',
        'correct': '約3000g',
        'wrongs': ['約300g', '約1000g', '約6000g'],
    },
]


def js_single(s):
    """JavaScript のシングルクォート文字列リテラルにする。"""
    return "'" + s.replace('\\', '\\\\').replace("'", "\\'") + "'"


def build_fn(name, bank):
    items = ','.join(
        '{q:' + js_single(p['q']) +
        ',correct:' + js_single(p['correct']) +
        ',wrongs:[' + ','.join(js_single(w) for w in p['wrongs']) + ']}'
        for p in bank
    )
    return ('function ' + name + '(){return _pickBank([' + items + ']);}'
            'try{window.' + name + '=' + name + ';}catch(e){}')


def build_insert():
    new_text = ANCHOR + build_fn('genMedaka5', MEDAKA) + build_fn('genHuman5', HUMAN)
    comment = (
        '      // 🐟 小5理科「メダカのたんじょう」「人のたんじょう」に生成関数が無く、単元を選ぶと\n'
        '      //    小数の計算問題が出たうえ、input:mcq のため trainSubmit が何もせず返り、\n'
        '      //    答えても正解にも不正解にもならない行き止まりになっていた。\n'
        '      //    小6理科3単元(genPlant6 ほか)と同じ作法でここに足す。' + SENTINEL + '\n'
    )
    return comment + '      t = t.replace(' + json.dumps(ANCHOR, ensure_ascii=False) + \
        ', ' + json.dumps(new_text, ensure_ascii=False) + ')\n'


def chain_count(src_text):
    i = src_text.index("app.get('/', async (c) => {")
    j = src_text.index("app.get('/logout'")
    return src_text[i:j].count('.replace(')


def main():
    with open(HTML, 'rb') as f:
        html = f.read().decode('utf-8')
    with open(SRC, 'rb') as f:
        src_bytes = f.read()
    src = src_bytes.decode('utf-8')

    if html.count(ANCHOR) != 1:
        print('FAIL: アンカー %r が public/index.html 内に %d 個（1個であること）'
              % (ANCHOR, html.count(ANCHOR)), file=sys.stderr)
        sys.exit(1)
    for name in ('function genMedaka5(', 'function genHuman5('):
        if name in html:
            print('NG: public/index.html 側に既に %s がある。'
                  'このパッチはチェーン経由で当てる前提なので中止する。' % name, file=sys.stderr)
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
        print('FAIL: チェーンが %d 件。想定は %d 件。'
              '比の修正(patch_ratio6_gcd.py)を先に流したか確認すること。'
              % (before, CHAIN_BEFORE), file=sys.stderr)
        sys.exit(1)

    if src.count(TAIL_ANCHOR) != 1:
        print('FAIL: 挿入位置 %r が %d 個（1個であること）'
              % (TAIL_ANCHOR, src.count(TAIL_ANCHOR)), file=sys.stderr)
        sys.exit(1)

    out = src.replace(TAIL_ANCHOR, insert + TAIL_ANCHOR, 1)

    after = chain_count(out)
    if after != CHAIN_AFTER:
        print('FAIL: 適用後のチェーンが %d 件。想定は %d 件。' % (after, CHAIN_AFTER), file=sys.stderr)
        sys.exit(1)

    if out.replace(insert, '', 1) != src:
        print('FAIL: 非破壊検証に失敗（挿入以外の場所が変わっている）', file=sys.stderr)
        sys.exit(1)

    with open(SRC, 'wb') as f:
        f.write(out.encode('utf-8'))

    print('OK  : 小5理科2単元の生成関数をチェーンに追加（%d → %d 件）' % (before, after), file=sys.stderr)
    print('      src/index.tsx sha256 %s -> %s'
          % (hashlib.sha256(src_bytes).hexdigest()[:12],
             hashlib.sha256(out.encode('utf-8')).hexdigest()[:12]), file=sys.stderr)


# ── ワークフローから呼ぶ検証関数（目印は見ない。実際に生成して数える）──
def verify_units(built_html, trials=5000):
    """変換後のHTMLから genMedaka5 / genHuman5 を取り出して実行し、品質を数える。
    返り値 (ok, メッセージ)。node が必要。"""
    import re, subprocess, tempfile, os

    def grab(name):
        m = re.search(r'function ' + name + r'\(\)\{', built_html)
        if not m:
            return None
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
        return built_html[i:k + 1]

    fns = {}
    for n in ('genMedaka5', 'genHuman5'):
        f = grab(n)
        if not f:
            return False, 'NG: 変換後のHTMLに %s が無い' % n
        fns[n] = f

    js = """
const _ri=(a,b)=>Math.floor(Math.random()*(b-a+1))+a;
function _pickBank(bank){
  const p=bank[_ri(0,bank.length-1)];
  const options=[p.correct,...p.wrongs].sort(()=>Math.random()-0.5);
  const ans=options.indexOf(p.correct);
  const _strip=s=>(s||'').replace(/（[^）]*）/g,'').replace(/\\([^)]*\\)/g,'').trim();
  return {q:p.q, ans:ans, options:options.map(o=>_strip(o)), inputType:'mcq'};
}
__FNS__
const N=__N__;
const out={};
for(const [name,g] of Object.entries({genMedaka5, genHuman5})){
  const qs=new Set(); let dup=0,noans=0,longest=0,badlen=0,empty=0;
  for(let i=0;i<N;i++){
    const p=g(); qs.add(p.q);
    const o=p.options;
    if(o.length!==4) badlen++;
    if(new Set(o).size<o.length) dup++;
    if(p.ans<0||p.ans>=o.length){ noans++; continue; }
    if(o.some(x=>!x)) empty++;
    const a=o[p.ans], w=o.filter((x,j)=>j!==p.ans);
    if(a.length>Math.max(...w.map(x=>x.length))) longest++;
  }
  out[name]={patterns:qs.size, dup:dup, noans:noans, badlen:badlen, empty:empty,
             longestPct:Math.round(100*longest/N)};
}
console.log(JSON.stringify(out));
""".replace('__FNS__', '\n'.join(fns.values())).replace('__N__', str(trials))

    fd, path = tempfile.mkstemp(suffix='.js')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(js)
        r = subprocess.run(['node', path], capture_output=True, text=True)
        if r.returncode != 0:
            return False, 'NG: 検証スクリプトが失敗\n' + r.stdout + r.stderr
        res = json.loads(r.stdout.strip().splitlines()[-1])
        msgs, ok = [], True
        for name, v in res.items():
            line = ('%s: %dパターン / 選択肢重複%d / 正解なし%d / 選択肢数おかしい%d / 空%d / 正解が最長%d%%'
                    % (name, v['patterns'], v['dup'], v['noans'], v['badlen'], v['empty'], v['longestPct']))
            if v['patterns'] != 6:
                ok = False; line += '  ← NG: 6パターンでない'
            if v['dup'] or v['noans'] or v['badlen'] or v['empty']:
                ok = False; line += '  ← NG: 選択肢に不備'
            if v['longestPct'] >= 80:
                ok = False; line += '  ← NG: 正解がほぼ常に最長（消去法で当たる）'
            msgs.append(line)
        return ok, '\n'.join(msgs)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


if __name__ == '__main__':
    main()
