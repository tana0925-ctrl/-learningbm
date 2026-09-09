# scripts/patch_ratio6_gcd.py
# 小6算数「比」の答えが 36% の問題でまちがっている件を直す。
#
# 何が起きているか:
#   genRatio6 は a=_ri(1,6)*g, b=_ri(1,6)*g で数を作り、答えを a/g としている。
#   g で割っただけでは既約にならない。i=a/g と j=b/g に共通の約数が残るため。
#     例) g=2, a=3*2=6, b=3*2=6 → 「6：6 の左の数は？」の正解が 3（正しくは 1）
#     例) g=2, a=2*2=4, b=4*2=8 → 「4：8 の右の数は？」の正解が 4（正しくは 2）
#   本番ビルドで4万回生成して測ったところ 36.2% の問題で採点上の正解が数学的に誤り。
#   理論上の最高正答率は 63.8%。D1 の実測正答率は 65.8%（325問中214問）で、
#   児童はほぼ正しく答えていて、外れているぶんはほぼ全部アプリ側の誤りだった。
#
# 直し方:
#   すでに同型のバグを直した約分（genFracReduce5 の ans:n/_gcd(n,d)）と同じ作法で、
#   g ではなく _gcd(a,b) で割る。_gcd は同じ <script> ブロック内の前方で定義済み。
#
#   public/index.html は直接編集せず、src/index.tsx の .replace() チェーンに
#   48件目として追加する（約分の修正も同じチェーンにあるため、場所を揃える）。
#   挿入位置はチェーンの最後（_rootHtmlCache = t の直前）。他セッションが
#   チェーンの途中を編集しても衝突しない。
#
# 検証（sentinel と検証条件は分けてある）:
#   - sentinel(__RATIO6_GCD_FIX__) は「src/index.tsx に入れたか」の冪等判定にだけ使う
#   - 正しさの判定は目印を見ない。チェーンを実際に走らせて genRatio6 を取り出し、
#     2万回生成して _gcd で検算し、誤りが0件であることを数える
#   - アンカーは public/index.html 内で1個であること
#   - .replace() チェーン 適用前47 / 適用後48（どちらもズレたら中止）
#   - 非破壊検証（挿入した分を取り除くと元ファイルと完全一致）
import sys, json, hashlib

SRC = 'src/index.tsx'
HTML = 'public/index.html'

SENTINEL = '__RATIO6_GCD_FIX__'

CHAIN_BEFORE = 47
CHAIN_AFTER = 48

# チェーンの末尾（この行の直前に差し込む）
TAIL_ANCHOR = '      _rootHtmlCache = t'

# ── 置換の中身 ────────────────────────────────────────────────
# public/index.html 内にこの全文がちょうど1個あること。
OLD_FN = (
    "function genRatio6(){\n"
    "  const g=_ri(2,5),a=_ri(1,6)*g,b=_ri(1,6)*g;\n"
    "  const p=_ri(0,1);\n"
    "  if(p===0)return{q:a+'：'+b+'\\nかんたんな比にすると？\\n（左の数を答えて）',ans:a/g};\n"
    "  return{q:a+'：'+b+'\\nかんたんな比にすると？\\n（右の数を答えて）',ans:b/g};\n"
    "}"
)

NEW_FN = (
    "function genRatio6(){\n"
    "  const g=_ri(2,5),a=_ri(1,6)*g,b=_ri(1,6)*g;\n"
    "  const p=_ri(0,1);\n"
    "  const G=_gcd(a,b);\n"
    "  if(p===0)return{q:a+'：'+b+'\\nかんたんな比にすると？\\n（左の数を答えて）',ans:a/G};\n"
    "  return{q:a+'：'+b+'\\nかんたんな比にすると？\\n（右の数を答えて）',ans:b/G};\n"
    "}"
)

COMMENT = (
    '      // ⚖️ 比: 公約数 g で割っただけで既約になっておらず、36%の問題で採点上の正解が'
    'まちがっていた（例: 6：6 の左の数の正解が 3 になっていた）。\n'
    '      //    約分(genFracReduce5)と同じ型のバグ。同じ作法で _gcd(a,b) で割る。'
    + SENTINEL + '\n'
)


def build_insert():
    """挿入する2行（コメント + t = t.replace(...)）を作る。
    文字列リテラルは json.dumps で作るので、引用符・改行・\\n の手書きエスケープ事故が起きない。"""
    old_lit = json.dumps(OLD_FN, ensure_ascii=False)
    new_lit = json.dumps(NEW_FN, ensure_ascii=False)
    return COMMENT + '      t = t.replace(' + old_lit + ', ' + new_lit + ')\n'


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

    # ── 事前チェック: アンカーが public/index.html 内で1個 ──
    n_old = html.count(OLD_FN)
    n_new = html.count(NEW_FN)
    if n_new > 0:
        print('NG: public/index.html 側に既に修正版 genRatio6 がある。'
              'このパッチはチェーン経由で当てる前提なので中止する。', file=sys.stderr)
        sys.exit(1)
    if n_old != 1:
        print('FAIL: genRatio6 のアンカーが %d 個（1個であること）。'
              'public/index.html 側で genRatio6 が書き換わった可能性がある。' % n_old, file=sys.stderr)
        sys.exit(1)

    insert = build_insert()

    # ── 冪等: sentinel で判定 ──
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
              '他の変更が入っている可能性があるので中止する。' % (before, CHAIN_BEFORE), file=sys.stderr)
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

    # ── 非破壊検証: 入れた分を取り除くと元に戻ること ──
    if out.replace(insert, '', 1) != src:
        print('FAIL: 非破壊検証に失敗（挿入以外の場所が変わっている）', file=sys.stderr)
        sys.exit(1)

    with open(SRC, 'wb') as f:
        f.write(out.encode('utf-8'))

    print('OK  : 比の修正をチェーンに追加（%d → %d 件）' % (before, after), file=sys.stderr)
    print('      src/index.tsx sha256 %s -> %s'
          % (hashlib.sha256(src_bytes).hexdigest()[:12],
             hashlib.sha256(out.encode('utf-8')).hexdigest()[:12]), file=sys.stderr)


# ── ワークフローから呼ぶ検証関数（目印は見ない。実際に生成して検算する）──
def verify_ratio6(built_html, trials=20000):
    """変換後のHTMLから genRatio6 を取り出して実行し、_gcd で検算する。
    返り値 (ok, メッセージ)。node が必要。"""
    import re, subprocess, tempfile, os

    m = re.search(r'function genRatio6\(\)\{', built_html)
    if not m:
        return False, 'NG: 変換後のHTMLに genRatio6 が無い'
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

    js = """
const _ri=(a,b)=>Math.floor(Math.random()*(b-a+1))+a;
function _gcd(a,b){return b===0?a:_gcd(b,a%b);}
__FN__
const N=__N__;
let bad=0, worst=null;
for(let i=0;i<N;i++){
  const p=genRatio6();
  const m=String(p.q).replace(/\\s+/g,' ').match(/(\\d+)：(\\d+).*（(左|右)の数/);
  if(!m){ console.log('NG: 問題文の形が想定と違う: '+p.q); process.exit(1); }
  const a=+m[1], b=+m[2], g=_gcd(a,b);
  const want = (m[3]==='左') ? a/g : b/g;
  if(want !== p.ans){ bad++; if(!worst) worst = a+'：'+b+' ('+m[3]+') 期待'+want+' 実際'+p.ans; }
  if(!Number.isInteger(p.ans) || p.ans < 1){ console.log('NG: 答えが正の整数でない: '+p.ans); process.exit(1); }
}
console.log(JSON.stringify({N:N, bad:bad, worst:worst}));
""".replace('__FN__', fn).replace('__N__', str(trials))

    fd, path = tempfile.mkstemp(suffix='.js')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(js)
        r = subprocess.run(['node', path], capture_output=True, text=True)
        if r.returncode != 0:
            return False, 'NG: 検算スクリプトが失敗\n' + r.stdout + r.stderr
        res = json.loads(r.stdout.strip().splitlines()[-1])
        if res['bad'] != 0:
            return False, 'NG: %d/%d 件で答えがまちがっている（例: %s）' % (res['bad'], res['N'], res['worst'])
        return True, 'OK: %d 回生成して、答えのまちがい 0 件' % res['N']
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


if __name__ == '__main__':
    main()
