# scripts/patch_idfix_v1.py
# 【第1弾】キャラIDの衝突を解消する。
#
# 何が起きていたか:
#   夏フェス7体・敬語3体・ネンリキ・まるやまード の定義が、先に登録済みの
#   別キャラと同じIDを名乗っていたため、ゲーム内に一体も存在していなかった。
#   夏フェス側は「同じIDが既にあれば push しない」というガードのせいで
#   エラーも出さずに黙って捨てられていた。
#
# この第1弾でやること（配り直しはしない。第2弾）:
#   1. 死んでいる側だけを 1501以上へ移す（既存IDは1つも動かさない）
#   2. 黙って捨てるガードを、気づける形に変える
#   3. IDの範囲をベタ書きしている箇所（交換禁止・ボール無効・図鑑カテゴリ）を追随させる
#
# 移動表（すべて現在ゲーム内に存在しない＝所持者0人のものだけ）:
#   957→1501 わたがしフワリン / 958→1502 ソフ蔵 / 959→1503 モロコシオ
#   960→1504 だんごさぶろう / 961→1505 フウリンタロウ / 962→1506 マスクメロ夫
#   963→1507 アメジロウ
#   1042→1511 ソンケイ / 1043→1512 ソンケーン / 1044→1513 ソンケーア
#   1045→1514 ネンリキ（nextIdは1046のまま。1046/1047は所持者がいるので動かさない）
#   1050→1515 まるやまード（まるやまーンの nextId も追随させる）
#
# 検証:
#   - アンカーはすべて public/index.html 内で1個であること
#   - .replace() チェーン 適用前25 / 適用後34（どちらもズレたら中止）
#   - 非破壊検証（挿入分を戻すと元ファイルと完全一致）
#   - 適用後の index.html を実際に組み立てて、ID衝突が0件になることを
#     「定義そのものを数えて」確認する（目印は見ない）
#   - 黙って捨てるガードが残っていたら中止
import sys, os, re, hashlib

SRC = 'src/index.tsx'
HTML = 'public/index.html'

SENTINEL = '__IDFIX_V1__'

CHAIN_BEFORE = 25
CHAIN_AFTER = 34

# ===== 1. index.html への置換（.replace() チェーンに足す） =====
# (説明, 置換前, 置換後) — 置換前は public/index.html 内で一意であること
EDITS = [
    (
        '夏フェス定数 958-963 → 1502-1507',
        "        const SUMMER_SOFUZO_ID    = 958; // 🍦 ソフ蔵（前半）\n"
        "        const SUMMER_MOROKOSHI_ID = 959; // 🌽 モロコシオ（前半）\n"
        "        const SUMMER_DANGO_ID     = 960; // 🍡 だんごさぶろう（前半）\n"
        "        const SUMMER_FURIN_ID     = 961; // 🎐 フウリンタロウ（後半）\n"
        "        const SUMMER_MELON_ID     = 962; // 🍈 マスクメロ夫（後半）\n"
        "        const SUMMER_AME_ID       = 963; // 🍭 アメジロウ（後半）",
        "        const SUMMER_SOFUZO_ID    = 1502; // 🍦 ソフ蔵（前半）\n"
        "        const SUMMER_MOROKOSHI_ID = 1503; // 🌽 モロコシオ（前半）\n"
        "        const SUMMER_DANGO_ID     = 1504; // 🍡 だんごさぶろう（前半）\n"
        "        const SUMMER_FURIN_ID     = 1505; // 🎐 フウリンタロウ（後半）\n"
        "        const SUMMER_MELON_ID     = 1506; // 🍈 マスクメロ夫（後半）\n"
        "        const SUMMER_AME_ID       = 1507; // 🍭 アメジロウ（後半）",
    ),
    (
        'わたがしフワリン 957 → 1501',
        "        var SUMMER_WATAGASHI_ID = 957; // 🍬 わたがしフワリン（スタンプ10日限定・配布）※940はリバイブ博士と衝突するため957",
        "        var SUMMER_WATAGASHI_ID = 1501; // 🍬 わたがしフワリン（スタンプ10日限定・配布）"
        "※957はSECRET_ELEC4（バッテリン）と衝突していたため1501へ。940→957の変更は衝突を移しただけだった。",
    ),
    (
        '敬語ライン 1042-1044 → 1511-1513',
        "const SECRET_KEIGO5_MONSTER_ID = 1042;\n"
        "const SECRET_KEIGO5_EVOLVE_1_ID = 1043;\n"
        "const SECRET_KEIGO5_EVOLVE_2_ID = 1044;",
        "const SECRET_KEIGO5_MONSTER_ID = 1511;  // 旧1042: オチャと衝突し、ソンケイが存在しなかった\n"
        "const SECRET_KEIGO5_EVOLVE_1_ID = 1512; // 旧1043: オチャ大魔王と衝突\n"
        "const SECRET_KEIGO5_EVOLVE_2_ID = 1513; // 旧1044: ブロッコリー大先生と衝突",
    ),
    (
        'ネンリキ 1045 → 1514',
        "const SECRET_COMBUST6_MONSTER_ID = 1045;",
        "const SECRET_COMBUST6_MONSTER_ID = 1514; // 旧1045: ミユウツーと衝突。"
        "nextIdの1046/1047は所持者がいるため動かさない",
    ),
    (
        'まるやまード 1050 → 1515',
        "    id: 1050,\n    name: 'まるやまード',",
        "    id: 1515,\n    name: 'まるやまード',",
    ),
    (
        'まるやまーンの進化先 1050 → 1515（Lv36でポポになる不具合の修正）',
        "    evoLevel: 36,\n    nextId: 1050,",
        "    evoLevel: 36,\n    nextId: 1515,",
    ),
    (
        'ボール無効の範囲 957-963 → 1501-1507',
        "(enemy.id >= 957 && enemy.id <= 963)",
        "(enemy.id >= 1501 && enemy.id <= 1507)",
    ),
    (
        '図鑑カテゴリに夏フェスの新範囲を追加',
        "if((id>=981 && id<=991)||(id>=1201 && id<=1216)||(id>=1301 && id<=1303)) return 'イベント・攻略モード';",
        "if((id>=981 && id<=991)||(id>=1201 && id<=1216)||(id>=1301 && id<=1303)||(id>=1501 && id<=1510)) return 'イベント・攻略モード';",
    ),
]

# ガードは2か所あり前後の形が違うので、共通する「条件式」だけを1本の正規表現で
# 置き換える。黙って捨てるのをやめ、衝突したらコンソールに残す。
# （置換後も「同じIDがあれば push しない」動作は同じ。気づけるかどうかだけが違う）
GUARD_OLD = "!MONSTERS.some(function(m){ return m.id === d.id; })"
GUARD_NEW = (
    "(function(){var _p=MONSTERS.filter(function(m){return m.id===d.id;})[0];"
    "if(_p){try{console.error('[ID衝突] id='+d.id+' 「'+d.name+'」は既にある「'+_p.name+'」と衝突していて登録されません');}catch(e){}return false;}"
    "return true;})()"
)
GUARD_COUNT = 2

# ===== 2. src/index.tsx 自身への直接修正（交換禁止の範囲） =====
TRADE_OLD = "(i>=957&&i<=963)"
TRADE_NEW = "(i>=1501&&i<=1507)"
TRADE_COUNT = 2

# 差し込み先: 図鑑カテゴリの replace の直後（既存の最後の replace の後ろ）
ANCHOR_CHAIN = "      _rootHtmlCache = t\n"


def die(msg):
    print('[patch] NG: ' + msg)
    sys.exit(1)


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'")
    return s[i:j].count('.replace(')


def jsq(s):
    """JS のシングルクォート文字列リテラルにする"""
    return "'" + s.replace('\\', '\\\\').replace("'", "\\'").replace('\n', '\\n') + "'"


def re_lit(s):
    """JS の正規表現リテラルの中身にする（全メタ文字をエスケープ）"""
    out = ''
    for ch in s:
        out += ('\\' + ch) if ch in '\\^$.|?*+()[]{}/' else ch
    return out


def main():
    if not os.path.exists(HTML):
        die('public/index.html が無い')
    with open(HTML, 'r', encoding='utf-8') as f:
        html = f.read()
    with open(SRC, 'r', encoding='utf-8') as f:
        orig = f.read()
    print('[patch] src/index.tsx before sha256: ' + hashlib.sha256(orig.encode()).hexdigest())
    print('[patch] public/index.html    sha256: ' + hashlib.sha256(html.encode()).hexdigest())

    if SENTINEL in orig:
        print('[patch] already applied (idempotent). nothing to do.')
        return

    # --- アンカーの一意性を index.html 側で確認 ---
    for label, old, new in EDITS:
        n = html.count(old)
        if n != 1:
            die('index.html のアンカー「%s」が %d 個（1個であるべき）' % (label, n))
        if html.count(new) != 0:
            die('index.html に置換後の文字列が既にある: ' + label)
    print('[patch] index.html アンカー %d 件すべて一意' % len(EDITS))

    if html.count(GUARD_OLD) != GUARD_COUNT:
        die('黙って捨てるガードが %d 個（%d 個であるべき）' % (html.count(GUARD_OLD), GUARD_COUNT))
    if GUARD_NEW in html:
        die('index.html に置換後のガードが既にある')

    # --- src/index.tsx 側 ---
    if orig.count(ANCHOR_CHAIN) != 1:
        die('チェーンの差し込み位置が %d 個' % orig.count(ANCHOR_CHAIN))
    if orig.count(TRADE_OLD) != TRADE_COUNT:
        die('交換禁止の範囲 %s が %d 個（%d 個であるべき）' % (TRADE_OLD, orig.count(TRADE_OLD), TRADE_COUNT))
    if TRADE_NEW in orig:
        die('交換禁止の新しい範囲が既にある')

    before = chain_count(orig)
    print('[patch] .replace() chain before: %d' % before)
    if before != CHAIN_BEFORE:
        die('.replace() チェーンが %d 件ではない（%d 件）' % (CHAIN_BEFORE, before))

    # --- 適用 ---
    lines = ['      // ' + SENTINEL + ' キャラIDの衝突解消（第1弾）。既存IDは1つも動かしていない。\n']
    for label, old, new in EDITS:
        lines.append('      // ' + label + '\n')
        lines.append('      t = t.replace(' + jsq(old) + ', ' + jsq(new) + ')\n')
    # ガードは2か所まとめて（正規表現1本 = .replace() 1件）
    lines.append('      // IDが衝突したら黙って捨てず、コンソールに残す（2か所まとめて）\n')
    lines.append('      t = t.replace(/' + re_lit(GUARD_OLD) + '/g, ' + jsq(GUARD_NEW) + ')\n')
    block = ''.join(lines)

    out = orig.replace(ANCHOR_CHAIN, block + ANCHOR_CHAIN, 1)
    out = out.replace(TRADE_OLD, TRADE_NEW)

    # --- 非破壊検証 ---
    check = out.replace(block, '', 1).replace(TRADE_NEW, TRADE_OLD)
    if check != orig:
        die('非破壊検証に失敗（元ファイルを復元できない）')

    after = chain_count(out)
    print('[patch] .replace() chain after : %d' % after)
    if after != CHAIN_AFTER:
        die('.replace() チェーンが %d 件になっていない（%d 件）' % (CHAIN_AFTER, after))
    if out.count(TRADE_NEW) != TRADE_COUNT:
        die('交換禁止の範囲が %d 個に置き換わっていない' % TRADE_COUNT)

    # --- 結果そのものの検証: 組み立てた HTML で衝突が消えるか ---
    built = html
    for label, old, new in EDITS:
        if built.count(old) != 1:
            die('組み立て時にアンカーが一意でない: ' + label)
        built = built.replace(old, new, 1)
    built = built.replace(GUARD_OLD, GUARD_NEW)

    ok, msg = verify_no_collision(built)
    print(msg)
    if not ok:
        die('適用後もIDが衝突している')

    if GUARD_OLD in built:
        die('黙って捨てるガードが残っている')
    if built.count(GUARD_NEW) != GUARD_COUNT:
        die('ガードが %d 箇所とも置き換わっていない' % GUARD_COUNT)

    for need in ['1501', '1502', '1507', '1511', '1513', '1514', '1515']:
        if ('= ' + need) not in built and (': ' + need) not in built:
            die('新しいIDが組み立て後のHTMLに現れない: ' + need)

    with open(SRC, 'w', encoding='utf-8') as f:
        f.write(out)
    print('[patch] src/index.tsx after  sha256: ' + hashlib.sha256(out.encode()).hexdigest())
    print('[patch] OK: applied (+%d bytes)' % (len(out) - len(orig)))


def verify_no_collision(src):
    """定義そのものを数えて衝突を検出する（目印は見ない）。
    MONSTERS.push の id 式と *_ID 定数の値を実際の数値まで解決し、
    同じ数値を2つ以上のものが名乗っていないかを見る。"""
    consts = {}
    for m in re.finditer(r'\b(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*_ID)\s*=\s*(\d+)', src):
        consts.setdefault(m.group(1), int(m.group(2)))
    base = consts.get('NEW_WILD_BASE_ID')

    owners = {}   # 数値 -> [名乗っているものの説明]

    def claim(num, who):
        owners.setdefault(num, []).append(who)

    for m in re.finditer(r'MONSTERS\s*\.\s*push\s*\(\s*\{', src):
        seg = src[m.end(): m.end() + 400]
        idm = re.search(r'\bid\s*:\s*([^,}\n]+)', seg)
        nm = re.search(r'\bname\s*:\s*[\'"]([^\'"]{0,40})', seg)
        if not idm:
            continue
        e = idm.group(1).strip()
        name = nm.group(1) if nm else '?'
        v = None
        if re.fullmatch(r'\d+', e):
            v = int(e)
        else:
            nwm = re.fullmatch(r'NW\((\d+)\)', e)
            if nwm and base is not None:
                v = base + int(nwm.group(1))
            elif e in consts:
                v = consts[e]
        if v is not None:
            claim(v, '定義 ' + name)

    # ループ生成の基本150体
    for i in range(1, 151):
        claim(i, '定義 (基本150体)')

    # 定数も名乗り手として数える（同じ値を別名の定数が指していたら衝突）
    byval = {}
    for n, v in consts.items():
        byval.setdefault(v, []).append(n)

    # 判定の原則:
    #   致命的 = 同じIDを「名前の違うもの」が2つ以上名乗っている
    #            （＝どちらかがゲーム内に存在できない。今回直したのはこれ）
    #   警告   = 同じIDを「同じ名前」で2回定義している
    #            （＝配られる中身は変わらない。掃除の対象ではあるが害はない）
    # 許可リストで個別に黙らせると、次に本物の衝突が出たときに見逃すため、
    # 番号ではなく性質で分ける。
    fatal, warn = [], []

    for v, names in byval.items():
        if len(set(names)) > 1:
            fatal.append('ID %d: 別名の定数が同じ値を指している → %s' % (v, ' / '.join(sorted(set(names)))))

    for v, who in owners.items():
        uniq = sorted(set(who))
        if len(uniq) > 1:
            fatal.append('ID %d: 別のキャラが同じIDを名乗っている → %s' % (v, ' / '.join(uniq)))
        elif len(who) > 1:
            warn.append('ID %d: %s が %d 回定義されている（同一キャラの二重定義・害なし）'
                        % (v, uniq[0], len(who)))

    lines = ['[patch] 衝突検出: 名乗り手のあるID %d 個 / 定数 %d 個' % (len(owners), len(consts))]
    for w in sorted(warn):
        lines.append('[patch]   警告: ' + w)
    for b in sorted(fatal):
        lines.append('[patch]   衝突: ' + b)
    if not fatal:
        lines.append('[patch] 別キャラどうしのID衝突なし')
    return (len(fatal) == 0), '\n'.join(lines)


main()
