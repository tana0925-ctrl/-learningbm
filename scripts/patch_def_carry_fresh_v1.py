# -*- coding: utf-8 -*-
# DEF_CARRY_FRESH_V1 : 持ち越し登録が古い形式のときは参加させない
# - defense_standing のスナップショットが spd / skills を欠いていたら entry を作らない
# - その子には out.carry_over_error で「もう一度えらんでね」と伝える（monster_gone と同じ経路）
# - defense_standing の行はそのまま残す（児童のデータは消さない）
# - DDL はここでは流さない
# - アンカーが1件でない、チェーン件数が想定外 → src/index.tsx には一切触らない（fail-closed）
import sys

SRC = "src/index.tsx"

# 冪等の番兵。検証条件（チェーン75件や各キーワード）とは別物にしてある。
SENTINEL = "__DEF_CARRY_FRESH_V1_SENTINEL__"

CHAIN_BEFORE = 74
CHAIN_AFTER = 75


def die(msg):
    print("NG: " + msg)
    sys.exit(1)


def chain_count(txt):
    i = txt.index("app.get('/', async (c) => {")
    j = txt.index("app.get('/logout'", i)
    return txt[i:j].count(".replace(")


src = open(SRC, encoding="utf-8").read()

if SENTINEL in src:
    print("SKIP: すでに適用ずみ。src/index.tsx には触らない。")
    sys.exit(0)

# A0 : 判定関数を足す。defEntryOk はすでに読み込みずみなのでそれを使う。
A0 = "import { defServerResolve, defEntryOk } from './def_resolve'"
A0NEW = (
    "import { defServerResolve, defEntryOk } from './def_resolve'\n"
    "\n"
    "// __DEF_CARRY_FRESH_V1_SENTINEL__ 持ち越しの編成が新しい形式（spd・skills あり）かを見る。\n"
    "// 古い形式のまま参加させると番人にはじかれ、サーバ計算がいつまでも動かないため。\n"
    "function defCarrySnapOk(mj: any): boolean {\n"
    "  try { return defEntryOk(JSON.parse(String(mj))) } catch (_e) { return false }\n"
    "}"
)

# A1 : 決戦前の持ち越し。古い形式なら参加させず、やり直しを伝える。
A1 = "if (_dsRow && _dsRow.mj) {"
A1NEW = (
    "if (_dsRow && _dsRow.mj && !defCarrySnapOk(_dsRow.mj)) { out.carry_over_error = 'needs_reselect' }"
    " else if (_dsRow && _dsRow.mj) {"
)

# A2 : 決戦後のクラス一括。古い形式の行はそもそも対象から外す。
A2 = "const _dsRows = ((_dsAll && _dsAll.results) || []).filter((r: any) => r && r.mj && r.curlv != null)"
A2NEW = (
    "const _dsRows = ((_dsAll && _dsAll.results) || [])"
    ".filter((r: any) => r && r.mj && r.curlv != null && defCarrySnapOk(r.mj))"
)

# A3 : 決戦後の自分の分。古い形式ならやり直しを伝える。
A3 = "if (_dsMe && _dsMe.mj && _dsMe.curlv != null) {"
A3NEW = (
    "if (_dsMe && _dsMe.mj && !defCarrySnapOk(_dsMe.mj)) { out.carry_over_error = 'needs_reselect' }"
    " else if (_dsMe && _dsMe.mj && _dsMe.curlv != null) {"
)

# A4 : 児童画面のお知らせ。monster_gone と同じ場所に1本足す。
UI_TARGET = "if (d.carry_over_error==='monster_gone') {"
UI_MSG = (
    "if (d.carry_over_error==='needs_reselect') { head+='<div style=\"background:#fff7ed;"
    "border:1px solid #fed7aa;border-radius:10px;padding:10px;margin-bottom:8px;color:#c2410c;"
    "font-weight:900;\">まえの データが ふるいままだよ。もういちど えらんでね。</div>'; }"
)
BQ = chr(96)  # バッククォート。この .py の中には書かずに組み立てる。
A4 = "_rootHtmlCache = t"
A4NEW = (
    "// __DEF_CARRY_FRESH_V1_UI__ 古い持ち越しのときのお知らせ\n"
    "    t = t.replace(" + BQ + UI_TARGET + BQ + ", " + BQ + UI_MSG + "\n    " + UI_TARGET + BQ + ")\n"
    "    _rootHtmlCache = t"
)

# --- 適用前チェック。ここで止まれば src/index.tsx は書き換えない ---
for name, anchor in (
    ("A0 def_resolve の読み込み", A0),
    ("A1 status 決戦前の持ち越し", A1),
    ("A2 status 決戦後のクラス一括", A2),
    ("A3 status 決戦後の自分の分", A3),
    ("A4 HTMLチェーン末尾", A4),
    ("UI monster_gone のお知らせ", UI_TARGET),
):
    n = src.count(anchor)
    if n != 1:
        die("アンカー %s が %d 件（1件でなければ適用しない）" % (name, n))

if "defCarrySnapOk" in src:
    die("defCarrySnapOk がすでにある（番兵なしで入っている）")
if "needs_reselect" in src:
    die("needs_reselect がすでにある")

n0 = chain_count(src)
if n0 != CHAIN_BEFORE:
    die(".replace() チェーンが %d 件（%d 件を想定）" % (n0, CHAIN_BEFORE))

out = src
out = out.replace(A0, A0NEW, 1)
out = out.replace(A1, A1NEW, 1)
out = out.replace(A2, A2NEW, 1)
out = out.replace(A3, A3NEW, 1)
out = out.replace(A4, A4NEW, 1)

# --- 適用後チェック ---
n1 = chain_count(out)
if n1 != CHAIN_AFTER:
    die("適用後の .replace() チェーンが %d 件（%d 件を想定）" % (n1, CHAIN_AFTER))
if SENTINEL not in out:
    die("番兵が入っていない")
if out.count("defCarrySnapOk") != 4:
    die("defCarrySnapOk が %d 件（定義1件＋使用3件を想定）" % out.count("defCarrySnapOk"))
if out.count("needs_reselect") != 3:
    die("needs_reselect が %d 件（3件を想定）" % out.count("needs_reselect"))
if out.count("ensureDefenseTables(") != 1:
    die("ensureDefenseTables の呼び出しが増えている（定義1件のみのはず）")

# 児童のデータを消す経路を増やしていないこと（語は組み立てて持つ）
_DROP = "DEL" + "ETE"
if out.count(_DROP + " FROM defense_standing") != src.count(_DROP + " FROM defense_standing"):
    die("defense_standing の行を消す経路が増えている")
if out.count("defense_standing") != src.count("defense_standing"):
    die("defense_standing の出現数が変わっている")
if out.count("defense_carry_lock") != src.count("defense_carry_lock"):
    die("defense_carry_lock の出現数が変わっている")
if ("stage" + " - " + "1") in out:
    die("ステージを下げる経路が入っている")

open(SRC, "w", encoding="utf-8").write(out)
print("OK: .replace() チェーン %d -> %d" % (n0, n1))
