#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# __DEF_SERVER_ENGINE_GEN_V2__
# scripts/patch_def_server_engine_v1.py（サーバ側エンジンの生成器）を直す。
#   (1) EXPECT_CHAIN = 72 のハードコードをやめ、実行時にチェーンの本数を実測する。
#       実測した本数を「適用後も同じであること」の基準にする。--chain-before=N で
#       期待値を外から渡せば、食い違ったときに止まる（fail-closed）。
#   (2) すでに当たっている（番兵あり＋def_engine.ts あり）ときは「再生成モード」。
#       src/index.tsx には一切さわらず、src/def_engine.ts だけを作りなおす。
#       これで本番HTML側に入った修正（__DEFMOP_V1__ / __DEFMOP_BASE_V1__ /
#       standStill のずれ）がサーバ側エンジンにも反映される。
# 生成器そのもの以外のファイルには一切さわらない。
# fail-closed: 一致しなければ何も書かずに exit 1
import io, os, sys

TGT  = 'scripts/patch_def_server_engine_v1.py'
SENT = '__DEF_SERVER_ENGINE_GEN_V2__'

EDITS = [
 # (ラベル, 元, 後)
 ('argv',
  "SRC  = 'src/index.tsx'",
  "# " + SENT + " --chain-before=N で チェーンの期待値を外から渡せる（省略可）\n"
  "CHAIN_BEFORE_ARG = None\n"
  "for _a in sys.argv[1:]:\n"
  "    if _a.startswith('--chain-before='):\n"
  "        CHAIN_BEFORE_ARG = int(_a.split('=', 1)[1])\n"
  "\n"
  "SRC  = 'src/index.tsx'"),

 ('expect_chain',
  "BE = \"app.get('/logout'\"\nEXPECT_CHAIN = 72\n",
  "BE = \"app.get('/logout'\"\n"
  "# " + SENT + " チェーンの本数はハードコードしない。実行時に実測する。\n"),

 ('regen_mode',
  "if SENT in src and os.path.exists(OUT):\n"
  "    print('ALREADY APPLIED (sentinel present) - no file touched')\n"
  "    sys.exit(0)\n"
  "if SENT in src or os.path.exists(OUT):\n"
  "    die('中途半端に適用されている（番兵と %s が食い違う）' % OUT)\n",
  "# " + SENT + " すでに当たっているときは 再生成モード。\n"
  "REGEN = False\n"
  "if SENT in src and os.path.exists(OUT):\n"
  "    REGEN = True\n"
  "    print('REGEN MODE: src/index.tsx はさわらない。%s だけ作りなおす。' % OUT)\n"
  "elif SENT in src or os.path.exists(OUT):\n"
  "    die('中途半端に適用されている（番兵と %s が食い違う）' % OUT)\n"),

 ('precheck',
  "chain = src[st:en].count('.replace(')\n"
  "print('chain before = %d' % chain)\n"
  "if chain != EXPECT_CHAIN:\n"
  "    die('chain %d != %d' % (chain, EXPECT_CHAIN))\n"
  "\n"
  "if src.count(IMP_ANCHOR) != 1:\n"
  "    die('import アンカーが %d 件' % src.count(IMP_ANCHOR))\n"
  "if src.count(ROUTE_ANCHOR) != 1:\n"
  "    die('route アンカーが %d 件' % src.count(ROUTE_ANCHOR))\n"
  "if src.count(\"'/api/defense/_engine_check'\") != 0:\n"
  "    die('_engine_check がすでにある')\n",
  "chain = src[st:en].count('.replace(')\n"
  "print('chain before = %d' % chain)\n"
  "EXPECT_CHAIN = chain   # " + SENT + " 実測値。適用後もこれと同じであることだけを見る。\n"
  "if chain <= 0:\n"
  "    die('chain を実測できなかった（%d）' % chain)\n"
  "if CHAIN_BEFORE_ARG is not None and chain != CHAIN_BEFORE_ARG:\n"
  "    die('chain 実測 %d が --chain-before %d と食い違う' % (chain, CHAIN_BEFORE_ARG))\n"
  "\n"
  "if src.count(ROUTE_ANCHOR) != 1:\n"
  "    die('route アンカーが %d 件' % src.count(ROUTE_ANCHOR))\n"
  "if REGEN:\n"
  "    if src.count(\"'/api/defense/_engine_check'\") != 1:\n"
  "        die('再生成モードなのに _engine_check が %d 件' % src.count(\"'/api/defense/_engine_check'\"))\n"
  "    if src.count(\"from './def_engine'\") != 1:\n"
  "        die('再生成モードなのに import が %d 件' % src.count(\"from './def_engine'\"))\n"
  "else:\n"
  "    if src.count(IMP_ANCHOR) != 1:\n"
  "        die('import アンカーが %d 件' % src.count(IMP_ANCHOR))\n"
  "    if src.count(\"'/api/defense/_engine_check'\") != 0:\n"
  "        die('_engine_check がすでにある')\n"),

 ('apply_src',
  "out_src = src.replace(IMP_ANCHOR, IMP_NEW, 1)\n"
  "out_src = out_src.replace(ROUTE_ANCHOR, ROUTE_NEW + ROUTE_ANCHOR, 1)\n",
  "if REGEN:\n"
  "    out_src = src   # " + SENT + " 再生成モードでは src/index.tsx は 1 文字も変えない\n"
  "else:\n"
  "    out_src = src.replace(IMP_ANCHOR, IMP_NEW, 1)\n"
  "    out_src = out_src.replace(ROUTE_ANCHOR, ROUTE_NEW + ROUTE_ANCHOR, 1)\n"),

 ('write',
  "io.open(OUT, 'w', encoding='utf-8').write(out_ts)\n"
  "io.open(SRC, 'w', encoding='utf-8').write(out_src)\n"
  "print('OK: applied (chain stays %d, engine %d bytes)' % (chain2, engine_bytes))",
  "io.open(OUT, 'w', encoding='utf-8').write(out_ts)\n"
  "if not REGEN:\n"
  "    io.open(SRC, 'w', encoding='utf-8').write(out_src)\n"
  "print('OK: %s (chain stays %d, engine %d bytes)'\n"
  "      % ('regenerated' if REGEN else 'applied', chain2, engine_bytes))"),
]


def die(m):
    print('ABORT: ' + m)
    sys.exit(1)


if not os.path.exists(TGT):
    die('%s が無い' % TGT)
s = io.open(TGT, encoding='utf-8').read()

if SENT in s:
    for label, _old, new in EDITS:
        if s.count(new) != 1:
            die('番兵はあるが %s の中身が想定と違う' % label)
    print('ALREADY APPLIED - no file touched')
    sys.exit(0)

if 'EXPECT_CHAIN = 72' not in s:
    die('EXPECT_CHAIN = 72 が見つからない（生成器がすでに別物）')

out = s
for label, old, new in EDITS:
    if out.count(old) != 1:
        die('%s の元の文字列が %d 件（1件でないと危険）' % (label, out.count(old)))
    out = out.replace(old, new, 1)

# ---- 適用後チェック ----
if out.count(SENT) < 5:
    die('番兵が足りない')
if 'EXPECT_CHAIN = 72' in out:
    die('ハードコードが残っている')
if out.count("EXPECT_CHAIN = chain") != 1:
    die('実測への差し替えが 1 件でない')
if out.count('REGEN = False') != 1 or out.count('REGEN = True') != 1:
    die('再生成モードの導入が想定と違う')
if out.count("io.open(SRC, 'w', encoding='utf-8').write(out_src)") != 1:
    die('src の書き出しが 1 件でない')
if out.count("if not REGEN:") != 1:
    die('src の書き出しガードが無い')
# 壊してはいけないもの
for k in ["PROD = 'https://learning-bm.pages.dev/'", 'EXPECT_DIFF = set(', 'RAW_MARK =',
          'def grab_fn(', 'def scan_block(', "if not (20000 <= engine_bytes <= 60000):",
          "die('本番 HTML が短すぎる"]:
    if k not in out:
        die('壊してはいけない部分が消えた: ' + k)
try:
    compile(out, TGT, 'exec')
except SyntaxError as e:
    die('直した生成器が Python として壊れている: %s' % e)

io.open(TGT, 'w', encoding='utf-8').write(out)
print('OK: %s を v2（チェーン実測＋再生成モード）に直した' % TGT)
