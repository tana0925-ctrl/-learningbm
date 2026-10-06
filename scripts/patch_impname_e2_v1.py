# -*- coding: utf-8 -*-
# IMPNAME_E2_V1 (2026-10-06)  別名の「要確認」を効かせすぎたのを戻す
#
# IMPNAME_E_V1 e2 で、別名（student_alias_map）に当たった行をすべて
# cand（要確認）にした。ねらいは「過去の読み違いが永久に無言で通る」のを止めること。
# ところが本番で確かめたら、実名そのもの（井上翔太・森川芽依など）まで
# 要確認に落ちた。別名にも同じ綴りが入っているため。10人中5人が要確認になり、
# 先生の手間が増えるだけで、安全にはなっていない。
#
# 直し方
#   別名に当たっても、その綴りが「その子の強い鍵」（実名・ふりがな・ログインID）
#   とも一致しているなら auto のままにする。別名だけが根拠のときに cand にする。
#   時限爆弾（裏づけのない別名）は今までどおり止まる。
#
# さわるのは _matchRosterRows の1行だけ。児童の配信チェーンは増減させない。
# アンカーが1件でなければ1文字も書かずに止まる（fail-closed）。
import os
import sys

TSX = 'src/index.tsx'


def die(msg):
    print('::error::' + msg)
    sys.exit(1)


def chain_count(s):
    a = s.index("app.get('/', async (c) => {")
    b = s.index("app.get('/logout'", a)
    return s[a:b].count('.replace(')


raw = (os.environ.get('CHAIN_BEFORE') or '').strip()
if not raw.isdigit():
    die('CHAIN_BEFORE が数字で渡されていません: %r' % raw)
CHAIN_BEFORE = int(raw)

tsx = open(TSX, encoding='utf-8').read()
chain0 = chain_count(tsx)
if chain0 != CHAIN_BEFORE:
    die('チェーン件数が合いません 実測=%d 申告=%d' % (chain0, CHAIN_BEFORE))
if tsx.count('IMPNAME_E_V1') < 3:
    die('IMPNAME_E_V1 が当たっていません。先に便 e を流してください')
if tsx.count('IMPNAME_E2_V1') != 0:
    die('IMPNAME_E2_V1 はすでに当たっています')

OLD = "if(nkey && aliases[nkey]){ for(var a=0;a<rk.length;a++){ if(rk[a].rm.userId===aliases[nkey]){ hit=rk[a].rm; status='cand'; break; } } }"
if tsx.count(OLD) != 1:
    die('別名の分岐が %d 件（1件のはず）' % tsx.count(OLD))

NEW = ("/* IMPNAME_E2_V1: 別名に当たっても、その綴りがその子の強い鍵（実名・ふりがな・ログインID）"
       "とも一致しているなら auto のまま。別名だけが根拠のときに cand にする。 */ "
       "if(nkey && aliases[nkey]){ for(var a=0;a<rk.length;a++){ if(rk[a].rm.userId===aliases[nkey]){ "
       "hit=rk[a].rm; status=(rk[a].strong[nkey]?'auto':'cand'); break; } } }")
tsx = tsx.replace(OLD, NEW, 1)

bad = False
chain1 = chain_count(tsx)
print('チェーン件数 前=%d 後=%d' % (chain0, chain1))
if chain0 != chain1:
    print('::error::チェーン件数が変わった')
    bad = True

need = {
    'IMPNAME_E2_V1': 1,
    "status=(rk[a].strong[nkey]?'auto':'cand')": 1,
    "hit=rk[a].rm; status='cand'": 2,
    "hit=rk[a].rm; status='auto'": 2,
    'IMPNAME_E_V1': 3,
}
for k, want in need.items():
    got = tsx.count(k)
    print('適用後 %-52s %d 件（期待 %d）' % (k, got, want))
    if got != want:
        bad = True

print('エスケープ事故の見張り（増えていないこと） = %d' % tsx.count("(\\'"))
for k in ['IMPNAME_A_V1', 'IMPNAME_B_V1', 'IMPNAME_D_V1', '__IMPORT_AUTO_V1__', '__IMPORT_CHECK_V1__',
          'QUICKNOTE_V1', '_qnMask', 'karte_material_uses', 'WARMIX', '__WORLD_V3__', '_hash']:
    if tsx.count(k) < 1:
        print('::error::安全マーカー %r が消えました' % k)
        bad = True
if bad:
    sys.exit(1)

open(TSX, 'w', encoding='utf-8', newline='').write(tsx)
print('OK: src/index.tsx %d 文字' % len(tsx))
