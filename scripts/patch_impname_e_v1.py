# -*- coding: utf-8 -*-
# IMPNAME_E_V1 (2026-10-06)  名前の取り違えを無言で通さない（歯止め3つ）
#
# いまのデータに取り違えは見つかっていない（student_records 89件・
# student_alias_map 16件を1件ずつ確認済み。壊れ方は「混ざった」ではなく「欠けた」）。
# ただし、無言で別の子に付きうる経路が3つ残っているので塞ぐ。
#
#   E1 _matchRosterRows が例外を出すと、サーバ側のゆるい部分一致の結果が
#      そのまま残り、画面に「✓自動」と出てしまう。例外時は全行を未マッチにする。
#   E2 別名（student_alias_map）経由の一致を auto から cand（要確認）に落とす。
#      別名は「過去に先生が手で直した読み違い文字列」なので、同じ綴りが別の子の
#      ものとして出てきたとき、永久に無言で通り続ける。チェック1つを挟む。
#   E3 ログインIDが数字だけのとき（"444" "626" "321" "0621" など）、
#      サーバ側の部分一致を使わない。数字同士は簡単に部分一致してしまう。
#
# さわるのは取り込みの突き合わせだけ。児童の配信チェーンは増減させない。
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
if tsx.count('IMPNAME_E_V1') != 0:
    die('IMPNAME_E_V1 はすでに当たっています')

# ---- E1 例外時はサーバの推測を捨てて全行を未マッチにする ----
O1 = "try{ _matchRosterRows(d, cid); }catch(_e){}"
if tsx.count(O1) != 1:
    die('E1 のアンカーが %d 件（1件のはず）' % tsx.count(O1))
N1 = ("try{ _matchRosterRows(d, cid); }catch(_e){ /* IMPNAME_E_V1 e1: 突き合わせが落ちたら、"
      "サーバ側のゆるい推測を ✓自動 として残さない。全部 先生に選んでもらう。 */ "
      "try{ for(var _z=0;_z<d.rows.length;_z++){ d.rows[_z].matchedUserId=null; d.rows[_z].matchStatus='none'; "
      "d.rows[_z].matchedName=null; } }catch(_e9){} }")
tsx = tsx.replace(O1, N1, 1)

# ---- E2 別名経由は cand（要確認）にする ----
O2 = "if(nkey && aliases[nkey]){ for(var a=0;a<rk.length;a++){ if(rk[a].rm.userId===aliases[nkey]){ hit=rk[a].rm; status='auto'; break; } } }"
if tsx.count(O2) != 1:
    die('E2 のアンカーが %d 件（1件のはず）' % tsx.count(O2))
N2 = ("/* IMPNAME_E_V1 e2: 別名は「過去に先生が手で直した読み違い文字列」。"
      "同じ綴りが別の子のものとして出てくると、auto だと永久に無言で通る。cand にして確認を挟む。 */ "
      "if(nkey && aliases[nkey]){ for(var a=0;a<rk.length;a++){ if(rk[a].rm.userId===aliases[nkey]){ hit=rk[a].rm; status='cand'; break; } } }")
tsx = tsx.replace(O2, N2, 1)

# ---- E3 ログインIDが数字だけのときは部分一致を使わない ----
O3 = "    if (!uid && keyNm) { for (const m of roster as any[]) { const nn = _recNorm(m.name); if (nn && (nn.indexOf(keyNm) >= 0 || keyNm.indexOf(nn) >= 0)) { uid = m.id; break } } }"
if tsx.count(O3) != 1:
    die('E3 のアンカーが %d 件（1件のはず）' % tsx.count(O3))
N3 = ("    // \U0001F4CC IMPNAME_E_V1 e3: users.name は \"444\" \"626\" \"321\" のような数字のことがある。\n"
      "    //    数字同士は簡単に部分一致してしまうので、部分一致の相手からは外す。\n"
      "    //    1文字の鍵も外す（短すぎて誰にでも当たる）。完全一致（上の idx）は今までどおり効く。\n"
      "    if (!uid && keyNm && keyNm.length >= 2) { for (const m of roster as any[]) { const nn = _recNorm(m.name); if (!nn || nn.length < 2) continue; if (/^[0-9]+$/.test(nn) || /^[0-9]+$/.test(keyNm)) continue; if (nn.indexOf(keyNm) >= 0 || keyNm.indexOf(nn) >= 0) { uid = m.id; break } } }")
tsx = tsx.replace(O3, N3, 1)

bad = False
chain1 = chain_count(tsx)
print('チェーン件数 前=%d 後=%d' % (chain0, chain1))
if chain0 != chain1:
    print('::error::チェーン件数が変わった')
    bad = True

need = {
    'IMPNAME_E_V1': 3,
    "if(rk[a].rm.userId===aliases[nkey]){ hit=rk[a].rm; status='cand'": 1,
    "d.rows[_z].matchStatus='none'": 1,
    "/^[0-9]+$/.test(nn)": 1,
    "hit=rk[a].rm; status='auto'": 2,
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
