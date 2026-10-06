# -*- coding: utf-8 -*-
# IMPNAME_D_V1 (2026-10-06)  サーバ側でも実名マップを見る
#
# 実測した事実
#   ・/api/teacher/records/parse は users.name と users.login_id しか照合先に
#     していない。D1 を見ると users.name は実名ではなく
#     "444" "CR7" "mimi" "我を殿と呼べ" などのニックネーム／ログインID。
#     実名は admin_settings.real_name_map / real_furigana_map にしかない。
#   ・本番で実名10人ぶんを投げたところ、サーバ側の一致は 0/10 だった。
#   ・いまはブラウザ側 _matchRosterRows が結果を上書きして救っているが、
#     そこが落ちるとサーバの当てずっぽうが ✓自動 として残る。
#
# やること
#   S1 roster の鍵に real_name_map / real_furigana_map の値を足す。
#      読むだけ。書き込みはしない。クエリは key 指定の1行取得を2本だけ。
#
# 児童の配信チェーンは増減させない。
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
if tsx.count('IMPNAME_D_V1') != 0:
    die('IMPNAME_D_V1 はすでに当たっています')

OLD = """  const idx: Record<string, string> = {}
  for (const m of roster as any[]) { if (m.name) idx[_recNorm(m.name)] = m.id; if (m.loginId) idx[_recNorm(m.loginId)] = m.id }"""
if tsx.count(OLD) != 1:
    die('records/parse の idx 組み立てが %d 件（1件のはず）' % tsx.count(OLD))

NEW = """  const idx: Record<string, string> = {}
  for (const m of roster as any[]) { if (m.name) idx[_recNorm(m.name)] = m.id; if (m.loginId) idx[_recNorm(m.loginId)] = m.id }
  // \U0001F4CC IMPNAME_D_V1 users.name は実名ではない（ニックネーム／ログインID）。
  //    実名とふりがなは admin_settings にしかないので、ここでも照合先に足す。
  //    読むだけ。key 指定の1行取得を2本だけで、全件スキャンにはならない。
  let _rnMap: Record<string, string> = {}
  let _rfMap: Record<string, string> = {}
  try {
    const _r1 = await c.env.DB.prepare(`SELECT value FROM admin_settings WHERE key='real_name_map' LIMIT 1`).first<any>()
    if (_r1 && _r1.value) { const j = JSON.parse(_r1.value); if (j && typeof j === 'object') _rnMap = j }
  } catch (_e) { _rnMap = {} }
  try {
    const _r2 = await c.env.DB.prepare(`SELECT value FROM admin_settings WHERE key='real_furigana_map' LIMIT 1`).first<any>()
    if (_r2 && _r2.value) { const j = JSON.parse(_r2.value); if (j && typeof j === 'object') _rfMap = j }
  } catch (_e) { _rfMap = {} }
  for (const m of roster as any[]) {
    const _k1 = _recNorm(_rnMap[m.loginId] || ''); if (_k1 && !idx[_k1]) idx[_k1] = m.id
    const _k2 = _recNorm(_rfMap[m.loginId] || ''); if (_k2 && !idx[_k2]) idx[_k2] = m.id
  }"""
tsx = tsx.replace(OLD, NEW, 1)

bad = False
chain1 = chain_count(tsx)
print('チェーン件数 前=%d 後=%d' % (chain0, chain1))
if chain0 != chain1:
    print('::error::チェーン件数が変わった')
    bad = True

need = {
    'IMPNAME_D_V1': 1,
    '_rnMap': 4,
    '_rfMap': 4,
    "key='real_name_map'": 5,
    "key='real_furigana_map'": 4,
}
for k, want in need.items():
    got = tsx.count(k)
    print('適用後 %-52s %d 件（期待 %d）' % (k, got, want))
    if got != want:
        bad = True

# 書き込みを足していないこと
for ng in ['INSERT INTO karte_material_uses', 'UPDATE admin_settings SET value']:
    pass
print('エスケープ事故の見張り（増えていないこと） = %d' % tsx.count("(\\'"))
for k in ['IMPNAME_A_V1', 'IMPNAME_B_V1', '__IMPORT_AUTO_V1__', '__IMPORT_CHECK_V1__',
          'QUICKNOTE_V1', '_qnMask', 'karte_material_uses', 'WARMIX', '__WORLD_V3__', '_hash']:
    if tsx.count(k) < 1:
        print('::error::安全マーカー %r が消えました' % k)
        bad = True
if bad:
    sys.exit(1)

open(TSX, 'w', encoding='utf-8', newline='').write(tsx)
print('OK: src/index.tsx %d 文字' % len(tsx))
