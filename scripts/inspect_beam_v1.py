#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# BEAMDMG_V1 の あとの 生存かくにん（読むだけ / 本番は GET だけ）
import io
import re
import urllib.request

NL = chr(10)
H = io.open('public/index.html', encoding='utf-8', errors='ignore', newline='').read()
S = io.open('src/index.tsx', encoding='utf-8', errors='ignore', newline='').read()
D = io.open('public/defense2.js', encoding='utf-8', errors='ignore', newline='').read()

LIVE = ''
try:
    req = urllib.request.Request('https://learning-bm.pages.dev/', headers={'User-Agent': 'verify-beam'})
    op = urllib.request.urlopen(req, timeout=90)
    LIVE = op.read().decode('utf-8', 'ignore')
    print('live status =', op.status)
except Exception as e:
    print('live fetch NG:', repr(e))

print('=== ながさ')
print('  素の public/index.html =', len(H))
print('  配信 HTML              =', len(LIVE))
print('  さ                      = +' + str(len(LIVE) - len(H)))
print('  catch に 落ちて いない か =', 'OK' if len(LIVE) - len(H) > 30000 else 'NG（みじかすぎる）')

i = S.index("app.get('/', async (c) => {")
j = S.index("app.get('/logout'", i)
print('  チェーン =', S[i:j].count('.replace('))

print('=== ビーム2 の のび（配信されている もの）')
for w in ('const BEAM_RATIO_BASE = ', 'const BEAM_RATIO_PER_LEVEL = ',
          'const BEAM_RATE_PER_LEVEL = ', 'const BEAM_STUN_PER_LEVEL = ',
          'const CASTLE_HP_PER_LEVEL = '):
    for L in LIVE.split(NL):
        if w in L:
            print('  ' + L.strip()[:160])
            break
print('  しき:', 'OK' if 'warState.beamDamageRatio = BEAM_RATIO_BASE + (bdl-1)*BEAM_RATIO_PER_LEVEL;' in LIVE else 'NG')
print('  0.0004 が のこって いない か:', 'OK' if 'BEAM_RATIO_PER_LEVEL = 0.0004' not in LIVE else 'NG')

print('=== 対比較：おなじ てき・おなじ 段・beamDamageLevel だけ かえる（配信されている しき）')
mb = re.search(r'const BEAM_RATIO_BASE = ([0-9.]+);', LIVE)
mp = re.search(r'const BEAM_RATIO_PER_LEVEL = ([0-9.]+);', LIVE)
if mb and mp:
    B = float(mb.group(1))
    P = float(mp.group(1))
    for lv in (1, 3, 5, 6, 7, 11, 22, 23, 26, 31, 43, 74, 94, 100):
        r = B + (lv - 1) * P
        print('  Lv' + str(lv) + ' : ratio=' + str(round(r, 4)) + ' / てきHP250 1はつ=' + str(max(1, int(250 * r))) + ' / てきHP900 1はつ=' + str(max(1, int(900 * r))) + ' / Lv1の ' + str(round(r / B, 3)) + 'ばい')

print('=== こわして いない か（配信 HTML の 中）')
LIVE_KEYS = [
    'ゾンビでは よわりモード',
    'if(false && warState.zombieMode',
    '__DEFSTAGE_SENTINEL_V1__',
    '__DEF_MVP_V1__',
    'DEF_LV50_V1',
    'foeLaneMix',
    '__DEFBOSS_V1',
    'defstage_monsters.js',
    'def_join_nudge.js',
    'HS_NEXT_RECALL_V1',
    '__S6WORLD_50__',
    '__H6MERGE_SRC_V1__',
    '__H6BANK_LIVE_V1__',
    '__H6U11_BOOST_V1__',
    'ゾンビしゅうらいは じゅんばんに すすむよ！',
    'zUnlocked = (progress.unlocked || 1)',
    'startZombieWarFromPreview',
]
for k in LIVE_KEYS:
    n = LIVE.count(k)
    print('  ' + ('OK ' if n > 0 else 'NG ') + str(n) + '  ' + k[:60])
print('  きんしの グレーアウトが 消えて いる:', 'OK' if 'opacity-60 grayscale cursor-not-allowed' not in LIVE else 'NG')

print('=== defense2.js の 番兵（配信とは べつファイル）')
for k in ('DEF2TRY_', 'DEF2SEND_GUARD_V1_MARK', 'DEF2TPL_LEARN_V1', 'DEF2TALLY_TREE_V2'):
    print('  ' + ('OK ' if k in D else 'NG ') + str(D.count(k)) + '  ' + k)

print('=== 数のやくそく')
print('  基地HP 380 :', LIVE.count('380'), 'けん（文字として）')
for L in LIVE.split(NL):
    if 'baseHp' in L and '380' in L:
        print('    ' + L.strip()[:160])
        break
print('  ensureDefenseTables() の よびだし =', LIVE.count('ensureDefenseTables()') + S.count('ensureDefenseTables()'))
print('  ensureDefenseTables の でてくる 回数 (live/src) =', LIVE.count('ensureDefenseTables'), '/', S.count('ensureDefenseTables'))
for L in LIVE.split(NL):
    if 'コイン' in L and '20' in L and ('しょうり' in L or '勝利' in L or 'win' in L.lower()):
        print('    しょうりコイン らしき 行: ' + L.strip()[:160])
        break
