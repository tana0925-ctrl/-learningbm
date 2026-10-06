#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 図鑑で見切れているキャラの絵に、透明の余白を足しなおす。
#
# 絵は描き直さない。αの輪郭(bbox)で切り出して、正方形のまんなかに置き直すだけ。
# 置き直したあと、絵は枠の 88.5% の大きさになる（＝上下左右に 11px ずつ余白）。
# これは 残り482枚の余白の中央値（11px）に合わせた値。
#
# 触るのは public/mon/<id>.png の 18枚だけ。
#   152 155 221 404 953 955 980 1002 1015 1016
#   1029 1037 1166 1302 1414 1511 1512 1513
#
# public/mon/list.js は触らない（idは増えも減りもしないので触る必要が無い）。
# src/index.tsx と public/index.html は 1文字も変えない。
#
# 守り（どれか1つでも合わなければ 何も書かずに止まる）:
#   - src/index.tsx の チェーン数 が 167 であること
#   - 18枚が すべてあって 192x192 であること
#   - 直す前の 最小余白が 4px 以下（＝本当に枠に接している）こと
#     ※2回流すと ここで止まる。二重に小さくしないため。
#   - 直したあと 192x192 であること
#   - 直したあと 最小余白が 6px 以上 20px 以下であること
#   - 1枚 20000 バイト以下であること
#     元の1.6倍（または +4000バイト）を超えそうなら
#     色数を 128->112->96->80->64 と落として入れなおす
#   - src/index.tsx と public/index.html が 無変更であること

import sys
import os
import io
import hashlib

try:
    from PIL import Image
except ImportError:
    print('### 中止: Pillow が入っていない')
    sys.exit(1)

SRC = 'src/index.tsx'
PUB = 'public/index.html'
MONDIR = 'public/mon'

CHAIN_BEFORE = 167
SIZE = 192
COVER = 0.885
ALPHA_MIN = 9
MAX_BYTES = 20000
MARGIN_BEFORE_MAX = 4
MARGIN_AFTER_MIN = 6
MARGIN_AFTER_MAX = 20

IDS = [152, 155, 221, 404, 953, 955, 980, 1002, 1015, 1016,
       1029, 1037, 1166, 1302, 1414, 1511, 1512, 1513]


def die(msg):
    print('### 中止: ' + msg)
    sys.exit(1)


def sha(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def alpha_bbox(im):
    a = im.getchannel('A').point(lambda v: 255 if v > ALPHA_MIN else 0)
    return a.getbbox()


def margins(im):
    bb = alpha_bbox(im)
    if bb is None:
        return None
    w, h = im.size
    return (bb[0], bb[1], w - bb[2], h - bb[3])


# ---- 守り 1: src/index.tsx のチェーン数 ----

with open(SRC, encoding='utf-8', newline='') as f:
    src_before = f.read()

a = src_before.find("app.get('/',")
b = src_before.find("app.get('/logout'")
if a < 0 or b < 0 or b <= a:
    die('src/index.tsx の目印が見つからない')
chain = src_before.count('.replace(', a, b)
if chain != CHAIN_BEFORE:
    die('チェーン数が ' + str(chain) + ' 件。' + str(CHAIN_BEFORE) + ' 件のはず。')
print('チェーン数 ' + str(chain) + ' 件を確認')

pub_before = sha(PUB)

if not os.path.isdir(MONDIR):
    die(MONDIR + ' が無い')

if len(IDS) != len(set(IDS)):
    die('IDS に重複がある')

# ---- 守り 2: 18枚ぜんぶ 先に調べてから 1枚も書かない ----

plan = []
for mid in IDS:
    path = os.path.join(MONDIR, str(mid) + '.png')
    if not os.path.exists(path):
        die(path + ' が無い')
    im = Image.open(path).convert('RGBA')
    if im.size != (SIZE, SIZE):
        die(path + ' が ' + str(im.size) + '。192x192 のはず。')
    mb = margins(im)
    if mb is None:
        die(path + ' に 中身が無い')
    if min(mb) > MARGIN_BEFORE_MAX:
        die(path + ' の最小余白が ' + str(min(mb)) + 'px。'
            + str(MARGIN_BEFORE_MAX) + 'px 以下のはず。'
            + '（もう直したあとかもしれない。二重に流さないこと）')
    plan.append((mid, path, mb, os.path.getsize(path)))

print('18枚ぜんぶ 直す前の確認が通った')

# ---- 作る（ここではまだ 1枚も書かない。18枚ぜんぶ通ってから まとめて書く）----

rows = []
blobs = []
for mid, path, mb, before_bytes in plan:
    im = Image.open(path).convert('RGBA')
    bb = alpha_bbox(im)
    cut = im.crop(bb)
    bw, bh = cut.size
    side = int(round(max(bw, bh) / COVER))
    if side < max(bw, bh) + 2:
        side = max(bw, bh) + 2
    cv = Image.new('RGBA', (side, side), (0, 0, 0, 0))
    cv.paste(cut, ((side - bw) // 2, (side - bh) // 2), cut)
    out = cv.resize((SIZE, SIZE), Image.LANCZOS)

    # ファイルが太らないように。128色でだめなら 色数を落として作りなおす。
    soft = min(MAX_BYTES, max(int(before_bytes * 1.6), before_bytes + 4000))
    used_colors = 0
    data = None
    for colors in (128, 112, 96, 80, 64):
        buf = io.BytesIO()
        out.quantize(colors=colors, method=Image.FASTOCTREE).save(
            buf, format='PNG', optimize=True)
        data = buf.getvalue()
        used_colors = colors
        if len(data) <= soft:
            break

    after_bytes = len(data)
    chk = Image.open(io.BytesIO(data)).convert('RGBA')
    if chk.size != (SIZE, SIZE):
        die(path + ' が 192x192 にならなかった')
    ma = margins(chk)
    if ma is None:
        die(path + ' が 空になった')
    if min(ma) < MARGIN_AFTER_MIN or min(ma) > MARGIN_AFTER_MAX:
        die(path + ' の 直したあとの余白が ' + str(min(ma)) + 'px。'
            + str(MARGIN_AFTER_MIN) + '〜' + str(MARGIN_AFTER_MAX) + 'px のはず。')
    if after_bytes > MAX_BYTES:
        die(path + ' が ' + str(after_bytes) + ' バイト。大きすぎる。')
    blobs.append((path, data))
    rows.append((mid, mb, ma, before_bytes, after_bytes, used_colors))

if len(blobs) != len(IDS):
    die('できたのが ' + str(len(blobs)) + ' 枚。' + str(len(IDS)) + ' 枚のはず。')

# ---- ここで はじめて書く ----

for path, data in blobs:
    with open(path, 'wb') as f:
        f.write(data)
    if os.path.getsize(path) != len(data):
        die(path + ' の書き込みが合わない')
print(str(len(blobs)) + ' 枚 書きこんだ')

# ---- 結果 ----

print('')
print('  id |  直す前の余白(左上右下)  |  直したあと  |  バイト  | 色数')
total_b = 0
total_a = 0
for mid, mb, ma, bb_, ab_, col in rows:
    total_b += bb_
    total_a += ab_
    print('%5d | %-22s | %-22s | %d -> %d | %d'
          % (mid, str(mb), str(ma), bb_, ab_, col))
print('')
print('合計 ' + str(total_b) + ' -> ' + str(total_a) + ' バイト')

# ---- 守り 3: ほかのファイルを変えていないこと ----

with open(SRC, encoding='utf-8', newline='') as f:
    if f.read() != src_before:
        die('src/index.tsx が変わってしまった')
if sha(PUB) != pub_before:
    die('public/index.html が変わってしまった')

print('src/index.tsx と public/index.html は無変更。'
      'チェーン ' + str(CHAIN_BEFORE) + ' -> ' + str(CHAIN_BEFORE))
print('OK: 18枚に余白を足しなおした。絵は1枚も描き直していない。')
