#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# /mon/ を「ワーカーを通さず そのまま配る」側に入れる。
#
# このプロジェクトでは dist/_routes.json は ビルドで作り直されず、
# リポジトリに置いてあるものが そのまま使われる（2026-09-30 に実測して確認）。
# なので ここで書きかえる。
#
# 触るのは exclude に /mon/* を1つ足すだけ。ほかの行は一切さわらない。

import json
import os
import sys

P = 'dist/_routes.json'
WANT = '/mon/*'


def die(msg):
    print('### 中止: ' + msg)
    sys.exit(1)


if not os.path.exists(P):
    die(P + ' が無い')

with open(P, encoding='utf-8') as f:
    j = json.load(f)

inc = j.get('include') or []
exc = j.get('exclude') or []

if WANT in exc:
    print('すでに ' + WANT + ' が入っている。何もしない。')
    sys.exit(0)

exc.append(WANT)
j['exclude'] = exc

if len(inc) + len(exc) > 100:
    die('ルールが ' + str(len(inc) + len(exc)) + ' 件。Cloudflare Pages の上限100件をこえる。')

with open(P, 'w', encoding='utf-8') as f:
    f.write(json.dumps(j, ensure_ascii=False, separators=(',', ':')))

print('dist/_routes.json に ' + WANT + ' を足した')
print('exclude: ' + ', '.join(exc))
