#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# ビルドしたあとの dist/_routes.json をたしかめる。
# /mon/* が「ワーカーを通さず そのまま配る」側に入っていなければ、
# 絵を置いても表示されないので、ここで止める。

import json
import os
import sys


def die(msg):
    print('### 中止: ' + msg)
    sys.exit(1)


P = 'dist/_routes.json'
if not os.path.exists(P):
    die(P + ' が無い。ビルドが走っていない。')

with open(P, encoding='utf-8') as f:
    j = json.load(f)

inc = j.get('include') or []
exc = j.get('exclude') or []
print('include ' + str(len(inc)) + ' 件 / exclude ' + str(len(exc)) + ' 件')

if '/mon/*' not in exc:
    print('exclude に入っているもの:')
    for e in sorted(exc):
        print('  ' + e)
    die('/mon/* が exclude に入っていない。絵を置いても表示されない。')

if len(inc) + len(exc) > 100:
    die('ルールが ' + str(len(inc) + len(exc)) + ' 件。Cloudflare Pages の上限100件をこえた。')

if not os.path.exists('dist/mon/list.js'):
    die('dist/mon/list.js が作られていない。public/mon/ がコピーされていない。')

if not os.path.exists('dist/mon/README.txt'):
    die('dist/mon/README.txt が作られていない。')

print('OK: /mon/* は そのまま配る側。dist/mon/list.js もある。')
