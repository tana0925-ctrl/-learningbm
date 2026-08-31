#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""public/mi.js の先頭に紛れ込んだ貼り付け確認用の行を取り除く（冪等）。"""
import io
import sys

P = 'public/mi.js'

with io.open(P, encoding='utf-8', newline='') as f:
    s = f.read()

i = s.find('/* =====')
if i < 0:
    sys.exit('FATAL: mi.js の先頭コメントが見つかりません')
if i == 0:
    print('no change (すでに正常)')
else:
    head = s[:i]
    if 'TEST-LINE' not in head:
        sys.exit('FATAL: 想定外の先頭内容なので中止: %r' % head[:150])
    with io.open(P, 'w', encoding='utf-8', newline='') as f:
        f.write(s[i:])
    print('removed %d chars: %r' % (i, head))
