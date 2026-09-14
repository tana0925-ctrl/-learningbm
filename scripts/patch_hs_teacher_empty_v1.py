#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# HS_TEACHER_EMPTY_V1
#   家庭学習シートの「先生から」欄は、先生の返却コメントが空のときは枠ごと出さない。
#   （欄そのものは残す。返却コメントという書き込み口があるため。）
#   public/index.html は手で編集せず、src/index.tsx の app.get('/') 配信チェーンに1本だけ足す。
#   配信コードでは throw しない。アンカー不一致なら console.error して skip する。
# fail-closed: アンカーが一意でなければ1文字も書かずに exit 1。
import sys, io

IDX = 'src/index.tsx'
PUB = 'public/index.html'
CHAIN_BEFORE = 103
CHAIN_AFTER = 104


def die(msg):
    print('NG: ' + msg)
    sys.exit(1)


def read(p):
    with io.open(p, encoding='utf-8') as f:
        return f.read()


def write(p, s):
    with io.open(p, 'w', encoding='utf-8') as f:
        f.write(s)


def chain_count(s):
    a = s.find('let _rootHtmlCache')
    b = s.find('_rootHtmlCache = t', a + 1)
    if a < 0 or b < 0:
        die('app.get(/) の .replace() チェーン範囲が見つからない')
    return s[a:b].count('.replace(')


src = read(IDX)
pub = read(PUB)

n0 = chain_count(src)
print('CHAIN before = ' + str(n0))
if n0 != CHAIN_BEFORE:
    die('チェーン件数が ' + str(CHAIN_BEFORE) + ' ではない（実測 ' + str(n0) + '）')

TARGET = "if (tcEl) tcEl.textContent = (entryToday && entryToday.teacherComment) || '';"
if pub.count(TARGET) != 1:
    die('public/index.html の hsTeacherComment 代入が1箇所ではない: ' + str(pub.count(TARGET)))
if pub.count('hs-sigBox') < 2:
    die('public/index.html の hs-sigBox が見つからない')

BLOCK = '''
    // __HS_TEACHER_EMPTY_V1__ 家庭学習シートの「先生から」欄は、返却コメントが空なら枠ごと出さない。
    const _hste1 = "if (tcEl) tcEl.textContent = (entryToday && entryToday.teacherComment) || '';"
    const _hste2 = "if (tcEl) { var _tcTxt = (entryToday && entryToday.teacherComment) || ''; tcEl.textContent = _tcTxt; var _tcBox = tcEl.parentNode; if (_tcBox && _tcBox.classList && _tcBox.classList.contains('hs-sigBox')) { _tcBox.style.display = _tcTxt ? '' : 'none'; } }"
    if (t.indexOf(_hste1) !== -1) { t = t.replace(_hste1, _hste2) } else { console.error('[__HS_TEACHER_EMPTY_V1__] anchor not found') }
'''

ANCHOR = chr(10) + '    _rootHtmlCache = t' + chr(10)
if src.count(ANCHOR) != 1:
    die('_rootHtmlCache = t の行が1箇所ではない: ' + str(src.count(ANCHOR)))
if '__HS_TEACHER_EMPTY_V1__' in src:
    die('すでに適用済み（__HS_TEACHER_EMPTY_V1__ がある）')

src = src.replace(ANCHOR, BLOCK + ANCHOR)

n1 = chain_count(src)
print('CHAIN after = ' + str(n1))
if n1 != CHAIN_AFTER:
    die('チェーン件数が ' + str(CHAIN_AFTER) + ' にならなかった（実測 ' + str(n1) + '）')
if src.count('__HS_TEACHER_EMPTY_V1__') != 2:
    die('目印の数が想定外')
if 'console.error' not in BLOCK:
    die('skip 時の console.error が無い')

write(IDX, src)
print('OK: src/index.tsx に配信チェーンを1本追加しました（103 -> 104）')
