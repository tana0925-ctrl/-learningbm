# -*- coding: utf-8 -*-
"""
patch_cleanup_s12.py — 左上の名前を、先生ご自身で入れられるようにする
2026-09-29  CLEANUP_S12

s10 で「undefined ()」は消えたが、本番で確かめたところ、この先生の
アカウント（tanaken）に保存されている名前は文字どおり "admin" だった。
teacher_accounts に行が無く、users.name が "admin" のままになっている。

つまり「名前が取れない」のではなく「名前がまだ入っていない」状態。
そこで、左上の名前の横に小さな ✏️ を置き、その場で入れ直せるようにする。
  ・入れた名前は保存され、次に開いたときも出る。
  ・管理画面のクラス一覧の「担任」欄にも同じ名前が出る（同じ列を見ているため）。
  ・入れるのは先生ご自身のアカウントの名前だけ。ほかの人の名前は触れない。
  ・児童の画面には出ない。

足す入口：PUT /api/teacher/my-name  { name }
  自分自身の行だけを書きかえる（teacher_accounts に行があればそちら、
  無ければ users）。40文字まで。空にはできない。

★配信チェーン（158件）は増減させない。
"""
import io
import sys

TSX = 'src/index.tsx'
ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"
CHAIN_WANT = 158


def die(msg):
    sys.stderr.write('NG: ' + msg + '\n')
    sys.exit(1)


def chain_count(s):
    i = s.index(ROOT_ANCHOR)
    j = s.index(END_ANCHOR, i)
    return s[i:j].count('.replace(')


def rep(s, old, new, label, times=1):
    n = s.count(old)
    if n != times:
        die(u'あて先 %s が %d 件（%d 件のはず）' % (label, n, times))
    return s.replace(old, new)


API_ANCHOR = u"app.get('/api/teacher/class/:classId/new-since', async (c) => {\n"
API_NEW = (u"// 2026-09-29 CLEANUP_S12：先生ご自身の表示名を入れ直す。自分の行だけを書きかえる。\n"
           u"app.put('/api/teacher/my-name', async (c) => {\n"
           u"  const u = requireTeacher(c)\n"
           u"  if (!u) return jsonError(c, 401, 'unauthorized')\n"
           u"  const body = await c.req.json().catch(() => null)\n"
           u"  if (!body) return jsonError(c, 400, 'invalid')\n"
           u"  const nm = String(body.name || '').trim().slice(0, 40)\n"
           u"  if (!nm) return jsonError(c, 400, 'empty')\n"
           u"  let done = false\n"
           u"  try {\n"
           u"    const t = await c.env.DB.prepare('SELECT id FROM teacher_accounts WHERE id=? LIMIT 1').bind(u.id).first<any>()\n"
           u"    if (t) { await c.env.DB.prepare('UPDATE teacher_accounts SET name=? WHERE id=?').bind(nm, u.id).run(); done = true }\n"
           u"  } catch {}\n"
           u"  if (!done) {\n"
           u"    try { await c.env.DB.prepare('UPDATE users SET name=? WHERE id=?').bind(nm, u.id).run(); done = true } catch {}\n"
           u"  }\n"
           u"  if (!done) return jsonError(c, 500, 'save_failed')\n"
           u"  return c.json({ ok: true, name: nm })\n"
           u"})\n\n"
           u"app.get('/api/teacher/class/:classId/new-since', async (c) => {\n")

P_OLD = u'          <p id="teacherInfo" class="text-sm text-slate-500"></p>\n'
P_NEW = (u'          <p class="text-sm text-slate-500">\n'
         u'            <span id="teacherInfo"></span>\n'
         u'            <!-- 2026-09-29: 名前がまだ入っていないアカウントがあるため、その場で入れ直せるようにした。 -->\n'
         u'            <button onclick="editTeacherName()" title="表示される名前を変える" class="ml-1 text-xs text-slate-400 hover:text-slate-700">✏️</button>\n'
         u'          </p>\n')

JS_OLD = u"        document.getElementById('teacherInfo').textContent = _tNm + (_tSc ? '（' + _tSc + '）' : '');"
JS_NEW = (u"        document.getElementById('teacherInfo').textContent = _tNm + (_tSc ? '（' + _tSc + '）' : '');\n"
          u"        window._teacherName = _tNm;")

FN_ANCHOR = u"      function switchTab(tab){\n"
FN_NEW = (u"      /* 2026-09-29: 左上の名前を先生ご自身で入れ直す。自分のアカウントの名前だけ。 */\n"
          u"      async function editTeacherName(){\n"
          u"        var cur = String(window._teacherName || '');\n"
          u"        var v = window.prompt('画面の左上に出す、先生のお名前を入れてください（40文字まで）', cur);\n"
          u"        if (v === null) return;\n"
          u"        v = String(v).trim();\n"
          u"        if (!v) { alert('空にはできません。'); return; }\n"
          u"        try {\n"
          u"          var r = await fetch('/api/teacher/my-name', { method:'PUT', headers:{'content-type':'application/json'}, body: JSON.stringify({ name: v }) });\n"
          u"          var d = await r.json();\n"
          u"          if (!d || !d.ok) { alert('保存できませんでした。'); return; }\n"
          u"          window._teacherName = d.name;\n"
          u"          var el = document.getElementById('teacherInfo');\n"
          u"          if (el) el.textContent = d.name;\n"
          u"        } catch (e) { alert('保存できませんでした: ' + (e && e.message ? e.message : e)); }\n"
          u"      }\n"
          u"\n"
          u"      function switchTab(tab){\n")


def main():
    s = io.open(TSX, encoding='utf-8').read()
    n0 = chain_count(s)
    if n0 != CHAIN_WANT:
        die(u'チェーンが %d 件（%d 件のはず）。止めます。' % (n0, CHAIN_WANT))
    s = rep(s, API_ANCHOR, API_NEW, '名前を保存する入口')
    s = rep(s, P_OLD, P_NEW, '左上の表示')
    s = rep(s, JS_OLD, JS_NEW, '名前を覚えておく')
    s = rep(s, FN_ANCHOR, FN_NEW, '名前を入れ直す処理')
    n1 = chain_count(s)
    if n1 != n0:
        die(u'チェーンが %d 件になった' % n1)
    io.open(TSX, 'w', encoding='utf-8').write(s)
    print('PATCH OK / chain %d -> %d' % (n0, n1))


main()
