# -*- coding: utf-8 -*-
"""
patch_cleanup_s11.py — 「まとめてコピー」と「作り直す」の使い分けを機械にやらせる
2026-09-29  CLEANUP_S11

先生の訴え：ボタンが2つ並んでいて、名前から違いが分からない。

分かったこと（第2便で確認ずみ）：
  ・「📋 まとめてコピー」は、同じクラス・同じチェック・同じ日なら、
    1回目に作った文を取り置いて、2回目以降はそれをそのまま渡していた。
  ・「🔄 最新データで作り直す」は、その取り置きを捨てて作り直す唯一の道だった。
  つまり2つは別物。ただし先生が名前から見分けるのは無理。

直し方（ボタンを覚えさせるのではなく、必要なときだけ機械が教える）：
  1. 取り置きを使ったときは、その場で「今日 14:32 に作った文です」と出す。
  2. そのあと新しく出した子がいるかをサーバに1回だけ数えさせ、
     いるときだけ「⚠ そのあと ◯人が新しく出しています」と赤で出し、
     その場に「いまのデータで作り直してコピー」ボタンを出す。
  3. 常時出ていた「🔄 最新データで作り直す」ボタンは画面から外す。
     （処理そのもの taiCopyFresh() は残っており、上の赤いボタンから呼ばれる）

数えるための入口を1つ足す：
  GET /api/teacher/class/:classId/new-since?ts=（ミリ秒）
  → そのクラスで、その時刻より後に家庭学習を出した「人数」だけを返す。
  COUNT(DISTINCT user_id) の1回だけで、中身は一切読まない（軽い）。

★配信チェーン（158件）は増減させない。
"""
import io
import sys

TSX = 'src/index.tsx'
AIJS = 'public/teacher-ai.js'
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


# ================================================================= サーバ側
API_ANCHOR = u"app.get('/api/teacher/student-full-analysis', async (c) => {\n"
API_NEW = (u"// 2026-09-29 CLEANUP_S11：「まとめてコピー」が取り置きの文を渡したあと、\n"
           u"//   そのあと新しく出した子が何人いるかだけを数える。人数しか返さない。\n"
           u"//   COUNT(DISTINCT ...) 1回きりで、提出の中身は読まない。\n"
           u"app.get('/api/teacher/class/:classId/new-since', async (c) => {\n"
           u"  const u = requireTeacher(c)\n"
           u"  if (!u) return jsonError(c, 401, 'unauthorized')\n"
           u"  const classId = c.req.param('classId')\n"
           u"  const cls = u.role === 'admin'\n"
           u"    ? await c.env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()\n"
           u"    : await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first<any>()\n"
           u"  if (!cls) return jsonError(c, 404, 'class_not_found')\n"
           u"  const ts = Number(c.req.query('ts') || 0)\n"
           u"  if (!ts || !isFinite(ts)) return c.json({ ok: true, count: 0 })\n"
           u"  let n = 0\n"
           u"  try {\n"
           u"    const row = await c.env.DB.prepare(\n"
           u"      `SELECT COUNT(DISTINCT hs.user_id) as n\n"
           u"       FROM homework_submissions hs\n"
           u"       JOIN class_members cm ON cm.user_id = hs.user_id AND cm.class_id = ?\n"
           u"       WHERE hs.submitted_at > ?`\n"
           u"    ).bind(classId, ts).first<any>()\n"
           u"    n = Number((row && row.n) || 0)\n"
           u"  } catch {}\n"
           u"  return c.json({ ok: true, count: n })\n"
           u"})\n\n"
           u"app.get('/api/teacher/student-full-analysis', async (c) => {\n")

# ================================================================= ボタンを外す
BTN_OLD = (u'            <button onclick="taiCopyAll()" class="bg-emerald-600 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:bg-emerald-700">'
           u'\U0001f4cb まとめてコピー</button>'
           u'<button onclick="taiCopyFresh()" class="ml-2 bg-white border border-emerald-300 text-emerald-700 rounded-lg px-3 py-2 text-xs font-bold hover:bg-emerald-50">'
           u'\U0001f504 最新データで作り直す</button>\n')
BTN_NEW = (u'            <!-- 2026-09-29 整理: 「\U0001f504 最新データで作り直す」を画面から外した。\n'
           u'                 2つのボタンの違いを先生に覚えてもらうのではなく、取り置きの文を渡したときに\n'
           u'                 「いつ作った文か」と「そのあと何人が新しく出したか」をこの下に出し、\n'
           u'                 必要なときだけ「作り直してコピー」ボタンが出るようにしてある。 -->\n'
           u'            <button onclick="taiCopyAll()" title="同じ条件で今日2回目からは、1回目に作った文をそのまま渡します。新しい提出があるときは下に知らせます。" class="bg-emerald-600 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:bg-emerald-700">'
           u'\U0001f4cb まとめてコピー</button>\n')

# ================================================================= teacher-ai.js
HIT_OLD = (u"      var hit = cacheGet(_ckey);\n"
           u"      if (hit && hit.text) {\n"
           u"        window.__taiLast = { chars: hit.text.length, blocks: hit.blocks, cached: true, noMaterial: hit.noMaterial || 0, peopleWords: hit.peopleWords || 0 };\n"
           u"        copyText(hit.text);\n"
           u"        return;\n"
           u"      }\n")
HIT_NEW = (u"      var hit = cacheGet(_ckey);\n"
           u"      if (hit && hit.text) {\n"
           u"        // 2026-09-29: 取り置きの文を渡したときは「いつ作った文か」を必ず出し、\n"
           u"        //   そのあと新しく出した子がいれば、その場で作り直せるようにする。\n"
           u"        window.__taiLast = { chars: hit.text.length, blocks: hit.blocks, cached: true, cachedAt: hit.at || 0, noMaterial: hit.noMaterial || 0, peopleWords: hit.peopleWords || 0 };\n"
           u"        copyText(hit.text);\n"
           u"        taiWarnIfStale(cid, hit.at || 0);\n"
           u"        return;\n"
           u"      }\n")

FROM_OLD = u"      var from = m.cached ? '（さっき作ったものを再利用：データベースは読んでいません）' : '';\n"
FROM_NEW = (u"      // 2026-09-29: 取り置きを使ったなら、何時何分に作った文かをその場で出す。\n"
            u"      var from = '';\n"
            u"      if (m.cached) {\n"
            u"        var _ct = m.cachedAt ? new Date(m.cachedAt) : null;\n"
            u"        var _chm = _ct ? (('0' + _ct.getHours()).slice(-2) + ':' + ('0' + _ct.getMinutes()).slice(-2)) : '';\n"
            u"        from = _chm ? ('（今日 ' + _chm + ' に作った文です。作り直してはいません）')\n"
            u"                    : '（さっき作った文をそのまま渡しています）';\n"
            u"      }\n")

FRESH_OLD = (u"  // \U0001f504 最新のデータで作り直す（キャッシュを捨ててから作る）\n"
             u"  async function taiCopyFresh() {\n")
FRESH_NEW = (u"  // 2026-09-29 CLEANUP_S11\n"
             u"  //  取り置きの文を渡したあと、そのあと新しく出した子がいないかを1回だけ数える。\n"
             u"  //  いたときだけ、赤い注意と「作り直してコピー」ボタンをその場に出す。\n"
             u"  //  いなければ何も出さない（ふだんは静かなまま）。\n"
             u"  async function taiWarnIfStale(cid, at) {\n"
             u"    if (!cid || !at) return;\n"
             u"    var el = $('taiStatus');\n"
             u"    if (!el) return;\n"
             u"    var n = 0;\n"
             u"    try {\n"
             u"      var r = await fetch('/api/teacher/class/' + encodeURIComponent(cid) + '/new-since?ts=' + encodeURIComponent(String(at)));\n"
             u"      var j = await r.json();\n"
             u"      n = (j && j.ok) ? Number(j.count || 0) : 0;\n"
             u"    } catch (e) { return; }\n"
             u"    if (!n) return;\n"
             u"    var _t = new Date(at);\n"
             u"    var _hm = ('0' + _t.getHours()).slice(-2) + ':' + ('0' + _t.getMinutes()).slice(-2);\n"
             u"    el.innerHTML =\n"
             u"      '<span style=\"color:#b91c1c;font-weight:800\">⚠ いまコピーしたのは 今日 ' + _hm +\n"
             u"      ' に作った文です。そのあと ' + n + '人が新しく出しています。</span>' +\n"
             u"      ' <button type=\"button\" onclick=\"taiCopyFresh()\" ' +\n"
             u"      'style=\"margin-left:6px;background:#dc2626;color:#fff;border:none;border-radius:8px;padding:5px 12px;font-size:12px;font-weight:800;cursor:pointer\">' +\n"
             u"      'いまのデータで作り直してコピー</button>';\n"
             u"  }\n"
             u"\n"
             u"  // \U0001f504 最新のデータで作り直す（取り置きを捨ててから作る）\n"
             u"  //   ふだんはボタンを出していない。上の赤い注意から呼ばれる。\n"
             u"  async function taiCopyFresh() {\n")

EXP_OLD = u"  window.taiCopyFresh = taiCopyFresh;\n"
EXP_NEW = (u"  window.taiCopyFresh = taiCopyFresh;\n"
           u"  window.taiWarnIfStale = taiWarnIfStale;\n")


def main():
    s = io.open(TSX, encoding='utf-8').read()
    n0 = chain_count(s)
    if n0 != CHAIN_WANT:
        die(u'チェーンが %d 件（%d 件のはず）。止めます。' % (n0, CHAIN_WANT))
    s = rep(s, API_ANCHOR, API_NEW, '新しい入口 new-since')
    s = rep(s, BTN_OLD, BTN_NEW, '作り直すボタンを外す')
    n1 = chain_count(s)
    if n1 != n0:
        die(u'チェーンが %d 件になった' % n1)
    io.open(TSX, 'w', encoding='utf-8').write(s)

    a = io.open(AIJS, encoding='utf-8').read()
    a = rep(a, HIT_OLD, HIT_NEW, '取り置きを使った時')
    a = rep(a, FROM_OLD, FROM_NEW, 'コピー後の文言')
    a = rep(a, FRESH_OLD, FRESH_NEW, '注意を出す処理')
    a = rep(a, EXP_OLD, EXP_NEW, '外に出す')
    io.open(AIJS, 'w', encoding='utf-8').write(a)

    print('PATCH OK / chain %d -> %d' % (n0, n1))


main()
