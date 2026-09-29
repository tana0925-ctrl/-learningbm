# -*- coding: utf-8 -*-
"""
patch_cleanup_s10.py — 別件2つを直す（その1）
2026-09-29  CLEANUP_S10

(1) 教師ダッシュボード左上の「undefined ()」
  原因：/api/auth/me は role が 'teacher' のときだけ名前を引いていた。
        この学校の先生は role が 'admin' で入っているため、名前を引く処理を
        素通りして、画面に undefined がそのまま出ていた（本番で確認）。
  直し：admin も teacher と同じ道を通す。名前は
        teacher_accounts → users の順に探し、どちらにも無ければ
        ログインIDを出す。空欄にはしない。
        画面側も、学校名が空のときは「（）」を出さないようにした。

(2) 人数が間違って出る
  本番の実データで確かめたこと：
   ・「6年１組」… 画面は 23人。実際に在籍している子は 1人。
     class_members に、すでに消えた利用者の行が 22件 残っており、
     人数がその行数をそのまま数えていた。
   ・「６年２組」… 画面は 23人。子どもは 22人。
     残りの1つは先生ご自身のアカウント（tanaken）がクラスに入っているぶん。
     カルテ印刷や直接入力の名簿にも、先生ご自身が1人分まざっていた。
  直し：人数と名簿は「子ども（role='student'）として今いる人」だけを数える。
     ・管理画面のクラス一覧 … 「子ども ◯人」と書く。
       行数と食い違うときは「＋ 使われていない登録 ◯件」も小さく出す（黙って隠さない）。
     ・教師画面のクラス一覧／「今日の学習状況」の分母／未学習リスト
     ・カルテ印刷・直接入力・授業メモの名簿、学習分析の人数
  ※ class_members の行は1件も消していない（数え方だけを直した）。

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


# ---------------------------------------------------------------- (1) 名前
ME_OLD = (u"  if (u.role === 'teacher') {\n"
          u"    const row = await c.env.DB.prepare(`SELECT name, school FROM teacher_accounts WHERE id = ? LIMIT 1`).bind(u.id).first<any>()\n"
          u"    return c.json({ ok: true, user: { ...u, name: row?.name, school: row?.school, grade: null } })\n"
          u"  }\n")
ME_NEW = (u"  // 2026-09-29: ここは role==='teacher' のときしか名前を引いていなかった。\n"
          u"  //   この学校の先生は role==='admin' で入っているため素通りしてしまい、\n"
          u"  //   教師ダッシュボードの左上が「undefined ()」と出ていた（本番で確認）。\n"
          u"  //   admin も同じ道を通し、名前は teacher_accounts → users の順に探す。\n"
          u"  //   どちらにも無ければログインIDを返す（空欄にはしない）。\n"
          u"  if (u.role === 'teacher' || u.role === 'admin') {\n"
          u"    let _nm = ''\n"
          u"    let _sc = ''\n"
          u"    try {\n"
          u"      const row = await c.env.DB.prepare(`SELECT name, school FROM teacher_accounts WHERE id = ? LIMIT 1`).bind(u.id).first<any>()\n"
          u"      if (row) { _nm = String(row.name || ''); _sc = String(row.school || '') }\n"
          u"    } catch {}\n"
          u"    if (!_nm) {\n"
          u"      try {\n"
          u"        const row2 = await c.env.DB.prepare(`SELECT name FROM users WHERE id = ? LIMIT 1`).bind(u.id).first<any>()\n"
          u"        if (row2) _nm = String(row2.name || '')\n"
          u"      } catch {}\n"
          u"    }\n"
          u"    if (!_nm) _nm = String(u.loginId || '')\n"
          u"    return c.json({ ok: true, user: { ...u, name: _nm, school: _sc, grade: null } })\n"
          u"  }\n")

INFO_OLD = u"        document.getElementById('teacherInfo').textContent = me.user.name + '（' + (me.user.school||'') + '）';"
INFO_NEW = (u"        /* 2026-09-29: 名前が取れないときに「undefined ()」と出ていた。\n"
            u"           名前 → ログインID の順に出す。学校名が空なら かっこ自体を出さない。 */\n"
            u"        var _tNm = String((me.user && me.user.name) || '').trim() || String((me.user && me.user.loginId) || '').trim() || '先生';\n"
            u"        var _tSc = String((me.user && me.user.school) || '').trim();\n"
            u"        document.getElementById('teacherInfo').textContent = _tNm + (_tSc ? '（' + _tSc + '）' : '');")

# ---------------------------------------------------------------- (2) 人数
ADM_OLD = (u"     (SELECT COUNT(*) FROM class_members cm WHERE cm.class_id = c.id) as memberCount\n")
ADM_NEW = (u"     (SELECT COUNT(*) FROM class_members cm JOIN users su ON su.id = cm.user_id WHERE cm.class_id = c.id AND su.role = 'student') as memberCount,\n"
           u"     (SELECT COUNT(*) FROM class_members cm WHERE cm.class_id = c.id) as rowCount\n")

TEA_OLD = (u"         (SELECT COUNT(*) FROM class_members cm WHERE cm.class_id = classes.id) as memberCount\n")
TEA_NEW = (u"         (SELECT COUNT(*) FROM class_members cm JOIN users su ON su.id = cm.user_id WHERE cm.class_id = classes.id AND su.role = 'student') as memberCount\n")

ACT_OLD = (u"    `SELECT u.id, u.login_id as loginId, u.name, u.last_login_at as lastLoginAt\n"
           u"     FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id = ?`\n")
ACT_NEW = (u"    `SELECT u.id, u.login_id as loginId, u.name, u.last_login_at as lastLoginAt\n"
           u"     FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id = ? AND u.role = 'student'`\n")

ROS_OLD = (u"SELECT u.id, u.login_id as loginId, u.name FROM class_members cm "
           u"JOIN users u ON u.id=cm.user_id WHERE cm.class_id=?').bind(classId).all<any>()")
ROS_NEW = (u"SELECT u.id, u.login_id as loginId, u.name FROM class_members cm "
           u"JOIN users u ON u.id=cm.user_id WHERE cm.class_id=? AND u.role=?').bind(classId, 'student').all<any>()")

NOT_OLD = (u"SELECT u.id as userId, u.login_id as loginId, u.name FROM class_members cm "
           u"JOIN users u ON u.id=cm.user_id WHERE cm.class_id=? ORDER BY u.name').bind(classId).all<any>()")
NOT_NEW = (u"SELECT u.id as userId, u.login_id as loginId, u.name FROM class_members cm "
           u"JOIN users u ON u.id=cm.user_id WHERE cm.class_id=? AND u.role=? ORDER BY u.name').bind(classId, 'student').all<any>()")

BADGE_OLD = (u"              ' <span class=\"bg-indigo-100 text-indigo-700 rounded px-2 py-0.5 text-xs ml-1\">' + cls.memberCount + '人</span>';\n")
BADGE_NEW = (u"              ' <span class=\"bg-indigo-100 text-indigo-700 rounded px-2 py-0.5 text-xs ml-1\">子ども ' + cls.memberCount + '人</span>' +\n"
             u"              /* 2026-09-29: いままでは class_members の行数をそのまま出していたため、\n"
             u"                 すでに消えた利用者の行や、先生ご自身のアカウントのぶんまで人数に入っていた。\n"
             u"                 人数は「いまいる子ども」だけにし、食い違うぶんは小さく別に出す（黙って隠さない）。 */\n"
             u"              ((cls.rowCount != null && cls.rowCount > cls.memberCount)\n"
             u"                ? ' <span class=\"text-xs text-gray-400\" title=\"すでに消えた利用者や先生のアカウントが、クラスの登録に残っています\">＋ 使われていない登録 ' + (cls.rowCount - cls.memberCount) + '件</span>'\n"
             u"                : '');\n")


def main():
    s = io.open(TSX, encoding='utf-8').read()
    n0 = chain_count(s)
    if n0 != CHAIN_WANT:
        die(u'チェーンが %d 件（%d 件のはず）。止めます。' % (n0, CHAIN_WANT))

    s = rep(s, ME_OLD, ME_NEW, '(1) /api/auth/me')
    s = rep(s, INFO_OLD, INFO_NEW, '(1) 左上の表示')
    s = rep(s, ADM_OLD, ADM_NEW, '(2) 管理画面の人数')
    s = rep(s, TEA_OLD, TEA_NEW, '(2) 教師画面の人数')
    s = rep(s, ACT_OLD, ACT_NEW, '(2) 今日の学習状況の分母')
    s = rep(s, ROS_OLD, ROS_NEW, '(2) 名簿3か所', times=3)
    s = rep(s, NOT_OLD, NOT_NEW, '(2) 授業メモの名簿')
    s = rep(s, BADGE_OLD, BADGE_NEW, '(2) 管理画面の人数表示')

    n1 = chain_count(s)
    if n1 != n0:
        die(u'チェーンが %d 件になった' % n1)
    io.open(TSX, 'w', encoding='utf-8').write(s)
    print('PATCH OK / chain %d -> %d' % (n0, n1))


main()
