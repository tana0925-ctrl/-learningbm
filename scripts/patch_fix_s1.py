#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_fix_s1.py --- 総点検 第1陣(1)(2)

【1】/api/teacher/class-analytics が存在しない列 homework_submissions.week_key を
     参照していたため、提出データが常に空だった。
     ・提出率が常に 0%、0/N人
     ・ヒートマップが全員 0回（赤）
     ・在籍児童「全員」に毎回 🔴「今週まだ提出なし」の誤アラート
     ・submission_drop / time_drop アラートは一度も発火していなかった
     本番D1で homework_submissions の列を確認済み（day_key はあるが week_key は無い）。
     両クエリとも try{}catch{} に握り潰されていたため、誰にも見えていなかった。
     V1/V2 で day_key の範囲検索に置き換える。日付範囲の出し方は
     同じ機能の /api/teacher/class/:classId/submission-dashboard と
     まったく同じ（getMondayFromWeekKey → 月曜〜日曜）にそろえる。
     catch も握りつぶしをやめて console.error を残す（同じ事故の再発防止）。

【2】/api/homework/analyze-photo の「1日1回」ゲートが、児童のブラウザが送った
     dayKey で決まっていた。photo_bonus_rewards の主キーは (user_id, day_key) で
     判定自体は正しいが、キーの片方をクライアントが自由に決められるため、
     dayKey を変えるだけでコイン・かけら・やくそう・ボール・強化チケットが
     無制限に取れ、聖なる神(ID 1500)の 1/1000 抽選も無制限に回せた。
     （2026-09-09 時点で悪用の形跡はなし。photo_bonus_rewards 49行の day_key は
       すべて連続した実在の日付だった）

     ※ 単純に jstDayKey() へ差し替えるのは誤り。家庭学習の「学習日」の区切りは
       深夜0時ではなく朝8:30（クライアントの hsGetDayKey830 = ローカル時刻 −8時間30分）。
       jstDayKey() にすると 00:00〜08:30 に出した写真が別の日付で保存され、
       homework_submissions との紐づけ（work_photo_key / GET /api/photo/:userId/:dayKey）
       が切れる。そこで役割を2つに分ける:
         ・写真の保存先キー … これまでどおりクライアント申告。ただし
                              サーバの学習日から前後1日以内に限る（V4）
         ・ごほうびの台帳キー … サーバが決める。クライアント申告は使わない（V5）
       これで台帳は 1日1回に固定され、写真の紐づけは一切変わらない。

【3】(1) を直すと数字は正しくなるが、no_submission アラートの条件は
     「今週まだ提出なし」なので、月曜の朝は全員がまだ0件で、
     やはり毎週「在籍児童全員に🔴」が出る。正しくても警告の意味がない。
     クラスで誰か1人でも提出があってから出すようにする（V6/V7）。
     submission_drop / time_drop は従来どおり。

V3 は上の2つが使う共通ヘルパーを追加する（jstDayKey の隣）。

public/index.html は触りません。
冪等（2回流しても安全）。sentinel と検証用アンカーは別文字列。
"""
import io, os, sys

STEPS = [
 {
  "tag": "V1 class-analytics 今週の提出を day_key の範囲で取る",
  "sen": ".bind(classId, _caMonStr, _caSunStr).all<any>()",
  "old": """  let hwData: any = { results: [] }, prevHwData: any = { results: [] }
  try {
    hwData = await c.env.DB.prepare(`
    SELECT hs.user_id, hs.submitted_at, hs.minutes
    FROM homework_submissions hs
    JOIN class_members cm ON cm.user_id = hs.user_id AND cm.class_id=?
    WHERE hs.week_key=?
  `).bind(classId, weekKey).all<any>()
  } catch {}
""",
  "new": """  // 週の月曜〜日曜（UTC基準）。submission-dashboard とまったく同じ出し方にそろえる。
  // homework_submissions に week_key 列は存在しない（day_key だけ）ので範囲で引く。
  const _caMonday = getMondayFromWeekKey(weekKey)
  const _caSunday = new Date(_caMonday)
  _caSunday.setUTCDate(_caMonday.getUTCDate() + 6)
  const _caMonStr = _caMonday.toISOString().split('T')[0]
  const _caSunStr = _caSunday.toISOString().split('T')[0]
  const _caPrevMonday = getMondayFromWeekKey(prevWeekKey)
  const _caPrevSunday = new Date(_caPrevMonday)
  _caPrevSunday.setUTCDate(_caPrevMonday.getUTCDate() + 6)
  const _caPrevMonStr = _caPrevMonday.toISOString().split('T')[0]
  const _caPrevSunStr = _caPrevSunday.toISOString().split('T')[0]

  let hwData: any = { results: [] }, prevHwData: any = { results: [] }
  try {
    hwData = await c.env.DB.prepare(`
    SELECT hs.user_id, hs.submitted_at, hs.minutes
    FROM homework_submissions hs
    JOIN class_members cm ON cm.user_id = hs.user_id AND cm.class_id=?
    WHERE hs.day_key >= ? AND hs.day_key <= ?
  `).bind(classId, _caMonStr, _caSunStr).all<any>()
  } catch (e) { console.error('class-analytics hwData error:', e) }
"""
 },
 {
  "tag": "V2 class-analytics 先週の提出も day_key の範囲で取る",
  "sen": ".bind(classId, _caPrevMonStr, _caPrevSunStr).all<any>()",
  "old": """    prevHwData = await c.env.DB.prepare(`
    SELECT hs.user_id, COUNT(*) as cnt, SUM(hs.minutes) as totalMin
    FROM homework_submissions hs
    JOIN class_members cm ON cm.user_id = hs.user_id AND cm.class_id=?
    WHERE hs.week_key=?
    GROUP BY hs.user_id
  `).bind(classId, prevWeekKey).all<any>()
  } catch {}
""",
  "new": """    prevHwData = await c.env.DB.prepare(`
    SELECT hs.user_id, COUNT(*) as cnt, SUM(hs.minutes) as totalMin
    FROM homework_submissions hs
    JOIN class_members cm ON cm.user_id = hs.user_id AND cm.class_id=?
    WHERE hs.day_key >= ? AND hs.day_key <= ?
    GROUP BY hs.user_id
  `).bind(classId, _caPrevMonStr, _caPrevSunStr).all<any>()
  } catch (e) { console.error('class-analytics prevHwData error:', e) }
"""
 },
 {
  "tag": "V3 学習日キーの共通ヘルパーを追加",
  "sen": "function jstStudyDayKey(",
  "old": """function jstDayKey(): string {
  return new Date(Date.now() + 9 * 3600 * 1000).toISOString().slice(0, 10)
}
""",
  "new": """function jstDayKey(): string {
  return new Date(Date.now() + 9 * 3600 * 1000).toISOString().slice(0, 10)
}

// 家庭学習の「学習日」キー。区切りは深夜0時ではなく朝8:30。
// クライアントの hsGetDayKey830()（public/index.html）= ローカル時刻 −8時間30分 と同じ定義。
// UTC +9時間(JST) −8時間30分 = UTC +30分。
function jstStudyDayKey(atMs?: number): string {
  return new Date((atMs || Date.now()) + 30 * 60 * 1000).toISOString().slice(0, 10)
}

// クライアントが申告した学習日キーが、サーバの学習日から前後1日以内かを見る。
// 端末の時計ずれや時差は許すが、任意の日付でゲートをすり抜けることは許さない。
function isNearStudyDayKey(k: string): boolean {
  if (!/^\\d{4}-\\d{2}-\\d{2}$/.test(k)) return false
  const now = Date.now()
  for (let d = -1; d <= 1; d++) {
    if (jstStudyDayKey(now + d * 86400000) === k) return true
  }
  return false
}
"""
 },
 {
  "tag": "V4 analyze-photo 申告された dayKey を前後1日に制限",
  "sen": "'day_key_out_of_range'",
  "old": """    const dayKey = String(formData.get('dayKey') || '').slice(0, 10)
    if (!dayKey) return jsonError(c, 400, 'day_key_required')
""",
  "new": """    const dayKey = String(formData.get('dayKey') || '').slice(0, 10)
    if (!dayKey) return jsonError(c, 400, 'day_key_required')
    // 写真の保存先キーは homework_submissions と合わせるためクライアント申告のままだが、
    // 任意の日付は受け付けない（サーバの学習日から前後1日まで）。
    if (!isNearStudyDayKey(dayKey)) return jsonError(c, 400, 'day_key_out_of_range')
"""
 },
 {
  "tag": "V5 写真ボーナスの台帳キーをサーバが決める",
  "sen": ".bind(u.id, jstStudyDayKey(), _res, _amt).run()",
  "old": """.bind(u.id, dayKey, _res, _amt).run()""",
  "new": """.bind(u.id, jstStudyDayKey(), _res, _amt).run()"""
 },
 {
  "tag": "V6 クラスに今週の提出があるかを先に数える",
  "sen": "const _caAnySubmission =",
  "old": """  const alerts: { userId: string, loginId: string, name: string, type: string, detail: string }[] = []
""",
  "new": """  // クラスで誰か1人でも今週の提出があるか。
  // 月曜の朝は全員がまだ0件なので、そのまま no_submission を出すと
  // 毎週「在籍児童全員に🔴」になり、警告として意味がなくなる。
  const _caAnySubmission = Object.keys(thisHwByUser).length > 0

  const alerts: { userId: string, loginId: string, name: string, type: string, detail: string }[] = []
"""
 },
 {
  "tag": "V7 誰も出していないうちは no_submission を出さない",
  "sen": "if (!thisW && _caAnySubmission) {",
  "old": """    // 今週ゼロ提出
    if (!thisW && (members.results || []).length > 0) {
      alerts.push({ userId: m.id, loginId: m.loginId, name: m.name, type: 'no_submission', detail: '今週まだ提出なし' })
    }
""",
  "new": """    // 今週ゼロ提出（クラスで誰か1人でも提出があってから出す）
    if (!thisW && _caAnySubmission) {
      alerts.push({ userId: m.id, loginId: m.loginId, name: m.name, type: 'no_submission', detail: '今週まだ提出なし' })
    }
"""
 },
]

# パッチ後も必ず残っていなければいけないもの
MUST = [
 "app.get('/api/teacher/class-analytics'",
 "app.get('/api/teacher/class/:classId/submission-dashboard'",
 "app.post('/api/homework/analyze-photo'",
 "function getMondayFromWeekKey(",
 "function getPrevWeekKey(",
 "function jstDayKey(): string {",
 "CREATE TABLE IF NOT EXISTS photo_bonus_rewards",
 "PRIMARY KEY(user_id, day_key)",
 "if (_ins.meta && _ins.meta.changes === 1) {",
 "photoLegend = { id: 1500, name: '聖なる神', sprite: '😇' }",
 "INSERT INTO homework_photos (user_id, day_key, mime_type, bytes, byte_size)",
 "UPDATE homework_submissions SET work_photo_key=? WHERE id=?",
 "type: 'no_submission', detail: '今週まだ提出なし'",
 "SELECT hs.user_id, hs.submitted_at, hs.minutes",
]

# パッチ後に残っていてはいけないもの
BAD = [
 "hs.week_key",                            # 存在しない列への参照
 ".bind(classId, prevWeekKey).all<any>()", # 先週の提出を週キーで引いていた旧クエリ
 ".bind(u.id, dayKey, _res, _amt)",        # 台帳キーがクライアント申告だった旧コード
 "if (!thisW && (members.results || []).length > 0) {",  # 常に真だった旧条件
]

# 数で見る検証（週キーは student_weekly_plans では正しく使われているので、
# 「週キーを全部消す」ではなく「homework_submissions から消す」であることを数で確かめる）
COUNTS = [
 (".bind(classId, weekKey).all<any>()", 4, 3),  # hwData の1本だけ減る
]


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tsx = os.path.join(root, 'src', 'index.tsx')
    src = io.open(tsx, encoding='utf-8', newline='').read()
    orig = src
    changes = []

    def fail(msg):
        print('❌ 中止: ' + msg)
        sys.exit(1)

    # src/index.tsx は LF。CRLF が混ざっていたら前提が崩れているので止める。
    if '\r\n' in src:
        fail('src/index.tsx に CRLF が混ざっています（LF のはず）')

    for st in STEPS:
        if st['sen'] in src:
            print('⏭ %s は適用済み（スキップ）' % st['tag']); continue
        n = src.count(st['old'])
        if n == 0: fail('%s のアンカーが見つかりません' % st['tag'])
        if n != 1: fail('%s のアンカーが %d 箇所（1箇所のはず）' % (st['tag'], n))
        src = src.replace(st['old'], st['new'], 1)
        changes.append(st['tag'])

    # 本番HTMLへの置換チェーン（25件）が壊れていないこと
    def root_replace_count(text):
        a = text.index("app.get('/', async (c) => {")
        b = text.index("app.get('/logout'", a)
        return text[a:b].count('.replace(')

    if root_replace_count(orig) != root_replace_count(src):
        fail('本番HTMLの置換チェーンの数が変わりました（%d -> %d）'
             % (root_replace_count(orig), root_replace_count(src)))
    print('\U0001f50e 置換チェーン: %d 件（適用前後で同数）' % root_replace_count(src))

    for m in MUST:
        if m not in src: fail('必須の要素が失われました: %s' % m)
    for x in BAD:
        if x in src: fail('消したはずのコードが残っています: %s' % x)
    for needle, before, after in COUNTS:
        # 2回目以降（適用済み）は after と一致するので、どちらでも通す
        if orig.count(needle) not in (before, after):
            fail('前提が違います: %s が適用前に %d 箇所（%d か %d のはず）'
                 % (needle, orig.count(needle), before, after))
        if src.count(needle) != after:
            fail('%s が適用後に %d 箇所（%d のはず）' % (needle, src.count(needle), after))

    # 追加の整合チェック
    if src.count('isNearStudyDayKey') != 2:
        fail('isNearStudyDayKey の定義+使用が 2 箇所ではありません（%d）' % src.count('isNearStudyDayKey'))
    if src.count('jstStudyDayKey') != 3:
        fail('jstStudyDayKey の出現が 3 箇所ではありません（%d）' % src.count('jstStudyDayKey'))
    if src.count('_caMonStr') != 2 or src.count('_caPrevMonStr') != 2:
        fail('週の日付範囲の変数の出現数がおかしい')
    if src.count('_caAnySubmission') != 2:
        fail('_caAnySubmission の定義+使用が 2 箇所ではありません（%d）' % src.count('_caAnySubmission'))

    if src != orig:
        io.open(tsx, 'w', encoding='utf-8', newline='').write(src)
        print('✅ src/index.tsx を更新しました')
    else:
        print('… 変更なし')
    print('---- 適用した項目 ----')
    for c in changes: print(' ・' + c)
    if not changes: print(' （なし）')


if __name__ == '__main__':
    main()
