// ==================== __TEACHER_SCREEN_PREVIEW_V1__ ====================
// 👀 児童画面プレビュー（先生用・完全に読み取り専用）
//
// 目的:
//   先生の言葉「子供の画面にどうでてるかよくわからないんだよね」に答える。
//   ある児童の画面に「先生から届くもの」が今どう出ているかを、先生が自分で確かめられるようにする。
//
// 設計上の約束（このブロックは以下を破らない）:
//   - すべて requireTeacher の内側。対象は「自分が担任のクラス(classes.teacher_id = 自分)」の児童のみ。
//     送られてきた studentId は必ず DB 側で担任クラス所属を再照合し、通らなければ 404。
//   - SELECT しか書かない。INSERT / UPDATE / DELETE は1つも無い。
//   - DDL は一切走らせない（CREATE / ALTER / DROP なし＝マイグレーション不要）。
//   - progress.state_json には触れない。
//   - 児童になりすまさない。セッションも作らない。児童用APIも呼ばない。DBを読んで並べるだけ。
//   - ポーリングなし（画面を開いた時と「再読み込み」を押した時だけ取得）。
//   - サーバーからは見えないもの（端末の localStorage / 端末内 state_json）は
//     uncertain を付けて「ここは分かりません」と正直に返す。嘘の「出ています」を作らない。
//
// 読み取り件数: 1児童あたり最大15クエリ（すべて LIMIT 付き）。

app.get('/teacher-preview.js', async (c) => {
  try {
    const a = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/teacher-preview.js')))
    if (a && a.status === 200) {
      return new Response(await a.text(), {
        headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' },
      })
    }
  } catch (e) {}
  return c.text('not found', 404)
})

// 1件だけ安全に取る（テーブル・カラムが無い環境でも 500 にしない）
async function _tspOne(c: any, sql: string, binds: any[]): Promise<any> {
  try { return await c.env.DB.prepare(sql).bind(...binds).first<any>() } catch (e) { return null }
}
async function _tspAll(c: any, sql: string, binds: any[]): Promise<any[]> {
  try {
    const r = await c.env.DB.prepare(sql).bind(...binds).all<any>()
    return (r && r.results) ? r.results : []
  } catch (e) { return [] }
}

app.get('/api/teacher/student-screen-preview', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const studentId = String(c.req.query('studentId') || '')
  if (!studentId) return jsonError(c, 400, 'studentId_required')

  // --- 担任クラスの児童かどうかを DB 側で再照合（ここを通らなければ何も読まない） ---
  const mem = u.role === 'admin'
    ? await _tspOne(c, 'SELECT cm.class_id AS classId FROM class_members cm WHERE cm.user_id=? LIMIT 1', [studentId])
    : await _tspOne(c, 'SELECT cm.class_id AS classId FROM class_members cm JOIN classes cl ON cl.id=cm.class_id AND cl.teacher_id=? WHERE cm.user_id=? LIMIT 1', [u.id, studentId])
  if (!mem || !mem.classId) return jsonError(c, 404, 'student_not_found')
  const classId = String(mem.classId)

  const weekKey = String(c.req.query('weekKey') || getWeekKey()).slice(0, 10)
  const prevWeekKey = getPrevWeekKey(weekKey)
  const thisWeekKey = getWeekKey()

  // --- 児童とクラスの基本情報 ---
  const stu = await _tspOne(c, 'SELECT id, name, grade, class_name AS className, login_id AS loginId, last_login_at AS lastLoginAt FROM users WHERE id=? LIMIT 1', [studentId])
  if (!stu) return jsonError(c, 404, 'student_not_found')

  const cls = await _tspOne(c, 'SELECT id, name, homework_enabled AS homeworkEnabled, contact_enabled AS contactEnabled, ranking_enabled AS rankingEnabled, menus_enabled AS menusEnabled FROM classes WHERE id=? LIMIT 1', [classId])

  // --- 週の計画まわり（計画アドバイス / 阪神マンのおすすめ / 承認 / 振り返り返却） ---
  const plan = await _tspOne(c,
    'SELECT plan_ai_comment AS planAiComment, plan_ai_comment_at AS planAiCommentAt, plan_suggestion AS planSuggestion, plan_suggestion_at AS planSuggestionAt, plan_approved AS planApproved, plan_approved_at AS planApprovedAt, reflection_comment AS reflectionComment, reflection_returned_at AS reflectionReturnedAt FROM student_weekly_plans WHERE user_id=? AND week_key=? LIMIT 1',
    [studentId, weekKey])

  // --- 📒 わたしのカルテ（公開制） ---
  const karteShared = await _tspOne(c, 'SELECT shared_at AS sharedAt FROM student_karte_shared WHERE user_id=? LIMIT 1', [studentId])
  const karteMsg = await _tspOne(c, 'SELECT comment, updated_at AS updatedAt FROM student_ai_comments WHERE user_id=? LIMIT 1', [studentId])

  // カルテの中身は児童用 /api/student/my-karte と同じ作り方（日本時間の月〜金）
  const jst = new Date(Date.now() + 9 * 3600000)
  const wd = (jst.getUTCDay() + 6) % 7
  const monMs = jst.getTime() - wd * 86400000
  const ymd = (ms: number) => new Date(ms).toISOString().slice(0, 10)
  const dayKeys: string[] = []
  for (let i = 0; i < 5; i++) dayKeys.push(ymd(monMs + i * 86400000))

  const karteSubs = await _tspAll(c, 'SELECT day_key AS dayKey, minutes, end_weather AS endWeather, weather_reason AS weatherReason FROM homework_submissions WHERE user_id=? AND day_key >= ? AND day_key <= ?', [studentId, dayKeys[0], dayKeys[4]])
  const byDay: Record<string, any> = {}
  for (const s of karteSubs) byDay[String(s.dayKey)] = s
  const DOWJA = ['月', '火', '水', '木', '金']
  const karteDays: any[] = []
  const karteVoices: string[] = []
  let karteDone = 0, karteMinutes = 0
  for (let i = 0; i < 5; i++) {
    const s = byDay[dayKeys[i]]
    if (s) {
      karteDone++
      karteMinutes += Number(s.minutes || 0)
      if (s.weatherReason) karteVoices.push(DOWJA[i] + ' ' + String(s.weatherReason).slice(0, 200))
      karteDays.push({ weather: String(s.endWeather || '') })
    } else {
      karteDays.push(null)
    }
  }
  const refl = await _tspOne(c, 'SELECT good_point AS goodPoint, improve_point AS improvePoint, next_action AS nextAction FROM structured_reflections WHERE user_id=? AND week_key IN (?, ?) ORDER BY week_key DESC LIMIT 1', [studentId, dayKeys[0], weekKey])

  // --- 家庭学習の返却コメント ---
  const hw = await _tspAll(c,
    'SELECT id, day_key AS dayKey, teacher_comment AS teacherComment, returned_at AS returnedAt, reward_claimed AS rewardClaimed, has_physical AS hasPhysical FROM homework_submissions WHERE user_id=? ORDER BY submitted_at DESC LIMIT 10',
    [studentId])

  // --- 先生からのメッセージ（メール画面） ---
  const msgs = await _tspAll(c,
    "SELECT id, body, read_at AS readAt, created_at AS createdAt FROM messages WHERE recipient_id=? AND sender_role IN ('teacher','admin') ORDER BY created_at DESC LIMIT 10",
    [studentId])

  // --- おしらせ（全体向け + 自分のクラス向け） ---
  const anns = await _tspAll(c,
    'SELECT a.id, a.title, a.body, a.created_at AS createdAt, a.class_id AS annClassId, ar.read_at AS readAt FROM announcements a LEFT JOIN announcement_reads ar ON ar.announcement_id = a.id AND ar.user_id = ? WHERE a.class_id IS NULL OR a.class_id = ? ORDER BY a.created_at DESC LIMIT 10',
    [studentId, classId])

  // --- 連絡帳 ---
  const notes = await _tspAll(c,
    'SELECT cn.id, cn.day_key AS dayKey, cn.body, cn.reward_deadline AS rewardDeadline, cn.reward_coins AS rewardCoins, cn.created_at AS createdAt, cnr.read_at AS readAt, cnr.reward_claimed AS rewardClaimed FROM contact_notes cn LEFT JOIN contact_note_reads cnr ON cnr.note_id = cn.id AND cnr.user_id = ? WHERE cn.class_id = ? ORDER BY cn.created_at DESC LIMIT 10',
    [studentId, classId])

  // --- 今週のメニュー（未配信なら前週にフォールバックするのも児童画面と同じ） ---
  const menuNow = await _tspOne(c, 'SELECT kanji_page AS kanjiPage, keisan_page AS keisanPage, other_tasks AS otherTasks, tests, week_key AS menuWeekKey, active_days AS activeDays FROM class_weekly_menu WHERE class_id = ? AND week_key = ? LIMIT 1', [classId, weekKey])
  const menuPrev = menuNow ? null : await _tspOne(c, 'SELECT kanji_page AS kanjiPage, keisan_page AS keisanPage, other_tasks AS otherTasks, tests, week_key AS menuWeekKey, active_days AS activeDays FROM class_weekly_menu WHERE class_id = ? AND week_key = ? LIMIT 1', [classId, prevWeekKey])

  // --- クラスミッション ---
  const mission = await _tspOne(c, 'SELECT id, title, goal_correct AS goalCorrect, reward_coins AS rewardCoins, reward_shards AS rewardShards, start_at AS startAt, end_at AS endAt FROM class_missions WHERE class_id=? ORDER BY created_at DESC LIMIT 1', [classId])
  const missionClaim = mission ? await _tspOne(c, 'SELECT 1 AS c FROM class_mission_claims WHERE mission_id=? AND user_id=? LIMIT 1', [mission.id, studentId]) : null

  // --- ごほうびの通知（先生発ではないが児童画面には出る） ---
  const rk = await _tspOne(c, 'SELECT COUNT(*) AS cnt FROM ranking_rewards WHERE user_id=? AND COALESCE(seen,0)=0', [studentId])
  const df = await _tspOne(c, 'SELECT COUNT(*) AS cnt FROM defense_rewards WHERE user_id=? AND COALESCE(seen,0)=0', [studentId])

  const txt = (v: any) => (v == null ? '' : String(v))
  const has = (v: any) => txt(v).trim().length > 0

  return c.json({
    ok: true,
    generatedAt: new Date().toISOString(),
    weekKey, prevWeekKey, thisWeekKey, isThisWeek: (weekKey === thisWeekKey),
    student: {
      id: stu.id, name: stu.name, grade: stu.grade, className: stu.className,
      loginId: stu.loginId, lastLoginAt: stu.lastLoginAt || null,
    },
    klass: cls ? {
      id: cls.id, name: cls.name,
      homeworkEnabled: Number(cls.homeworkEnabled == null ? 1 : cls.homeworkEnabled),
      contactEnabled: Number(cls.contactEnabled == null ? 1 : cls.contactEnabled),
      rankingEnabled: Number(cls.rankingEnabled == null ? 0 : cls.rankingEnabled),
      menusEnabled: cls.menusEnabled || null,
    } : null,
    items: {
      planAiComment: {
        text: txt(plan && plan.planAiComment),
        at: (plan && plan.planAiCommentAt) || null,
        present: has(plan && plan.planAiComment),
      },
      planSuggestion: {
        text: txt(plan && plan.planSuggestion),
        at: (plan && plan.planSuggestionAt) || null,
        present: has(plan && plan.planSuggestion),
      },
      planApproved: {
        approved: Number((plan && plan.planApproved) || 0),
        at: (plan && plan.planApprovedAt) || null,
      },
      reflectionReturn: {
        comment: txt(plan && plan.reflectionComment),
        returnedAt: (plan && plan.reflectionReturnedAt) || null,
        present: has(plan && plan.reflectionComment),
      },
      karte: {
        published: !!karteShared,
        sharedAt: (karteShared && karteShared.sharedAt) || null,
        teacherMessage: txt(karteMsg && karteMsg.comment),
        teacherMessageAt: (karteMsg && karteMsg.updatedAt) || null,
        week: { days: karteDays, done: karteDone, minutes: karteMinutes, voices: karteVoices },
        reflection: refl ? {
          goodPoint: txt(refl.goodPoint).slice(0, 300),
          improvePoint: txt(refl.improvePoint).slice(0, 300),
          nextAction: txt(refl.nextAction).slice(0, 100),
        } : null,
      },
      homework: hw.map((r: any) => ({
        id: r.id, dayKey: r.dayKey,
        teacherComment: txt(r.teacherComment),
        returnedAt: r.returnedAt || null,
        rewardClaimed: Number(r.rewardClaimed || 0),
        hasPhysical: Number(r.hasPhysical || 0),
      })),
      messages: msgs.map((r: any) => ({ id: r.id, body: txt(r.body), readAt: r.readAt || null, createdAt: r.createdAt })),
      announcements: anns.map((r: any) => ({ id: r.id, title: txt(r.title), body: txt(r.body), createdAt: r.createdAt, readAt: r.readAt || null, wholeSchool: !r.annClassId })),
      contactNotes: notes.map((r: any) => ({ id: r.id, dayKey: r.dayKey, body: txt(r.body), createdAt: r.createdAt, readAt: r.readAt || null, rewardDeadline: r.rewardDeadline || null, rewardCoins: Number(r.rewardCoins || 0) })),
      weeklyMenu: {
        published: !!menuNow,
        menu: menuNow || menuPrev || null,
        fallbackWeek: menuNow ? null : (menuPrev ? prevWeekKey : null),
      },
      classMission: mission ? {
        id: mission.id, title: txt(mission.title),
        goalCorrect: Number(mission.goalCorrect || 0),
        rewardCoins: Number(mission.rewardCoins || 0), rewardShards: Number(mission.rewardShards || 0),
        startAt: mission.startAt, endAt: mission.endAt || null,
        claimed: !!missionClaim,
      } : null,
      rankingRewardsUnseen: Number((rk && rk.cnt) || 0),
      defenseRewardsUnseen: Number((df && df.cnt) || 0),
    },
  })
})
// ==================== /__TEACHER_SCREEN_PREVIEW_V1__ ====================

