# -*- coding: utf-8 -*-
# __DEF_AUTO_RESOLVE_V1__ src/index.tsx への 配線だけ。
#
# やること（ぜんぶ 冪等・あて先が 1つでなければ 何も 書かずに 止まる）
#   1) src/def_auto_resolve.ts を import する
#   2) いちばん下で registerDefAutoResolve(app, {...}) を 登録する
#   3) /api/defense/status の 中から defAutoResolveHook を 1行 よぶ（案B）
#   4) 先生画面の 20秒タイマーを 直す
#      ・1回 しくじっても 1分ごとに もう一度 たたく
#      ・タブが もどってきた / 窓に focus / ネットが つながった ときに すぐ 見る
#   5) 先生画面に「12:30に 動かなかった」ことを 出す 帯を 足す
#
# 配信チェーン（app.get('/') の中の .replace( の数）は 104 のまま。
# 防衛戦の 戦闘エンジン（def_engine / def_resolve / def_stage / def_dex）には さわらない。

import io
import sys

PATH = "src/index.tsx"
MARK = "__DEF_AUTO_RESOLVE_V1__"


def die(msg):
    print("NG: " + msg)
    sys.exit(1)


def chain_count(s):
    i = s.find("app.get('/', async (c) => {")
    if i < 0:
        die("app.get('/', async (c) => { が 見つかりません")
    j = s.find("app.get('/logout'", i)
    if j < 0:
        die("app.get('/logout' が 見つかりません")
    return s[i:j].count(".replace(")


def once(s, anchor, label):
    n = s.count(anchor)
    if n != 1:
        die("あて先が 1つでは ありません（" + label + " / " + str(n) + "件）")
    return True


def put_after(s, anchor, add, label):
    once(s, anchor, label)
    return s.replace(anchor, anchor + add, 1)


def put_before(s, anchor, add, label):
    once(s, anchor, label)
    return s.replace(anchor, add + anchor, 1)


src = io.open(PATH, encoding="utf-8").read()
before_chain = chain_count(src)
print("chain(before):", before_chain)
if before_chain != 104:
    die("チェーンが 104件では ありません（" + str(before_chain) + "件）。ほかの作業と ぶつかっています。止めます。")

orig = src

# ---- 1) import ------------------------------------------------------------
A1 = "import { registerDefTeacherStart } from './def_teacher_start'"
if "from './def_auto_resolve'" not in src:
    src = put_after(
        src, A1,
        "\n// " + MARK + " 先生が 画面を ひらいていなくても 12:30 に 決戦が おきるようにする\n"
        "import { registerDefAutoResolve, defAutoResolveHook } from './def_auto_resolve'",
        "import",
    )

# ---- 2) 登録 --------------------------------------------------------------
A2 = "export default app"
if "registerDefAutoResolve(app, {" not in src:
    reg = (
        "// " + MARK + " だれの端末も 要らない 入口 /api/defense/auto-resolve と\n"
        "// 先生むけの 見はり /api/teacher/defense/health を 登録する。\n"
        "// わたす ものは registerDefTeacherStart と まったく 同じ。\n"
        "registerDefAutoResolve(app, {\n"
        "  requireTeacher: requireTeacher,\n"
        "  jsonError: jsonError,\n"
        "  defenseSettings: defenseSettings,\n"
        "  defServerResolve: defServerResolve,\n"
        "  defEntryOk: defEntryOk,\n"
        "  defDexEntry: defDexEntry,\n"
        "  defCarrySnapOk: defCarrySnapOk,\n"
        "  defStageEnemies: defStageEnemies,\n"
        "  defBossApply: defBossApply,\n"
        "  DEFENSE_ENEMIES: DEFENSE_ENEMIES,\n"
        "  defEntryCount: defEntryCount,\n"
        "  defMvpMakeLedger: defMvpMakeLedger,\n"
        "  defStageMakeLedger: defStageMakeLedger,\n"
        "  DEFENSE_WIN_COINS: DEFENSE_WIN_COINS,\n"
        "  DEFENSE_ENTRY_BONUS_COINS: DEFENSE_ENTRY_BONUS_COINS\n"
        "})\n\n"
    )
    src = put_before(src, A2, reg, "register")

# ---- 3) 児童の status から 決着まで（案B） --------------------------------
A3 = 'const es = await c.env.DB.prepare("SELECT de.monster_json as mj, de.strategy as strat'
if "defAutoResolveHook(c.env, st, classId)" not in src:
    hook = (
        "// " + MARK + " 決戦時刻を すぎていて まだ 結果が 無いなら、ここで 決着させる。\n"
        "        // 2分に 1台だけ 通す（defense_carry_lock の にせ鍵）ので、\n"
        "        // 22台で 戦闘計算が 走ることは ない。しくじっても 児童の画面は 止めない。\n"
        "        try { await defAutoResolveHook(c.env, st, classId) } catch (_e) {}\n"
        "        "
    )
    src = put_before(src, A3, hook, "status hook")

# ---- 4) 先生画面の タイマーを 直す ----------------------------------------
A4 = "var _defTsFired = '';"
if "var _defTsLast = 0;" not in src:
    src = put_after(
        src, A4,
        "\n      /* " + MARK + " 1回 しくじっても もう一度 たたけるように、さいごに たたいた時刻を のこす。 */\n"
        "      var _defTsLast = 0;",
        "_defTsLast",
    )

A5 = "_defTsFired = st.event_key;"
if "_defTsFired = st.event_key; _defTsLast = Date.now();" not in src:
    src = put_after(src, A5, " _defTsLast = Date.now();", "_defTsLast set")

A6 = "defTsMsg('決戦の時刻をすぎています。出陣 ' + (st.entries || 0) + '人。ボタンでもはじめられます。');"
if "_arNow - _defTsLast > 60000" not in src:
    retry = (
        "\n        /* " + MARK + " 1回 たたいても 決着していないなら 1分ごとに もう一度 たたく。\n"
        "           もとは たたく前に _defTsFired を 立てるだけだったので、通信が 1回 しくじると\n"
        "           そのページでは 二度と たたかず、だまったままに なっていた。 */\n"
        "        var _arNow = Date.now();\n"
        "        if(_arNow - _defTsLast > 60000){ _defTsLast = _arNow; defTeacherStart(); }"
    )
    src = put_after(src, A6, retry, "retry")

A7 = "setInterval(function(){ try{ defTeacherTick(); }catch(e){ console.error('[__DEF_TEACHER_START_V1__]', e); } }, 20000);"
if "visibilitychange" not in src:
    wake = (
        "\n      /* " + MARK + " タブが うしろに まわると setInterval は 1分に1回まで しぼられ、\n"
        "         PCが スリープ・画面ロックすると 止まる。もどってきた ときに すぐ 見にいく。 */\n"
        "      document.addEventListener('visibilitychange', function(){ if(!document.hidden){ try{ defTeacherTick(); }catch(e){} } });\n"
        "      window.addEventListener('focus', function(){ try{ defTeacherTick(); }catch(e){} });\n"
        "      window.addEventListener('online', function(){ try{ defTeacherTick(); }catch(e){} });"
    )
    src = put_after(src, A7, wake, "wake")

# ---- 5) 「動かなかった」ことに 気づく 帯 ----------------------------------
A8 = '<div id="defStartBox" class="mt-3 hidden">'
if 'id="defHealthBox"' not in src:
    box = (
        "<!-- " + MARK + " 12:30に 動かなかったことに 気づけるように する -->\n"
        '          <div id="defHealthBox" class="mt-3 hidden text-xs rounded-lg px-3 py-2"></div>\n'
        "          "
    )
    src = put_before(src, A8, box, "health box")

if "loadDefHealth" not in src:
    health = (
        "\n      /* " + MARK + " 「昨日は 12:30に 動きませんでした」を 先生の画面に 出す。\n"
        "         event_key（予定の時刻）と resolved_at（じっさいに 動いた時刻）の 差を 見るだけ。 */\n"
        "      async function loadDefHealth(){\n"
        "        var box = document.getElementById('defHealthBox');\n"
        "        if(!box) return;\n"
        "        var h = null;\n"
        "        try{ h = await api('/api/teacher/defense/health'); }catch(e){ return; }\n"
        "        if(!h || !h.ok) return;\n"
        "        var msgs = [];\n"
        "        try{\n"
        "          if(h.today && !h.today.resolved && Number(h.today.overdue_minutes) > 2){\n"
        "            msgs.push('きょうの決戦は まだ 動いていません（予定 ' + new Date(h.today.decision_at).toLocaleTimeString() + ' ／ ' + h.today.overdue_minutes + '分すぎ）。');\n"
        "          }\n"
        "          var rec = h.recent || [];\n"
        "          for(var i=0;i<rec.length;i++){\n"
        "            var r = rec[i];\n"
        "            if(r && r.late_minutes != null && Number(r.late_minutes) >= 5){\n"
        "              var got = new Date(String(r.resolved_at).replace(' ','T') + 'Z');\n"
        "              msgs.push(new Date(r.event_key).toLocaleDateString() + ' の決戦は 予定どおりに 動かず ' + got.toLocaleTimeString() + ' に 動きました（' + r.late_minutes + '分おくれ）。');\n"
        "            }\n"
        "          }\n"
        "        }catch(e){ return; }\n"
        "        if(!msgs.length){ box.className = 'mt-3 hidden text-xs rounded-lg px-3 py-2'; box.textContent = ''; return; }\n"
        "        box.className = 'mt-3 text-xs rounded-lg px-3 py-2 bg-amber-50 text-amber-800 border border-amber-300 font-bold';\n"
        "        box.textContent = '⚠ ' + msgs.join(' ／ ');\n"
        "      }\n"
        "      try{ loadDefHealth(); }catch(e){}\n"
        "      setInterval(function(){ try{ loadDefHealth(); }catch(e){} }, 60000);"
    )
    src = put_after(src, A7, health, "health js")

# ---- 検算 -----------------------------------------------------------------
after_chain = chain_count(src)
print("chain(after):", after_chain)
if after_chain != 104:
    die("チェーンが 104件から 変わりました（" + str(after_chain) + "件）")

need = {
    "from './def_auto_resolve'": 1,
    "registerDefAutoResolve(app, {": 1,
    "defAutoResolveHook(c.env, st, classId)": 1,
    "var _defTsLast = 0;": 1,
    "_defTsFired = st.event_key; _defTsLast = Date.now();": 1,
    "_arNow - _defTsLast > 60000": 1,
    "visibilitychange": 1,
    'id="defHealthBox"': 1,
    "async function loadDefHealth(){": 1,
    "/api/teacher/defense/health": 1,
}
ng = False
for k in sorted(need.keys()):
    n = src.count(k)
    print("  check", repr(k), "=", n, "(need", need[k], ")")
    if n != need[k]:
        ng = True
if ng:
    die("配線の 数が 合いません")

for k in ["app.post('/api/defense/resolve'", "app.get('/api/defense/status'", "app.post('/api/defense/entry'"]:
    if src.count(k) != 1:
        die("児童の みちすじが こわれています: " + k)

if src == orig:
    print("すでに あたっています（変更なし）")
else:
    io.open(PATH, "w", encoding="utf-8").write(src)
    print("OK: " + PATH + " を 書きかえました")
