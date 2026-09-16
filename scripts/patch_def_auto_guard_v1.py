# -*- coding: utf-8 -*-
# __DEF_AUTO_GUARD_V1__ 「出陣がそろう前に 決着させない」見はりを src/def_auto_resolve.ts に 足す。
#
# なぜ必要か
#   持ちこし＋全員じどう出陣（darMaterialize）は クラスで 1回だけ。
#   その 1回を とった 通信が 22人を 入れ終わるまで に 約1秒 かかる（9/15は 03:41:52→53）。
#   その 1秒のあいだに 別の 通信が 判定まで 走ると、数人だけで 戦って まける。
#   段が 3 に 上がって 敵が 強いいま、これは そのまま 負けに なる。
#
# 入れる 見はり（2つとも 迷ったら「待つ」側に 倒れる）
#   1) darRosterReady … 自分で 出陣を 作ったのでなければ、
#      defense_carry_lock が 5秒以上 前のものであることを 確かめる。
#      （作っている さい中に 割りこまない）
#   2) darTooFew … クラスに 5人以上 いるのに 出陣が 3人未満なら 判定しない。
#      あとで もう一度 見にくる（cronは5分おき、先生画面は1分おき、児童はひらくたび）。
#      動かなければ 先生画面の 黄色い帯に 出る。
#
# さらに、重い 戦闘計算を しぼる 鍵（darBucketLock）を 判定の すぐ前に 移す。
# 見はりで 見送ったときに 2分分の 鍵を 無駄に しないため。
#
# src/index.tsx には 1文字も さわらない。児童の 戦闘エンジンにも さわらない。

import io
import sys

PATH = "src/def_auto_resolve.ts"
MARK = "__DEF_AUTO_GUARD_V1__"


def die(msg):
    print("NG: " + msg)
    sys.exit(1)


def once(s, anchor, label):
    n = s.count(anchor)
    if n != 1:
        die("あて先が 1つでは ありません（" + label + " / " + str(n) + "件）")


src = io.open(PATH, encoding="utf-8").read()
orig = src

# ---- 1) 見はりの 部品を 足す -------------------------------------------
A1 = "// 児童の /api/defense/status から よぶ 入口（案B）。"
if "async function darRosterReady" not in src:
    once(src, A1, "helpers")
    helpers = (
        "// " + MARK + " クラスの 人数。\n"
        "async function darMemberCount(env: any, classId: any) {\n"
        "  try {\n"
        '    const r = await env.DB.prepare("SELECT COUNT(*) AS c FROM class_members WHERE class_id=? LIMIT 1").bind(String(classId)).first()\n'
        "    const n = Number(r && r.c)\n"
        "    return Number.isFinite(n) ? Math.floor(n) : 0\n"
        "  } catch (_e) { return 0 }\n"
        "}\n"
        "\n"
        "// " + MARK + " 出陣が できあがっているか。\n"
        "// 自分で 作ったなら もちろん OK（同じ通信の中で 順番に 走っている）。\n"
        "// ほかの 通信が 作ったなら、それが 終わるだけの 時間（5秒）が たっていること。\n"
        "async function darRosterReady(env: any, eventKey: any, classId: any, wonLock: any) {\n"
        "  if (wonLock) return true\n"
        "  try {\n"
        '    const r = await env.DB.prepare("SELECT 1 AS x FROM defense_carry_lock WHERE event_key=? AND class_id=? AND done_at <= datetime(\'now\',\'-5 seconds\') LIMIT 1").bind(String(eventKey), String(classId)).first()\n'
        "    return !!r\n"
        "  } catch (_e) { return false }\n"
        "}\n"
        "\n"
        "// " + MARK + " 人数が あまりに 少ないときは 判定しない。\n"
        "// 「時間どおりに 2人で 負ける」より「おくれて みんなで 勝つ」ほうが いい。\n"
        "async function darTooFew(env: any, eventKey: any, classId: any) {\n"
        "  const n = await darEntryCountRaw(env, eventKey, classId)\n"
        "  const m = await darMemberCount(env, classId)\n"
        "  return { few: (m >= 5 && n < 3), entries: n, members: m }\n"
        "}\n"
        "\n"
    )
    src = src.replace(A1, helpers + A1, 1)

# ---- 2) 児童側（案B）の 順番を 入れかえる ------------------------------
A2 = (
    "    const got = await darBucketLock(env, st.eventKey, classId, st.decisionAt)\n"
    "    if (!got) return false\n"
    "    await darMaterialize(env, st.eventKey, classId)\n"
    "    const r = await darResolve(env, st, classId)"
)
B2 = (
    "    // " + MARK + " 先に 出陣を つくる。できあがる前なら 判定しない。\n"
    "    const won = await darMaterialize(env, st.eventKey, classId)\n"
    "    if (!(await darRosterReady(env, st.eventKey, classId, won))) return false\n"
    "    const few = await darTooFew(env, st.eventKey, classId)\n"
    "    if (few.few) return false\n"
    "    const got = await darBucketLock(env, st.eventKey, classId, st.decisionAt)\n"
    "    if (!got) return false\n"
    "    const r = await darResolve(env, st, classId)"
)
if "darRosterReady(env, st.eventKey, classId, won)" not in src:
    once(src, A2, "hook order")
    src = src.replace(A2, B2, 1)

# ---- 3) cron 側の 順番を 入れかえる ----------------------------------
A3 = (
    "        const got = await darBucketLock(env, st.eventKey, cid, st.decisionAt)\n"
    "        if (!got) { out.classes.push({ class_id: cid, skipped: 'busy' }); continue }\n"
    "        await darMaterialize(env, st.eventKey, cid)\n"
    "        const r = await darResolve(env, st, cid)"
)
B3 = (
    "        // " + MARK + " 先に 出陣を つくる。できあがる前や 人数が 少なすぎるときは 待つ。\n"
    "        const won = await darMaterialize(env, st.eventKey, cid)\n"
    "        if (!(await darRosterReady(env, st.eventKey, cid, won))) { out.classes.push({ class_id: cid, skipped: 'roster_not_ready' }); continue }\n"
    "        const few = await darTooFew(env, st.eventKey, cid)\n"
    "        if (few.few) { out.classes.push({ class_id: cid, skipped: 'too_few', entries: few.entries, members: few.members }); continue }\n"
    "        const got = await darBucketLock(env, st.eventKey, cid, st.decisionAt)\n"
    "        if (!got) { out.classes.push({ class_id: cid, skipped: 'busy' }); continue }\n"
    "        const r = await darResolve(env, st, cid)"
)
if "darRosterReady(env, st.eventKey, cid, won)" not in src:
    once(src, A3, "cron order")
    src = src.replace(A3, B3, 1)

# ---- 検算 ---------------------------------------------------------------
need = {
    "async function darMemberCount": 1,
    "async function darRosterReady": 1,
    "async function darTooFew": 1,
    "darRosterReady(env, st.eventKey, classId, won)": 1,
    "darRosterReady(env, st.eventKey, cid, won)": 1,
    "const won = await darMaterialize(env, st.eventKey, classId)": 1,
    "const won = await darMaterialize(env, st.eventKey, cid)": 1,
    "roster_not_ready": 1,
    "too_few": 1,
}
ng = False
for k in sorted(need.keys()):
    n = src.count(k)
    print("  check", repr(k), "=", n, "(need", need[k], ")")
    if n != need[k]:
        ng = True

# 判定は 必ず 出陣づくりの あとで 走ること
for pair in [("const won = await darMaterialize(env, st.eventKey, classId)", "const r = await darResolve(env, st, classId)"),
             ("const won = await darMaterialize(env, st.eventKey, cid)", "const r = await darResolve(env, st, cid)")]:
    i, j = src.find(pair[0]), src.find(pair[1])
    print("  order", i, "<", j)
    if i < 0 or j < 0 or i >= j:
        print("   NG: 出陣づくりより 先に 判定しています")
        ng = True

if "await darMaterialize(env, st.eventKey, classId)\n    const r = await darResolve" in src:
    print("NG: 古い並びが のこっています"); ng = True

if ng:
    die("見はりの 配線が 合いません")

if src == orig:
    print("すでに あたっています（変更なし）")
else:
    io.open(PATH, "w", encoding="utf-8").write(src)
    print("OK: " + PATH + " を 書きかえました")
