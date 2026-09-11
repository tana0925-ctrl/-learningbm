# -*- coding: utf-8 -*-
"""
__DEF_AUTO_1230_V1__
防衛戦を「平日（月〜金）12:30 JST に自動ではじまる」ようにする。

方針
  - 先生が手で decision_at を入れた回（＝まだ来ていない予定）には自動は触らない
  - 決戦のあとも、その日のうちは結果が見られるように据え置く
  - JSTの日付が変わってから、次の平日 12:30 へ進める
  - DDL（CREATE/ALTER TABLE）は一切しない。テーブルは増やさない
  - 同時に22人が開いても書き込みは1本だけ（条件付きUPDATEで勝った1本のみ）

fail-closed: アンカーがちょうど1件でなければ src/index.tsx に触れずに exit(1)
冪等: すでに __DEF_AUTO_1230_V1__ が入っていれば何もせず exit(0)
"""
import sys

PATH = "src/index.tsx"
SENTINEL = "__DEF_AUTO_1230_V1__"

ANCHOR_FN = "async function defenseSettings(env: any) {"
ANCHOR_RET = "  return { active: s.defense_active === '1', decisionAt, eventKey: String(s.defense_event_key || decisionAt || '') }"
NEW_RET = "  return await defAutoAdvanceV1(env, { active: s.defense_active === '1', decisionAt, eventKey: String(s.defense_event_key || decisionAt || '') })"

BLOCK = r"""// __DEF_AUTO_1230_V1__ 平日（月〜金）12:30 JST に防衛戦を自動ではじめる。
// 先生が手で決めた回（まだ来ていない予定）があれば、そちらを優先して自動は何も書かない。
// 祝日は見ていない（先生からの指定がないため「平日＝月〜金」だけで判定している）。
function defAutoDayKeyV1(ms: number): string {
  // jstDayKey() と同じ定義（UTCに9時間足して日付だけ取る）
  return new Date(ms + 9 * 3600 * 1000).toISOString().slice(0, 10)
}
function defAutoTargetV1(nowMs: number): string {
  const j = new Date(nowMs + 9 * 3600 * 1000)
  const y = j.getUTCFullYear(), mo = j.getUTCMonth(), d = j.getUTCDate()
  const mins = j.getUTCHours() * 60 + j.getUTCMinutes()
  let add = (mins >= 12 * 60 + 30) ? 1 : 0
  for (let i = 0; i < 10; i++) {
    const wd = new Date(Date.UTC(y, mo, d + add)).getUTCDay()
    if (wd >= 1 && wd <= 5) break
    add++
  }
  // 12:30 JST は同じ日付の 03:30 UTC
  return new Date(Date.UTC(y, mo, d + add, 3, 30, 0, 0)).toISOString()
}
async function defAutoAdvanceV1(env: any, st: any) {
  try {
    const now = Date.now()
    const cur = String(st.decisionAt || '')
    const curMs = cur ? Date.parse(cur) : NaN
    // これから始まる回がある（先生の手動登録もここに入る）→ 触らない
    if (cur && isFinite(curMs) && curMs > now) return st
    // 決戦した当日のうちは、結果が見られるように据え置く
    if (cur && isFinite(curMs) && defAutoDayKeyV1(curMs) === defAutoDayKeyV1(now)) return st
    const target = defAutoTargetV1(now)
    if (target === cur) return st
    // 同時アクセスでも書き込みは1本だけ（value が cur のままの行だけ書き換わる）
    const r = await env.DB.prepare("INSERT INTO admin_settings (key, value, updated_at) VALUES ('defense_decision_at', ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now') WHERE admin_settings.value = ?").bind(target, cur).run()
    if (!r || !r.meta || Number(r.meta.changes || 0) <= 0) return st
    const setKv = async (k: string, v: string) => { await env.DB.prepare("INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now')").bind(k, v).run() }
    await setKv('defense_event_key', target)
    await setKv('defense_active', '1')
    return { active: true, decisionAt: target, eventKey: target }
  } catch (_e) { return st }
}

"""


def main():
    with open(PATH, encoding="utf-8") as f:
        s = f.read()

    if SENTINEL in s:
        print("すでに適用ずみ（" + SENTINEL + "）。ファイルには触りません。")
        return 0

    ok = True
    if s.count(ANCHOR_FN) != 1:
        print("NG: アンカーが一意ではありません ANCHOR_FN =", s.count(ANCHOR_FN))
        ok = False
    if s.count(ANCHOR_RET) != 1:
        print("NG: アンカーが一意ではありません ANCHOR_RET =", s.count(ANCHOR_RET))
        ok = False
    for name in ("defAutoDayKeyV1", "defAutoTargetV1", "defAutoAdvanceV1"):
        if s.count(name) != 0:
            print("NG: 追加予定の名前がすでにあります:", name, s.count(name))
            ok = False
    if s.count("ensureDefenseTables(") != 1:
        print("NG: ensureDefenseTables( の数が 1 ではありません:", s.count("ensureDefenseTables("))
        ok = False
    if s.count("CREATE TABLE") != 21:
        print("NG: CREATE TABLE の数が 21 ではありません:", s.count("CREATE TABLE"))
        ok = False
    if not ok:
        print("適用前チェックで停止しました。src/index.tsx には触っていません。")
        return 1

    out = s.replace(ANCHOR_FN, BLOCK + ANCHOR_FN, 1)
    out = out.replace(ANCHOR_RET, NEW_RET, 1)

    if out == s:
        print("NG: 置換が起きませんでした")
        return 1
    if SENTINEL not in out:
        print("NG: 番兵が入っていません")
        return 1
    if out.count("CREATE TABLE") != 21:
        print("NG: CREATE TABLE が増減しました")
        return 1

    with open(PATH, "w", encoding="utf-8", newline="") as f:
        f.write(out)
    print("OK: 適用しました（" + SENTINEL + "）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
