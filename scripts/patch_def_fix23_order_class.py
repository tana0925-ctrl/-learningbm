#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
防衛戦 修正#2/#3 : src/index.tsx

#2 出撃者の並び順を固定する
   /api/defense/status の entries 取得 SQL に ORDER BY が無く、返却順が保証されない。
   _abFighter は curLn = index % 3 でレーンを決めるため、順序が変わると配置が変わり
   結果が変わる。ORDER BY de.created_at ASC, de.user_id ASC を付ける。

#3 class_id='' を防衛戦から除外する
   defenseClassId() は class_members に行が無いと '' を返す。防衛戦の結果は
   (event_key, class_id) キーなので、未所属アカウントは「空文字クラス」として
   独立した戦闘・独立した勝敗を持ってしまう（D1 に実例4件。いずれも admin アカウント）。
   status / entry / resolve の3箇所で空 class_id を弾く。

冪等性:
  目印(SENTINEL)はコメントとして埋めるが、適用済み判定には使わない。
  判定・検証はいずれも「結果そのもの」= 置換後の文字列が存在するかで行う。

使い方:
  python3 scripts/patch_def_fix23_order_class.py            # 適用
  python3 scripts/patch_def_fix23_order_class.py --check    # 適用せず状態だけ表示
"""

import hashlib
import pathlib
import sys

SENTINEL = "DEFFIX23_ORDER_AND_CLASS_20260909"  # 目印。検証条件には使わない。

TARGET = pathlib.Path("src/index.tsx")

# ---------------------------------------------------------------- #2 ORDER BY
OLD_SQL = (
    "FROM defense_entries de JOIN users u ON u.id=de.user_id "
    "WHERE de.event_key=? AND de.class_id=?\""
)
NEW_SQL = (
    "FROM defense_entries de JOIN users u ON u.id=de.user_id "
    "WHERE de.event_key=? AND de.class_id=? "
    "ORDER BY de.created_at ASC, de.user_id ASC\""
)

# ------------------------------------------------- #3-a status: 空クラスを弾く
OLD_STATUS = (
    "  if (!st.eventKey) return c.json(out)\n"
    "  const decided = !!st.decisionAt && Date.now() >= Date.parse(st.decisionAt)\n"
)
NEW_STATUS = (
    "  if (!st.eventKey) return c.json(out)\n"
    "  // " + SENTINEL + " : クラス未所属は防衛戦の対象外（空文字クラスの独立バトルを作らない）\n"
    "  if (!classId) { out.active = false; out.no_class = true; return c.json(out) }\n"
    "  const decided = !!st.decisionAt && Date.now() >= Date.parse(st.decisionAt)\n"
)

# -------------------------------------------------- #3-b entry: 空クラスを弾く
OLD_ENTRY = (
    "  const classId = await defenseClassId(c.env, u.id)\n"
    "  const mj = JSON.stringify(body.monster).slice(0, 4000)\n"
)
NEW_ENTRY = (
    "  const classId = await defenseClassId(c.env, u.id)\n"
    "  if (!classId) return jsonError(c, 403, 'no_class')\n"
    "  const mj = JSON.stringify(body.monster).slice(0, 4000)\n"
)

# ------------------------------------------------ #3-c resolve: 空クラスを弾く
OLD_RESOLVE = (
    "  const classId = await defenseClassId(c.env, u.id)\n"
    "  if (classId == null || classId !== String(body.class_id)) "
    "return jsonError(c, 403, 'class_mismatch')\n"
)
NEW_RESOLVE = (
    "  const classId = await defenseClassId(c.env, u.id)\n"
    "  if (!classId) return jsonError(c, 403, 'no_class')\n"
    "  if (classId !== String(body.class_id)) "
    "return jsonError(c, 403, 'class_mismatch')\n"
)

EDITS = [
    ("#2 ORDER BY", OLD_SQL, NEW_SQL),
    ("#3-a status", OLD_STATUS, NEW_STATUS),
    ("#3-b entry", OLD_ENTRY, NEW_ENTRY),
    ("#3-c resolve", OLD_RESOLVE, NEW_RESOLVE),
]


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def fail(msg: str):
    print("NG: " + msg)
    sys.exit(1)


def main():
    check_only = "--check" in sys.argv

    if not TARGET.exists():
        fail("対象が見つかりません: %s (リポジトリ直下で実行してください)" % TARGET)

    before = TARGET.read_bytes()
    src = before.decode("utf-8")

    print("=== 適用前 ===")
    print("file   : %s" % TARGET)
    print("bytes  : %d" % len(before))
    print("sha256 : %s" % sha(before))
    print("replace chain (.replace( の総数) : %d" % src.count(".replace("))

    # --- 冪等性: 「結果そのもの」で判定する（SENTINEL では判定しない） ---
    applied = [label for label, _o, new in EDITS if src.count(new) == 1]
    if len(applied) == len(EDITS):
        print("=== 適用済み（変更なし） ===")
        return
    if applied:
        fail("一部だけ適用済みです: %s / 手で確認してください。" % ", ".join(applied))

    # --- アンカー一意性検証 ---
    for label, old, _new in EDITS:
        n = src.count(old)
        if n != 1:
            fail("%s のアンカー出現回数が %d です（1 であるべき）。" % (label, n))
        print("anchor : %-14s = 1  (一意)" % label)

    if check_only:
        print("--check のため書き込みません。適用可能です。")
        return

    # --- 適用 ---
    out = src
    for _label, old, new in EDITS:
        out = out.replace(old, new, 1)

    after = out.encode("utf-8")
    TARGET.write_bytes(after)

    # --- 適用後の照合（結果そのものを見る） ---
    verify = TARGET.read_bytes().decode("utf-8")
    checks = []
    for label, old, new in EDITS:
        checks.append((label + " 新形が1つ", verify.count(new) == 1))
        checks.append((label + " 旧形が消えた", verify.count(old) == 0))
    checks.append((
        ".replace( の本数が変わっていない",
        verify.count(".replace(") == src.count(".replace("),
    ))
    checks.append((
        "defense のルートが4本のまま",
        verify.count("'/api/defense/") == src.count("'/api/defense/"),
    ))
    checks.append((
        "no_class の追加が3箇所",
        verify.count("jsonError(c, 403, 'no_class')") == 2
        and verify.count("out.no_class = true") == 1,
    ))
    checks.append((
        "class_mismatch は1箇所のまま",
        verify.count("'class_mismatch'") == src.count("'class_mismatch'"),
    ))

    print("=== 適用後の照合 ===")
    ok = True
    for label, res in checks:
        print(("  OK  " if res else "  NG  ") + label)
        ok = ok and res

    print("bytes  : %d -> %d (+%d)" % (len(before), len(after), len(after) - len(before)))
    print("sha256 : %s -> %s" % (sha(before), sha(after)))

    if not ok:
        TARGET.write_bytes(before)
        fail("照合に失敗したためロールバックしました。")

    print("=== 完了 ===")


if __name__ == "__main__":
    main()
