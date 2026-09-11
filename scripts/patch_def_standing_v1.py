# -*- coding: utf-8 -*-
# DEF_STANDING_V1 : 防衛戦「一度登録したらずっと登録されている」ようにする
#   - defense_standing / defense_carry_lock の読み書きを src/index.tsx に追加する
#   - DDL はここでは流さない（migrations/0031_defense_standing.sql を D1 へ直接適用ずみ）
#   - アンカーが1件でない、チェーン件数が想定外 → src/index.tsx には一切触らない（fail-closed）
import sys

SRC = "src/index.tsx"
HTML = "public/index.html"

# 冪等の番兵。検証条件（チェーン71件や各キーワード）とは別物にしてある。
SENTINEL = "__DEF_STANDING_V1_SENTINEL__"

CHAIN_BEFORE = 69
CHAIN_AFTER = 71


def die(msg):
    print("NG: " + msg)
    sys.exit(1)


def chain_count(txt):
    i = txt.index("let t = await a.text()")
    j = txt.index("return c.html(", i)
    return txt[i:j].count(".replace(")


src = open(SRC, encoding="utf-8").read()
html = open(HTML, encoding="utf-8").read()

if SENTINEL in src:
    print("SKIP: すでに適用ずみ。src/index.tsx には触らない。")
    sys.exit(0)

A1 = "  await c.env.DB.prepare(\"INSERT INTO defense_entries (event_key, user_id, class_id, monster_json, strategy, created_at) VALUES (?,?,?,?,?,datetime('now')) ON CONFLICT(event_key, user_id) DO UPDATE SET class_id=excluded.class_id, monster_json=excluded.monster_json, strategy=excluded.strategy, created_at=datetime('now')\").bind(st.eventKey, u.id, classId, mj, strat).run()"
A1NEW = "  // __DEF_STANDING_V1_ENTRY__ 所持しているモンスターかをサーバ側で確認する（クライアントの申告だけを信じない）\n  const _dsMid = Number((body.monster as any) && (body.monster as any).id)\n  if (!Number.isFinite(_dsMid) || _dsMid <= 0) return jsonError(c, 400, 'invalid_monster')\n  let _dsOwned = false\n  try {\n    const _dsP = await c.env.DB.prepare(\"SELECT json_extract(state_json, '$.monsters.\\\"' || ? || '\\\"') AS m FROM progress WHERE user_id=? LIMIT 1\").bind(String(_dsMid), u.id).first<any>()\n    _dsOwned = !!(_dsP && _dsP.m != null)\n  } catch (_e) { _dsOwned = false }\n  if (!_dsOwned) return jsonError(c, 403, 'monster_not_owned')\n  await c.env.DB.prepare(\"INSERT INTO defense_entries (event_key, user_id, class_id, monster_json, strategy, created_at) VALUES (?,?,?,?,?,datetime('now')) ON CONFLICT(event_key, user_id) DO UPDATE SET class_id=excluded.class_id, monster_json=excluded.monster_json, strategy=excluded.strategy, created_at=datetime('now')\").bind(st.eventKey, u.id, classId, mj, strat).run()\n  // __DEF_STANDING_V1_ENTRY__ 一度登録したらずっと参加できるように、持ち越し用の編成を保存する\n  try {\n    const _dsLv = Math.max(1, Math.floor(Number(((body.monster as any) && (body.monster as any).level) || 1)))\n    await c.env.DB.prepare(\"INSERT INTO defense_standing (user_id, monster_id, strategy, snapshot_json, snapshot_level, updated_at) VALUES (?,?,?,?,?,datetime('now')) ON CONFLICT(user_id) DO UPDATE SET monster_id=excluded.monster_id, strategy=excluded.strategy, snapshot_json=excluded.snapshot_json, snapshot_level=excluded.snapshot_level, updated_at=datetime('now')\").bind(u.id, _dsMid, strat, mj, _dsLv).run()\n  } catch (_e) {}"

A2 = "    const e = await c.env.DB.prepare(\"SELECT monster_json, strategy FROM defense_entries WHERE event_key=? AND user_id=?\").bind(st.eventKey, u.id).first<any>()\n    if (e) { let mj: any = null; try { mj = JSON.parse(e.monster_json) } catch (_e) {} out.my_entry = { monster: mj, strategy: e.strategy } }\n  } catch (_e) {}"
A2NEW = "    const e = await c.env.DB.prepare(\"SELECT monster_json, strategy FROM defense_entries WHERE event_key=? AND user_id=?\").bind(st.eventKey, u.id).first<any>()\n    if (e) { let mj: any = null; try { mj = JSON.parse(e.monster_json) } catch (_e) {} out.my_entry = { monster: mj, strategy: e.strategy } }\n  } catch (_e) {}\n  // __DEF_STANDING_V1_STATUS__ 決戦前：前回の編成が残っていれば自動でエントリーする（持ち越し）\n  if (!out.my_entry && !decided && classId) {\n    try {\n      const _dsRow = await c.env.DB.prepare(\"SELECT ds.strategy AS strat, ds.snapshot_json AS mj, ds.snapshot_level AS lv, json_extract(p.state_json, '$.monsters.\\\"' || ds.monster_id || '\\\".level') AS curlv FROM defense_standing ds LEFT JOIN progress p ON p.user_id = ds.user_id WHERE ds.user_id=? LIMIT 1\").bind(u.id).first<any>()\n      if (_dsRow && _dsRow.mj) {\n        if (_dsRow.curlv == null) {\n          out.carry_over_error = 'monster_gone'\n        } else {\n          await c.env.DB.prepare(\"INSERT INTO defense_entries (event_key, user_id, class_id, monster_json, strategy, created_at) VALUES (?,?,?,?,?,datetime('now')) ON CONFLICT(event_key, user_id) DO NOTHING\").bind(st.eventKey, u.id, classId, String(_dsRow.mj), String(_dsRow.strat || 'balance')).run()\n          let _dsM: any = null\n          try { _dsM = JSON.parse(String(_dsRow.mj)) } catch (_e2) {}\n          out.my_entry = { monster: _dsM, strategy: String(_dsRow.strat || 'balance') }\n          out.carried_over = true\n          if (Number(_dsRow.curlv || 0) > Number(_dsRow.lv || 0)) out.carry_over_stale = true\n        }\n      }\n    } catch (_e) {}\n  }"

A3 = "        const es = await c.env.DB.prepare(\"SELECT de.monster_json as mj, de.strategy as strat, de.user_id as uid, u.name as nm FROM defense_entries de JOIN users u ON u.id=de.user_id WHERE de.event_key=? AND de.class_id=? ORDER BY de.created_at ASC, de.user_id ASC\").bind(st.eventKey, classId).all<any>()"
A3NEW = "        // __DEF_STANDING_V1_STATUS__ 決戦後：アプリを開かなかった子も前回の編成で参加できるようにする（クラスで最初の1人だけが走らせる）\n        try {\n          const _dsLock = await c.env.DB.prepare(\"INSERT INTO defense_carry_lock (event_key, class_id, done_at) VALUES (?,?,datetime('now')) ON CONFLICT(event_key, class_id) DO NOTHING\").bind(st.eventKey, classId).run()\n          if (_dsLock && _dsLock.meta && Number(_dsLock.meta.changes || 0) > 0) {\n            const _dsAll = await c.env.DB.prepare(\"SELECT ds.user_id AS uid, ds.snapshot_json AS mj, ds.strategy AS strat, json_extract(p.state_json, '$.monsters.\\\"' || ds.monster_id || '\\\".level') AS curlv FROM defense_standing ds JOIN class_members cm ON cm.user_id = ds.user_id LEFT JOIN progress p ON p.user_id = ds.user_id WHERE cm.class_id=? LIMIT 200\").bind(classId).all<any>()\n            const _dsRows = ((_dsAll && _dsAll.results) || []).filter((r: any) => r && r.mj && r.curlv != null)\n            if (_dsRows.length) {\n              const _dsIns = c.env.DB.prepare(\"INSERT INTO defense_entries (event_key, user_id, class_id, monster_json, strategy, created_at) VALUES (?,?,?,?,?,datetime('now')) ON CONFLICT(event_key, user_id) DO NOTHING\")\n              await c.env.DB.batch(_dsRows.map((r: any) => _dsIns.bind(st.eventKey, String(r.uid), classId, String(r.mj), String(r.strat || 'balance'))))\n            }\n          }\n          if (!out.my_entry) {\n            const _dsMe = await c.env.DB.prepare(\"SELECT ds.strategy AS strat, ds.snapshot_json AS mj, json_extract(p.state_json, '$.monsters.\\\"' || ds.monster_id || '\\\".level') AS curlv FROM defense_standing ds LEFT JOIN progress p ON p.user_id = ds.user_id WHERE ds.user_id=? LIMIT 1\").bind(u.id).first<any>()\n            if (_dsMe && _dsMe.mj && _dsMe.curlv != null) {\n              await c.env.DB.prepare(\"INSERT INTO defense_entries (event_key, user_id, class_id, monster_json, strategy, created_at) VALUES (?,?,?,?,?,datetime('now')) ON CONFLICT(event_key, user_id) DO NOTHING\").bind(st.eventKey, u.id, classId, String(_dsMe.mj), String(_dsMe.strat || 'balance')).run()\n              out.carried_over = true\n            } else if (_dsMe && _dsMe.mj) {\n              out.carry_over_error = 'monster_gone'\n            }\n          }\n        } catch (_e) {}\n        const es = await c.env.DB.prepare(\"SELECT de.monster_json as mj, de.strategy as strat, de.user_id as uid, u.name as nm FROM defense_entries de JOIN users u ON u.id=de.user_id WHERE de.event_key=? AND de.class_id=? ORDER BY de.created_at ASC, de.user_id ASC\").bind(st.eventKey, classId).all<any>()"

A4 = "      _rootHtmlCache = t"
A4NEW = "      // __DEF_STANDING_V1_SENTINEL__ __DEF_STANDING_V1_UI__ 持ち越し参加のお知らせ／レベルが上がっていたときの自動更新\n      t = t.replace(`          var head='<div style=\"font-size:12px;color:#64748b;margin-bottom:6px;\">決戦：'+_defEsc(decTxt)+'</div>'+enemyHtml;`, `          var head='<div style=\"font-size:12px;color:#64748b;margin-bottom:6px;\">決戦：'+_defEsc(decTxt)+'</div>'+enemyHtml;\n          if (d.carried_over) { head+='<div style=\"background:#eff6ff;border:1px solid #bfdbfe;border-radius:10px;padding:10px;margin-bottom:8px;color:#1d4ed8;font-weight:900;\">🔁 前回と同じで参加中</div>'; }\n          if (d.carry_over_error==='monster_gone') { head+='<div style=\"background:#fff7ed;border:1px solid #fed7aa;border-radius:10px;padding:10px;margin-bottom:8px;color:#c2410c;font-weight:900;\">前に出したモンスターがいなくなったよ。もう一度えらんでね。</div>'; }`)\n      t = t.replace(`          var d=await _defFetch(); _defStatus=d;`, `          var d=await _defFetch(); _defStatus=d;\n          try { if (d && d.ok && d.active && d.carry_over_stale && !d.decided && d.my_entry && d.my_entry.monster && d.event_key) { var _dsSnap=_defSnapshot(d.my_entry.monster.id); if (_dsSnap) { await fetch('/api/defense/entry',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({event_key:d.event_key,monster:_dsSnap,strategy:(d.my_entry.strategy||'balance')})}); d=await _defFetch(); _defStatus=d; } } } catch(e) {}`)\n      _rootHtmlCache = t"

H1 = "          var head='<div style=\"font-size:12px;color:#64748b;margin-bottom:6px;\">決戦：'+_defEsc(decTxt)+'</div>'+enemyHtml;"
H2 = "          var d=await _defFetch(); _defStatus=d;"

# --- 適用前チェック。ここで止まれば src/index.tsx は書き換えない ---
for name, anchor, hay in (
    ("A1 出陣API", A1, src),
    ("A2 status 決戦前", A2, src),
    ("A3 status 決戦後", A3, src),
    ("A4 HTMLチェーン末尾", A4, src),
    ("H1 児童画面 head", H1, html),
    ("H2 児童画面 _defRender", H2, html),
):
    n = hay.count(anchor)
    if n != 1:
        die("アンカー %s が %d 件（1件でなければ適用しない）" % (name, n))

n0 = chain_count(src)
if n0 != CHAIN_BEFORE:
    die(".replace() チェーンが %d 件（%d 件を想定）" % (n0, CHAIN_BEFORE))

out = src
out = out.replace(A1, A1NEW, 1)
out = out.replace(A2, A2NEW, 1)
out = out.replace(A3, A3NEW, 1)
out = out.replace(A4, A4NEW, 1)

n1 = chain_count(out)
if n1 != CHAIN_AFTER:
    die("適用後の .replace() チェーンが %d 件（%d 件を想定）" % (n1, CHAIN_AFTER))
if SENTINEL not in out:
    die("番兵が入っていない")
if out.count("ensureDefenseTables(") != 1:
    die("ensureDefenseTables の呼び出しが増えている（定義1件のみのはず）")

open(SRC, "w", encoding="utf-8").write(out)
print("OK: .replace() チェーン %d -> %d" % (n0, n1))
