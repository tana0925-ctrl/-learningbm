#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_ts_rtdedupe.py

タイプシュート「友達対戦」で、相手が打っていないのに同じ文字が何本も降ってくる不具合の修正。

原因（2026-09-11 の実データで確定）:
  vPoll() は 250ms の setInterval で回っており、レスポンスが返るまで V.lastEventId が
  更新されない。往復が 210〜600ms あるため、同じ after= 値を持つリクエストが同時に
  2〜3 本飛び、サーバは同じ行を全部返し、その全部が vSpawnIncoming() を呼んでいた。
  （ルーム ZDTF5A: 相手の発射 4 語に対して被弾 12 件 = 3 倍）

修正（二重の守り + 単調前進）:
  1. polling フラグ … 実行中なら即 return。完了時に必ず倒す（成功・失敗どちらでも）。
  2. seen マップ    … 適用済み ev.id は二度と vSpawnIncoming() に渡さない（本命の保険）。
                       V ごと作り直されるのでルームごとにリセットされる。
  3. lastEventId    … レスポンス内の最大 id で単調前進。0 件でも巻き戻さない。
  さらに setInterval を廃し、「応答が返ってから次を投げる」自己再帰 setTimeout に変更。
  加えて ctx（そのポーリングが属する対戦オブジェクト）を捕まえておき、別の対戦に
  切り替わった後に古いレスポンスやタイマーが effect を起こさないようにする。

適用対象: public/typeshoot.js のみ（src/index.tsx は触らない）
"""

import os
import subprocess
import sys

TARGET = os.path.join("public", "typeshoot.js")

# 冪等性の番兵（マーカー文字列）。適用後の検証条件とは意図的に別物にしてある。
SENTINEL = "rtdedupe-v1"

# ---------------------------------------------------------------- anchors

A1_OLD = """  function vPoll() {
    if (!V || !V.roomId) return;
    fetch('/api/rt/room/' + V.roomId + '?after=' + V.lastEventId).then(function (r) { return r.json(); }).then(function (d) {
      if (!d || !d.ok) return;
      var room = d.room || {};
      if (V.role === 'host') { V.myHp = room.hostHp; V.oppHp = room.guestHp; } else { V.myHp = room.guestHp; V.oppHp = room.hostHp; }
      vSetBars();
      var evs = d.events || [];
      for (var i = 0; i < evs.length; i++) {
        var ev = evs[i];
        if (ev.id > V.lastEventId) V.lastEventId = ev.id;
        if (!V.synced) continue;
        if (V.mine[ev.id]) continue;
        var m = null; try { m = ev.meta_json ? JSON.parse(ev.meta_json) : null; } catch (e) {}
        if (m && m.from === V.role) continue;
        if (m && m.k === 'f') vSpawnIncoming(m.w, m.ty || 'normal');
      }
      if (!V.synced && evs.length < 50) V.synced = true;
      if (room.status === 'finished' || room.winner) vFinish(room.winner);
    }).catch(function () {});
  }
"""

A1_NEW = """  /* rtdedupe-v1 : ポーリング多重化と重複スポーンの対策
   * 1. polling フラグ : 実行中は次を投げない。完了時（成功・失敗とも）に必ず倒す。
   * 2. seen マップ    : 適用済み ev.id は二度と画面に出さない（本命の保険）。
   * 3. lastEventId は最大 id で単調前進。0 件でも巻き戻さない。
   * setInterval はやめ、応答が返ってから次を投げる自己再帰 setTimeout にした。
   * ctx は「このポーリングが属する対戦」。別の対戦に切り替わったら何もしない。
   */
  var V_POLL_GAP_MS = 200;
  function vPollSchedule(ctx) {
    if (!ctx || ctx !== V || ctx.ended || !ctx.roomId) return;
    ctx.poll = setTimeout(function () { if (ctx === V) vPoll(); }, V_POLL_GAP_MS);
  }
  function vPollDone(ctx) {
    /* finally 相当。ここを必ず通すこと（通らないとポーリングが永久に止まる）。 */
    if (!ctx) return;
    ctx.polling = false;
    vPollSchedule(ctx);
  }
  function vPoll() {
    if (!V || !V.roomId) return;
    if (V.polling) return;
    var ctx = V;
    ctx.polling = true;
    fetch('/api/rt/room/' + ctx.roomId + '?after=' + ctx.lastEventId).then(function (r) { return r.json(); }).then(function (d) {
      if (ctx !== V) return;
      if (!d || !d.ok) return;
      var room = d.room || {};
      if (ctx.role === 'host') { ctx.myHp = room.hostHp; ctx.oppHp = room.guestHp; } else { ctx.myHp = room.guestHp; ctx.oppHp = room.hostHp; }
      vSetBars();
      var evs = d.events || [];
      var maxId = ctx.lastEventId;
      for (var i = 0; i < evs.length; i++) {
        var ev = evs[i];
        if (ev.id > maxId) maxId = ev.id;
        if (ctx.seen[ev.id]) continue;
        ctx.seen[ev.id] = 1;
        if (!ctx.synced) continue;
        if (ctx.mine[ev.id]) continue;
        var m = null; try { m = ev.meta_json ? JSON.parse(ev.meta_json) : null; } catch (e) {}
        if (m && m.from === ctx.role) continue;
        if (m && m.k === 'f') vSpawnIncoming(m.w, m.ty || 'normal');
      }
      if (maxId > ctx.lastEventId) ctx.lastEventId = maxId;
      if (!ctx.synced && evs.length < 50) ctx.synced = true;
      if (room.status === 'finished' || room.winner) vFinish(room.winner);
    }).catch(function () {}).then(function () { vPollDone(ctx); });
  }
"""

A2_OLD = ("      V = { roomId: roomId, role: role || 'host', oppName: oppName || 'あいて', "
          "mode: 'attack', word: '', pats: [], typed: '', myHp: 100, oppHp: 100, missiles: [], "
          "raf: null, poll: null, last: 0, ended: false, ready: false, mine: {}, "
          "lastEventId: 0, synced: false };")

A2_NEW = ("      V = { roomId: roomId, role: role || 'host', oppName: oppName || 'あいて', "
          "mode: 'attack', word: '', pats: [], typed: '', myHp: 100, oppHp: 100, missiles: [], "
          "raf: null, poll: null, last: 0, ended: false, ready: false, mine: {}, "
          "lastEventId: 0, synced: false, seen: {}, polling: false };")

A3_OLD = "      V.poll = setInterval(vPoll, 250);"
A3_NEW = "      vPoll(); /* 初回は即時。以後は応答が返ってから自己再帰でスケジュールする */"

A4_OLD = "    if (V.poll) { clearInterval(V.poll); V.poll = null; }"
A4_NEW = "    if (V.poll) { clearTimeout(V.poll); V.poll = null; }"

A5_OLD = "if (V.raf) cancelAnimationFrame(V.raf); if (V.poll) clearInterval(V.poll);"
A5_NEW = "if (V.raf) cancelAnimationFrame(V.raf); if (V.poll) { clearTimeout(V.poll); V.poll = null; }"

REPLACEMENTS = [
    ("vPoll 本体", A1_OLD, A1_NEW),
    ("V 初期化", A2_OLD, A2_NEW),
    ("ポーリング開始", A3_OLD, A3_NEW),
    ("vFinish の停止", A4_OLD, A4_NEW),
    ("vClose の停止", A5_OLD, A5_NEW),
]

# 適用前に必ず存在してほしいもの / 存在してはいけないもの
PRE_MUST_EXIST = ["setInterval(vPoll, 250)", "function vSpawnIncoming", "V.mine[ev.id]",
                  "window.startTypeShootVS = startTypeShootVS;"]
PRE_MUST_ABSENT = ["ctx.seen", "ctx.polling", "vPollSchedule", "V_POLL_GAP_MS", "vPollDone"]

# 適用後の検証条件（番兵の有無では判定しない）
POST_EXPECT_COUNT = {
    "var V_POLL_GAP_MS = 200;": 1,
    "if (V.polling) return;": 1,
    "ctx.polling = true;": 1,
    "ctx.polling = false;": 1,
    "var ctx = V;": 1,
    "if (ctx !== V) return;": 1,
    "if (ctx.seen[ev.id]) continue;": 1,
    "ctx.seen[ev.id] = 1;": 1,
    "if (maxId > ctx.lastEventId) ctx.lastEventId = maxId;": 1,
    "setTimeout(function () { if (ctx === V) vPoll(); }, V_POLL_GAP_MS);": 1,
    ".catch(function () {}).then(function () { vPollDone(ctx); });": 1,
    "function vPollSchedule(ctx) {": 1,
    "function vPollDone(ctx) {": 1,
    "vPollSchedule(ctx);": 1,
    "seen: {}, polling: false };": 1,
    "clearTimeout(V.poll)": 2,
}
POST_EXPECT_ABSENT = [
    "setInterval(vPoll",
    "clearInterval(V.poll)",
    "if (ev.id > V.lastEventId) V.lastEventId = ev.id;",
]
# 対戦以外のモードに触っていないこと
UNTOUCHED = [
    "function startGame()",
    "function cpuFire()",
    "function spawnEnemyWord()",
    "window.startTypeShoot = startGame;",
    "window.startTypeShootVS = startTypeShootVS;",
    "S.cpuTimer = setInterval(cpuFire, stageInterval(S.stage));",
]


def fail(msg):
    print("NG: " + msg, file=sys.stderr)
    sys.exit(1)


def main():
    if not os.path.exists(TARGET):
        fail("%s が見つからない（リポジトリのルートで実行すること）" % TARGET)

    with open(TARGET, "r", encoding="utf-8") as f:
        src = f.read()
    before_len = len(src)
    print("読み込み: %s (%d chars)" % (TARGET, before_len))

    # ---- 冪等性: 番兵があれば何もしない ---------------------------------
    if SENTINEL in src:
        print("SKIP: 既に %s が適用済み。変更なしで終了。" % SENTINEL)
        return 0

    # ---- 適用前の状態検証 -----------------------------------------------
    for s in PRE_MUST_EXIST:
        if src.count(s) < 1:
            fail("適用前チェック: %r が見つからない。対象ファイルが想定と違う。" % s)
    for s in PRE_MUST_ABSENT:
        if s in src:
            fail("適用前チェック: %r が既にある。番兵なしで中途半端に適用された疑い。" % s)
    print("適用前チェック OK")

    # ---- アンカー一意性 --------------------------------------------------
    for name, old, _new in REPLACEMENTS:
        n = src.count(old)
        if n != 1:
            fail("アンカー[%s]の出現回数が %d（1 でなければならない）" % (name, n))
        print("アンカー一意性 OK: %s" % name)

    # ---- 適用 -------------------------------------------------------------
    out = src
    for name, old, new in REPLACEMENTS:
        out = out.replace(old, new, 1)
        print("適用: %s" % name)

    # ---- 適用後の内容検証（番兵とは別条件） --------------------------------
    for s, want in sorted(POST_EXPECT_COUNT.items()):
        got = out.count(s)
        if got != want:
            fail("適用後チェック: %r の出現回数が %d（期待 %d）" % (s, got, want))
    for s in POST_EXPECT_ABSENT:
        if s in out:
            fail("適用後チェック: %r が残っている" % s)
    for s in UNTOUCHED:
        if src.count(s) != out.count(s):
            fail("非干渉チェック: %r の数が変わった" % s)
    if out.count(SENTINEL) != 1:
        fail("適用後チェック: 番兵 %s の数が %d（期待 1）" % (SENTINEL, out.count(SENTINEL)))
    print("適用後チェック OK")

    delta = len(out) - before_len
    if delta <= 0:
        fail("適用後チェック: ファイルが増えていない（delta=%d）" % delta)
    print("サイズ: %d -> %d (+%d)" % (before_len, len(out), delta))

    # ---- 構文チェック（node があれば） -------------------------------------
    tmp = TARGET + ".rtdedupe.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(out)
    ok = True
    msg = ""
    try:
        r = subprocess.run(["node", "--check", tmp], capture_output=True, text=True)
        ok = (r.returncode == 0)
        msg = r.stdout + r.stderr
    except FileNotFoundError:
        ok, msg = True, "(node が無いのでスキップ)"
        print("WARN: node が無いので構文チェックはスキップ")
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    if not ok:
        fail("node --check 失敗: " + msg)
    print("node --check OK")

    # ---- 書き込み -----------------------------------------------------------
    with open(TARGET, "w", encoding="utf-8") as f:
        f.write(out)
    print("OK: %s を更新した" % TARGET)
    return 0


if __name__ == "__main__":
    sys.exit(main())
