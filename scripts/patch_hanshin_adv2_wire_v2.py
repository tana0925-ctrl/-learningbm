#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""阪神マン アドバイス配線 v2 — public/hanshin_advice2.js のみを書き換える。

背景:
  HANSHIN_ADVICE_TREE は src/index.tsx の initGame() 内の const なので、
  initGame() が呼ばれるたびに別のオブジェクトが作られる。
  旧 public/hanshin_advice2.js は200msごとの待ち受けで window.HANSHIN_ADVICE_TREE を
  探し、最初のマージ成功で待ち受けを止めていた。そのため2回目以降の initGame()
  (復習チャレンジ / QR読み取り / バトル終了後の onclick など) で作られた木には
  中1〜高1の93件が入らず、「すまん！この修行のアドバイスはまだ準備中や！」が出ていた。
  本番で initGame() を再実行して再現済み (207キー -> 114キー)。

対策:
  Object.defineProperty で window.HANSHIN_ADVICE_TREE への代入そのものを捕捉し、
  代入の瞬間に同期マージする。待ち受けとタイムアウトは全廃。
  あわせて CURRICULUM の全単元と突き合わせ、アドバイス未登録の単元IDを
  console.warn に出す (先生がバグ報告するときの手がかり)。

src/index.tsx には一切触らない。
"""

import re
import sys

PATH = "public/hanshin_advice2.js"

# 冪等性の番兵。適用後検証の条件とは別物にしてある（番兵と検証が同じだと
# 「パッチがスキップされたのに検証が通る」事故が起きるため）。
SENTINEL = "__HANSHIN_ADV2_WIRE_V2__"

ANCHOR_ADD_EXPORT = "window.__HANSHIN_ADV2_ADD = ADD;"
ANCHOR_OLD_START = "var _adv2Last = null;"
ADD_KEY_RE = re.compile(r"^    '[a-z0-9-]+': \{ question:", re.M)
EXPECTED_ADD_KEYS = 93

NEW_TAIL = r'''  /* __HANSHIN_ADV2_WIRE_V2__
     配線v2: ポーリングを全廃し、window.HANSHIN_ADVICE_TREE への代入そのものを捕捉して同期マージする。

     旧実装の不具合: HANSHIN_ADVICE_TREE は initGame() 内の const なので、initGame() が
     呼ばれるたびに別オブジェクトが作られる。旧実装は200msごとの待ち受けを回し、最初の
     マージ成功時に待ち受けを止めていたため、2回目以降の initGame()（復習チャレンジ、
     QR読み取り、バトル終了後の onclick など）で作られた木には中1〜高1の93件が入らず、
     「すまん！この修行のアドバイスはまだ準備中や！」が出ていた。

     代入をフックすれば、initGame() が何回走っても代入の瞬間にマージが完了する。 */

  var _adv2Tree = null;
  var _adv2PrevMiss = null;

  function _adv2UnitIds() {
    var ids = [];
    try {
      var C = window.CURRICULUM;
      for (var s in C) {
        var grades = C[s] && C[s].grades;
        if (!grades) continue;
        for (var g in grades) {
          var us = (grades[g] && grades[g].units) || [];
          for (var i = 0; i < us.length; i++) { if (us[i] && us[i].id) ids.push(us[i].id); }
        }
      }
    } catch (e) {}
    return ids;
  }

  function _adv2ReportGaps(t) {
    try {
      var ids = _adv2UnitIds(), miss = [], i;
      for (i = 0; i < ids.length; i++) { if (!t[ids[i]]) miss.push(ids[i]); }
      window.__HANSHIN_ADV2_MISSING = miss;
      var key = miss.join(',');
      if (miss.length && key !== _adv2PrevMiss) {
        console.warn('[阪神マン] アドバイス未登録の単元ID (' + miss.length + '件): ' + key);
      }
      _adv2PrevMiss = key;
    } catch (e) {}
  }

  function _adv2Merge(t) {
    if (!t || typeof t !== 'object') return false;
    var n = 0, total = 0;
    for (var k in ADD) {
      if (!Object.prototype.hasOwnProperty.call(ADD, k)) continue;
      try { if (!t[k]) { t[k] = ADD[k]; n++; } if (t[k]) total++; } catch (e) {}
    }
    try {
      window.__HANSHIN_ADV2_COUNT = n;
      window.__HANSHIN_ADV2_TOTAL = total;
      window.__HANSHIN_ADV2_MERGES = (window.__HANSHIN_ADV2_MERGES || 0) + 1;
      window.__HANSHIN_ADV2_READY = true;
    } catch (e) {}
    _adv2ReportGaps(t);
    return true;
  }

  // 参照側から同期的に呼べる保険。呼んだ時点でマージ済みを保証する。
  window.__HANSHIN_ADV2_ENSURE = function () {
    var t = null;
    try { t = window.HANSHIN_ADVICE_TREE; } catch (e) {}
    if (!t) return false;
    _adv2Merge(t);
    return true;
  };

  (function _adv2Install() {
    var existing = null;
    try { existing = window.HANSHIN_ADVICE_TREE; } catch (e) {}
    var ok = false;
    try {
      Object.defineProperty(window, 'HANSHIN_ADVICE_TREE', {
        configurable: true,
        enumerable: true,
        get: function () { return _adv2Tree; },
        set: function (v) { _adv2Tree = v; _adv2Merge(v); }
      });
      ok = true;
    } catch (e) {
      try { console.warn('[阪神マン] 配線v2の設置に失敗。即時マージにフォールバックします。', e); } catch (e2) {}
    }
    if (existing) {
      if (ok) { window.HANSHIN_ADVICE_TREE = existing; }
      else { _adv2Tree = existing; _adv2Merge(existing); }
    }
  })();
})();
'''


def fail(msg):
    print("[中止] " + msg)
    sys.exit(1)


def main():
    with open(PATH, encoding="utf-8") as f:
        src = f.read()

    if SENTINEL in src:
        print("[スキップ] 既に配線v2が適用済み (番兵 " + SENTINEL + " を検出)")
        return

    n_add = src.count(ANCHOR_ADD_EXPORT)
    if n_add != 1:
        fail("アンカー ADD公開行 が %d 個。ちょうど1個であるべき" % n_add)

    n_old = src.count(ANCHOR_OLD_START)
    if n_old != 1:
        fail("アンカー 旧配線先頭 が %d 個。ちょうど1個であるべき" % n_old)

    if not src.rstrip().endswith("})();"):
        fail("ファイル末尾が })(); で終わっていない")

    i_add = src.index(ANCHOR_ADD_EXPORT)
    i_old = src.index(ANCHOR_OLD_START)
    if i_old <= i_add:
        fail("旧配線が ADD公開行 より前にある。想定外の並び")

    add_before = len(ADD_KEY_RE.findall(src))
    if add_before != EXPECTED_ADD_KEYS:
        fail("ADD のエントリ数が %d 件。%d 件であるべき" % (add_before, EXPECTED_ADD_KEYS))

    line_start = src.rfind("\n", 0, i_old) + 1
    out = src[:line_start] + NEW_TAIL

    checks = [
        ("旧待ち受けが残存", "setInterval" not in out and "clearInterval" not in out),
        ("旧マージ関数が残存", "_adv2Last" not in out),
        ("代入フックが1個でない",
         out.count("Object.defineProperty(window, 'HANSHIN_ADVICE_TREE'") == 1),
        ("ENSURE が無い", "__HANSHIN_ADV2_ENSURE" in out),
        ("READY フラグが無い", "__HANSHIN_ADV2_READY" in out),
        ("未登録単元の警告が無い", "アドバイス未登録の単元ID" in out),
        ("ADD のエントリ数が変化", len(ADD_KEY_RE.findall(out)) == add_before),
        ("ADD公開行が消えた", out.count(ANCHOR_ADD_EXPORT) == 1),
        ("末尾が })(); でない", out.rstrip().endswith("})();")),
    ]
    ng = [name for name, ok in checks if not ok]
    if ng:
        fail("適用後検証に失敗: " + " / ".join(ng))

    with open(PATH, "w", encoding="utf-8") as f:
        f.write(out)

    print("[完了] %s を配線v2に更新 (%d -> %d バイト, ADD %d件を維持)"
          % (PATH, len(src.encode("utf-8")), len(out.encode("utf-8")), add_before))


main()
