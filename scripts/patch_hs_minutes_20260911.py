#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_hs_minutes_20260911.py  ---- 家庭学習「学習時間」の改修（2/2）

src/index.tsx の .replace() チェーン末尾に 5 件追加する。
public/index.html は触らない。タイマーは残したまま、手入力を成立させる。

  P5  タイマー未使用のときだけ「タイマーでも手入力でもOK」を表示（経過表示と自動入れ替え）
  P6  タイマーが手入力の値を上書きしないようにする
  P7  スタート未押下でも、分が入っていれば提出できるようにする
  P8  上限300分（責めない文言でまるめる）／0分のときだけ1回確認する
  P9  提出ボタンの活性条件も合わせて緩める（P7 とセット。これが無いと P7 に到達しない）

冪等性:
  SENTINEL の有無で二重適用を防ぐ。
  検証は SENTINEL ではなく「結果そのもの」を見る。
  さらに、アンカー文字列そのものの SHA-256 を実行時に照合する。
"""

import hashlib
import json
import pathlib
import sys

SRC = pathlib.Path("src/index.tsx")

SENTINEL = "hs-minutes-input-20260911"
INSERT_ANCHOR = "\n      _rootHtmlCache = t\n"
CHAIN_BEGIN = "let t = await a.text()"
CHAIN_END = "return c.html("

N = "\n"

# .hs-timeBox は height:140px / overflow:hidden の固定枠なので、行を足すと隠れる。
# .hs-subLabel も white-space:nowrap で「...」に切れる。
# そこで、タイマー停止中だけ空いている「経過表示」の位置に出し、
# 走り出したら CSS の隣接セレクタで自動的に経過表示に入れ替える（JSは触らない）。
P5_FROM = ('<div id="hsElapsedLine" class="hs-elapsedLine hidden">'
           '経過 0:00</div>')
P5_TO = (
    '<div id="hsElapsedLine" class="hs-elapsedLine hidden" data-hint="1">経過 0:00</div>'
    '<div id="hsMinHint">⏱タイマーでも、手入力でもOK</div>'
    '<style>#hsMinHint{display:none; position:absolute; left:8px; right:8px; top:31px; '
    'text-align:center; font-size:10px; font-weight:700; color:#0e7490; line-height:1.2; '
    'white-space:nowrap; overflow:hidden; text-overflow:ellipsis;} '
    '#hsElapsedLine.hidden + #hsMinHint{display:block;}</style>'
)

# 児童が自分で打った値は、タイマーが上書きしない。
# 「直前にタイマーが書いた値」と違っていれば手入力とみなす方式なので、
# フラグを立てる箇所を増やさずに1か所の変更で完結する。
P6_FROM = (
    "      // 経過時間を自動でやった時間に反映" + N +
    "      if(minEl && !submitted){" + N +
    "        minEl.value = elapsedMin;" + N +
    "        if(sess) sess.minutesManual = String(elapsedMin);" + N +
    "      }"
)
P6_TO = (
    "      // 経過時間を自動でやった時間に反映（手で入力された値は上書きしない）" + N +
    "      if(minEl && !submitted){" + N +
    '        var _curMin = String(minEl.value || "").trim();' + N +
    '        var _lastAuto = (sess && sess.minutesTimerLast != null) ? String(sess.minutesTimerLast) : "";' + N +
    '        if (_curMin === "" || _curMin === _lastAuto){' + N +
    "          minEl.value = elapsedMin;" + N +
    "          if(sess){ sess.minutesManual = String(elapsedMin); sess.minutesTimerLast = String(elapsedMin); }" + N +
    "        }" + N +
    "      }"
)

# 紙で勉強してから記録だけ付けたい子のための経路。
P7_FROM = ("    if (!sess.started || !sess.unlocked) { hsRender(); if (btn) { btn.disabled = false; "
           "btn.textContent = '\U0001F4E4 先生に提出'; } return; }")
P7_TO = (
    '    var _mEl0 = document.getElementById("hsMinutes");' + N +
    '    var _typedMin = Math.max(0, parseInt(String((_mEl0 && _mEl0.value) '
    '|| sess.minutesManual || "0"), 10) || 0);' + N +
    "    if ((!sess.started || !sess.unlocked) && _typedMin <= 0) { hsRender(); if (btn) { btn.disabled = false; "
    "btn.textContent = '\U0001F4E4 先生に提出'; } return; }"
)

# 上限は300分。こえてもブロックせず、まるめて通す。責める文言にしない。
# 0分は「1回だけ」確認する。キャンセル（このまま出す）で通る。休みの日は確認しない。
P8_FROM = (
    '    const minEl = document.getElementById("hsMinutes");' + N +
    '    const minutes = Math.max(0, (parseInt((minEl && minEl.value) ? minEl.value : '
    '(sess.minutesManual||"0"), 10) || 0));'
)
P8_TO = (
    '    const minEl = document.getElementById("hsMinutes");' + N +
    '    let minutes = Math.max(0, (parseInt((minEl && minEl.value) ? minEl.value : '
    '(sess.minutesManual||"0"), 10) || 0));' + N +
    "    if (minutes > 300){" + N +
    "      minutes = 300;" + N +
    '      if (minEl) minEl.value = "300";' + N +
    "      try { alert('300分をこえたみたいだね。300分にしておくね。"
    "長くやったことは先生に伝わってるよ！'); } catch(_e0){}" + N +
    "    }" + N +
    "    if (minutes === 0 && !hsIsRestDay(dayKey) && !sess.zeroMinAsked){" + N +
    "      sess.zeroMinAsked = true;" + N +
    "      try { hsSetSession(sess); } catch(_e1){}" + N +
    "      let _wantInput = false;" + N +
    "      try { _wantInput = confirm('時間が0分のままだよ。\\n"
    "入れなくても出せるけど、だいたいでいいから入れる？\\n\\n"
    "［OK］入れる　／　［キャンセル］このまま出す'); } catch(_e2){ _wantInput = false; }" + N +
    "      if (_wantInput){" + N +
    "        if (minEl) { try { minEl.focus(); } catch(_e3){} }" + N +
    "        hsRender();" + N +
    "        if (btn) { btn.disabled = false; btn.textContent = '\U0001F4E4 先生に提出'; }" + N +
    "        return;" + N +
    "      }" + N +
    "    }"
)

P9_FROM = ("      const canExport = !!(sess && sess.started && unlocked "
           "&& !submitted && minOk);")
P9_TO = ("      const canExport = !!(sess && (sess.started || minOk) && unlocked "
         "&& !submitted && minOk);")

PATCHES = [
    ("P5", "str", P5_FROM, P5_TO, "タイマー未使用時だけヒントを出す",
     "35beec726f4d6b88d971d869f99cbca4", "c1e3a9d71f4493d211f6406d85520eb8"),
    ("P6", "str", P6_FROM, P6_TO, "タイマーが手入力を上書きしない",
     "ac274132e085869c31b5356ba45ab0f3", "bbf42913fcedc0480a60fa61aa990ef9"),
    ("P7", "str", P7_FROM, P7_TO, "スタート未押下でも分があれば提出可",
     "b08d738a8135d2a6b5a765eb4313699b", "a8bc6fc1a605fb1339c73a74e2775422"),
    ("P8", "str", P8_FROM, P8_TO, "上限300分（責めない）／0分は1回だけ確認",
     "c6290704fe17956093d3446f7611f8ef", "9451c4fbb4919d809479ebbdda8f0a5b"),
    ("P9", "str", P9_FROM, P9_TO, "提出ボタンの活性条件も緩める（P7とセット）",
     "6cc28fad24eda473d4d781beafda633e", "bad87aceb3eff77d996e57c0b7616d0b"),
]


def js(s):
    return json.dumps(s, ensure_ascii=False)


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:32]


def chain_slice(text):
    i = text.index(CHAIN_BEGIN)
    j = text.index(CHAIN_END, i)
    return text[i:j]


def build_block():
    out = [N + "      // ===== " + SENTINEL + " =====" + N]
    for pid, kind, frm, to, comment, _hf, _ht in PATCHES:
        out.append("      // " + pid + " " + comment + N)
        left = ("/" + frm + "/") if kind == "re" else js(frm)
        out.append("      t = t.replace(" + left + ", " + js(to) + ")" + N)
    return "".join(out)


def main():
    if not SRC.exists():
        print("ERROR: src/index.tsx が見つかりません")
        return 1

    text = SRC.read_text(encoding="utf-8")

    if SENTINEL in text:
        print("SKIP: すでに適用済みです（sentinel あり）。何も変更しません。")
        return 0

    bad = []
    for pid, kind, frm, to, _c, hf, ht in PATCHES:
        if sha(frm) != hf:
            bad.append("%s の FROM が想定と違います（%s != %s）" % (pid, sha(frm), hf))
        if sha(to) != ht:
            bad.append("%s の TO が想定と違います（%s != %s）" % (pid, sha(to), ht))
    if bad:
        print("ERROR: アンカー文字列の照合に失敗しました。書き込みません。")
        for b in bad:
            print("  - " + b)
        return 1
    print("アンカー照合: %d 件すべて一致" % (len(PATCHES) * 2))

    n_anchor = text.count(INSERT_ANCHOR)
    if n_anchor != 1:
        print("ERROR: 挿入アンカーが %d 個です" % n_anchor)
        return 1

    before = chain_slice(text).count(".replace(")
    print("適用前: チェーンの .replace( = %d 件" % before)

    for pid, kind, frm, to, _c, _hf, _ht in PATCHES:
        lit = ("/" + frm + "/") if kind == "re" else js(frm)
        if lit in text:
            print("ERROR: %s のアンカーリテラルが既に index.tsx にあります" % pid)
            return 1

    block = build_block()
    new_text = text.replace(INSERT_ANCHOR, block + INSERT_ANCHOR, 1)

    after = chain_slice(new_text).count(".replace(")
    print("適用後: チェーンの .replace( = %d 件" % after)

    errs = []
    if after != before + len(PATCHES):
        errs.append("件数が %d → %d（期待 +%d）" % (before, after, len(PATCHES)))
    for pid, kind, frm, to, _c, _hf, _ht in PATCHES:
        lit = ("/" + frm + "/") if kind == "re" else js(frm)
        if new_text.count(lit) != 1:
            errs.append("%s のアンカーが %d 個" % (pid, new_text.count(lit)))
        if new_text.count(js(to)) != 1:
            errs.append("%s の置換後リテラルが %d 個" % (pid, new_text.count(js(to))))
    if new_text.count(INSERT_ANCHOR) != 1:
        errs.append("挿入アンカーが複数になりました")

    if errs:
        print("ERROR: 検証に失敗しました。書き込みません。")
        for e in errs:
            print("  - " + e)
        return 1

    SRC.write_text(new_text, encoding="utf-8")
    print("OK: src/index.tsx を更新しました（+%d 件、%+d bytes）"
          % (len(PATCHES), len(new_text) - len(text)))
    for pid, _k, _f, _t, comment, _hf, _ht in PATCHES:
        print("  %s  %s" % (pid, comment))
    return 0


if __name__ == "__main__":
    sys.exit(main())
