#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_hs_photo_20260911.py  ---- 家庭学習「写真提出」の改修（1/2）

src/index.tsx の .replace() チェーン末尾に 5 件追加する。
public/index.html は触らない。

  P1  旧・単一写真ブロックを撤去（hsPhotoSection / hsPhotoInput / hsPhotoStatus のID重複を解消）
  P2  提出前にボーナスの存在を知らせる（キャラ名は出さない）
  P3  multiple を外す（DB は user_id+day_key の1日1枚）
  P4  「n枚セット済み」の嘘表示を廃止／選び直しで差し替え／送信前に写真を縮小
  P10 縮小コールバックを閉じる（P4 とセット）

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

SENTINEL = "hs-photo-submit-20260911"
INSERT_ANCHOR = "\n      _rootHtmlCache = t\n"
CHAIN_BEGIN = "let t = await a.text()"
CHAIN_END = "return c.html("

N = "\n"

P1_RE_SRC = (r'<div id="hsPhotoSection"[\s\S]*?'
             r'<div id="hsPhotoAnalysis"[\s\S]*?<\/div>\s*<\/div>')
P1_TO = ("<!-- 2026-09: 旧・単一写真ブロックを撤去。"
         "hsPhotoSection / hsPhotoInput / hsPhotoStatus のID重複を解消 -->")

P2_FROM = ('<div style="font-size:13px; font-weight:bold; color:#0e7490;">'
           '\U0001F4F7 成果物の写真（任意・複数OK）</div>')
P2_TO = (
    '<div style="font-size:13px; font-weight:bold; color:#0e7490;">'
    '\U0001F4F7 写真をつけるとボーナス！'
    '<span style="font-weight:normal; font-size:11px;">（1日1回）</span></div>'
    + N + '          '
    '<div style="font-size:11px; color:#0e7490; line-height:1.5; margin:2px 0 4px;">'
    'がんばったノートやプリントの写真をつけると、コインなどがもらえるよ。'
    'すごくまれに、とくべつなことが起きるかも。'
    '写真なしでも、ふつうに提出できます。</div>'
)

P3_FROM = ('写真を追加' + N + '            '
           '<input type="file" id="hsPhotoInput" accept="image/*" multiple '
           'style="display:none;" onchange="hsPhotosSelected(this)"/>')
P3_TO = ('写真をえらぶ' + N + '            '
         '<input type="file" id="hsPhotoInput" accept="image/*" '
         'style="display:none;" onchange="hsPhotosSelected(this)"/>')

P4_FROM = (
    "    if (_hsPhotoFiles.length >= 5) { alert('写真は最大5枚までです'); break; }" + N +
    "    _hsPhotoFiles.push(file);" + N +
    "    hsAddPhotoPreview(file, _hsPhotoFiles.length - 1);" + N +
    "  }" + N +
    "  input.value = '';" + N +
    "  if (statusEl) statusEl.textContent = _hsPhotoFiles.length ? "
    "'\U0001F4CE ' + _hsPhotoFiles.length + '枚セット済み' : '';" + N +
    "  // 最初の1枚だけAI分析（教師用）" + N +
    "  if (_hsPhotoFiles.length > 0 && !_hsPhotoAnalysisResult) {" + N +
    "    var sess = hsGetSession();" + N +
    "    var dayKey = sess ? sess.dayKey : hsGetDayKey830(new Date());" + N +
    "    var fd = new FormData();" + N +
    "    fd.append('photo', _hsPhotoFiles[0]);" + N +
    "    fd.append('dayKey', dayKey);" + N +
    "    fetch('/api/homework/analyze-photo', { method: 'POST', body: fd })"
)

_SHRINK = (
    "  // 送信前に写真を小さくする（長辺1200px / JPEG 0.7）。"
    "うまくいかないときは元のまま送る。" + N +
    "  function hsShrinkPhoto(f, cb){" + N +
    "    try{" + N +
    "      if (!f || !/^image\\//.test(f.type || '')) { cb(f); return; }" + N +
    "      var u = URL.createObjectURL(f);" + N +
    "      var im = new Image();" + N +
    "      im.onload = function(){" + N +
    "        try{" + N +
    "          var MX = 1200;" + N +
    "          var w = im.naturalWidth || im.width, h = im.naturalHeight || im.height;" + N +
    "          if (!w || !h) { URL.revokeObjectURL(u); cb(f); return; }" + N +
    "          var sc = Math.min(1, MX / Math.max(w, h));" + N +
    "          var cw = Math.max(1, Math.round(w * sc)), ch = Math.max(1, Math.round(h * sc));" + N +
    "          var cv = document.createElement('canvas'); cv.width = cw; cv.height = ch;" + N +
    "          var cx = cv.getContext('2d');" + N +
    "          cx.imageSmoothingEnabled = true;" + N +
    "          try { cx.imageSmoothingQuality = 'high'; } catch(_q){}" + N +
    "          cx.drawImage(im, 0, 0, cw, ch);" + N +
    "          cv.toBlob(function(b){ URL.revokeObjectURL(u); "
    "cb(b && b.size && b.size < f.size ? b : f); }, 'image/jpeg', 0.7);" + N +
    "        }catch(_a){ URL.revokeObjectURL(u); cb(f); }" + N +
    "      };" + N +
    "      im.onerror = function(){ URL.revokeObjectURL(u); cb(f); };" + N +
    "      im.src = u;" + N +
    "    }catch(_b){ cb(f); }" + N +
    "  }" + N
)

P4_TO = (
    "    if (_hsPhotoFiles.length >= 1) { _hsPhotoFiles = []; _hsPhotoAnalysisResult = ''; "
    "var _pl0 = document.getElementById('hsPhotoPreviewList'); if (_pl0) _pl0.innerHTML = ''; }" + N +
    "    _hsPhotoFiles.push(file);" + N +
    "    hsAddPhotoPreview(file, _hsPhotoFiles.length - 1);" + N +
    "    break;" + N +
    "  }" + N +
    _SHRINK +
    "  input.value = '';" + N +
    "  if (statusEl) statusEl.textContent = _hsPhotoFiles.length ? "
    "'\U0001F4CE 写真をセットしたよ' : '';" + N +
    "  // 最初の1枚だけAI分析（教師用）" + N +
    "  if (_hsPhotoFiles.length > 0 && !_hsPhotoAnalysisResult) {" + N +
    "    var sess = hsGetSession();" + N +
    "    var dayKey = sess ? sess.dayKey : hsGetDayKey830(new Date());" + N +
    "    hsShrinkPhoto(_hsPhotoFiles[0], function(_sent){" + N +
    "    var fd = new FormData();" + N +
    "    fd.append('photo', _sent, 'photo.jpg');" + N +
    "    fd.append('dayKey', dayKey);" + N +
    "    fetch('/api/homework/analyze-photo', { method: 'POST', body: fd })"
)

P10_FROM = ("      .catch(function(e) { console.warn('[photo-analysis]', e); });" + N +
            "  }" + N + "}")
P10_TO = ("      .catch(function(e) { console.warn('[photo-analysis]', e); });" + N +
          "    });" + N + "  }" + N + "}")

PATCHES = [
    ("P1", "re", P1_RE_SRC, P1_TO, "旧ブロック撤去（ID重複の解消）",
     "d1b856ab940f545284e9714fd8017807", "f8d41926868aeaa41e451f6ed76f396c"),
    ("P2", "str", P2_FROM, P2_TO, "提出前にボーナスの存在を知らせる",
     "8506252872939d4553b0cfadba4a6606", "4ac25b74e3807cc50b802b34af7e64ba"),
    ("P3", "str", P3_FROM, P3_TO, "multiple を外す（1日1枚）",
     "9db463eb990dd416d6e3dab2c247300e", "346bfe716e973470815676b9b9e27b4e"),
    ("P4", "str", P4_FROM, P4_TO, "枚数表示の是正＋送信前の縮小（長辺1200px/JPEG0.7）",
     "51d4bd7486121ba4a95e33a86fae955b", "9ca7db84f5f8ae88811792ff48d3d16d"),
    ("P10", "str", P10_FROM, P10_TO, "縮小コールバックを閉じる（P4とセット）",
     "4107c5025fd96b3663e3c81957b4efb2", "fd4d1a2649009454dcaa3ec9959c121d"),
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
