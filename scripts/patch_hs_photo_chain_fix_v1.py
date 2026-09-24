# -*- coding: utf-8 -*-
"""
patch_hs_photo_chain_fix_v1.py — 配信チェーンと HS_PHOTO_MULTI_V1 の食いちがいを直す
2026-09-24  HS_PHOTO_CHAIN_FIX_V1

何が起きていたか：
  app.get('/') の配信チェーンに、2026-09-11 の「hs-photo-submit-20260911」という
  写真まわりの置換が5本（P1〜P4・P10）入っていた。これは同じ問題を
  「配信時に文字を差し替える」やり方で先に直していたもの。
  今日の HS_PHOTO_MULTI_V1 でソース側を作り直した結果、
    ・P1（旧ブロック撤去）  … 目印が hsPhotoSection → hsPhotoSection1 に変わって不一致 → 効かなくなった
                              ＝ 旧い写真欄が配信ページに復活していた
    ・P2（ボーナスの案内文）… 見出しを書きかえたので不一致 → 効かなくなった
                              ＝ 子どもへの「写真をつけるとボーナス」の案内が消えていた
    ・P3（multiple を外す）… ここだけ一致し続けていた
                              ＝ 複数まい選べるようにしたのに、配信時に剥がされて1まいに戻っていた
    ・P4/P10（1まい制限と縮小）… 不一致 → 効かなくなった（縮小はソース側で実装ずみなので問題なし）

直し方：
  置換の本数は増やさない（チェーンの数は変えない）。中身だけ実態に合わせる。
    P1 → 目印を hsPhotoSection1 にして、旧ブロックの撤去を復活させる
    P2 → 新しい見出しに合わせ、ボーナスの案内文を復活させる
    P3 → multiple を残したまま、ボタンの文字だけ整える（複数まいを殺さない）
  P4/P10 は、いまはどの文字とも一致しない死んだ置換。数を変えないためこの便では残すが、
  片づけの回で消すこと。※このファイルのいちばん下に、そのための目印を書いてある。
"""
import io
import sys

TSX = 'src/index.tsx'


def apply(s):
    # ---- P1: 旧ブロック撤去の目印を hsPhotoSection1 に ----
    old = 't = t.replace(/<div id="hsPhotoSection"[\\s\\S]*?<div id="hsPhotoAnalysis"[\\s\\S]*?<\\/div>\\s*<\\/div>/, "<!-- 2026-09: 旧・単一写真ブロックを撤去。hsPhotoSection / hsPhotoInput / hsPhotoStatus のID重複を解消 -->")'
    new = 't = t.replace(/<div id="hsPhotoSection1"[\\s\\S]*?<div id="hsPhotoAnalysis"[\\s\\S]*?<\\/div>\\s*<\\/div>/, "<!-- 2026-09-24: 旧・単一写真ブロックを撤去（目印が hsPhotoSection1 に変わったので追従）。写真欄は下の1か所だけにする -->")'
    assert s.count(old) == 1, 'P1: %d' % s.count(old)
    s = s.replace(old, new)

    # ---- P2: 見出しを新しいものに合わせ、ボーナスの案内文を復活 ----
    old = '"<div style=\\"font-size:13px; font-weight:bold; color:#0e7490;\\">📷 成果物の写真（任意・複数OK）</div>"'
    new = '"<div style=\\"font-size:13px; font-weight:bold; color:#0e7490;\\">📷 成果物の写真（任意・3まいまでOK）</div>"'
    assert s.count(old) == 1, 'P2: %d' % s.count(old)
    s = s.replace(old, new)

    # ボーナス案内の差し替え先にも「3まいまで」を書いておく
    old = '"<div style=\\"font-size:13px; font-weight:bold; color:#0e7490;\\">📷 写真をつけるとボーナス！<span style=\\"font-weight:normal; font-size:11px;\\">（1日1回）</span></div>\\n          <div style=\\"font-size:11px; color:#0e7490; line-height:1.5; margin:2px 0 4px;\\">がんばったノートやプリントの写真をつけると、コインなどがもらえるよ。すごくまれに、とくべつなことが起きるかも。写真なしでも、ふつうに提出できます。</div>"'
    new = '"<div style=\\"font-size:13px; font-weight:bold; color:#0e7490;\\">📷 写真をつけるとボーナス！<span style=\\"font-weight:normal; font-size:11px;\\">（1日1回・3まいまで）</span></div>\\n          <div style=\\"font-size:11px; color:#0e7490; line-height:1.5; margin:2px 0 4px;\\">がんばったノートやプリントの写真をつけると、コインなどがもらえるよ。3まいまで出せます。すごくまれに、とくべつなことが起きるかも。写真なしでも、ふつうに提出できます。</div>"'
    assert s.count(old) == 1, 'P2b: %d' % s.count(old)
    s = s.replace(old, new)

    # ---- P3: multiple を剥がすのをやめる（ボタンの文字だけ整える） ----
    old = '"写真をえらぶ\\n            <input type=\\"file\\" id=\\"hsPhotoInput\\" accept=\\"image/*\\" style=\\"display:none;\\" onchange=\\"hsPhotosSelected(this)\\"/>"'
    new = '"写真をえらぶ／とる\\n            <input type=\\"file\\" id=\\"hsPhotoInput\\" accept=\\"image/*\\" multiple style=\\"display:none;\\" onchange=\\"hsPhotosSelected(this)\\"/>"'
    assert s.count(old) == 1, 'P3: %d' % s.count(old)
    s = s.replace(old, new)

    return s


def main():
    src = io.open(TSX, encoding='utf-8').read()
    out = apply(src)
    if out == src:
        print('NO CHANGE')
        sys.exit(1)
    io.open(TSX, 'w', encoding='utf-8').write(out)
    print('patched %s (%d -> %d)' % (TSX, len(src), len(out)))


if __name__ == '__main__':
    main()
