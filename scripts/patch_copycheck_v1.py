# -*- coding: utf-8 -*-
"""
patch_copycheck_v1.py — COPYCHECK_V1  2026-10-05

先生の訴え：「コピーした？ けどコピーしてない」「なんかコピーできてない」

本番で実際に押して分かったこと：
  ・22人ぶんを集めるのに 82.5秒かかる（API 27本を1本ずつ順番に呼んでいる）。
  ・そのあと navigator.clipboard.writeText() が「成功」を返しても、
    クリップボードが空のことがある（本番で実測。16文字でも空になった）。
  ・失敗したときの逃げ道 document.execCommand('copy') は false を返す。
    82秒たつと「いまユーザーが押した」あつかいが切れているため、ブラウザが拒む。
  ・それでも copyText() は done() を必ず呼ぶので、画面には
    「✓ コピーしました」と出る。入っていないのに成功と言っていた。

直すこと（2件）:
  A. 書いたあと必ず読み返して、本当に入ったか確かめる。
     入っていなければ「⚠ コピーできていません」と出し、
     手で Ctrl+C できる逃げ道の枠（textarea）をその場に出す。
     ・fallbackCopy() は成否（true/false）を返すようにする。今は握りつぶしている。
     ・読み返しが許されない環境では、今までどおり成功あつかいにする（後退させない）。
     ・改行は Windows で \r\n に変わるので、比べる前にそろえる。
  B. 絵文字の文字化けを直す。
     Python の u'\\U0001F4C5' がそのまま JS の文字列に書き出され、
     JS に \\U のエスケープが無いため「U0001F4C5」と画面に出ていた（commit 02798b6）。
     📅 と 📊 に直す。

  ・public/teacher-ai.js を変えるので src/index.tsx の ?v=9 → ?v=10 に上げる。
  ・入れる HTML に onclick= は使わない（addEventListener にする）。
    テンプレートリテラルのエスケープ事故を構造でさける。
  ・★配信チェーン（159件）は1件も増減させない。合わなければ1文字も書かずに止まる。
"""
import io
import sys

TSX = 'src/index.tsx'
AIJS = 'public/teacher-ai.js'
ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"
CHAIN_WANT = 159


def die(msg):
    sys.stderr.write('NG: ' + msg + '\n')
    sys.exit(1)


def chain_count(s):
    i = s.index(ROOT_ANCHOR)
    j = s.index(END_ANCHOR, i)
    return s[i:j].count('.replace(')


def rep(s, old, new, label, times=1):
    n = s.count(old)
    if n != times:
        die(u'あて先 %s が %d 件（%d 件のはず）' % (label, n, times))
    return s.replace(old, new)


# ===================================================== A-1 コピーの成否を見る
COPY_OLD = (
    u"    if (navigator.clipboard && navigator.clipboard.writeText) {\n"
    u"      navigator.clipboard.writeText(txt).then(done, function () { fallbackCopy(txt); done(); });\n"
    u"    } else { fallbackCopy(txt); done(); }\n"
    u"  }\n"
)
COPY_NEW = (
    u"    // 2026-10-05 COPYCHECK_V1：入っていないのに「コピーしました」と言わない。\n"
    u"    //   書いたあと読み返して確かめる。読み返せない環境では今までどおり成功あつかい。\n"
    u"    var ok = function () {\n"
    u"      var b = $('taiManualBox');\n"
    u"      if (b && b.parentNode) b.parentNode.removeChild(b);\n"
    u"      done();\n"
    u"    };\n"
    u"    var ng = function (why) {\n"
    u"      say('⚠ コピーできていません（' + why + '）。この画面を開いたまま、'\n"
    u"        + 'もう一度「\U0001f4cb まとめてコピー」を押してください。'\n"
    u"        + '作り直しはしないので、すぐ終わります。');\n"
    u"      taiManualBox(txt);\n"
    u"    };\n"
    u"    var norm = function (v) { return String(v == null ? '' : v).replace(/\\r\\n/g, '\\n'); };\n"
    u"    if (!(navigator.clipboard && navigator.clipboard.writeText)) {\n"
    u"      if (fallbackCopy(txt)) ok(); else ng('このブラウザでは書きこめません');\n"
    u"      return;\n"
    u"    }\n"
    u"    navigator.clipboard.writeText(txt).then(function () {\n"
    u"      if (!navigator.clipboard.readText) { ok(); return; }\n"
    u"      navigator.clipboard.readText().then(function (t) {\n"
    u"        var got = norm(t);\n"
    u"        if (got.length && got.slice(0, 120) === txt.slice(0, 120)\n"
    u"            && got.length >= Math.floor(txt.length * 0.9)) ok();\n"
    u"        else ng('書きこめたように見えて、中身が入っていません');\n"
    u"      }, function () { ok(); });\n"
    u"    }, function (e) {\n"
    u"      if (fallbackCopy(txt)) { ok(); return; }\n"
    u"      var nm = (e && e.name) || '';\n"
    u"      ng(nm === 'NotAllowedError'\n"
    u"         ? 'ほかの画面に切りかえているあいだは書きこめません'\n"
    u"         : (nm || String(e)));\n"
    u"    });\n"
    u"  }\n"
    u"  // 手で Ctrl+C できる逃げ道。コピーに失敗したときだけ出す。\n"
    u"  //   onclick 属性は使わない（エスケープ事故を構造でさける）。\n"
    u"  function taiManualBox(txt) {\n"
    u"    try {\n"
    u"      var st = $('taiStatus');\n"
    u"      var host = (st && st.parentNode) || document.body;\n"
    u"      var old = $('taiManualBox');\n"
    u"      if (old && old.parentNode) old.parentNode.removeChild(old);\n"
    u"      var box = document.createElement('div');\n"
    u"      box.id = 'taiManualBox';\n"
    u"      box.style.cssText = 'margin-top:8px;border:2px solid #dc2626;border-radius:10px;padding:8px;background:#fef2f2';\n"
    u"      var lead = document.createElement('div');\n"
    u"      lead.style.cssText = 'font-size:12px;font-weight:800;color:#b91c1c;margin-bottom:5px';\n"
    u"      lead.textContent = '下の枠の中が、コピーしたかった文です。「ぜんぶ選ぶ」を押してから Ctrl+C（Mac は ⌘+C）でコピーできます。';\n"
    u"      var ta = document.createElement('textarea');\n"
    u"      ta.id = 'taiManualText';\n"
    u"      ta.readOnly = true;\n"
    u"      ta.rows = 5;\n"
    u"      ta.style.cssText = 'width:100%;font-size:11px;border:1px solid #fca5a5;border-radius:8px;padding:6px';\n"
    u"      ta.value = txt;\n"
    u"      var btn = document.createElement('button');\n"
    u"      btn.type = 'button';\n"
    u"      btn.textContent = 'ぜんぶ選ぶ';\n"
    u"      btn.style.cssText = 'margin-top:5px;background:#dc2626;color:#fff;border:none;border-radius:8px;padding:5px 12px;font-size:12px;font-weight:800;cursor:pointer';\n"
    u"      btn.addEventListener('click', function () { ta.focus(); ta.select(); });\n"
    u"      box.appendChild(lead); box.appendChild(ta); box.appendChild(btn);\n"
    u"      host.appendChild(box);\n"
    u"      ta.focus(); ta.select();\n"
    u"    } catch (e) {}\n"
    u"  }\n"
)

# ===================================================== A-2 逃げ道が成否を返す
FB_OLD = (
    u"  function fallbackCopy(txt) {\n"
    u"    try {\n"
    u"      if (typeof _faFallbackCopy === 'function') { _faFallbackCopy(txt); return; }\n"
    u"      var ta = document.createElement('textarea');\n"
    u"      ta.value = txt; ta.style.position = 'fixed'; ta.style.left = '-9999px';\n"
    u"      document.body.appendChild(ta); ta.select(); document.execCommand('copy');\n"
    u"      document.body.removeChild(ta);\n"
    u"    } catch (e) {}\n"
    u"  }\n"
)
FB_NEW = (
    u"  // 2026-10-05 COPYCHECK_V1：できたかどうかを返す（今までは握りつぶしていた）。\n"
    u"  //   _faFallbackCopy() は成否を返さないので、ここでは使わず自前でやる（やることは同じ）。\n"
    u"  function fallbackCopy(txt) {\n"
    u"    try {\n"
    u"      var ta = document.createElement('textarea');\n"
    u"      ta.value = txt; ta.style.position = 'fixed'; ta.style.left = '-9999px';\n"
    u"      document.body.appendChild(ta); ta.select();\n"
    u"      var okc = document.execCommand('copy');\n"
    u"      document.body.removeChild(ta);\n"
    u"      return !!okc;\n"
    u"    } catch (e) { return false; }\n"
    u"  }\n"
)

# ===================================================== B 絵文字の文字化け
EMO1_OLD = u"  note.textContent = '\\U0001F4C5 今日は月曜日です。"
EMO1_NEW = u"  note.textContent = '\U0001f4c5 今日は月曜日です。"
EMO2_OLD = u"-800\">\\U0001F4CA いま何人ぶんの材料があるか</div>'"
EMO2_NEW = u"-800\">\U0001f4ca いま何人ぶんの材料があるか</div>'"

# ===================================================== 配信の版を上げる
VER_OLD = u'<script src="/teacher-ai.js?v=9"></script>'
VER_NEW = u'<script src="/teacher-ai.js?v=10"></script>'


def main():
    s = io.open(TSX, encoding='utf-8').read()
    n0 = chain_count(s)
    if n0 != CHAIN_WANT:
        die(u'チェーンが %d 件（%d 件のはず）。止めます。' % (n0, CHAIN_WANT))

    a = io.open(AIJS, encoding='utf-8').read()
    a = rep(a, COPY_OLD, COPY_NEW, u'コピーの成否を見る')
    a = rep(a, FB_OLD, FB_NEW, u'逃げ道が成否を返す')
    a = rep(a, EMO1_OLD, EMO1_NEW, u'文字化け 📅')
    a = rep(a, EMO2_OLD, EMO2_NEW, u'文字化け 📊')
    if u'\\U0001F4C' in a:
        die(u'まだ壊れたエスケープが残っています')

    s = rep(s, VER_OLD, VER_NEW, u'teacher-ai.js の版を上げる')
    n1 = chain_count(s)
    if n1 != n0:
        die(u'チェーンが %d 件になった（%d 件のはず）' % (n1, n0))

    io.open(AIJS, 'w', encoding='utf-8').write(a)
    io.open(TSX, 'w', encoding='utf-8').write(s)
    print('PATCH OK / chain %d -> %d' % (n0, n1))


main()
