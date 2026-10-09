#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# REVIEW_C_V1 : 復習チャレンジを「四択／自己採点」にする
#
# ■ 何が問題だったか
#   復習チャレンジは、もとが四択だろうと必ずテキスト入力を出し、
#   checkReviewAnswer() が完全一致で判定していた。
#   「3Rの『R』には何と何と何がある？」のような問題は、正解を一字ずれず
#   打てないと正解にならない。入力で答えるのは不可能。
#
# ■ このパッチがすること（答えの形で判定する。単元名では判定しない）
#   ・答えが数字          -> 今までどおりの入力式（算数の計算）
#   ・数字でなく opts あり -> 四択のボタンを縦1列で出す（高さ 52px 以上）
#   ・数字でなく opts 無し -> 「こたえを見る」→ 自己採点
#   自己採点の「できた／まだ」は、もとからある
#     「✅ マスターした！」= reviewNextQuestion(true)  -> 復習リストから消える
#     「もう一度」        = reviewNextQuestion(false) -> 残る
#   をそのまま使う。新しいボタンは作らない。
#
#   opts は 10/09 の REVIEW_BCD_V1 から保存され始めたので、
#   それより前の記録はほとんど自己採点になる。これから間違えた四択は四択になる。
#
#   あわせて、問題文が1文字以下の壊れた記録（admin に 'j5-keigo || ? || 2' が1件）
#   を復習に出さない。
#
# ■ 触る範囲
#   public/index.html の9か所だけ。src/index.tsx は1バイトも触らない
#   （9つの足場がどれも src/index.tsx に無いことを下で確かめる）。
#   REVIEW_BADANS_A1 / REVIEW_BCD_V1 / REVIEW_MATH_V1 はそのまま残す。
#   D1 にも触らない。
#
# 前提が1つでも崩れたら、ファイルに書かずに exit 1（フェイルクローズ）。

import os
import sys

HTML = 'public/index.html'
SRC = 'src/index.tsx'

SENTINEL = '__REVIEW_C_V1__'

ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"


def die(msg):
    print('NG: ' + msg)
    sys.exit(1)


def count(text, needle):
    n = 0
    i = 0
    while True:
        i = text.find(needle, i)
        if i < 0:
            return n
        n += 1
        i += len(needle)


# ---------------------------------------------------------------- 鎖を数える
with open(SRC, 'r', encoding='utf-8', newline='') as f:
    src = f.read()

i0 = src.find(ROOT_ANCHOR)
i1 = src.find(END_ANCHOR)
if i0 < 0 or i1 < 0 or i1 <= i0:
    die('src/index.tsx の app.get の範囲が取れない')
chain = count(src[i0:i1], '.replace(')
print('chain(actual) = %d' % chain)

want = os.environ.get('CHAIN_BEFORE', '').strip()
if not want:
    die('CHAIN_BEFORE が渡されていない')
if not want.isdigit():
    die('CHAIN_BEFORE が数字でない: %r' % want)
if int(want) != chain:
    die('鎖の本数が合わない: CHAIN_BEFORE=%s / 実際=%d' % (want, chain))

# ---------------------------------------------------------------- 本体を読む
with open(HTML, 'r', encoding='utf-8', newline='') as f:
    html = f.read()

if '\r\n' in html:
    die('public/index.html に CRLF がある（LFのはず）')

if SENTINEL in html:
    print('SKIP: %s はもう入っている（冪等）' % SENTINEL)
    sys.exit(0)

if 'reviewModalChoices' in html:
    die('reviewModalChoices がもうある（別の便と衝突）')

# 壊してはいけない先行の便が居ることを確かめる
for k in ('__REVIEW_BADANS_A1__', '__REVIEW_BCD_V1__', '__REVIEW_MATH_V1__'):
    if k not in html:
        die('先行の便 %s が見つからない' % k)

# ---------------------------------------------------------------- 足場と置換
NEW_FUNCS = """
/* __REVIEW_C_V1__ : 答えの形で 入力式／四択／自己採点 を切り替える
   ・答えが数字          -> 入力式（今までどおり）
   ・数字でなく opts あり -> 四択
   ・数字でなく opts 無し -> こたえを見る → 自己採点
   単元名では判定しない。答えの形だけで判定する。 */
var _reviewAnsMode = 'input';
var _reviewPicked = null;

function _revIsNumAns(a) {
  return /^-?[0-9]+(\\.[0-9]+)?$/.test(String(a == null ? '' : a).trim());
}

function _revChoiceCls(on) {
  return 'w-full block text-left px-4 py-3 mb-2 rounded-xl border-2 font-bold text-lg leading-snug '
       + (on ? 'bg-amber-200 border-amber-500' : 'bg-white border-amber-300 hover:bg-amber-50');
}

/* 選択肢として使えるか。使えないなら null を返す（疑わしきは四択にしない） */
function _revChoiceList(x) {
  try {
    var raw = x && (x.opts || x.options);
    if (!raw || Object.prototype.toString.call(raw) !== '[object Array]') return null;
    var ans = String((x && x.ans) == null ? '' : x.ans).trim();
    if (!ans) return null;
    var seen = {}, out = [];
    for (var i = 0; i < raw.length; i++) {
      var t = String(raw[i] == null ? '' : raw[i]).trim();
      if (!t) continue;
      if (seen[t]) continue;
      seen[t] = 1;
      out.push(t);
    }
    if (out.length < 2) return null;
    var at = -1;
    for (var k = 0; k < out.length; k++) { if (out[k] === ans) { at = k; break; } }
    if (at < 0) return null;   /* 正解が選択肢に無い -> 四択にしない */
    /* 並びをまぜる */
    for (var j = out.length - 1; j > 0; j--) {
      var r = Math.floor(Math.random() * (j + 1));
      var tmp = out[j]; out[j] = out[r]; out[r] = tmp;
    }
    if (out.length > 4) {
      var cut = out.slice(0, 4);
      var has = false;
      for (var m = 0; m < cut.length; m++) { if (cut[m] === ans) { has = true; break; } }
      if (!has) cut[cut.length - 1] = ans;
      out = cut;
    }
    return out;
  } catch (e) { return null; }
}

function _revPickChoice(el, txt) {
  _reviewPicked = txt;
  var box = document.getElementById('reviewModalChoices');
  if (box) {
    var bs = box.getElementsByTagName('button');
    for (var i = 0; i < bs.length; i++) bs[i].className = _revChoiceCls(bs[i] === el);
  }
  checkReviewAnswer();
}

function _revSetupAnswerUI(item) {
  try {
    var area = document.getElementById('reviewModalAnswerArea');
    var box = document.getElementById('reviewModalChoices');
    var inp = document.getElementById('reviewModalInput');
    var btn = document.getElementById('reviewModalGoBtn');

    _reviewPicked = null;
    var ans = String((item && item.ans) == null ? '' : item.ans).trim();
    var list = _revIsNumAns(ans) ? null : _revChoiceList(item);
    _reviewAnsMode = _revIsNumAns(ans) ? 'input' : (list ? 'choice' : 'self');

    /* 毎回まっさらに戻す */
    if (area) { area.classList.remove('hidden'); area.style.display = ''; }
    if (box) { box.innerHTML = ''; box.classList.add('hidden'); box.style.display = 'none'; }
    if (inp) { inp.classList.remove('hidden'); inp.style.display = ''; }
    if (btn) { btn.classList.remove('hidden'); btn.style.display = ''; btn.textContent = 'こたえる！'; }

    if (_reviewAnsMode === 'choice' && box) {
      if (inp) { inp.classList.add('hidden'); inp.style.display = 'none'; }
      if (btn) { btn.classList.add('hidden'); btn.style.display = 'none'; }
      box.classList.remove('hidden');
      box.style.display = '';
      for (var i = 0; i < list.length; i++) {
        var b = document.createElement('button');
        b.type = 'button';
        b.className = _revChoiceCls(false);
        b.style.minHeight = '52px';
        b.textContent = list[i];
        b.onclick = (function (t) {
          return function (ev) { _revPickChoice(ev.currentTarget, t); };
        })(list[i]);
        box.appendChild(b);
      }
    } else if (_reviewAnsMode === 'self') {
      if (inp) { inp.classList.add('hidden'); inp.style.display = 'none'; }
      if (btn) btn.textContent = '\\ud83d\\udc40 こたえを見る';
    }
  } catch (e) { _reviewAnsMode = 'input'; }
}

"""

EDITS = [
    # (1) 選択肢の入れ物を、答え欄のいちばん上に置く
    (
        '    <div id="reviewModalAnswerArea">\n'
        '      <input type="text" id="reviewModalInput"',

        '    <div id="reviewModalAnswerArea">\n'
        '      <div id="reviewModalChoices" class="hidden mb-3"></div>\n'
        '      <input type="text" id="reviewModalInput"',
    ),

    # (2) 「こたえる！」ボタンに id を付ける（四択では隠し、自己採点では文字を変える）
    (
        '      <button onclick="checkReviewAnswer()" class="w-full bg-amber-500 hover:bg-amber-600 '
        'text-white font-black py-3 rounded-xl text-lg">こたえる！</button>',

        '      <button id="reviewModalGoBtn" onclick="checkReviewAnswer()" class="w-full bg-amber-500 hover:bg-amber-600 '
        'text-white font-black py-3 rounded-xl text-lg">こたえる！</button>',
    ),

    # (3) 問題を出すたびに答え欄を組み立て直す（_showReviewQuestion の最後）
    (
        '    if(progEl) progEl.textContent = `${_reviewCurrentIdx+1}/${_reviewQueue.length}問目`;',

        '    if(progEl) progEl.textContent = `${_reviewCurrentIdx+1}/${_reviewQueue.length}問目`;\n'
        '    try { _revSetupAnswerUI(_reviewCurrentItem); } catch(e){}   /* __REVIEW_C_V1__ */',
    ),

    # (4) 部品を checkReviewAnswer の手前に置く
    (
        'function checkReviewAnswer(){',
        NEW_FUNCS + 'function checkReviewAnswer(){',
    ),

    # (5) 判定を3通りにする。self は isOk = None 相当（○でも×でもない）
    (
        "    const userAns = (inputEl ? inputEl.value.trim() : '');\n"
        "    const correct = String(_reviewCurrentItem.ans||'').trim();\n"
        "    const isOk = (userAns === correct);",

        "    const userAns = (_reviewAnsMode === 'choice')\n"
        "      ? String(_reviewPicked == null ? '' : _reviewPicked).trim()\n"
        "      : (inputEl ? inputEl.value.trim() : '');\n"
        "    const correct = String(_reviewCurrentItem.ans||'').trim();\n"
        "    const isOk = (_reviewAnsMode === 'self') ? null : (userAns === correct);",
    ),

    # (6) 自己採点のときは赤でも緑でもない色にする
    (
        "      fbEl.className = 'mt-3 rounded-xl p-4 text-center ' + "
        "(isOk ? 'bg-green-50 border-2 border-green-300' : 'bg-red-50 border-2 border-red-300');",

        "      fbEl.className = 'mt-3 rounded-xl p-4 text-center ' + "
        "(isOk === null ? 'bg-amber-50 border-2 border-amber-300' : "
        "(isOk ? 'bg-green-50 border-2 border-green-300' : 'bg-red-50 border-2 border-red-300'));",
    ),

    # (7) 自己採点のときの絵文字
    (
        "    if(iconEl) iconEl.textContent = isOk ? '⭕' : '❌';",
        "    if(iconEl) iconEl.textContent = (isOk === null) ? '\U0001f440' : (isOk ? '⭕' : '❌');",
    ),

    # (8) 自己採点のときの文字（○×を言わず、下の「できた／まだ」に渡す）
    (
        "    if(txtEl) txtEl.innerHTML = (isOk ? 'せいかい！' : 'ちがうよ…')",
        "    if(txtEl) txtEl.innerHTML = (isOk === null ? 'こたえを見たよ。できたかな？' : "
        "(isOk ? 'せいかい！' : 'ちがうよ…'))",
    ),

    # (9) 問題文が1文字以下の壊れた記録を復習に出さない
    (
        '      if (_revMathBad(x) === true) { return false; }\n',
        '      if (_revMathBad(x) === true) { return false; }\n'
        '      if (String((x && x.q) == null ? \'\' : x.q).trim().length <= 1) { return false; }'
        '   /* __REVIEW_C_V1__ 問題文が無い壊れた記録 */\n',
    ),
]

# ---------------------------------------------------------------- 足場の検査
for n, (old, new) in enumerate(EDITS, 1):
    c_html = count(html, old)
    c_src = count(src, old)
    if c_html != 1:
        die('足場(%d) が public/index.html に %d 個（1個のはず）' % (n, c_html))
    if c_src != 0:
        die('足場(%d) が src/index.tsx に %d 個ある（鎖かもしれない。中止）' % (n, c_src))
    if new == old:
        die('足場(%d) の置換前後が同じ' % n)

# ---------------------------------------------------------------- 置換
out = html
for n, (old, new) in enumerate(EDITS, 1):
    before = len(out)
    out = out.replace(old, new, 1)
    if len(out) == before:
        die('置換(%d) が効かなかった' % n)

# ---------------------------------------------------------------- 後の検査
if count(out, SENTINEL) != 3:
    die('目印 %s が %d 個（3個のはず）' % (SENTINEL, count(out, SENTINEL)))

if count(out, 'id="reviewModalChoices"') != 1:
    die('reviewModalChoices が 1 個でない')
if count(out, 'id="reviewModalGoBtn"') != 1:
    die('reviewModalGoBtn が 1 個でない')
if count(out, 'function _revSetupAnswerUI') != 1:
    die('_revSetupAnswerUI が 1 個でない')
if count(out, 'function _revChoiceList') != 1:
    die('_revChoiceList が 1 個でない')
if count(out, 'function _revPickChoice') != 1:
    die('_revPickChoice が 1 個でない')

# 先行の便を壊していないこと
for k in ('__REVIEW_BADANS_A1__', '__REVIEW_BCD_V1__', '__REVIEW_MATH_V1__'):
    if k not in out:
        die('置換で %s を壊した' % k)
if count(out, '_revMathBad(x) === true') != 1:
    die('REVIEW_MATH_V1 の呼び出しが 1 個でない')

# 「こたえる！」ボタンは増やさない（部品の中の文字で +1 だけ増える）
if count(out, 'こたえる！') != count(html, 'こたえる！') + 1:
    die('「こたえる！」の個数が %d -> %d（+1 のはず）'
        % (count(html, 'こたえる！'), count(out, 'こたえる！')))
# もとからある「もう一度」「マスターした」を使い回す（増やさない）
for k in ('reviewNextQuestion(false)', 'reviewNextQuestion(true)'):
    if count(out, k) != count(html, k):
        die('%s の個数が変わった（新しいボタンを作ってしまった）' % k)

if '\r\n' in out:
    die('出力に CRLF が混ざった')

delta = len(out) - len(html)
if delta <= 0 or delta > 8000:
    die('増えた量がおかしい: %d バイト' % delta)

# ---------------------------------------------------------------- 書き出し
with open(HTML, 'w', encoding='utf-8', newline='') as f:
    f.write(out)

print('OK: %s を適用（+%d バイト / 置換 %d か所 / 鎖 %d 本はそのまま）'
      % (SENTINEL, delta, len(EDITS), chain))
