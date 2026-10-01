import sys

# 連続日数の直し 第6便の「もどし」
# 児童画面の表示とお知らせを、第6便の前にもどす。
# 第1〜5便はそのまま残る。

PATH = 'public/index.html'
SRC = 'src/index.tsx'
CHAIN_BEFORE = 158

FN_END = ("    if (hsHasLogForDay(logs, key)){\n"
          "      streak += 1;\n"
          "      key = hsAddDays(key, -1);\n"
          "      continue;\n"
          "    }\n"
          "    break;\n"
          "  }\n"
          "  return streak;\n"
          "}\n")

FN_ADD = ("\n"
          "// 2026-10-02: 画面に見せる用の連続日数。\n"
          "//   今日はまだ出していなくても、連続を 0 にしない。\n"
          "//   （朝8時半をすぎると、その日に出すまで 0 に見えてしまうのを直すため）\n"
          "//   ごほうび（コイン・かけら）の計算には使わない。そちらは hsCalcRequiredStreak のまま。\n"
          "//   サーバ側の hwStreakCurrent（カルテ・教師一覧・カフート券）とまったく同じ数え方。\n"
          "function hsCalcStreakShown(logs, todayKey){\n"
          "  var key = todayKey;\n"
          "  if (!hsHasLogForDay(logs, key) && !hsIsRestDay(key)) key = hsAddDays(key, -1);\n"
          "  var streak = 0;\n"
          "  for (var i = 0; i < 400; i++){\n"
          "    if (hsHasLogForDay(logs, key)){ streak += 1; key = hsAddDays(key, -1); continue; }\n"
          "    if (hsIsRestDay(key)){ key = hsAddDays(key, -1); continue; }\n"
          "    break;\n"
          "  }\n"
          "  return streak;\n"
          "}\n")

C1_OLD = "        const streak = hsCalcRequiredStreak(logs, realTodayKey);"
C1_NEW = "        const streak = hsCalcStreakShown(logs, realTodayKey);"
C2_OLD = "    const streak = hsCalcRequiredStreak(logs, todayKey);"
C2_NEW = "    const streak = hsCalcStreakShown(logs, todayKey);"

ANCHOR = '              <div id="hsTodayInfo" class="text-[11px] text-slate-400 mt-1"></div>'
NOTICE = ('              <div id="hsFixNotice2026" class="text-[11px] text-amber-900 bg-amber-50 '
          'border border-amber-300 rounded-lg px-2 py-1 mt-1">🔧 かぞえ方を直しました。'
          '土日やお休みの日はとばして数えるので、前と日数がちがって見えることがあります。</div>\n'
          '              <script>try{ if (new Date() > new Date(2026, 9, 10)) { '
          'var e = document.getElementById("hsFixNotice2026"); if (e) e.style.display = "none"; } }catch(e){}</script>\n')

# ごほうびの計算に使われている2か所。ここは絶対にさわらない。
REWARD = ["    let streakAfter = hsCalcRequiredStreak(logs, dayKey);",
          "      streakAfter = hsCalcRequiredStreak(tmp, dayKey);"]


def die(msg):
    print('### 中止: ' + msg)
    sys.exit(1)


def chain_count(src):
    a = src.index("app.get('/'")
    b = src.index("app.get('/logout'")
    if b <= a:
        die('チェーンの範囲が取れない')
    return src.count('.replace(', a, b)


def main():
    with open(SRC, encoding='utf-8') as f:
        tsx = f.read()
    ch = chain_count(tsx)
    print('チェーン数:', ch)
    if ch != CHAIN_BEFORE:
        die('チェーン数が %d（%d のはず）' % (ch, CHAIN_BEFORE))

    with open(PATH, encoding='utf-8') as f:
        h = f.read()

    for name, s in [('新しい関数', FN_ADD), ('表示1', C1_NEW), ('表示2', C2_NEW), ('お知らせ', NOTICE)]:
        if h.count(s) != 1:
            die('%s のもどし先が %d 件（1件のはず）。第6便が当たっていない？' % (name, h.count(s)))

    out = h.replace(FN_ADD, '', 1)
    out = out.replace(C1_NEW, C1_OLD, 1)
    out = out.replace(C2_NEW, C2_OLD, 1)
    out = out.replace(NOTICE, '', 1)

    if 'hsCalcStreakShown' in out or 'hsFixNotice2026' in out:
        die('もどし切れていない')
    if out.count('hsCalcRequiredStreak') != 5:
        die('hsCalcRequiredStreak が %d 回（5回のはず）' % out.count('hsCalcRequiredStreak'))
    for r in REWARD:
        if out.count(r) != 1:
            die('ごほうびの計算が壊れた: ' + r)
    if out.count('<script') != h.count('<script') - 1:
        die('script が1個だけ減っていない')

    with open(PATH, 'w', encoding='utf-8', newline='') as f:
        f.write(out)

    print('OK: 児童画面の表示とお知らせを第6便の前にもどした（第1〜5便はそのまま）')


if __name__ == '__main__':
    main()
