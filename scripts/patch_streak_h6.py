import sys

PATH = 'public/index.html'
SRC = 'src/index.tsx'
CHAIN_BEFORE = 158

# 連続日数の直し 第6便：児童画面の日数表示を直し、お知らせを出す
#
# 1) 画面に見せる用の関数 hsCalcStreakShown を足す。
#    ・今日はまだ出していなくても連続を 0 にしない
#      （朝8時半をすぎると、その日に出すまで 0 に見えていた）
#    ・休みの日に出していたら、その分も数える
#    サーバ側の hwStreakCurrent とまったく同じ数え方。
# 2) 表示の2か所だけ、それに差しかえる。
#    ★ごほうび（コイン・かけら）の計算に使われている hsCalcRequiredStreak には
#      いっさいさわらない。もらえる額は1枚も変わらない。
#      下でその2行が1文字も変わっていないことを毎回たしかめる。
# 3) お知らせを出す。2026-10-10 に自動で消える。
#
# もどすときは scripts/patch_streak_h6_revert.py

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

    if '\r\n' in h:
        die('この便は改行がLFの前提。CRLFが混ざっている')
    if 'hsCalcStreakShown' in h or 'hsFixNotice2026' in h:
        die('この便はもう当たっている')

    for name, s in [('関数の終わり', FN_END), ('表示1', C1_OLD), ('表示2', C2_OLD),
                    ('お知らせの置き場所', ANCHOR)]:
        if h.count(s) != 1:
            die('%s のあて先が %d 件（1件のはず）' % (name, h.count(s)))
    for r in REWARD:
        if h.count(r) != 1:
            die('ごほうびの計算のところが見つからない: ' + r)
    if h.count('hsCalcRequiredStreak') != 5:
        die('あてる前の hsCalcRequiredStreak が %d 回（5回のはず）' % h.count('hsCalcRequiredStreak'))

    out = h.replace(FN_END, FN_END + FN_ADD, 1)
    out = out.replace(C1_OLD, C1_NEW, 1)
    out = out.replace(C2_OLD, C2_NEW, 1)
    out = out.replace(ANCHOR, NOTICE + ANCHOR, 1)

    # ごほうびの計算は1文字も変えていないこと
    for r in REWARD:
        if out.count(r) != 1:
            die('ごほうびの計算を壊してしまった: ' + r)
    # 後 = 定義1 + ごほうび2 + 新関数のコメント1 = 4
    if out.count('hsCalcRequiredStreak') != 4:
        die('あてた後の hsCalcRequiredStreak が %d 回（4回のはず）' % out.count('hsCalcRequiredStreak'))
    # 新しい関数の定義1 + 表示2 = 3
    if out.count('hsCalcStreakShown') != 3:
        die('hsCalcStreakShown が %d 回（3回のはず）' % out.count('hsCalcStreakShown'))
    if out.count('hsFixNotice2026') != 2:
        die('お知らせが %d 回（2回のはず）' % out.count('hsFixNotice2026'))
    if out.count('<script') - h.count('<script') != 1:
        die('script が1個だけ増えていない')

    grew = len(out) - len(h)
    want = len(FN_ADD) + (len(C1_NEW) - len(C1_OLD)) + (len(C2_NEW) - len(C2_OLD)) + len(NOTICE)
    if grew != want:
        die('増えた文字数が %d（%d のはず）' % (grew, want))

    with open(PATH, 'w', encoding='utf-8', newline='') as f:
        f.write(out)

    print('OK: 画面に見せる用の hsCalcStreakShown を足し、表示の2か所を差しかえた')
    print('OK: ごほうびの計算（hsCalcRequiredStreak）は1文字も変えていない')
    print('OK: お知らせを入れた（2026-10-10 に自動で消える）')


if __name__ == '__main__':
    main()
