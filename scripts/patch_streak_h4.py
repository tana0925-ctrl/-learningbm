import sys

PATH = 'src/index.tsx'
CHAIN_BEFORE = 158

# 連続日数の直し 第4便：先生しか見ない3か所を、新しい数え方に切りかえる
#   ・カルテ（student-full-analysis）
#   ・Area1（learning-analytics）
#   ・要因分析（factor-analysis）
# 子どもの画面とカフート券はこの便ではさわらない。
# もどすときは scripts/patch_streak_h4_revert.py。

A1_OLD = ("    if (daysSinceLast <= 1) currentStreak = streaksList[streaksList.length - 1].length\n"
          "  }\n")
A1_NEW = (A1_OLD +
          "  // 2026-09-30: 連続日数の数え方を1本に統一した。\n"
          "  //   土日・祝日・学校独自の休みはとばす／その日に出していたら数える／今日はまだ数えない。\n"
          "  //   上にある『これまでの連続の一覧』は今までどおりのまま残してある。\n"
          "  currentStreak = hwStreakCurrent(dayKeys, khtTodayKey(Date.now()), {})\n"
          "  maxStreak = hwStreakMax(dayKeys, {})\n")

A2_OLD = "    return { userId: m.id, name: m.name, loginId: m.loginId, submissions: days.length, currentStreak, maxStreak, recent7, prev7, dropping }"
A2_NEW = ("    // 2026-09-30: 連続日数の数え方を1本に統一した（カルテと同じ）。\n"
          "    currentStreak = hwStreakCurrent(days, khtTodayKey(Date.now()), {})\n"
          "    maxStreak = hwStreakMax(days, {})\n" + A2_OLD)

A3_OLD = "      f.streak = maxStreak"
A3_NEW = "      f.streak = hwStreakMax(days, {})"

NEEDED = ['function hwStreakCurrent(', 'function hwStreakMax(', 'function khtTodayKey(',
          'function hwHolidayNotice(', 'KHT_HOLIDAYS_UNTIL']
UNTOUCHED = ['KHT_PRICE_STREAK = 500', 'KHT_PRICE_MID = 1500', 'KHT_PRICE_NONE = 3000',
             'KHT_STREAK_NEED = 3', 'function khtStreak(', 'function khtIsRest(',
             'function khtRecent(', 'function khtPriceOf(', 'function khtTodayKey(']


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
    with open(PATH, encoding='utf-8') as f:
        src = f.read()

    before = chain_count(src)
    print('チェーン数（前）:', before)
    if before != CHAIN_BEFORE:
        die('チェーン数が %d（%d のはず）。ほかの便とぶつかっている。' % (before, CHAIN_BEFORE))

    for k in NEEDED:
        if k not in src:
            die('前提が足りない（前の便が当たっていない）: ' + k)

    # 注意: 関数の定義そのものが hwStreakCurrent(dayKeys ... なので、
    # 「もう当たっているか」は、入れる行そのもので見ること。
    if A1_NEW in src or A2_NEW in src or A3_NEW in src:
        die('この便はもう当たっている')

    for name, old in [('カルテ', A1_OLD), ('Area1', A2_OLD), ('要因分析', A3_OLD)]:
        if src.count(old) != 1:
            die('%s のあて先が %d 件（1件のはず）' % (name, src.count(old)))

    out = src.replace(A1_OLD, A1_NEW, 1)
    out = out.replace(A2_OLD, A2_NEW, 1)
    out = out.replace(A3_OLD, A3_NEW, 1)

    after = chain_count(out)
    print('チェーン数（後）:', after)
    if after != before:
        die('チェーン数が %d -> %d に変わった' % (before, after))

    if out.count('hwStreakCurrent(') - src.count('hwStreakCurrent(') != 2:
        die('hwStreakCurrent の呼び出しが2つ増えていない')
    if out.count('hwStreakMax(') - src.count('hwStreakMax(') != 3:
        die('hwStreakMax の呼び出しが3つ増えていない')

    for k in UNTOUCHED:
        if src.count(k) != out.count(k):
            die('さわってはいけないところが変わった: ' + k)

    if src.count('streaksList') != out.count('streaksList'):
        die('これまでの連続の一覧の数が変わった')

    grew = len(out) - len(src)
    want = (len(A1_NEW) - len(A1_OLD)) + (len(A2_NEW) - len(A2_OLD)) + (len(A3_NEW) - len(A3_OLD))
    if grew != want:
        die('増えた文字数が %d（%d のはず）' % (grew, want))

    with open(PATH, 'w', encoding='utf-8', newline='') as f:
        f.write(out)

    print('OK: カルテ・Area1・要因分析 の3か所を hwStreakCurrent / hwStreakMax に切りかえた')
    print('OK: 子どもの画面とカフート券はこの便ではさわっていない')


if __name__ == '__main__':
    main()
