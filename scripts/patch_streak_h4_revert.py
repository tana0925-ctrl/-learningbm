import sys

# 連続日数の直し 第4便の「もどし」
# 何かずれていたら、これを流せば第4便の3か所だけ元にもどる。
# 第1〜3便（祝日表・数え方の関数・教師画面の知らせ）はそのまま残る。

PATH = 'src/index.tsx'
CHAIN_BEFORE = 158

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
        die('チェーン数が %d（%d のはず）' % (before, CHAIN_BEFORE))

    for name, new in [('カルテ', A1_NEW), ('Area1', A2_NEW), ('要因分析', A3_NEW)]:
        if src.count(new) != 1:
            die('%s のもどし先が %d 件（1件のはず）。第4便が当たっていない？' % (name, src.count(new)))

    out = src.replace(A1_NEW, A1_OLD, 1)
    out = out.replace(A2_NEW, A2_OLD, 1)
    out = out.replace(A3_NEW, A3_OLD, 1)

    after = chain_count(out)
    print('チェーン数（後）:', after)
    if after != before:
        die('チェーン数が %d -> %d に変わった' % (before, after))

    if A1_NEW in out or A2_NEW in out or A3_NEW in out:
        die('もどし切れていない')
    if out.count('hwStreakCurrent(') != 1 or out.count('hwStreakMax(') != 1:
        die('呼び出しが残っている（定義の1個だけになるはず）')
    for k in ['function hwStreakCurrent(', 'function hwStreakMax(', 'function hwHolidayNotice(', 'KHT_HOLIDAYS_UNTIL']:
        if k not in out:
            die('第1〜3便まで消えてしまった: ' + k)

    with open(PATH, 'w', encoding='utf-8', newline='') as f:
        f.write(out)

    print('OK: 第4便の3か所を元にもどした（第1〜3便はそのまま）')


if __name__ == '__main__':
    main()
