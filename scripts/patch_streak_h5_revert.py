import sys

# 連続日数の直し 第5便の「もどし」
# カフート券の数え方を、第5便の前（古い数え方）にもどす。
# 第1〜4便はそのまま残る。

PATH = 'src/index.tsx'
CHAIN_BEFORE = 158

OLD = ("// public/index.html の hsCalcRequiredStreak と同じ数え方。\n"
       "function khtStreak(days: any, todayKey: string, extra: any): number {\n"
       "  let k = todayKey\n"
       "  let s = 0\n"
       "  for (let i = 0; i < 400; i++) {\n"
       "    if (khtIsRest(k, extra)) { k = khtAddDay(k, -1); continue }\n"
       "    if (days[k]) { s++; k = khtAddDay(k, -1); continue }\n"
       "    break\n"
       "  }\n"
       "  return s\n"
       "}\n")

NEW = ("// 2026-10-01: 数え方は hwStreakCurrent ただ1本（カルテ・教師一覧と共通）。\n"
       "//   ・今日はまだ出していなくても切らない\n"
       "//   ・休みの日に出していたら、その分も数える\n"
       "//   どちらも連続を増やす向きにしか働かないので、券の値段が上がることはない。\n"
       "function khtStreak(days: any, todayKey: string, extra: any): number {\n"
       "  return hwStreakCurrent(Object.keys(days || {}), todayKey, extra)\n"
       "}\n")


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

    if src.count(NEW) != 1:
        die('もどし先が %d 件（1件のはず）。第5便が当たっていない？' % src.count(NEW))

    out = src.replace(NEW, OLD, 1)

    after = chain_count(out)
    print('チェーン数（後）:', after)
    if after != before:
        die('チェーン数が %d -> %d に変わった' % (before, after))

    if NEW in out:
        die('もどし切れていない')
    if out.count('function khtStreak(') != 1:
        die('khtStreak の定義が1個でない')
    if out.count('khtStreak(days, todayKey, extra)') != 3:
        die('khtStreak の呼び出しが3件でない')
    for k in ['function hwStreakCurrent(', 'function hwStreakMax(', 'currentStreak = hwStreakCurrent(']:
        if k not in out:
            die('第1〜4便まで消えてしまった: ' + k)

    with open(PATH, 'w', encoding='utf-8', newline='') as f:
        f.write(out)

    print('OK: カフート券の数え方を第5便の前にもどした（第1〜4便はそのまま）')


if __name__ == '__main__':
    main()
