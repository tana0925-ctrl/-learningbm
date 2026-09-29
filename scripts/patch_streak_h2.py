import sys

PATH = 'src/index.tsx'
CHAIN_BEFORE = 158

# 連続日数の直し 第2便：数え方を1本だけ足す（まだどこからも呼ばない）
#
# 画面に出る数字はこの便では1つも変わらない。
# 次の便で、カルテ・教師一覧・Area1 をここに切りかえる。

ANCHOR = "function khtRecent(days: any, todayKey: string, extra: any, n: number): boolean {"

BLOCK = """// ── 家庭学習の「何日連続」は、ここ1か所で数える ──────────────────
// 先生が決めたルール:
//   ・土日、祝日、学校独自の休みは「とばす」。出していなくても連続は切れない。
//   ・その休みの日に出していたら、その分はちゃんと数える。
//   ・今日はまだ出していなくても切らない（朝に見て全員0になるのを防ぐため）。
// 休みの日の判定は khtIsRest ひとつだけを使う。数え方を2本に増やさないこと。
// 日付はすべて khtParseDay / khtFmtDay（UTCそろえ）で扱う。日本時間とのずれを出さないため。
// 「今日」は khtTodayKey（朝8時半で切りかわる。児童画面の hsGetDayKey830 と同じ）。
function hwDayMap(dayKeys: any): any {
  const m: any = {}
  if (Array.isArray(dayKeys)) {
    for (let i = 0; i < dayKeys.length; i++) {
      const k = dayKeys[i]
      if (k) m[String(k)] = 1
    }
  }
  return m
}

function hwStreakCurrent(dayKeys: any, todayKey: string, extra: any): number {
  const days = hwDayMap(dayKeys)
  let k = String(todayKey)
  let s = 0
  if (!days[k] && !khtIsRest(k, extra)) k = khtAddDay(k, -1)
  for (let i = 0; i < 400; i++) {
    if (days[k]) { s++; k = khtAddDay(k, -1); continue }
    if (khtIsRest(k, extra)) { k = khtAddDay(k, -1); continue }
    break
  }
  return s
}

function hwStreakMax(dayKeys: any, extra: any): number {
  const ds = (Array.isArray(dayKeys) ? dayKeys : []).filter(Boolean).map(String).sort()
  let best = 0
  let run = 0
  let prev = ''
  for (let i = 0; i < ds.length; i++) {
    const d = ds[i]
    if (d === prev) continue
    if (!prev) {
      run = 1
    } else {
      let k = khtAddDay(prev, 1)
      let ok = true
      let guard = 0
      while (k < d) {
        if (guard++ > 400) { ok = false; break }
        if (!khtIsRest(k, extra)) { ok = false; break }
        k = khtAddDay(k, 1)
      }
      run = ok ? run + 1 : 1
    }
    if (run > best) best = run
    prev = d
  }
  return best
}

"""

NEW_NAMES = ['function hwDayMap(', 'function hwStreakCurrent(', 'function hwStreakMax(']
NEEDED = ['function khtIsRest(', 'function khtAddDay(', 'function khtTodayKey(', 'KHT_HOLIDAYS_UNTIL']
UNTOUCHED = ['KHT_PRICE_STREAK = 500', 'KHT_PRICE_MID = 1500', 'KHT_PRICE_NONE = 3000',
             'KHT_STREAK_NEED = 3', 'function khtStreak(', 'function khtIsRest(',
             'function khtRecent(', 'function khtPriceOf(']


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
        die('チェーン数が %d（%d のはず）。ほかの便とぶつかっている可能性がある。' % (before, CHAIN_BEFORE))

    for k in NEEDED:
        if k not in src:
            die('前提が足りない（第1便が当たっていない？）: ' + k)

    for k in NEW_NAMES:
        if k in src:
            die('すでにある（この便はもう当たっている）: ' + k)

    if src.count(ANCHOR) != 1:
        die('あて先が %d 件（1件のはず）' % src.count(ANCHOR))

    out = src.replace(ANCHOR, BLOCK + ANCHOR, 1)

    after = chain_count(out)
    print('チェーン数（後）:', after)
    if after != before:
        die('チェーン数が %d -> %d に変わった' % (before, after))

    for k in NEW_NAMES:
        if out.count(k) != 1:
            die('%s が %d 個（1個のはず）' % (k, out.count(k)))

    for k in UNTOUCHED:
        if src.count(k) != out.count(k):
            die('さわってはいけないところが変わった: ' + k)

    d_lines = out.count('\n') - src.count('\n')
    if d_lines != BLOCK.count('\n'):
        die('増えた行数が %d（%d のはず）' % (d_lines, BLOCK.count('\n')))

    if len(out) - len(src) != len(BLOCK):
        die('増えた文字数がおかしい')

    with open(PATH, 'w', encoding='utf-8', newline='') as f:
        f.write(out)

    print('OK: hwDayMap / hwStreakCurrent / hwStreakMax を追加した（まだどこからも呼んでいない）')
    print('OK: 画面に出る数字はこの便では変わらない')


if __name__ == '__main__':
    main()
