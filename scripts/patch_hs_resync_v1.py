# -*- coding: utf-8 -*-
"""
patch_hs_resync_v1.py — 「出したのに出してない判定」を直す
2026-09-28  HS_RESYNC_V1

何が起きていたか（実データで確認ずみ）：
  子どもの週間ビューは、提出したかどうかを「端末側の記録」だけで判断していた
  （player.homeStudy.logs。サーバの homework_submissions は一度も見ていない）。
  端末側の記録はまるごと state_json としてサーバに保存されるが、
  保存が届かなかったり、別の端末や古いタブがあとから上書きしたりすると、
  その日のぶんだけ端末側から消える。提出そのものは homework_submissions に
  残っているので、先生の画面には出る。子どもの画面にだけ出ない。

  本番の実測（2026-09-28）：
    ・ある児童（ログイン名 626）… サーバ65日 / 端末61日。
      端末側にだけ無い日 = 6/26, 6/30, 9/8, 9/10, 9/16。
      本人が「水曜だけおかしい」と言っていた週の水曜は 9/16 で、ぴったり一致。
    ・クラス全体 … 32人・214日ぶんが同じ状態。

直し方：
  「提出したかどうか」はサーバを正とする。家庭学習の画面を開いたときに
  サーバの提出記録を見て、端末側に無い日を書きもどす（自己修復）。
  ・すでに取ってある /api/homework/my の返事をそのまま使うので、
    通信もクエリも増えない。
  ・端末側にある日は触らない（上書きしない）。書きもどすのは「無い日」だけ。
  ・書きもどした日は ✅ 提出ずみとして出る。中身（時間・天気・やったこと）も
    サーバから返ってくるぶんは埋める。

  あわせて /api/homework/my の LIMIT を 30 → 120 にする。
  30件だと直近1か月ぶんしか戻せず、6月に消えた日が救えないため。
  1人ぶんの user_id 索引つきの引き方なので、読み取りは軽いまま。
"""
import io
import sys

TSX = 'src/index.tsx'
HTML = 'public/index.html'


def apply_tsx(s):
    old = """    SELECT id, day_key as dayKey, submitted_at as submittedAt, rest_day as restDay,
           teacher_comment as teacherComment, has_physical as hasPhysical,
           returned_at as returnedAt, reward_claimed as rewardClaimed,
           reward_kind as rewardKind, reward_coins as rewardCoins, reward_shards as rewardShards,
           bonus_coins as bonusCoins, bonus_shards as bonusShards
    FROM homework_submissions WHERE user_id=? ORDER BY submitted_at DESC LIMIT 30"""
    new = """    SELECT id, day_key as dayKey, submitted_at as submittedAt, rest_day as restDay,
           teacher_comment as teacherComment, has_physical as hasPhysical,
           returned_at as returnedAt, reward_claimed as rewardClaimed,
           reward_kind as rewardKind, reward_coins as rewardCoins, reward_shards as rewardShards,
           bonus_coins as bonusCoins, bonus_shards as bonusShards,
           minutes, end_weather as endWeather, todo,
           weather_reason as weatherReason, next_improve as nextImprove
    FROM homework_submissions WHERE user_id=? ORDER BY submitted_at DESC LIMIT 120"""
    assert s.count(old) == 1, 'T1: %d' % s.count(old)
    return s.replace(old, new)


def apply_html(s):
    old = """    const r = await apiJson('/api/homework/my');
    const pending = (r.submissions || []).filter(s => s.returnedAt && !s.rewardClaimed);"""
    new = """    const r = await apiJson('/api/homework/my');
    // 📌 2026-09-28 HS_RESYNC_V1: サーバにあるのに端末側に無い提出を書きもどす。
    //   子どもの画面は今まで端末側の記録だけを見ていたので、保存が届かなかった日は
    //   「出していない」ままだった（本番で32人・214日ぶん）。サーバを正とする。
    try { hsResyncFromServer(r.submissions || []); } catch (e) { console.warn('[hs-resync]', e); }
    const pending = (r.submissions || []).filter(s => s.returnedAt && !s.rewardClaimed);"""
    assert s.count(old) == 1, 'H1: %d' % s.count(old)
    s = s.replace(old, new)

    old = """async function hsCheckReturned() {"""
    new = """// 📌 2026-09-28 HS_RESYNC_V1: サーバの提出記録を、端末側の記録に足しもどす。
//   ・端末側にすでにある日は、いっさい触らない（上書きしない）
//   ・無い日だけ足す。足した日は ✅ 提出ずみとして出る
//   ・1件も足すものが無ければ、保存もしない（むだに書かない）
function hsResyncFromServer(subs) {
  if (!Array.isArray(subs) || !subs.length) return 0;
  hsEnsureState();
  var logs = hsLogs();
  var have = {};
  for (var i = 0; i < logs.length; i++) {
    if (logs[i] && logs[i].dayKey) have[String(logs[i].dayKey)] = true;
  }
  var added = 0;
  for (var k = 0; k < subs.length; k++) {
    var s = subs[k];
    if (!s || !s.dayKey) continue;
    var dk = String(s.dayKey);
    if (have[dk]) continue;
    logs.push({
      dayKey: dk,
      minutes: Number(s.minutes || 0),
      endWeather: s.endWeather || '',
      todo: s.todo || '',
      weatherReason: s.weatherReason || '',
      nextImprove: s.nextImprove || '',
      restDay: !!s.restDay,
      teacherComment: s.teacherComment || '',
      dbSubmitted: true,
      _restored: true
    });
    have[dk] = true;
    added++;
  }
  if (!added) return 0;
  // 新しい順にそろえる（画面は上から新しい順に出す）
  logs.sort(function (a, b) { return String((b && b.dayKey) || '').localeCompare(String((a && a.dayKey) || '')); });
  if (logs.length > 200) logs = logs.slice(0, 200);
  player.homeStudy.logs = logs;
  try { saveData(); } catch (e) {}
  try { if (typeof hwRenderWeekView === 'function') hwRenderWeekView(); } catch (e) {}
  console.log('[hs-resync] restored ' + added + ' day(s) from server');
  return added;
}

async function hsCheckReturned() {"""
    assert s.count(old) == 1, 'H2: %d' % s.count(old)
    s = s.replace(old, new)
    return s


def main():
    a = io.open(TSX, encoding='utf-8').read()
    b = apply_tsx(a)
    h1 = io.open(HTML, encoding='utf-8').read()
    h2 = apply_html(h1)
    if b == a or h2 == h1:
        print('NO CHANGE'); sys.exit(1)
    io.open(TSX, 'w', encoding='utf-8').write(b)
    io.open(HTML, 'w', encoding='utf-8').write(h2)
    print('src/index.tsx     %d -> %d' % (len(a), len(b)))
    print('public/index.html %d -> %d' % (len(h1), len(h2)))


if __name__ == '__main__':
    main()
