#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_karte_add_v1.py --- KARTE_ADD_V1 毎週の紙に「その週にしかないもの」を足す

第1便で年度累計の欄を外し、第3便でグラフを先生の画面へ移した。
残ったのは「先週のようす」「阪神マン」「先生からの記録」の3つ。実測255.2mm -> 約181mm。
A4の裏表（使える高さ 273mm×2面）に対して余りが大きいので、ここで足す。

足すものは「その週にしかないもの」だけ。毎週変わらないものは足さない（今回の教訓）。

この便でやること:
  (A) サーバ側 … student-full-analysis に「先週ぶん」を足す
      1) lastWeek … 先週アプリで解いた問題（単元ごと・日数・のべ問題数）
         実測：ある子は先週 5日・7単元・602問 解いていたのに、紙のどこにも出ていなかった。
         （家庭学習の提出がゼロだったので「記録がお休みやったな」で始まる紙になっていた）
         索引 idx_learning_results_user_time(user_id, answered_at) を使うため、
         substr() ではなく answered_at の範囲でしぼる。
      2) special … 先週の図鑑・タイプシュート・野生（ranking_weekly_scores、主キー引き）
         実測で該当者が週1〜2人しかいないので、あった子にだけ出す。
      3) prevAsk … 前回のカルテの最後の問いかけ（ai_review_drafts の2本目）
      4) reflections に freeText を足す
         児童が実際に書いているのは free_text だけ（good/improve/next は全週ゼロ件）。
         これまで画面もAPIも free_text を無視していたので、週の振り返りが一度も紙に出ていなかった。

  (B) カルテ側
      5) 🗣 自分のことば … 50字で切るのをやめて全文にする
      6) 📝 この週のふりかえり … freeText を出す
      7) 🐯 阪神マンの下に「先週きかれたこと」を小さく再掲（つながりを紙の上でも見せる）
      8) ✨ 先週のひろがり … アプリで解いた数・日数・単元名・はじめて出会った単元・今週のとくべつ
      9) 🌱 今週かわったこと … 先週やった単元で、1週間の正答率が年度の正答率と
         15ポイント以上ちがうもの（10問以上）。無い週は欄ごと出さない。
         「はじめて出会った単元」は ✨ 側に出すので、ここでは重ねない。

  ※ 「顔ぶれが変わった」を 前期/後期（2か月幅）で判定するのは避けた。
    それをやると、いま直している「幅の広い期間で“今週”と言う」不具合を作り直すことになる。
    先週ぶんの材料がそろった この便で、週の幅だけを見て判定する。

さわるファイル:
  src/index.tsx だけ。
  ※ teacher-ai.js / student-karte.js / index.html / 防衛戦 /
    scripts/patch_karte_slim_v1.py（別セッションのぶん）には触らない。
  ※ .replace( チェーンは1本も増やさない。
  ※ D1には書き込まない。読み取りを3本足す（どれも user_id でしぼった小さなもの）。

安全策:
  - アンカーはすべて「ちょうど1箇所」であることを確認してから置換する
  - 冪等: 目印 SENTINEL があれば何もしない
  - 第1便・第3便が入っていることを確かめる
  - チェーン件数を CHAIN_BEFORE と照合し、合わなければ1文字も書かずに中止
  - 数えるときは grep -c を使わない（src/index.tsx は巨大な1行）
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')

SENTINEL = 'KARTE_ADD_V1'


def fail(msg):
    print('NG 中止: ' + msg)
    sys.exit(1)


def chain_count(text):
    a = text.index("app.get('/', async (c) => {")
    b = text.index("app.get('/logout'", a)
    return text[a:b].count('.replace(')


def rep1(text, old, new, label):
    n = text.count(old)
    if n != 1:
        fail('%s が %d 箇所（1箇所のはず）' % (label, n))
    return text.replace(old, new, 1)


tsx = io.open(TSX, encoding='utf-8', newline='').read()
chain_before = chain_count(tsx)
want = os.environ.get('CHAIN_BEFORE', '').strip()
if not want or not want.isdigit():
    fail('CHAIN_BEFORE が渡されていない/数字でない: %r' % want)
if chain_before != int(want):
    fail('置換チェーンが %d 件（期待 %s 件）。ほかの便が入った可能性があるので中止'
         % (chain_before, want))
print('OK 置換チェーン: %d 件（期待どおり）' % chain_before)

if SENTINEL in tsx:
    print('-- すでに適用済み（目印あり）。何もしません')
    sys.exit(0)
for mark in ('KARTE_WEEKLY_V1', 'KARTE_WEEKLY_V2'):
    if mark not in tsx:
        fail('%s が入っていない。先にそちらを流すこと' % mark)

NL = '\n'

# ==================================================================
# (A) サーバ側: student-full-analysis に「先週ぶん」を足す
# ==================================================================

# A-4 reflections に freeText
tsx = rep1(
    tsx,
    "    reflections: allRefs.map((r: any) => ({ weekKey: r.week_key, concentration: r.concentration, goodPoint: r.good_point, improvePoint: r.improve_point, nextAction: r.next_action })),",
    "    // KARTE_ADD_V1 freeText を足した。児童が実際に書いているのはここだけで"
    "（good/improve/next は全週ゼロ件）、これまで紙にも画面にも一度も出ていなかった。" + NL +
    "    reflections: allRefs.map((r: any) => ({ weekKey: r.week_key, concentration: r.concentration, goodPoint: r.good_point, improvePoint: r.improve_point, nextAction: r.next_action, freeText: r.free_text })),",
    'A-4 reflections の freeText')

# A-1〜3 先週ぶんの材料を集める（返却のすぐ前に置く）
LW = (
    "  // ══════ KARTE_ADD_V1 先週ぶんの材料 ══════" + NL +
    "  //  毎週渡す紙に「その週にしかないもの」を載せるため。" + NL +
    "  //  これまで渡していたのは年度累計と前期/後期（2か月幅）だけだったので、" + NL +
    "  //  先週アプリで何百問解いても紙には出ていなかった（実測：ある子は先週602問）。" + NL +
    "  //  日付は answered_at の範囲でしぼる。substr() にすると" + NL +
    "  //  idx_learning_results_user_time(user_id, answered_at) が使えなくなるため。" + NL +
    "  //  （answered_at はUTC。週の境目が日本時間と数時間ずれるが、既存の集計と同じ扱いにしてある）" + NL +
    "  const _lwNow = new Date()" + NL +
    "  const _lwJst = new Date(_lwNow.getTime() + _lwNow.getTimezoneOffset() * 60000 + 9 * 3600000)" + NL +
    "  const _lwWd = (_lwJst.getDay() + 6) % 7" + NL +
    "  const _lwMonD = new Date(_lwJst.getTime() - _lwWd * 86400000 - 7 * 86400000)" + NL +
    "  const _lwP2 = (x: number) => (x < 10 ? '0' : '') + x" + NL +
    "  const _lwFmt = (d: Date) => d.getFullYear() + '-' + _lwP2(d.getMonth() + 1) + '-' + _lwP2(d.getDate())" + NL +
    "  const _lwFrom = _lwFmt(_lwMonD)" + NL +
    "  const _lwNext = _lwFmt(new Date(_lwMonD.getTime() + 7 * 86400000))" + NL +
    "  const _lwYearTotal: Record<string, number> = {}" + NL +
    "  for (const su of (subjectAnalysis as any[])) _lwYearTotal[String(su.unit)] = Number(su.total || 0)" + NL +
    "  const _lwYearRate: Record<string, number> = {}" + NL +
    "  for (const su of (subjectAnalysis as any[])) _lwYearRate[String(su.unit)] = Number(su.rate || 0)" + NL +
    "  let lastWeek: any = { from: _lwFrom, days: 0, total: 0, correct: 0, units: [] }" + NL +
    "  try {" + NL +
    "    const _lwAll = await c.env.DB.prepare(" + NL +
    "      'SELECT COUNT(*) AS n, SUM(is_correct) AS c, COUNT(DISTINCT substr(answered_at,1,10)) AS d FROM learning_results WHERE user_id=? AND answered_at >= ? AND answered_at < ?'" + NL +
    "    ).bind(studentId, _lwFrom, _lwNext).first<any>()" + NL +
    "    lastWeek.total = Number((_lwAll && _lwAll.n) || 0)" + NL +
    "    lastWeek.correct = Number((_lwAll && _lwAll.c) || 0)" + NL +
    "    lastWeek.days = Number((_lwAll && _lwAll.d) || 0)" + NL +
    "    if (lastWeek.total > 0) {" + NL +
    "      const _lwU = await c.env.DB.prepare(" + NL +
    "        'SELECT unit, COUNT(*) AS n, SUM(is_correct) AS c FROM learning_results WHERE user_id=? AND answered_at >= ? AND answered_at < ? GROUP BY unit ORDER BY n DESC LIMIT 10'" + NL +
    "      ).bind(studentId, _lwFrom, _lwNext).all<any>()" + NL +
    "      lastWeek.units = (((_lwU && _lwU.results) || []) as any[]).map((r: any) => {" + NL +
    "        const u = String(r.unit || '')" + NL +
    "        const n = Number(r.n || 0), cc = Number(r.c || 0)" + NL +
    "        // 年度のぜんぶが先週ぶんと同じなら、その単元に出会ったのは先週がはじめて" + NL +
    "        const firstEver = (_lwYearTotal[u] || 0) > 0 && (_lwYearTotal[u] || 0) === n" + NL +
    "        return { unit: u, total: n, correct: cc, rate: n ? Math.round(cc / n * 100) : 0, yearRate: _lwYearRate[u] != null ? _lwYearRate[u] : null, firstEver }" + NL +
    "      })" + NL +
    "    }" + NL +
    "  } catch (e) { console.error('KARTE_ADD_V1 先週のアプリ学習が読めません', e) }" + NL +
    "  // 先週の図鑑・タイプシュート・野生。該当者が週1〜2人しかいないので、あった子にだけ紙に出す。" + NL +
    "  let lastWeekSpecial: any = null" + NL +
    "  try {" + NL +
    "    const _sp = await c.env.DB.prepare('SELECT pokedex, typeshoot, wild FROM ranking_weekly_scores WHERE user_id=? AND week_key=?').bind(studentId, _lwFrom).first<any>()" + NL +
    "    if (_sp) lastWeekSpecial = { pokedex: Number(_sp.pokedex || 0), typeshoot: Number(_sp.typeshoot || 0), wild: Number(_sp.wild || 0) }" + NL +
    "  } catch (e) {}" + NL +
    "  // 前回のカルテの最後の問いかけ。紙の上でも「あれ、どうなった？」が見えるようにする。" + NL +
    "  let prevAsk = ''" + NL +
    "  try {" + NL +
    "    const _pv = await c.env.DB.prepare(\"SELECT body FROM ai_review_drafts WHERE target_id=? AND kind='KARTE' AND status='published' ORDER BY published_at DESC LIMIT 2\").bind(studentId).all<any>()" + NL +
    "    const _pvr = (((_pv && _pv.results) || []) as any[])" + NL +
    "    const _pb = String((_pvr[1] && _pvr[1].body) || '')" + NL +
    "    const _qi = _pb.lastIndexOf('？')" + NL +
    "    if (_qi > 0) {" + NL +
    "      let st = 0" + NL +
    "      for (const mk of ['。', '！', '？', '\\n']) { const p = _pb.lastIndexOf(mk, _qi - 1); if (p + 1 > st) st = p + 1 }" + NL +
    "      const q = _pb.slice(st, _qi + 1).trim()" + NL +
    "      if (q.length >= 6 && q.length <= 60) prevAsk = q" + NL +
    "    }" + NL +
    "  } catch (e) {}" + NL +
    "\n"
)
tsx = rep1(
    tsx,
    "  return c.json({\n    ok: true,\n    student",
    LW + "  return c.json({\n    ok: true,\n    student",
    'A-1〜3 先週ぶんの材料')

tsx = rep1(
    tsx,
    "    planSuggestion, mi: miInfo, aiComment: aiComment2, aiCommentMeta,",
    "    planSuggestion, mi: miInfo, aiComment: aiComment2, aiCommentMeta,\n"
    "    lastWeek, lastWeekSpecial, prevAsk,   // KARTE_ADD_V1",
    'A 返却に足す')

# ==================================================================
# (B) カルテ側
# ==================================================================

# B-5 自分のことばを全文に
tsx = rep1(
    tsx,
    "if(_ks.weather_reason){ var _vt=String(_ks.weather_reason); if(_vt.length>50) _vt=_vt.slice(0,49)+'…'; _kVoice.push(_kDn[kd2]+' '+_vt); }",
    "if(_ks.weather_reason){ /* KARTE_ADD_V1 50字で切るのをやめた。本人のことばは紙のいちばんの中身で、"
    "途中で切れると引用として成立しない。紙に余りができたぶんをここに使う。 */ "
    "_kVoice.push(_kDn[kd2]+' '+String(_ks.weather_reason)); }",
    'B-5 自分のことばを全文に')

# B-6 週の振り返りに freeText
tsx = rep1(
    tsx,
    "if(_kRef&&(_kRef.goodPoint||_kRef.improvePoint||_kRef.nextAction)){",
    "/* KARTE_ADD_V1 freeText を出す。児童が実際に書いているのはここだけで、"
    "これまで表示側が good/improve/next しか見ていなかったため一度も出ていなかった。 */ "
    "if(_kRef&&(_kRef.goodPoint||_kRef.improvePoint||_kRef.nextAction||_kRef.freeText)){",
    'B-6 ふりかえりの条件')
tsx = rep1(
    tsx,
    "if(_kRef.nextAction) _kH+='<div>つぎにやること … '+esc(_kRef.nextAction)+'</div>';",
    "if(_kRef.nextAction) _kH+='<div>つぎにやること … '+esc(_kRef.nextAction)+'</div>'; "
    "if(_kRef.freeText) _kH+='<div>'+esc(_kRef.freeText)+'</div>';   /* KARTE_ADD_V1 */",
    'B-6 ふりかえりの freeText')

# B-7〜9 阪神マンの直後に 先週きかれたこと・✨先週のひろがり・🌱今週かわったこと
ADD = (
    "+_acNote+'</div>':'')+'</div>'); } } "
    "/* KARTE_ADD_V1 ここから下は「その週にしかないもの」。毎週変わらないものは入れない。 */ "
    "if(d.prevAsk&&String(d.prevAsk).trim()){ "
    "H.push('<div style=\"margin:-8px 0 13px;font-size:11px;color:#94a3b8;padding-left:15px\">先週きかれたこと … 「'+esc(d.prevAsk)+'」</div>'); } "
    "var _lw=d.lastWeek||null; var _lwU=(_lw&&_lw.units)||[]; "
    "var _sp=d.lastWeekSpecial||null; "
    "var _spParts=[]; "
    "if(_sp){ if(_sp.pokedex>0) _spParts.push('図鑑に '+_sp.pokedex+'ひき'); if(_sp.typeshoot>0) _spParts.push('タイプシュート '+_sp.typeshoot+'点'); if(_sp.wild>0) _spParts.push('野生 '+_sp.wild); } "
    "if((_lw&&_lw.total>0)||_spParts.length){ "
    "var _xH='<div class=\"sec\" style=\"border-color:#bae6fd;background:#f0f9ff\"><h2>✨ 先週のひろがり</h2>'; "
    "if(_lw&&_lw.total>0){ "
    "_xH+='<div style=\"font-size:12px;color:#0369a1;font-weight:700\">アプリで '+_lw.total+'問（'+_lw.days+'日・'+_lwU.length+'単元）</div>'; "
    "var _uNames=[]; for(var ui=0;ui<_lwU.length&&ui<6;ui++){ _uNames.push(esc(_unitJa(_lwU[ui].unit))+'('+_lwU[ui].total+'問)'); } "
    "if(_uNames.length) _xH+='<div style=\"font-size:12px;color:#475569;margin-top:3px\">やった単元 … '+_uNames.join('、')+'</div>'; "
    "var _fe=[]; for(var fi=0;fi<_lwU.length;fi++){ if(_lwU[fi].firstEver) _fe.push(esc(_unitJa(_lwU[fi].unit))); } "
    "if(_fe.length) _xH+='<div style=\"font-size:12px;color:#7c3aed;font-weight:700;margin-top:3px\">🆕 はじめて出会った単元 … '+_fe.slice(0,4).join('、')+'</div>'; } "
    "if(_spParts.length) _xH+='<div style=\"font-size:12px;color:#ea580c;font-weight:700;margin-top:3px\">🎉 今週のとくべつ … '+_spParts.join('／')+'</div>'; "
    "_xH+='</div>'; H.push(_xH); } "
    "/* 🌱 KARTE_ADD_V1 先週やった単元のうち、1週間の正答率が年度の正答率と15ポイント以上ちがうもの。"
    " 10問以上やった単元だけ。はじめて出会った単元は ✨ 側に出すので ここでは重ねない。"
    " 変わった単元が無い週は、この欄ごと出さない。出たときに意味を持たせるため。 */ "
    "var _chg=[]; "
    "for(var ci=0;ci<_lwU.length;ci++){ var _cu=_lwU[ci]; "
    "if(_cu.firstEver||_cu.total<10||_cu.yearRate==null) continue; "
    "var _df=_cu.rate-_cu.yearRate; "
    "if(_df>=15) _chg.push({t:esc(_unitJa(_cu.unit))+' は先週いい手ごたえやったな',c:'#16a34a'}); "
    "else if(_df<=-15) _chg.push({t:esc(_unitJa(_cu.unit))+' は先週てこずっとったな',c:'#ea580c'}); } "
    "if(_chg.length){ var _cH='<div class=\"sec\" style=\"border-color:#bbf7d0;background:#f0fdf4\"><h2>🌱 今週かわったこと</h2>'; "
    "for(var cj=0;cj<_chg.length&&cj<3;cj++){ _cH+='<div style=\"font-size:12px;font-weight:700;color:'+_chg[cj].c+'\">・'+_chg[cj].t+'</div>'; } "
    "_cH+='</div>'; H.push(_cH); }"
)
tsx = rep1(tsx, "+_acNote+'</div>':'')+'</div>'); } }", ADD, 'B-7〜9 足す欄')

# ── 置換後の確認 ────────────────────────────────────────────
chain_after = chain_count(tsx)
if chain_after != chain_before:
    fail('置換チェーンが %d -> %d 件に変わった。書かずに中止' % (chain_before, chain_after))
print('OK 置換チェーン（後）: %d 件（変化なし）' % chain_after)

for need, label in (
    ('lastWeek, lastWeekSpecial, prevAsk,', '返却に足したもの'),
    ('freeText: r.free_text', 'reflections の freeText'),
    ('idx_learning_results_user_time', '索引を使う説明'),
    ('✨ 先週のひろがり', '先週のひろがり'),
    ('🌱 今週かわったこと', '今週かわったこと'),
    ('先週きかれたこと', '先週きかれたこと'),
    ('_kRef.freeText', 'ふりかえりの freeText'),
):
    if need not in tsx:
        fail('%s が無い' % label)
if "if(_vt.length>50)" in tsx:
    fail('自分のことばの切り詰めが残っている')
if tsx.count(SENTINEL) < 7:
    fail('目印が %d 個しかない（7個以上のはず）' % tsx.count(SENTINEL))

io.open(TSX, 'w', encoding='utf-8', newline='').write(tsx)
print('OK 書き込み完了: src/index.tsx')
print('   サーバ: lastWeek / lastWeekSpecial / prevAsk / reflections.freeText を足した')
print('   カルテ: 自分のことばを全文に / ふりかえりの freeText / 先週きかれたこと /')
print('           ✨先週のひろがり / 🌱今週かわったこと（変わった週だけ）')
