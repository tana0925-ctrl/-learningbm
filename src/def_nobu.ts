// ⚔️ DEF_NOBU_V1（2026-11-13 先生の指示）クラス基地防衛戦「信長編」
//   ステージ1から じゅんに、織田信長が 経験した 戦いを たどる。
//   ・てきの 名前・すがた・大将を その 戦いの ものに する（つよさの きまりは いままでと おなじ式）
//   ・15の 戦いを、むかしの ステージ 1〜26 の つよさに わりあてる（さいごの 本能寺の変 ＝ 26）
//   ・ボス（12/15/18/21 の 段の 入れかえ）は 信長編では つかわない。かわりに その 戦いの 大将が 8体目
//   ・15を こえたら「信長編 クリア」。てきは 本能寺の変の まま、つよさも 26 の まま
// @ts-nocheck
/* eslint-disable */

export const DEF_NOBU_ON = false   // 先生の OK が 出たら true に して ステージを 1 に もどす

// sprites: 0,1 足軽（こうげき） 2,3 はやい たい（はやさ） 4,5 まもる たい（まもり） 6 侍大将 7 大将
export const NOBU_BATTLES = [
  { year: 1556, title: '稲生の戦い', army: '信勝軍', general: '織田信勝', kind: ['足軽', '騎馬', 'やり隊'],
    story: '信長は 尾張（いまの 愛知県 西部）の 大名の 家を つぎました。でも 弟の 信勝と 家来の 一部が 信長に さからい、兄弟で 戦うことに なりました。信長は 勝って 尾張を まとめていきます。' },
  { year: 1560, title: '桶狭間の戦い', army: '今川軍', general: '今川義元', kind: ['足軽', '騎馬', 'やり隊'],
    story: '駿河（いまの 静岡県）の 今川義元が 大軍で 尾張に せめこんできました。信長は ずっと 少ない 兵で、休んでいた 今川軍の 本陣を ねらって 勝ちました。信長の 名前が 一気に 広まります。' },
  { year: 1567, title: '稲葉山城の戦い', army: '斎藤軍', general: '斎藤龍興', kind: ['足軽', '騎馬', 'やり隊'],
    story: '美濃（いまの 岐阜県）の 斎藤氏の 城を せめおとしました。信長は 地名を「岐阜」と かえ、「天下布武」（武の 力で 天下を おさめる）の 印を つかいはじめます。' },
  { year: 1568, title: '観音寺城の戦い', army: '六角軍', general: '六角義賢', kind: ['足軽', '騎馬', '弓隊'],
    story: '信長は 足利義昭を つれて 京都へ 向かいます（上洛）。とちゅうで じゃまを した 近江（いまの 滋賀県）の 六角氏を やぶり、義昭を 室町幕府の 将軍に しました。' },
  { year: 1570, title: '金ケ崎の退き口', army: '朝倉・浅井軍', general: '朝倉義景', kind: ['足軽', '騎馬', 'やり隊'],
    story: '越前（いまの 福井県）の 朝倉氏を せめていた とき、妹の お市の 夫・浅井長政が 朝倉の 味方に つきました。はさみうちに なる 前に、信長は 京都へ にげかえります。基地を 守りながら 退く 戦いです。' },
  { year: 1570, title: '姉川の戦い', army: '浅井・朝倉軍', general: '浅井長政', kind: ['足軽', '騎馬', 'やり隊'],
    story: '信長は 徳川家康と 力を あわせ、近江の 姉川で 浅井・朝倉の 連合軍と 戦い、勝ちました。でも 浅井・朝倉は まだ ほろびません。' },
  { year: 1570, title: '石山合戦のはじまり', army: '本願寺勢', general: '顕如', kind: ['一揆勢', '僧兵', '鉄砲隊'],
    story: '大阪の 石山本願寺（一向宗の 大きな お寺）が 信長と 戦いはじめました。全国の 信者（一向一揆）も 立ちあがり、この 戦いは 10年も つづきます。' },
  { year: 1573, title: '槇島城の戦い', army: '足利軍', general: '足利義昭', kind: ['足軽', '騎馬', '弓隊'],
    story: '将軍に した 足利義昭が、こんどは 信長を たおそうと 兵を あげました。信長は 義昭を 京都から 追いだし、室町幕府は ほろびました。' },
  { year: 1573, title: '一乗谷・小谷城の戦い', army: '朝倉・浅井軍', general: '浅井長政', kind: ['足軽', '騎馬', 'やり隊'],
    story: '信長は 朝倉氏の 一乗谷と、浅井氏の 小谷城を つぎつぎに せめおとしました。長い 戦いの 末、朝倉氏と 浅井氏は ほろびます。' },
  { year: 1575, title: '長篠の戦い', army: '武田軍', general: '武田勝頼', kind: ['足軽', '騎馬隊', 'やり隊'],
    story: '甲斐（いまの 山梨県）の 武田勝頼が、強い 騎馬隊で せめてきました。信長と 家康は 馬防柵を つくり、たくさんの 鉄砲を つかって 武田軍を やぶりました。' },
  { year: 1577, title: '手取川の戦い', army: '上杉軍', general: '上杉謙信', kind: ['足軽', '騎馬', 'やり隊'],
    story: '越後（いまの 新潟県）の 上杉謙信と、信長の 家来・柴田勝家の 軍が 加賀（いまの 石川県）で 戦いました。このときは 上杉軍が 勝ちました。いちばん 強い 相手の ひとりです。' },
  { year: 1577, title: '信貴山城の戦い', army: '松永軍', general: '松永久秀', kind: ['足軽', '鉄砲隊', 'やり隊'],
    story: '大和（いまの 奈良県）の 松永久秀が 信長に そむき、信貴山城に たてこもりました。信長の 軍は 城を せめおとしました。' },
  { year: 1580, title: '石山合戦のおわり', army: '本願寺勢', general: '顕如', kind: ['一揆勢', '僧兵', '鉄砲隊'],
    story: '10年 つづいた 石山本願寺との 戦いが、朝廷の 仲立ちで おわりました。本願寺は 石山を 出ていき、信長は 大阪を 手に 入れます。' },
  { year: 1582, title: '甲州征伐', army: '武田軍', general: '武田勝頼', kind: ['足軽', '騎馬隊', 'やり隊'],
    story: '信長は 武田氏の 領地に 大軍で せめこみました。武田勝頼は たおれ、戦国の 名門・武田氏は ほろびました。天下統一まで あと 少し です。' },
  { year: 1582, title: '本能寺の変', army: '明智軍', general: '明智光秀', kind: ['足軽', '鉄砲隊', 'やり隊'],
    story: '京都の 本能寺に とまっていた 信長を、家来の 明智光秀が とつぜん おそいました。信長は ここで たおれ、天下統一は 豊臣秀吉に うけつがれます。本能寺を 守りきれるか？' },
]
export const NOBU_N = NOBU_BATTLES.length
const DIFF_MAX = 26

export function nobuIdx(stage) {
  const n = Math.floor(Number(stage))
  if (!Number.isFinite(n) || n < 1) return 0
  return Math.min(NOBU_N, n) - 1
}
// 信長編の ステージ → むかしの ステージの つよさ（1 → 1、15 → 26）
export function nobuDiff(stage) {
  const i = nobuIdx(stage)
  return 1 + Math.round(i * (DIFF_MAX - 1) / (NOBU_N - 1))
}
const SPR = { '足軽': '⚔️', '騎馬': '🐎', '騎馬隊': '🐎', 'やり隊': '🔱', '弓隊': '🏹', '鉄砲隊': '💥', '一揆勢': '🔥', '僧兵': '📿' }
// てきの 名前・すがたを その 戦いの ものに する（数・つよさには さわらない）
export function nobuSkin(squad, stage) {
  try {
    if (!Array.isArray(squad) || !squad.length) return squad
    const b = NOBU_BATTLES[nobuIdx(stage)]
    const k = b.kind
    return squad.map(function (e, i) {
      const o = {}
      for (const p in e) o[p] = e[p]
      const nm = i <= 1 ? k[0] : i <= 3 ? k[1] : i <= 5 ? k[2] : ''
      if (i === squad.length - 1) { o.name = b.general; o.sprite = '👹'; o.boss = true }
      else if (i === squad.length - 2) { o.name = b.army.replace(/(軍|勢)$/, '') + 'の侍大将'; o.sprite = '🪖' }
      else { o.name = nm; o.sprite = SPR[nm] || '⚔️' }
      return o
    })
  } catch (_e) { return squad }
}
export function nobuInfo(stage) {
  const n = Math.floor(Number(stage)) || 1
  const i = nobuIdx(n), b = NOBU_BATTLES[i]
  return { n: i + 1, total: NOBU_N, title: b.title, year: b.year, army: b.army, general: b.general, story: b.story, cleared: n > NOBU_N }
}
