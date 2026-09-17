// __WORLD_V2__ 3周目「世界編」第2段（ごほうびキャラ10体と、その配り先）
//
// やくそく（第1段と同じ）
//  - public/index.html は手で編集しない。ここの文字列を src/index.tsx のチェーンが当てる。
//  - アンカーが見つからないときは throw せず console.error して飛ばす。
//    （チェーンは try/catch に包まれていて、throw すると全件が黙って消えるため）
//  - 既存の進行データ（current / clearedMax / unlocked / zombieCleared）は読むだけ。
//  - 宇宙人化（青い敵）は 第3段。ここでは1体も青くしない。
//
// キャラのID
//  2101 リバティ / 2102 ビッグ・ベン / 2103 東京スカイツリー … 子どもが考えた3体
//  2111〜2117 … こちらで足した7体
//  絵文字は 2017年以前のものだけ。本番の433体で 未使用であることを機械確認済み。
//
// 配り先は 世界編の index（0〜23）。src/index.tsx の WORLD_STAGE_REWARDS と 同じ表にすること。
// 実際に配るのは サーバの台帳。ここは カードに 見せるだけ。

export type WorldPatch2 = { tag: string, a: string, b: string }

// ---- 1) ごほうび10体を MONSTERS に足す ------------------------------------
const A_CHARS = '        // --- 属性タイプが未設定のモンスター補完（表示・相性計算用） ---'

const B_CHARS = `        /* __WORLD_V2__ 世界編のごほうび10体。
           表のならび = [id, 名前, 絵文字, 体力, 攻撃, 防御, 速さ, buff, 属性, せつめい, 技1, 技2, 技3, 技3の効果, 技3のせつめい] */
        (function(){
          try{
            var WV2 = [
              [2103,'東京スカイツリー','📡',430,140,70,80,'speed','electric','空の上から でんぱを おくる。まいごの なかまを かならず みつける。','でんぱビーム','そらのとう','ぜんいんアンテナ','buff_spd_party','みんなの 足を はやくする'],
              [2112,'アンカーロス','⚓',520,130,110,55,'guard','water','みなとの ぬし。いちど いかりを おろすと だれにも どかせない。','いかりストライク','だいびょうしゃ','ふかづめの かまえ','buff_def_party','みんなの まもりを かためる'],
              [2111,'ピラミッドン','🕋',560,135,120,50,'guard','ground','さばくに たつ 石のかたまり。四千年 うごいていない。','すなあらし','せきばんプレス','さばくの のろい','debuff_atk_all','あいて ぜんいんの こうげきを さげる'],
              [2117,'コメットン','💫',420,160,60,130,'attack','psychic','よぞらを よこぎる ひとすじ。ねがいごとを されるのが にがて。','ながれぼし','こうそくらっか','だいきえんとつ','buff_spd','じぶんの 足を はやくする'],
              [2114,'オリエントごう','🚂',600,150,100,70,'guard','steel','大陸を よこぎる きかんしゃ。とまる駅を じぶんで きめる。','せきたんダッシュ','てっきょうわたり','はっしゃオーライ','buff_atk_party','みんなの こうげきを あげる'],
              [2102,'ビッグ・ベン','🔔',580,160,115,65,'attack','steel','ロンドンの おおどけい。ほんとうは かねの 名まえ。','ときのかね','だいしょうげき','じこくを くるわす','debuff_random','あいての ちからを ランダムで さげる'],
              [2113,'ヤシノカゲ','🌴',500,170,80,95,'attack','grass','あつい国の 木かげ。休ませてくれるが なかなか かえしてくれない。','はっぱカッター','きょだいなかげ','ひるねの さそい','heal_party','みんなを すこし かいふくする'],
              [2115,'ナイアガラン','⛲',620,165,105,75,'attack','water','おちつづける 水のかべ。音で あいての こえが きこえなくなる。','ばくすいホーン','たきつぼドロップ','みずけむり','debuff_def','あいての まもりを さげる'],
              [2116,'ギンガノヌシ','🌌',600,185,95,100,'attack','psychic','星の川の おく。うちゅう人たちを したがえている ほんとうの ぬし。','ぎんがのうねり','スターゲイズ','じゅうりょくの わな','debuff_enemy','あいてを よわらせる'],
              [2101,'リバティ','🗽',700,195,120,90,'attack','fairy','じゆうの たいまつ。くらい 夜ほど よく もえる。','ひかりのたいまつ','じゆうのいちげき','かかげる ともしび','buff_all_party','みんなを ふるいたたせる']
            ];
            for (var _i = 0; _i < WV2.length; _i++){
              var r = WV2[_i];
              /* getMonster は 見つからないとき MONSTERS[0] を返すので 重複判定には使えない */
              var dup = false;
              for (var _j = 0; _j < MONSTERS.length; _j++){ if (MONSTERS[_j] && MONSTERS[_j].id === r[0]) { dup = true; break; } }
              if (dup) { console.error('[__WORLD_V2__] id already exists: ' + r[0]); continue; }
              var mk = [
                { name: r[10], type: r[8], pow: 18, acc: 0.95, desc: r[10] },
                { name: r[11], type: r[8], pow: 32, acc: 0.78, desc: r[11] },
                { name: r[12], type: 'unique', pow: 0, acc: 1.0, effect: r[13], desc: r[14] }
              ];
              MONSTERS.push({ id: r[0], name: r[1], sprite: r[2], hp: r[3], atk: r[4], def: r[5], spd: r[6],
                buff: r[7], elementType: r[8], rarity: 6, desc: r[9], skills: mk, moves: mk });
            }
          }catch(e){ console.error('[__WORLD_V2__] chars', e); }
        })();

        /* __WORLD_V2__ どのステージで どれが もらえるか（世界編の index 0〜23）。
           src/index.tsx の WORLD_STAGE_REWARDS と 同じ表であること。 */
        window.WORLD_REWARD_BY_STAGE = { '3':2103, '6':2112, '8':2111, '10':2117, '13':2114, '16':2102, '18':2113, '21':2115, '22':2116, '23':2101 };
        window.worldRewardLabel = function(i){
          try{
            var id = window.WORLD_REWARD_BY_STAGE[String(i)];
            if(!id) return '🎁 コイン＆ひでんの書';
            /* getMonster は 見つからないとき MONSTERS[0] を返すので id を つき合わせる */
            var m = null;
            try{ for (var _j = 0; _j < MONSTERS.length; _j++){ if (MONSTERS[_j] && MONSTERS[_j].id === id) { m = MONSTERS[_j]; break; } } }catch(e){}
            if(!m) return '🎁 コイン＆ひでんの書';
            var got = false;
            try{ got = !!(window.player && player.monsters && player.monsters[String(id)]); }catch(e){}
            return (got ? '✅ ' : '🎁 ') + m.sprite + ' ' + m.name;
          }catch(e){ console.error('[__WORLD_V2__] rewardLabel', e); return '🎁 コイン＆ひでんの書'; }
        };
` + A_CHARS

// ---- 2) カードの ごほうび欄を 実態に合わせる ------------------------------
const A_CARD = "          h += '<div class=\"war-stage-reward\">🎁 コイン＆ひでんの書</div>';"

const B_CARD = "          h += '<div class=\"war-stage-reward\">' + ((typeof window.worldRewardLabel === 'function') ? window.worldRewardLabel(i) : '🎁 コイン＆ひでんの書') + '</div>';"

export const WORLD_V2_PATCHES: WorldPatch2[] = [
  { tag: 'V01_chars', a: A_CHARS, b: B_CHARS },
  { tag: 'V02_card', a: A_CARD, b: B_CARD }
]
