/* 💰 COINLOG_V1（11/24）コインが ふえた・へった ときに「何で」を 記録する（先生が あとで 見られる）
 *  ・player.coins を 見はって、かわったら player.coinLog に のこす（さいごの 200件）
 *  ・理由は window.__coinWhy（買い物・ガチャなどで 入れる）→ なければ 呼び出し元の 関数名から おしはかる
 *  ・子どもには 見せない。保存は ふつうの セーブで いっしょに 送られる
 */
(function () {
  var NAMES = {
    pullGacha: 'ガチャ', pullGacha10: 'ガチャ10連', buyItem: 'ショップ', buyBread: 'パン', rollGacha: 'ガチャ',
    _rbClaimMission: 'クラスミッション', _defClaimReward: '防衛戦のごほうび', _gcReward: 'ジムチャレンジ',
    checkRankingRewards: 'ランキングのごほうび', claimDaily: 'デイリー', redeemCode: 'ひみつのコード'
  };
  function guess() {
    var why = window.__coinWhy;
    if (why) return String(why).slice(0, 40);
    try {
      var st = String(new Error().stack || '').split('\n').slice(3, 9), fn = [];
      st.forEach(function (l) {
        var m = /at (?:Object\.|window\.|HTMLButtonElement\.|HTMLDivElement\.)?([A-Za-z0-9_$.]+) /.exec(l) || /^([A-Za-z0-9_$.]+)@/.exec(l);
        if (m && m[1] && !/^(set|Array|Function|eval|anonymous|async|Promise)/.test(m[1])) fn.push(m[1].replace(/^.*\./, ''));
      });
      for (var i = 0; i < fn.length; i++) if (NAMES[fn[i]]) return NAMES[fn[i]];
      var f = (location.pathname || '').indexOf('/pj') === 0 ? '先生PJ' : '';
      return (f ? f + ' ' : '') + (fn.slice(0, 2).join('<') || '?');
    } catch (e) { return '?'; }
  }
  function hook() {
    var p = (typeof window.getPlayer === 'function' ? window.getPlayer() : null) || window.player;
    if (!p || typeof p !== 'object' || p.__clHook) return;
    var v = p.coins;
    try {
      Object.defineProperty(p, '__clHook', { value: 1, enumerable: false, configurable: true });
      Object.defineProperty(p, 'coins', {
        enumerable: true, configurable: true,
        get: function () { return v; },
        set: function (x) {
          var a = Number(v) || 0, b = Number(x) || 0; v = x;
          if (a === b || !isFinite(b)) return;
          try {
            if (!Array.isArray(p.coinLog)) p.coinLog = [];
            p.coinLog.push({ t: Date.now(), d: b - a, a: b, w: guess() });
            if (p.coinLog.length > 200) p.coinLog.splice(0, p.coinLog.length - 200);
          } catch (e) {}
        }
      });
    } catch (e) {}
  }
  setInterval(hook, 1000);
  hook();
})();
