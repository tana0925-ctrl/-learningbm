/* RT Egg-Battle Sync (egg mode ONLY)
 * 友達対戦(wild)・ジムバトル(gym)には一切干渉しない。
 * 本体HTML(index.html)が wild/gym/ロビー/勝敗を完全に担当するため、
 * このスクリプトは「たまごバトルの相手同期」だけを自己起動方式で提供する。
 */
(function () {
  'use strict';

  var _eg = { roomId: null, role: null, lastEventId: 0, pollTimer: null, active: false, myEventIds: {} };

  function rtSendEggBattleEvent(data) {
    if (!_eg.roomId) return;
    fetch('/api/rt/damage/' + _eg.roomId, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ damage: 0, monsterId: 0, eventType: 'egg_battle', meta: data })
    }).then(function (r) { return r.json(); })
      .then(function (d) { if (d && d.eventId) _eg.myEventIds[d.eventId] = 1; })
      .catch(function () {});
  }

  function hookEggBattle(role) {
    var eb = window.EggBattle;
    if (!eb || !eb.active || !eb.state) {
      setTimeout(function () { hookEggBattle(role); }, 300);
      return;
    }
    if (eb._vsHooked) return;
    eb._vsHooked = true;
    var s = eb.state;
    var W = eb.canvas.width;
    var H = eb.canvas.height;
    s._vsMode = true;

    if (role === 'guest' && s.player) {
      s.player.x = W - 80;
      s.player.y = 80;
      s.player.dirX = -1;
      s.player.dirY = 0;
      if (s.enemyBase) { s.enemyBase.x = 90; s.enemyBase.y = H - 70; }
    }

    var origAEL = eb.autoEnemyLay;
    if (origAEL) {
      eb.autoEnemyLay = function (dt) {
        if (this.state && this.state._vsMode) return;
        return origAEL.call(this, dt);
      };
    }

    var origPE = eb.placeEgg;
    if (origPE) {
      eb.placeEgg = function () {
        var s2 = eb.state; var bl = s2 && s2.eggs ? s2.eggs.length : -1;
        var r = origPE.call(this);
        if (s2 && s2.eggs && s2.eggs.length > bl) {
          var egg = s2.eggs[s2.eggs.length - 1];
          rtSendEggBattleEvent({ type: 'eb_egg', x: egg.x, y: egg.y, r: egg.r || 5, id: egg.id, hatchSec: egg.hatchSec || 5 });
        }
        return r;
      };
    }

    var origPW = eb.placeWall;
    if (origPW) {
      eb.placeWall = function () {
        var s2 = eb.state; var bl = s2 && s2.placedWalls ? s2.placedWalls.length : -1;
        var r = origPW.call(this);
        if (s2 && s2.placedWalls && s2.placedWalls.length > bl) {
          var wall = s2.placedWalls[s2.placedWalls.length - 1];
          rtSendEggBattleEvent({ type: 'eb_wall', x: wall.x, y: wall.y, w: wall.w, h: wall.h });
        }
        return r;
      };
    }

    var origFM = eb.fireMissile;
    if (origFM) {
      eb.fireMissile = function () {
        var s2 = eb.state; var bl = s2 && s2.missiles ? s2.missiles.length : -1;
        var r = origFM.call(this);
        if (s2 && s2.missiles && s2.missiles.length > bl) {
          var m = s2.missiles[s2.missiles.length - 1];
          rtSendEggBattleEvent({ type: 'eb_missile', x: m.x, y: m.y, vx: m.vx, vy: m.vy, r: m.r || 3 });
        }
        return r;
      };
    }

    var origKMB = eb.killMyBase;
    if (origKMB) {
      eb.killMyBase = function () {
        rtSendEggBattleEvent({ type: 'eb_game_over' });
        return origKMB.call(this);
      };
    }
    console.log('[RT-egg] EggBattle VS hooked, role:', role);
  }

  function handleEggBattleEvent(metaJson) {
    var eb = window.EggBattle;
    if (!eb || !eb.state || !eb.canvas) return;
    var s = eb.state; var W = eb.canvas.width; var H = eb.canvas.height;
    var data;
    try { data = typeof metaJson === 'string' ? JSON.parse(metaJson) : (metaJson || {}); } catch (e) { return; }
    var mx = W - (data.x || 0); var my = H - (data.y || 0);
    if (data.type === 'eb_egg') {
      s.enemyEggs = s.enemyEggs || [];
      var hs = data.hatchSec || 5;
      s.enemyEggs.push({ x: mx, y: my, r: data.r || 5, id: data.id || ('re' + Date.now()), hatchAt: Date.now() + hs * 1000, hatchSec: hs });
    } else if (data.type === 'eb_wall') {
      s.placedWalls = s.placedWalls || [];
      s.placedWalls.push({ x: W - (data.x || 0) - (data.w || 40), y: H - (data.y || 0) - (data.h || 20), w: data.w || 40, h: data.h || 20, hp: 2, maxHp: 2, team: 2, breakable: true });
    } else if (data.type === 'eb_missile') {
      s.enemyShots = s.enemyShots || [];
      s.enemyShots.push({ x: mx, y: my, r: data.r || 3, vx: -(data.vx || 0), vy: -(data.vy || 0) });
    } else if (data.type === 'eb_game_over') {
      if (eb.killEnemyBase) eb.killEnemyBase();
    }
  }

  function eggPoll() {
    if (!_eg.roomId) return;
    fetch('/api/rt/room/' + _eg.roomId + '?after=' + _eg.lastEventId)
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (!d || !d.ok) return;
        var evs = d.events || [];
        for (var i = 0; i < evs.length; i++) {
          var ev = evs[i];
          if (ev.id > _eg.lastEventId) _eg.lastEventId = ev.id;
          if (ev.event_type !== 'egg_battle') continue;
          if (_eg.myEventIds[ev.id]) continue;
          try { handleEggBattleEvent(ev.meta_json); } catch (e) {}
        }
      })
      .catch(function () {});
  }

  function startEggPoll() { stopEggPoll(); _eg.pollTimer = setInterval(eggPoll, 300); }
  function stopEggPoll() { if (_eg.pollTimer) { clearInterval(_eg.pollTimer); _eg.pollTimer = null; } }

  function stopEgg() {
    stopEggPoll();
    var eb = window.EggBattle;
    if (eb) eb._vsHooked = false;
    _eg.active = false;
    _eg.roomId = null;
    _eg.role = null;
    _eg.lastEventId = 0;
    _eg.myEventIds = {};
  }

  function tryActivate() {
    var eb = window.EggBattle;
    if (!eb || !eb.active) return;
    var codeEl = document.getElementById('rtMyRoomCode');
    var code = codeEl ? (codeEl.textContent || '').trim().replace(/[\s　\-]/g, '').toUpperCase() : '';
    if (!code || code.length < 4) return;
    fetch('/api/rt/room/' + code)
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (!d || !d.ok || !d.room) return;
        if (d.room.battleType !== 'egg') return;
        if (d.room.status !== 'playing' && d.room.status !== 'ready') return;
        _eg.active = true;
        _eg.roomId = code;
        _eg.role = d.room.myRole || 'host';
        _eg.lastEventId = 0;
        _eg.myEventIds = {};
        hookEggBattle(_eg.role);
        startEggPoll();
        console.log('[RT-egg] sync started room=' + code + ' role=' + _eg.role);
      })
      .catch(function () {});
  }

  setInterval(function () {
    var eb = window.EggBattle;
    var battleOn = !!(eb && eb.active);
    if (_eg.active && !battleOn) { stopEgg(); return; }
    if (!_eg.active && battleOn) { tryActivate(); }
  }, 700);

  console.log('[RT Egg-Battle Sync] loaded (egg-only, wild/gym untouched)');
})();
