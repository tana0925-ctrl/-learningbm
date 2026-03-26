/* RT Battle System v3 - 友達対戦＋ジムバトル対応 */
(function () {
  'use strict';

  // ===== State =====
  const _rt = {
    roomId: null, role: null, lastEventId: 0, pollTimer: null,
    status: 'idle', hostHp: 100, guestHp: 100,
    myHp: 100, oppHp: 100,
    myName: '', oppName: '', area: '', dmgPending: false,
    mode: 'wild',        // 'wild' | 'gym' | 'egg'
    gymPollTimer: null,
    lastCastleHp: null
  };

  const el = id => document.getElementById(id);

  // ===== Panel =====
  function buildPanel() {
    if (el('_rtPanel')) return;
    const div = document.createElement('div');
    div.id = '_rtPanel';
    div.style.cssText = 'position:fixed;top:8px;right:8px;z-index:99999;background:#0f172a;border:2px solid #3b82f6;border-radius:14px;padding:14px 16px;min-width:250px;max-width:290px;color:#f1f5f9;font-family:system-ui,sans-serif;font-size:13px;box-shadow:0 4px 24px rgba(0,0,0,.6);display:none';
    div.innerHTML =
      '<div style="font-weight:700;font-size:14px;color:#60a5fa;margin-bottom:8px">⚡ RT対戦</div>' +
      '<div id="_rtMsg" style="color:#94a3b8;font-size:12px;margin-bottom:6px"></div>' +
      '<div id="_rtRoomRow" style="display:none;margin-bottom:8px">' +
        '<span style="color:#94a3b8;font-size:11px">ルームID: </span>' +
        '<span id="_rtRoomId" style="color:#fbbf24;font-weight:700;font-size:17px;letter-spacing:3px"></span>' +
        '<button onclick="navigator.clipboard&&navigator.clipboard.writeText(document.getElementById(\'_rtRoomId\').textContent)" style="background:#1e40af;color:#fff;border:none;border-radius:5px;padding:2px 7px;font-size:11px;cursor:pointer;margin-left:4px">コピー</button>' +
      '</div>' +
      '<div id="_rtHpBox" style="display:none">' +
        '<div id="_rtModeLabel" style="font-size:10px;color:#94a3b8;margin-bottom:4px;text-align:center"></div>' +
        '<div style="margin-bottom:7px">' +
          '<div style="display:flex;justify-content:space-between;margin-bottom:2px">' +
            '<span id="_rtMyLbl" style="font-size:11px;color:#4ade80;font-weight:600">自分</span>' +
            '<span id="_rtMyVal" style="font-size:11px;color:#4ade80">100/100</span>' +
          '</div>' +
          '<div style="background:#1e293b;border-radius:6px;height:10px;overflow:hidden;position:relative">' +
            '<div id="_rtMyBar" style="height:10px;border-radius:6px;width:100%;transition:width .4s ease;background:linear-gradient(90deg,#4ade80,#22c55e)"></div>' +
            '<div id="_rtMyFlash" style="position:absolute;inset:0;background:#fff;opacity:0;pointer-events:none;transition:opacity .08s"></div>' +
          '</div>' +
        '</div>' +
        '<div style="margin-bottom:10px;position:relative">' +
          '<div style="display:flex;justify-content:space-between;margin-bottom:2px">' +
            '<span id="_rtOppLbl" style="font-size:11px;color:#f87171;font-weight:600">相手</span>' +
            '<span id="_rtOppVal" style="font-size:11px;color:#f87171">100/100</span>' +
          '</div>' +
          '<div style="background:#1e293b;border-radius:6px;height:10px;overflow:hidden;position:relative">' +
            '<div id="_rtOppBar" style="height:10px;border-radius:6px;width:100%;transition:width .4s ease;background:linear-gradient(90deg,#f87171,#ef4444)"></div>' +
            '<div id="_rtOppFlash" style="position:absolute;inset:0;background:#fff;opacity:0;pointer-events:none;transition:opacity .08s"></div>' +
          '</div>' +
        '</div>' +
        '<div id="_rtAttackBox" style="display:none;background:#1e293b;border-radius:8px;padding:7px 10px;margin-bottom:8px;font-size:12px">' +
          '<div id="_rtAttackLine" style="font-weight:700;margin-bottom:2px"></div>' +
          '<div id="_rtDamageLine" style="font-size:15px;font-weight:700"></div>' +
        '</div>' +
        '<div style="background:#020617;border-radius:6px;padding:4px 6px;border:1px solid #1e293b;max-height:72px;overflow-y:auto" id="_rtLogBox">' +
          '<div id="_rtLogInner" style="font-size:10px;color:#475569"></div>' +
        '</div>' +
      '</div>' +
      '<div id="_rtWin" style="display:none;font-size:22px;text-align:center;font-weight:700;padding:8px 0"></div>' +
      '<button onclick="window.rtLeave()" id="_rtLeaveBtn" style="display:none;margin-top:8px;background:#7f1d1d;color:#fff;border:none;border-radius:7px;padding:4px 12px;font-size:11px;cursor:pointer">退出</button>';
    document.body.appendChild(div);
  }

  function panelShow() { buildPanel(); el('_rtPanel').style.display = 'block'; }
  function panelHide() { const p = el('_rtPanel'); if (p) p.style.display = 'none'; }
  function setMsg(m) { const e = el('_rtMsg'); if (e) e.textContent = m; }
  function setModeLabel(m) { const e = el('_rtModeLabel'); if (e) e.textContent = m; }

  function hpColor(hp) {
    return hp > 50 ? 'linear-gradient(90deg,#4ade80,#22c55e)'
         : hp > 25 ? 'linear-gradient(90deg,#fbbf24,#f59e0b)'
                   : 'linear-gradient(90deg,#f87171,#ef4444)';
  }

  function updateHpBars() {
    const pct = v => Math.max(0, Math.min(100, v));
    if (el('_rtMyBar'))  { el('_rtMyBar').style.width  = pct(_rt.myHp)  + '%'; el('_rtMyBar').style.background  = hpColor(_rt.myHp); }
    if (el('_rtOppBar')) { el('_rtOppBar').style.width = pct(_rt.oppHp) + '%'; el('_rtOppBar').style.background = hpColor(_rt.oppHp); }
    if (el('_rtMyVal'))  el('_rtMyVal').textContent  = _rt.myHp  + '/100';
    if (el('_rtOppVal')) el('_rtOppVal').textContent = _rt.oppHp + '/100';
  }

  function flashBar(id) { const f = el(id); if (!f) return; f.style.opacity = '0.75'; setTimeout(() => { if (f) f.style.opacity = '0'; }, 150); }
  function flashOppBar() { flashBar('_rtOppFlash'); }
  function flashMyBar()  { flashBar('_rtMyFlash'); }

  function showAttackNotif(line1, line2, color) {
    const box = el('_rtAttackBox'), aln = el('_rtAttackLine'), dln = el('_rtDamageLine');
    if (!box) return;
    if (aln) { aln.textContent = line1; aln.style.color = color; }
    if (dln) { dln.textContent = line2; dln.style.color = color; }
    box.style.display = 'block';
    box.style.borderLeft = '3px solid ' + color;
    clearTimeout(window._rtNotifT);
    window._rtNotifT = setTimeout(() => { if (box) box.style.display = 'none'; }, 2500);
  }

  function addLog(txt) {
    const inner = el('_rtLogInner');
    if (!inner) return;
    const d = document.createElement('div');
    const t = new Date();
    d.textContent = '[' + String(t.getMinutes()).padStart(2,'0') + ':' + String(t.getSeconds()).padStart(2,'0') + '] ' + txt;
    inner.appendChild(d);
    const box = el('_rtLogBox');
    if (box) box.scrollTop = box.scrollHeight;
    while (inner.children.length > 20) inner.removeChild(inner.firstChild);
  }

  function parseMeta(raw) {
    if (!raw) return {};
    try { return typeof raw === 'string' ? JSON.parse(raw) : raw; } catch(e) { return {}; }
  }

  function getMyMonsterInfo() {
    try {
      const name  = el('playerNameDisplay')?.textContent?.trim() || '';
      const sprite = el('playerSpriteDisplay');
      let emoji = '';
      if (sprite) { const txt = (sprite.textContent || '').trim(); if (txt) emoji = [...txt][0] || ''; }
      return { name, emoji, moveName: _rt.area || '' };
    } catch(e) { return { name: '', emoji: '', moveName: '' }; }
  }

  // ===== Polling =====
  async function rtPoll() {
    if (!_rt.roomId) return;
    try {
      const r = await fetch('/api/rt/room/' + _rt.roomId + '?after=' + _rt.lastEventId);
      if (!r.ok) return;
      const d = await r.json();
      if (!d.ok) return;
      const room = d.room;
      _rt.role = room.myRole;
      _rt.area = room.area || '';
      if (room.battleType && !_rt._modeSet) { _rt.mode = room.battleType === 'egg' ? 'egg' : room.battleType === 'gym' ? 'gym' : 'wild'; _rt._modeSet = true; }

      const newMyHp  = _rt.role === 'host' ? room.hostHp  : room.guestHp;
      const newOppHp = _rt.role === 'host' ? room.guestHp : room.hostHp;
      const myHpDiff  = _rt.myHp  - newMyHp;
      const oppHpDiff = _rt.oppHp - newOppHp;

      const myN  = _rt.role === 'host' ? room.hostName  : room.guestName;
      const oppN = _rt.role === 'host' ? room.guestName : room.hostName;
      if (el('_rtMyLbl'))  el('_rtMyLbl').textContent  = '自分: ' + myN;
      if (el('_rtOppLbl')) el('_rtOppLbl').textContent = '相手: ' + (oppN || '待機中...');

      for (const ev of (d.events || [])) {
        if (ev.id > _rt.lastEventId) _rt.lastEventId = ev.id;
      }

      if (_rt.mode === 'gym') {
        // ジムバトルモード: 城HPの追跡
        if (myHpDiff > 0) {
          flashMyBar();
          showAttackNotif('⚔️ 自分の城が攻撃された！', '−' + myHpDiff + ' ダメージ！', '#f87171');
          addLog('自分の城: -' + myHpDiff + 'HP');
        }
        if (oppHpDiff > 0) {
          flashOppBar();
          showAttackNotif('⚔️ 相手の城も攻撃された！', '−' + oppHpDiff + ' ダメージ！', '#fbbf24');
          addLog('相手の城: -' + oppHpDiff + 'HP');
        }
      } else {
        // 野生/友達対戦モード: モンスターHP追跡
        if (myHpDiff > 0) {
          flashOppBar();
          const dmgEvs = (d.events || []).filter(e => e.event_type === 'damage');
          const latest = dmgEvs[dmgEvs.length - 1];
          const meta = parseMeta(latest?.meta_json);
          const name  = meta.attackerName  || '相手';
          const emoji = meta.attackerEmoji || '⚔️';
          const move  = meta.moveName      || 'こうげき';
          showAttackNotif(emoji + ' ' + name + ' の ' + move + '！', '−' + myHpDiff + ' ダメージ！', '#f87171');
          addLog('相手: ' + (emoji||'') + name + ' → -' + myHpDiff + 'HP');
        }
        for (const ev of (d.events || [])) {
          if (ev.event_type === 'faint') {
            const meta = parseMeta(ev.meta_json);
            addLog((meta.attackerName || 'モンスター') + ' が倒れた！');
          }
        }
      }

      _rt.myHp  = newMyHp;
      _rt.oppHp = newOppHp;
      _rt.hostHp  = room.hostHp;
      _rt.guestHp = room.guestHp;
      // タマゴバトル VS mode
      if (_rt.mode === 'egg') {
        if (!window._ebVsHooked && window.EggBattle && window.EggBattle.active) {
          window._ebVsHooked = true;
          hookEggBattle(_rt.role || 'host');
        }
        const ebEvs = (d.events || []).filter(function(e){ return e.event_type === 'egg_battle'; });
        for (var _i = 0; _i < ebEvs.length; _i++) {
          try { handleEggBattleEvent(ebEvs[_i].meta_json); } catch(_e) {}
        }
      }
      updateHpBars();

      if (room.status === 'waiting') {
        setMsg('相手の参加を待っています...');
      } else if (room.status === 'playing') {
        if (_rt.status !== 'playing') {
          _rt.status = 'playing';
          const modeStr = _rt.mode === 'gym' ? 'ジムバトル'  : _rt.mode === 'egg' ? 'タマゴバトル': '友達対戦';
          setMsg('⚔️ バトル中！ [' + modeStr + ']');
          setModeLabel(_rt.mode === 'gym' ? 'ジムバトルモード 🏰' : '友達対戦モード 🤎');
          if (el('_rtHpBox')) el('_rtHpBox').style.display = 'block';
          addLog('バトルスタート！ [' + modeStr + ']');
          if (_rt.mode === 'egg') { setTimeout(function(){ hookEggBattle(_rt.role || 'host'); }, 800); }
        }
      } else if (room.status === 'finished' && room.winner) {
        rtStopPoll(); gymStopPoll();
        _rt.status = 'finished';
        const win = room.winner === _rt.role;
        const we = el('_rtWin');
        if (we) { we.style.display = 'block'; we.textContent = win ? '🏆 勝利！！' : '💀 敗北...'; we.style.color = win ? '#4ade80' : '#f87171'; }
        addLog(win ? '勝利！' : '敗北...');
        setMsg('');
      }
    } catch (e) { /* ignore */ }
  }

  function rtStartPoll() { rtStopPoll(); _rt.pollTimer = setInterval(rtPoll, 500); }
  function rtStopPoll()  { if (_rt.pollTimer)    { clearInterval(_rt.pollTimer);    _rt.pollTimer = null; } }
  function gymStopPoll() { if (_rt.gymPollTimer) { clearInterval(_rt.gymPollTimer); _rt.gymPollTimer = null; } }

  // ===== ジムバトル: 城HPポーリング =====
  function gymPollCastle() {
    if (!_rt.roomId || _rt.status !== 'playing') return;
    try {
      const ws = window.warState;
      if (!ws || !ws.active) return;
      const curHp = Number(ws.playerCastleHp || 0);
      const maxHp = Number(ws.playerCastleHpMax || 600);
      if (_rt.lastCastleHp !== null && curHp < _rt.lastCastleHp) {
        const delta = _rt.lastCastleHp - curHp;
        const dmgPct = Math.max(1, Math.round(delta / maxHp * 100));
        window.rtSendSelfDamage(dmgPct, { attackerName: '敵ユニット', attackerEmoji: '⚔️', moveName: '城攻撃' });
      }
      _rt.lastCastleHp = curHp;
    } catch(e) {}
  }

  // ===== Public API =====
  // index.html が先に window.rtCreateRoom/rtJoinRoom を設定しているので保存してラップ
  var _indexRtCreateRoom = typeof window.rtCreateRoom === 'function' ? window.rtCreateRoom : null;
  var _indexRtJoinRoom   = typeof window.rtJoinRoom   === 'function' ? window.rtJoinRoom   : null;

  window.rtCreateRoom = async function (name, party, area, battleType, code) {
    // 引数なし = HTMLボタンから呼ばれた → index.html版に委譲して状態を同期
    if (name === undefined && _indexRtCreateRoom) {
      _indexRtCreateRoom();
      _syncStateFromRoomCode('host');
      return;
    }
    // 引数あり = 明示的な呼び出し（後方互換）
    try {
      panelShow(); setMsg('ルーム作成中...');
      const r = await fetch('/api/rt/create', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name || 'プレイヤー', party: party || [], area: area || 'rounding', battleType: battleType || 'normal', code: code })
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || 'create failed');
      _rt.roomId = d.roomId; _rt.role = 'host'; _rt.status = 'waiting';
      _rt.lastEventId = 0; _rt.myHp = 100; _rt.oppHp = 100;
      fetch('/api/rt/room/' + _rt.roomId).then(function(rr){return rr.json();}).then(function(rd){ if(rd.room&&rd.room.battleType&&!_rt._modeSet){ _rt.mode=rd.room.battleType==='egg'?'egg':rd.room.battleType==='gym'?'gym':'wild'; _rt._modeSet=true; } }).catch(function(){});
      if (el('_rtRoomRow')) el('_rtRoomRow').style.display = 'block';
      if (el('_rtRoomId'))  el('_rtRoomId').textContent = d.roomId;
      if (el('_rtLeaveBtn')) el('_rtLeaveBtn').style.display = 'inline-block';
      setMsg('ルームIDを相手に伝えてSTARTを押してください');
      rtStartPoll();
      return d.roomId;
    } catch (e) { setMsg('エラー: ' + e.message); return null; }
  };

  window.rtJoinRoom = async function (roomId, name, party) {
    // 引数なし = HTMLボタンから呼ばれた → index.html版に委譲して状態を同期
    if (roomId === undefined && _indexRtJoinRoom) {
      _indexRtJoinRoom();
      _syncStateFromRoomCode('guest');
      return;
    }
    try {
      panelShow(); setMsg('参加中...');
      const r = await fetch('/api/rt/join/' + roomId.toUpperCase(), {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name || 'プレイヤー', party: party || [] })
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || 'join failed');
      _rt.roomId = roomId.toUpperCase(); _rt.role = 'guest'; _rt.status = 'waiting';
      _rt.lastEventId = 0; _rt.myHp = 100; _rt.oppHp = 100;
      if (el('_rtLeaveBtn')) el('_rtLeaveBtn').style.display = 'inline-block';
      setMsg('参加OK！バトル開始を待っています...');
      rtStartPoll();
      return true;
    } catch (e) { setMsg('エラー: ' + e.message); return false; }
  };

  window.rtSendDamage = async function (damage, monsterId, meta) {
    if (!_rt.roomId || _rt.status !== 'playing') return;
    try {
      await fetch('/api/rt/damage/' + _rt.roomId, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ damage: Math.round(damage), monsterId: monsterId || 0, eventType: 'damage', meta: meta || null })
      });
    } catch (e) {}
  };

  window.rtSendSelfDamage = async function (damage, meta) {
    if (!_rt.roomId || _rt.status !== 'playing') return;
    try {
      await fetch('/api/rt/damage/' + _rt.roomId, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ damage: Math.round(damage), monsterId: 0, eventType: 'self_damage', meta: meta || null })
      });
    } catch (e) {}
  };

  window.rtSendReady = async function () {
    if (!_rt.roomId) return;
    try { await fetch('/api/rt/ready/' + _rt.roomId, { method: 'POST' }); _rt.status = 'playing'; rtStartPoll(); } catch (e) {}
  };

  window.rtLeave = function () {
    rtStopPoll(); gymStopPoll();
    _rt.roomId = null; _rt.role = null; _rt.status = 'idle';
    _rt.lastEventId = 0; _rt.mode = 'wild'; _rt.lastCastleHp = null;
    panelHide();
  };

  window._rtGetState = function () { return _rt; };

  // ===== index.html と状態同期 =====
  // rtMyRoomCode 要素が更新されたら rt-battle.js の _rt 状態を同期する
  function _syncStateFromRoomCode(role) {
    var codeEl = el('rtMyRoomCode');
    if (!codeEl) return;
    var attempts = 0;
    var timer = setInterval(function() {
      var code = (codeEl.textContent || '').trim().replace(/[\s\u3000\-]/g, '');
      if (code && code.length >= 4 && code !== '------') {
        clearInterval(timer);
        if (!_rt.roomId) {
          _rt.roomId = code;
          _rt.role = role;
          _rt.status = 'waiting';
          _rt.lastEventId = 0; _rt.myHp = 100; _rt.oppHp = 100;
          _rt._modeSet = false;  // 次の poll でサーバーから battleType を取得
          panelShow();
          setMsg('RT対戦: ' + (role === 'host' ? 'ルーム作成済' : '参加済'));
          rtStartPoll();
        }
      }
      if (++attempts > 30) clearInterval(timer);  // 15秒タイムアウト
    }, 500);
  }

  // ===== 友達対戦: calculateDamage フック =====
  function hookCalcDamage() {
    if (typeof window.calculateDamage !== 'function') return false;
    if (window.calculateDamage._rtHooked) return true;
    const orig = window.calculateDamage;
    window.calculateDamage = function () {
      const dmg = orig.apply(this, arguments);
      if (_rt.roomId && _rt.status === 'playing' && _rt.mode === 'wild' && dmg > 0 && !_rt.dmgPending) {
        _rt.dmgPending = true;
        const info = getMyMonsterInfo();
        showAttackNotif(
          (info.emoji || '⚔️') + ' ' + (info.name || '自分') + ' の ' + (info.moveName || 'こうげき') + '！',
          '−' + dmg + ' ダメージ！', '#4ade80'
        );
        addLog('自分: ' + (info.emoji||'') + (info.name||'?') + ' → -' + dmg + 'HP');
        window.rtSendDamage(dmg, 0, { attackerName: info.name, attackerEmoji: info.emoji, moveName: info.moveName });
        setTimeout(() => { _rt.dmgPending = false; }, 1000);
      }
      return dmg;
    };
    window.calculateDamage._rtHooked = true;
    return true;
  }

  // ===== 友達対戦: バトル開始フック =====
  function hookStartBattle() {
    if (typeof window.startBattleSequence !== 'function') return false;
    if (window.startBattleSequence._rtHooked) return true;
    const orig = window.startBattleSequence;
    window.startBattleSequence = async function () {
      if (_rt.roomId && (_rt.status === 'waiting' || _rt.status === 'idle')) {
        var _isEgg = _rt.mode === 'egg';
        if (!_isEgg) _rt.mode = 'wild';
        await window.rtSendReady();
        if (_isEgg) { setTimeout(function(){ if(window.EggBattle&&typeof window.EggBattle.start==='function'){window.EggBattle.start();window.EggBattle.startCountdown&&window.EggBattle.startCountdown();hookEggBattle(_rt.role||'host');} },300); return; }
      } else {
        var _sv=document.querySelector('[name="rtBattleType"]:checked');
        if(_sv&&_sv.value==='egg'){ setTimeout(function(){ if(window.EggBattle&&typeof window.EggBattle.start==='function'){window.EggBattle.start();window.EggBattle.startCountdown&&window.EggBattle.startCountdown();hookEggBattle(_rt.role||'host');} },300); return; }
      }
      return orig.apply(this, arguments);
    };
    window.startBattleSequence._rtHooked = true;
    return true;
  }

  // ===== ジムバトル: startWarMode フック =====
  function hookWarBattle() {
    if (typeof window.startWarMode !== 'function') return false;
    if (window.startWarMode._rtHooked) return true;
    const origStart = window.startWarMode;
    window.startWarMode = async function () {
      if (_rt.roomId && (_rt.status === 'waiting' || _rt.status === 'playing')) {
        _rt.mode = 'gym';
        _rt.lastCastleHp = null;
        if (_rt.status === 'waiting') await window.rtSendReady();
        gymStopPoll();
        _rt.gymPollTimer = setInterval(gymPollCastle, 800);
        addLog('ジムバトル開始！');
      }
      return origStart.apply(this, arguments);
    };
    window.startWarMode._rtHooked = true;
    return true;
  }

  // ===== ジムバトル: stopWarMode フック =====
  function hookStopWar() {
    if (typeof window.stopWarMode !== 'function') return false;
    if (window.stopWarMode._rtHooked) return true;
    const origStop = window.stopWarMode;
    window.stopWarMode = function () {
      gymStopPoll();
      if (_rt.mode === 'gym' && _rt.roomId && _rt.status === 'playing') {
        try {
          const ws = window.warState;
          if (ws && _rt.lastCastleHp !== null) {
            const curHp = Number(ws.playerCastleHp || 0);
            if (curHp < _rt.lastCastleHp) {
              const delta = _rt.lastCastleHp - curHp;
              const dmgPct = Math.max(1, Math.round(delta / Number(ws.playerCastleHpMax || 600) * 100));
              window.rtSendSelfDamage(dmgPct, { attackerName: '敵ユニット', attackerEmoji: '⚔️', moveName: '最終攻撃' });
            }
          }
        } catch(e) {}
        addLog('ジムバトル終了');
      }
      _rt.mode = 'wild';
      return origStop.apply(this, arguments);
    };
    window.stopWarMode._rtHooked = true;
    return true;
  }

  // ===== ゲームUIとの統合 =====
  // 状態同期は window.rtCreateRoom/rtJoinRoom のラップ + _syncStateFromRoomCode で処理
  function hookGameRoomCreate() {
    if (hookGameRoomCreate._hooked) return;
    hookGameRoomCreate._hooked = true;
    // 旧来の observer/ボタンフックは不要（ラップ方式に移行）
  }

  // ===== タマゴバトル VS Mode =====
  function hookEggBattle(role) {
    var eb = window.EggBattle;
    if (!eb || !eb.active || !eb.state) {
      setTimeout(function(){ hookEggBattle(role); }, 300);
      return;
    }
    if (eb._vsHooked) return;
    eb._vsHooked = true;
    var s = eb.state;
    var W = eb.canvas.width;
    var H = eb.canvas.height;
    s._vsMode = true;

    // ゲストは右上スタート
    if (role === 'guest' && s.player) {
      s.player.x = W - 80;
      s.player.y = 80;
      s.player.dirX = -1;
      s.player.dirY = 0;
      if (s.enemyBase) { s.enemyBase.x = 90; s.enemyBase.y = H - 70; }
    }

    // AI無効化
    var origAEL = eb.autoEnemyLay;
    if (origAEL) {
      eb.autoEnemyLay = function(dt) {
        if (this.state && this.state._vsMode) return;
        return origAEL.call(this, dt);
      };
    }

    // placeEgg をフック
    var origPE = eb.placeEgg;
    if (origPE) {
      eb.placeEgg = function() {
        var s2 = eb.state; var bl = s2 && s2.eggs ? s2.eggs.length : -1;
        var r = origPE.call(this);
        if (s2 && s2.eggs && s2.eggs.length > bl) {
          var egg = s2.eggs[s2.eggs.length - 1];
          rtSendEggBattleEvent({type:'eb_egg', x:egg.x, y:egg.y, r:egg.r||5, id:egg.id, hatchSec:egg.hatchSec||5});
        }
        return r;
      };
    }

    // placeWall をフック
    var origPW = eb.placeWall;
    if (origPW) {
      eb.placeWall = function() {
        var s2 = eb.state; var bl = s2 && s2.placedWalls ? s2.placedWalls.length : -1;
        var r = origPW.call(this);
        if (s2 && s2.placedWalls && s2.placedWalls.length > bl) {
          var wall = s2.placedWalls[s2.placedWalls.length - 1];
          rtSendEggBattleEvent({type:'eb_wall', x:wall.x, y:wall.y, w:wall.w, h:wall.h});
        }
        return r;
      };
    }

    // fireMissile をフック
    var origFM = eb.fireMissile;
    if (origFM) {
      eb.fireMissile = function() {
        var s2 = eb.state; var bl = s2 && s2.missiles ? s2.missiles.length : -1;
        var r = origFM.call(this);
        if (s2 && s2.missiles && s2.missiles.length > bl) {
          var m = s2.missiles[s2.missiles.length - 1];
          rtSendEggBattleEvent({type:'eb_missile', x:m.x, y:m.y, vx:m.vx, vy:m.vy, r:m.r||3});
        }
        return r;
      };
    }

    // killMyBase をフック (負けを通知)
    var origKMB = eb.killMyBase;
    if (origKMB) {
      eb.killMyBase = function() {
        rtSendEggBattleEvent({type:'eb_game_over'});
        return origKMB.call(this);
      };
    }
    console.log('[RT] EggBattle VS hooked, role:', role);
  }

  function handleEggBattleEvent(metaJson) {
    var eb = window.EggBattle;
    if (!eb || !eb.state || !eb.canvas) return;
    var s = eb.state; var W = eb.canvas.width; var H = eb.canvas.height;
    var data;
    try { data = typeof metaJson === 'string' ? JSON.parse(metaJson) : (metaJson || {}); } catch(e){ return; }
    var mx = W - (data.x || 0); var my = H - (data.y || 0);
    if (data.type === 'eb_egg') {
      s.enemyEggs = s.enemyEggs || [];
      var hs = data.hatchSec || 5;
      s.enemyEggs.push({x:mx, y:my, r:data.r||5, id:data.id||('re'+Date.now()), hatchAt:Date.now()+hs*1000, hatchSec:hs});
    } else if (data.type === 'eb_wall') {
      s.placedWalls = s.placedWalls || [];
      s.placedWalls.push({x:W-(data.x||0)-(data.w||40), y:H-(data.y||0)-(data.h||20), w:data.w||40, h:data.h||20, hp:2, maxHp:2, team:2, breakable:true});
    } else if (data.type === 'eb_missile') {
      s.enemyShots = s.enemyShots || [];
      s.enemyShots.push({x:mx, y:my, r:data.r||3, vx:-(data.vx||0), vy:-(data.vy||0)});
    } else if (data.type === 'eb_game_over') {
      if (eb.killEnemyBase) eb.killEnemyBase();
    }
  }

  function rtSendEggBattleEvent(data) {
    if (!_rt.roomId) return;
    fetch('/api/rt/damage/' + _rt.roomId, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({damage:0, monsterId:0, eventType:'egg_battle', meta:data})
    }).catch(function(){});
  }

  function applyTeacherDashboardLink() {
    fetch('/api/auth/me', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d || !d.user || d.user.role !== 'teacher') return;

        function inject() {
          if (document.getElementById('_teacherDashboardBtn')) return;
          var candidates = Array.prototype.slice.call(document.querySelectorAll('button, a'));
          var logoutBtn = candidates.find(function (node) {
            return ((node.textContent || '').trim() === 'ログアウト');
          });
          if (!logoutBtn || !logoutBtn.parentElement) return;

          var btn = document.createElement('a');
          btn.id = '_teacherDashboardBtn';
          btn.href = '/teacher';
          btn.textContent = '教師用ダッシュボードへ';
          btn.style.cssText = 'display:inline-block;text-decoration:none;background:#dcfce7;color:#166534;border-radius:8px;padding:6px 12px;font-size:12px;font-weight:700;margin-right:8px;';

          if (logoutBtn.parentElement.firstChild === logoutBtn) {
            logoutBtn.parentElement.insertBefore(btn, logoutBtn);
          } else {
            logoutBtn.parentElement.insertBefore(btn, logoutBtn);
          }
        }

        inject();
        setTimeout(inject, 800);
        setTimeout(inject, 2000);
        setTimeout(inject, 4000);
      })
      .catch(function () {});
  }

  // ===== Init =====
  function init() {
    buildPanel();
    hookCalcDamage();
    hookStartBattle();
    hookWarBattle();
    hookStopWar();
    hookGameRoomCreate();
    applyTeacherDashboardLink();
  }

  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', init); } else { init(); }
  setTimeout(() => { hookCalcDamage(); hookStartBattle(); hookWarBattle(); hookStopWar(); hookGameRoomCreate(); applyTeacherDashboardLink(); }, 1500);
  setTimeout(() => { hookCalcDamage(); hookStartBattle(); hookWarBattle(); hookStopWar(); hookGameRoomCreate(); applyTeacherDashboardLink(); }, 4000);
  console.log('[RT Battle System v3] loaded');
})();