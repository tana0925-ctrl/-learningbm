/* RT Battle System v3 - 友達対戦＋ジムバトル対応 */
(function () {
  'use strict';

  // ===== State =====
  const _rt = {
    roomId: null, role: null, lastEventId: 0, pollTimer: null,
    status: 'idle', hostHp: 100, guestHp: 100,
    myHp: 100, oppHp: 100,
    myName: '', oppName: '', area: '', dmgPending: false,
    mode: 'wild',        // 'wild' | 'gym'
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
      '<div style="font-weight:700;font-size:14px;color:#60a5fa;margin-bottom:8px">\u26a1 RT\u5bfe\u6226</div>' +
      '<div id="_rtMsg" style="color:#94a3b8;font-size:12px;margin-bottom:6px"></div>' +
      '<div id="_rtRoomRow" style="display:none;margin-bottom:8px">' +
        '<span style="color:#94a3b8;font-size:11px">\u30eb\u30fc\u30e0ID: </span>' +
        '<span id="_rtRoomId" style="color:#fbbf24;font-weight:700;font-size:17px;letter-spacing:3px"></span>' +
        '<button onclick="navigator.clipboard&&navigator.clipboard.writeText(document.getElementById(\'_rtRoomId\').textContent)" style="background:#1e40af;color:#fff;border:none;border-radius:5px;padding:2px 7px;font-size:11px;cursor:pointer;margin-left:4px">\u30b3\u30d4\u30fc</button>' +
      '</div>' +
      '<div id="_rtHpBox" style="display:none">' +
        '<div id="_rtModeLabel" style="font-size:10px;color:#94a3b8;margin-bottom:4px;text-align:center"></div>' +
        '<div style="margin-bottom:7px">' +
          '<div style="display:flex;justify-content:space-between;margin-bottom:2px">' +
            '<span id="_rtMyLbl" style="font-size:11px;color:#4ade80;font-weight:600">\u81ea\u5206</span>' +
            '<span id="_rtMyVal" style="font-size:11px;color:#4ade80">100/100</span>' +
          '</div>' +
          '<div style="background:#1e293b;border-radius:6px;height:10px;overflow:hidden;position:relative">' +
            '<div id="_rtMyBar" style="height:10px;border-radius:6px;width:100%;transition:width .4s ease;background:linear-gradient(90deg,#4ade80,#22c55e)"></div>' +
            '<div id="_rtMyFlash" style="position:absolute;inset:0;background:#fff;opacity:0;pointer-events:none;transition:opacity .08s"></div>' +
          '</div>' +
        '</div>' +
        '<div style="margin-bottom:10px;position:relative">' +
          '<div style="display:flex;justify-content:space-between;margin-bottom:2px">' +
            '<span id="_rtOppLbl" style="font-size:11px;color:#f87171;font-weight:600">\u76f8\u624b</span>' +
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
      '<button onclick="window.rtLeave()" id="_rtLeaveBtn" style="display:none;margin-top:8px;background:#7f1d1d;color:#fff;border:none;border-radius:7px;padding:4px 12px;font-size:11px;cursor:pointer">\u9000\u51fa</button>';
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

      const newMyHp  = _rt.role === 'host' ? room.hostHp  : room.guestHp;
      const newOppHp = _rt.role === 'host' ? room.guestHp : room.hostHp;
      const myHpDiff  = _rt.myHp  - newMyHp;
      const oppHpDiff = _rt.oppHp - newOppHp;

      const myN  = _rt.role === 'host' ? room.hostName  : room.guestName;
      const oppN = _rt.role === 'host' ? room.guestName : room.hostName;
      if (el('_rtMyLbl'))  el('_rtMyLbl').textContent  = '\u81ea\u5206: ' + myN;
      if (el('_rtOppLbl')) el('_rtOppLbl').textContent = '\u76f8\u624b: ' + (oppN || '\u5f85\u6a5f\u4e2d...');

      for (const ev of (d.events || [])) {
        if (ev.id > _rt.lastEventId) _rt.lastEventId = ev.id;
      }

      if (_rt.mode === 'gym') {
        // ジムバトルモード: 城HPの追跡
        if (myHpDiff > 0) {
          flashMyBar();
          showAttackNotif('\u2694\ufe0f \u81ea\u5206\u306e\u57ce\u304c\u653b\u6483\u3055\u308c\u305f\uff01', '\u2212' + myHpDiff + ' \u30c0\u30e1\u30fc\u30b8\uff01', '#f87171');
          addLog('\u81ea\u5206\u306e\u57ce: -' + myHpDiff + 'HP');
        }
        if (oppHpDiff > 0) {
          flashOppBar();
          showAttackNotif('\u2694\ufe0f \u76f8\u624b\u306e\u57ce\u3082\u653b\u6483\u3055\u308c\u305f\uff01', '\u2212' + oppHpDiff + ' \u30c0\u30e1\u30fc\u30b8\uff01', '#fbbf24');
          addLog('\u76f8\u624b\u306e\u57ce: -' + oppHpDiff + 'HP');
        }
      } else {
        // 野生/友達対戦モード: モンスターHP追跡
        if (myHpDiff > 0) {
          flashOppBar();
          const dmgEvs = (d.events || []).filter(e => e.event_type === 'damage');
          const latest = dmgEvs[dmgEvs.length - 1];
          const meta = parseMeta(latest?.meta_json);
          const name  = meta.attackerName  || '\u76f8\u624b';
          const emoji = meta.attackerEmoji || '\u2694\ufe0f';
          const move  = meta.moveName      || '\u3053\u3046\u3052\u304d';
          showAttackNotif(emoji + ' ' + name + ' \u306e ' + move + '\uff01', '\u2212' + myHpDiff + ' \u30c0\u30e1\u30fc\u30b8\uff01', '#f87171');
          addLog('\u76f8\u624b: ' + (emoji||'') + name + ' \u2192 -' + myHpDiff + 'HP');
        }
        for (const ev of (d.events || [])) {
          if (ev.event_type === 'faint') {
            const meta = parseMeta(ev.meta_json);
            addLog((meta.attackerName || '\u30e2\u30f3\u30b9\u30bf\u30fc') + ' \u304c\u5012\u308c\u305f\uff01');
          }
        }
      }

      _rt.myHp  = newMyHp;
      _rt.oppHp = newOppHp;
      _rt.hostHp  = room.hostHp;
      _rt.guestHp = room.guestHp;
      updateHpBars();

      if (room.status === 'waiting') {
        setMsg('\u76f8\u624b\u306e\u53c2\u52a0\u3092\u5f85\u3063\u3066\u3044\u307e\u3059...');
      } else if (room.status === 'playing') {
        if (_rt.status !== 'playing') {
          _rt.status = 'playing';
          const modeStr = _rt.mode === 'gym' ? '\u30b8\u30e0\u30d0\u30c8\u30eb' : '\u53cb\u9054\u5bfe\u6226';
          setMsg('\u2694\ufe0f \u30d0\u30c8\u30eb\u4e2d\uff01 [' + modeStr + ']');
          setModeLabel(_rt.mode === 'gym' ? '\u30b8\u30e0\u30d0\u30c8\u30eb\u30e2\u30fc\u30c9 \ud83c\udff0' : '\u53cb\u9054\u5bfe\u6226\u30e2\u30fc\u30c9 \ud83e\udd0e');
          if (el('_rtHpBox')) el('_rtHpBox').style.display = 'block';
          addLog('\u30d0\u30c8\u30eb\u30b9\u30bf\u30fc\u30c8\uff01 [' + modeStr + ']');
        }
      } else if (room.status === 'finished' && room.winner) {
        rtStopPoll(); gymStopPoll();
        _rt.status = 'finished';
        const win = room.winner === _rt.role;
        const we = el('_rtWin');
        if (we) { we.style.display = 'block'; we.textContent = win ? '\ud83c\udfc6 \u52dd\u5229\uff01\uff01' : '\ud83d\udc80 \u6557\u5317...'; we.style.color = win ? '#4ade80' : '#f87171'; }
        addLog(win ? '\u52dd\u5229\uff01' : '\u6557\u5317...');
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
        window.rtSendSelfDamage(dmgPct, { attackerName: '\u6575\u30e6\u30cb\u30c3\u30c8', attackerEmoji: '\u2694\ufe0f', moveName: '\u57ce\u653b\u6483' });
      }
      _rt.lastCastleHp = curHp;
    } catch(e) {}
  }

  // ===== Public API =====
  window.rtCreateRoom = async function (name, party, area, battleType) {
    try {
      panelShow(); setMsg('\u30eb\u30fc\u30e0\u4f5c\u6210\u4e2d...');
      const r = await fetch('/api/rt/create', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name || '\u30d7\u30ec\u30a4\u30e4\u30fc', party: party || [], area: area || 'rounding', battleType: battleType || 'normal' })
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || 'create failed');
      _rt.roomId = d.roomId; _rt.role = 'host'; _rt.status = 'waiting';
      _rt.lastEventId = 0; _rt.myHp = 100; _rt.oppHp = 100;
      if (el('_rtRoomRow')) el('_rtRoomRow').style.display = 'block';
      if (el('_rtRoomId'))  el('_rtRoomId').textContent = d.roomId;
      if (el('_rtLeaveBtn')) el('_rtLeaveBtn').style.display = 'inline-block';
      setMsg('\u30eb\u30fc\u30e0ID\u3092\u76f8\u624b\u306b\u4f1d\u3048\u3066START\u3092\u62bc\u3057\u3066\u304f\u3060\u3055\u3044');
      rtStartPoll();
      return d.roomId;
    } catch (e) { setMsg('\u30a8\u30e9\u30fc: ' + e.message); return null; }
  };

  window.rtJoinRoom = async function (roomId, name, party) {
    try {
      panelShow(); setMsg('\u53c2\u52a0\u4e2d...');
      const r = await fetch('/api/rt/join/' + roomId.toUpperCase(), {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name || '\u30d7\u30ec\u30a4\u30e4\u30fc', party: party || [] })
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || 'join failed');
      _rt.roomId = roomId.toUpperCase(); _rt.role = 'guest'; _rt.status = 'waiting';
      _rt.lastEventId = 0; _rt.myHp = 100; _rt.oppHp = 100;
      if (el('_rtLeaveBtn')) el('_rtLeaveBtn').style.display = 'inline-block';
      setMsg('\u53c2\u52a0OK\uff01\u30d0\u30c8\u30eb\u958b\u59cb\u3092\u5f85\u3063\u3066\u3044\u307e\u3059...');
      rtStartPoll();
      return true;
    } catch (e) { setMsg('\u30a8\u30e9\u30fc: ' + e.message); return false; }
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
          (info.emoji || '\u2694\ufe0f') + ' ' + (info.name || '\u81ea\u5206') + ' \u306e ' + (info.moveName || '\u3053\u3046\u3052\u304d') + '\uff01',
          '\u2212' + dmg + ' \u30c0\u30e1\u30fc\u30b8\uff01', '#4ade80'
        );
        addLog('\u81ea\u5206: ' + (info.emoji||'') + (info.name||'?') + ' \u2192 -' + dmg + 'HP');
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
        _rt.mode = 'wild';
        await window.rtSendReady();
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
        addLog('\u30b8\u30e0\u30d0\u30c8\u30eb\u958b\u59cb\uff01');
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
              window.rtSendSelfDamage(dmgPct, { attackerName: '\u6575\u30e6\u30cb\u30c3\u30c8', attackerEmoji: '\u2694\ufe0f', moveName: '\u6700\u7d42\u653b\u6483' });
            }
          }
        } catch(e) {}
        addLog('\u30b8\u30e0\u30d0\u30c8\u30eb\u7d42\u4e86');
      }
      _rt.mode = 'wild';
      return origStop.apply(this, arguments);
    };
    window.stopWarMode._rtHooked = true;
    return true;
  }

  // ===== RTコントロール注入 (リアルタイムタブ内 #rtLobby末尾) =====
  function injectRtControls() {
    if (el('_rtControls')) return;
    // ゲームの既存リアルタイムタブ内 #rtLobby の末尾に注入
    const anchor = el('rtLobby') || el('friendAreaRT') || el('friendTabRT');
    if (!anchor) return;
    const div = document.createElement('div');
    div.id = '_rtControls';
    div.innerHTML =
      '<div style="margin-top:14px;padding:12px;background:#f0f9ff;border:2px solid #0ea5e9;border-radius:12px">' +
        '<div style="font-weight:700;font-size:13px;color:#0369a1;margin-bottom:10px">\u26a1 \u30ea\u30a2\u30eb\u30bf\u30a4\u30e0\u5bfe\u6226 (RT)</div>' +
        '<div style="font-size:11px;color:#64748b;margin-bottom:8px">\u53cb\u9054\u5bfe\u6226\u30fb\u30b8\u30e0\u30d0\u30c8\u30eb\u5171\u901a</div>' +
        '<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">' +
          '<button id="_rtHostBtn" onclick="window._rtHostClick()" style="background:#3b82f6;color:#fff;border:none;border-radius:9px;padding:9px 18px;font-size:13px;font-weight:700;cursor:pointer">\ud83c\udfe0 \u30db\u30b9\u30c8\u4f5c\u6210</button>' +
          '<div style="display:flex;gap:6px;align-items:center">' +
            '<input id="_rtJoinId" placeholder="\u30eb\u30fc\u30e0ID (4\u6587\u5b57)" maxlength="4" style="border:2px solid #0ea5e9;border-radius:8px;padding:7px 10px;font-size:14px;font-weight:700;width:130px;text-transform:uppercase"/>' +
            '<button onclick="window._rtGuestClick()" style="background:#10b981;color:#fff;border:none;border-radius:9px;padding:9px 14px;font-size:13px;font-weight:700;cursor:pointer">\u53c2\u52a0</button>' +
          '</div>' +
        '</div>' +
        '<div id="_rtControlMsg" style="margin-top:8px;font-size:12px;color:#64748b"></div>' +
      '</div>';
    anchor.appendChild(div);
  }

  window._rtHostClick = async function () {
    const name = (document.querySelector('#playerNameDisplay,#userName,[id*="playerName"],[id*="userName"]')?.textContent || '\u30db\u30b9\u30c8').trim();
    const area = el('friendWildAreaSelect')?.value || 'rounding';
    const bt   = document.querySelector('[name="friendBattleType"]:checked')?.value || 'normal';
    if (el('_rtControlMsg')) el('_rtControlMsg').textContent = '\u30eb\u30fc\u30e0\u4f5c\u6210\u4e2d...';
    const id = await window.rtCreateRoom(name, [], area, bt);
    if (el('_rtControlMsg')) el('_rtControlMsg').textContent = id ? ('\u30eb\u30fc\u30e0ID: ' + id + ' \u3092\u76f8\u624b\u306b\u4f1d\u3048\u3066START\u3092\u62bc\u3057\u3066\u304f\u3060\u3055\u3044') : '\u4f5c\u6210\u306b\u5931\u6557\u3057\u307e\u3057\u305f';
  };

  window._rtGuestClick = async function () {
    const rid = (el('_rtJoinId')?.value || '').toUpperCase().trim();
    if (rid.length < 3) { alert('\u30eb\u30fc\u30e0ID\u3092\u5165\u529b\u3057\u3066\u304f\u3060\u3055\u3044'); return; }
    const name = (document.querySelector('#playerNameDisplay,#userName,[id*="playerName"],[id*="userName"]')?.textContent || '\u30b2\u30b9\u30c8').trim();
    if (el('_rtControlMsg')) el('_rtControlMsg').textContent = '\u53c2\u52a0\u4e2d...';
    const ok = await window.rtJoinRoom(rid, name, []);
    if (el('_rtControlMsg')) el('_rtControlMsg').textContent = ok ? '\u30d0\u30c8\u30eb\u958b\u59cb\u3092\u5f85\u3063\u3066\u3044\u307e\u3059\uff01' : '\u53c2\u52a0\u306b\u5931\u6557\u3057\u307e\u3057\u305f';
  };

  // ===== Init =====
  function init() {
    buildPanel();
    hookCalcDamage();
    hookStartBattle();
    hookWarBattle();
    hookStopWar();
    injectRtControls();
  }

  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', init); } else { init(); }
  setTimeout(() => { hookCalcDamage(); hookStartBattle(); hookWarBattle(); hookStopWar(); injectRtControls(); }, 1500);
  setTimeout(() => { hookCalcDamage(); hookStartBattle(); hookWarBattle(); hookStopWar(); injectRtControls(); }, 4000);
  console.log('[RT Battle System v3] loaded');
})();
