/* RT Battle System - リアルタイム対戦モジュール */
(function () {
  'use strict';

  // ===== 状態管理 =====
  const _rt = {
    roomId: null,
    role: null,       // 'host' | 'guest'
    lastEventId: 0,
    pollTimer: null,
    status: 'idle',   // idle | waiting | playing | finished
    hostHp: 100,
    guestHp: 100,
    myName: '',
    oppName: '',
    dmgPending: false // 正解ダメージ送信フラグ
  };

  // ===== UI パネル =====
  function buildPanel() {
    if (document.getElementById('_rtPanel')) return;
    const div = document.createElement('div');
    div.id = '_rtPanel';
    div.style.cssText = [
      'position:fixed','top:8px','right:8px','z-index:99999',
      'background:#0f172a','border:2px solid #3b82f6',
      'border-radius:14px','padding:14px 16px',
      'min-width:220px','color:#f1f5f9',
      'font-family:system-ui,sans-serif','font-size:13px',
      'box-shadow:0 4px 24px rgba(0,0,0,.5)','display:none'
    ].join(';');
    div.innerHTML = [
      '<div style="font-weight:700;font-size:14px;color:#60a5fa;margin-bottom:8px">⚡ RT対戦</div>',
      '<div id="_rtMsg" style="color:#94a3b8;font-size:12px;margin-bottom:6px"></div>',
      '<div id="_rtRoomRow" style="display:none;margin-bottom:8px">',
        '<span style="color:#94a3b8;font-size:11px">ルームID: </span>',
        '<span id="_rtRoomId" style="color:#fbbf24;font-weight:700;font-size:17px;letter-spacing:3px"></span>',
        ' <button onclick="navigator.clipboard&&navigator.clipboard.writeText(document.getElementById(\'_rtRoomId\').textContent)" style="background:#1e40af;color:#fff;border:none;border-radius:5px;padding:2px 7px;font-size:11px;cursor:pointer">コピー</button>',
      '</div>',
      '<div id="_rtHpBox" style="display:none">',
        '<div style="margin-bottom:6px">',
          '<div style="font-size:11px;color:#4ade80" id="_rtMyLbl">自分</div>',
          '<div style="background:#1e293b;border-radius:6px;height:12px;margin:3px 0">',
            '<div id="_rtMyBar" style="background:#4ade80;height:12px;border-radius:6px;width:100%;transition:width .4s"></div>',
          '</div>',
          '<span id="_rtMyVal" style="font-size:11px;color:#4ade80">100/100</span>',
        '</div>',
        '<div>',
          '<div style="font-size:11px;color:#f87171" id="_rtOppLbl">相手</div>',
          '<div style="background:#1e293b;border-radius:6px;height:12px;margin:3px 0">',
            '<div id="_rtOppBar" style="background:#f87171;height:12px;border-radius:6px;width:100%;transition:width .4s"></div>',
          '</div>',
          '<span id="_rtOppVal" style="font-size:11px;color:#f87171">100/100</span>',
        '</div>',
      '</div>',
      '<div id="_rtWin" style="display:none;font-size:20px;text-align:center;font-weight:700;padding:6px 0"></div>',
      '<button onclick="window.rtLeave()" style="margin-top:8px;background:#7f1d1d;color:#fff;border:none;border-radius:7px;padding:4px 12px;font-size:11px;cursor:pointer;display:none" id="_rtLeaveBtn">退出</button>'
    ].join('');
    document.body.appendChild(div);
  }

  function panelShow() { buildPanel(); document.getElementById('_rtPanel').style.display = 'block'; }
  function panelHide() { const p = document.getElementById('_rtPanel'); if (p) p.style.display = 'none'; }
  function setMsg(m) { const e = document.getElementById('_rtMsg'); if (e) e.textContent = m; }

  function updateHp() {
    const myHp  = _rt.role === 'host' ? _rt.hostHp : _rt.guestHp;
    const oppHp = _rt.role === 'host' ? _rt.guestHp : _rt.hostHp;
    const pct   = v => Math.max(0, Math.min(100, v));
    const el = id => document.getElementById(id);
    if (el('_rtMyBar'))  el('_rtMyBar').style.width  = pct(myHp)  + '%';
    if (el('_rtOppBar')) el('_rtOppBar').style.width = pct(oppHp) + '%';
    if (el('_rtMyVal'))  el('_rtMyVal').textContent  = myHp  + '/100';
    if (el('_rtOppVal')) el('_rtOppVal').textContent = oppHp + '/100';
  }

  // ===== ポーリング =====
  async function rtPoll() {
    if (!_rt.roomId) return;
    try {
      const r = await fetch('/api/rt/room/' + _rt.roomId + '?after=' + _rt.lastEventId);
      if (!r.ok) return;
      const d = await r.json();
      if (!d.ok) return;
      const room = d.room;
      _rt.role    = room.myRole;
      _rt.hostHp  = room.hostHp;
      _rt.guestHp = room.guestHp;
      const myN   = _rt.role === 'host' ? room.hostName : room.guestName;
      const oppN  = _rt.role === 'host' ? room.guestName : room.hostName;
      const el = id => document.getElementById(id);
      if (el('_rtMyLbl'))  el('_rtMyLbl').textContent  = '自分: ' + myN;
      if (el('_rtOppLbl')) el('_rtOppLbl').textContent = '相手: ' + (oppN || '待機中...');
      updateHp();
      for (const ev of (d.events || [])) {
        if (ev.id > _rt.lastEventId) _rt.lastEventId = ev.id;
      }
      if (room.status === 'waiting') {
        setMsg('相手の参加を待っています...');
      } else if (room.status === 'playing') {
        if (_rt.status !== 'playing') {
          _rt.status = 'playing';
          setMsg('⚔ バトル中！');
          const hb = el('_rtHpBox');
          if (hb) hb.style.display = 'block';
        }
      } else if (room.status === 'finished' && room.winner) {
        rtStopPoll();
        _rt.status = 'finished';
        const win = room.winner === _rt.role;
        const we = el('_rtWin');
        if (we) { we.style.display = 'block'; we.textContent = win ? '🎉 勝利！' : '😢 敗北'; we.style.color = win ? '#4ade80' : '#f87171'; }
        setMsg('');
      }
    } catch (e) { /* ignore */ }
  }

  function rtStartPoll() { rtStopPoll(); _rt.pollTimer = setInterval(rtPoll, 500); }
  function rtStopPoll()  { if (_rt.pollTimer) { clearInterval(_rt.pollTimer); _rt.pollTimer = null; } }

  // ===== 公開 API =====
  window.rtCreateRoom = async function (name, party, area, battleType) {
    try {
      panelShow(); setMsg('ルーム作成中...');
      const r = await fetch('/api/rt/create', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name || 'プレイヤー', party: party || [], area: area || 'rounding', battleType: battleType || 'normal' })
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || 'create failed');
      _rt.roomId = d.roomId; _rt.role = 'host'; _rt.status = 'waiting'; _rt.lastEventId = 0;
      const rr = document.getElementById('_rtRoomRow'), ri = document.getElementById('_rtRoomId'), lb = document.getElementById('_rtLeaveBtn');
      if (rr) rr.style.display = 'block';
      if (ri) ri.textContent = d.roomId;
      if (lb) lb.style.display = 'inline-block';
      setMsg('ルームIDを相手に教えてください');
      rtStartPoll(); return d.roomId;
    } catch (e) { setMsg('エラー: ' + e.message); return null; }
  };

  window.rtJoinRoom = async function (roomId, name, party) {
    try {
      panelShow(); setMsg('参加中...');
      const r = await fetch('/api/rt/join/' + roomId.toUpperCase(), {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name || 'プレイヤー', party: party || [] })
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || 'join failed');
      _rt.roomId = roomId.toUpperCase(); _rt.role = 'guest'; _rt.status = 'waiting'; _rt.lastEventId = 0;
      const lb = document.getElementById('_rtLeaveBtn');
      if (lb) lb.style.display = 'inline-block';
      setMsg('参加OK！バトル開始を待っています...');
      rtStartPoll(); return true;
    } catch (e) { setMsg('エラー: ' + e.message); return false; }
  };

  window.rtSendDamage = async function (damage, monsterId) {
    if (!_rt.roomId || _rt.status !== 'playing') return;
    try {
      await fetch('/api/rt/damage/' + _rt.roomId, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ damage: Math.round(damage), monsterId: monsterId || 0, eventType: 'damage' })
      });
    } catch (e) { /* ignore */ }
  };

  window.rtSendReady = async function () {
    if (!_rt.roomId) return;
    try { await fetch('/api/rt/ready/' + _rt.roomId, { method: 'POST' }); _rt.status = 'playing'; rtStartPoll(); } catch (e) { /* ignore */ }
  };

  window.rtLeave = function () {
    rtStopPoll(); _rt.roomId = null; _rt.role = null; _rt.status = 'idle'; _rt.lastEventId = 0; panelHide();
  };

  window._rtGetState = function () { return _rt; };

  // ===== calculateDamage フック =====
  function hookCalcDamage() {
    if (typeof window.calculateDamage !== 'function') return false;
    if (window.calculateDamage._rtHooked) return true;
    const orig = window.calculateDamage;
    window.calculateDamage = function () {
      const dmg = orig.apply(this, arguments);
      if (_rt.roomId && _rt.status === 'playing' && dmg > 0 && !_rt.dmgPending) {
        _rt.dmgPending = true;
        window.rtSendDamage(dmg, 0).finally
          ? window.rtSendDamage(dmg, 0).finally(() => { _rt.dmgPending = false; })
          : window.rtSendDamage(dmg, 0);
        setTimeout(() => { _rt.dmgPending = false; }, 1000);
      }
      return dmg;
    };
    window.calculateDamage._rtHooked = true;
    console.log('[RT] calculateDamage hooked');
    return true;
  }

  // ===== startBattleSequence フック =====
  function hookStartBattle() {
    if (typeof window.startBattleSequence !== 'function') return false;
    if (window.startBattleSequence._rtHooked) return true;
    const orig = window.startBattleSequence;
    window.startBattleSequence = async function () {
      if (_rt.roomId && (_rt.status === 'waiting' || _rt.status === 'idle')) {
        await window.rtSendReady();
      }
      return orig.apply(this, arguments);
    };
    window.startBattleSequence._rtHooked = true;
    console.log('[RT] startBattleSequence hooked');
    return true;
  }

  // ===== フレンドバトル UI にRT対戦コントロール追加 =====
  function injectRtControls() {
    if (document.getElementById('_rtControls')) return;
    const radio = document.querySelector('[name="friendBattleType"]');
    if (!radio) return;
    const anchor = radio.closest('div');
    if (!anchor) return;
    const wrap = anchor.closest('div[class]') || anchor.parentElement;
    if (!wrap) return;
    const div = document.createElement('div');
    div.id = '_rtControls';
    div.innerHTML = [
      '<div style="margin-top:14px;padding:12px;background:#f0f9ff;border:2px solid #0ea5e9;border-radius:12px">',
        '<div style="font-weight:700;font-size:13px;color:#0369a1;margin-bottom:10px">⚡ リアルタイム対戦 (RT)</div>',
        '<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">',
          '<button id="_rtHostBtn" onclick="window._rtHostClick()" style="background:#3b82f6;color:#fff;border:none;border-radius:9px;padding:9px 18px;font-size:13px;font-weight:700;cursor:pointer">🏠 ホスト作成</button>',
          '<div style="display:flex;gap:6px;align-items:center">',
            '<input id="_rtJoinId" placeholder="ルームID (4文字)" maxlength="4" style="border:2px solid #0ea5e9;border-radius:8px;padding:7px 10px;font-size:14px;font-weight:700;width:120px;text-transform:uppercase"/>',
            '<button onclick="window._rtGuestClick()" style="background:#10b981;color:#fff;border:none;border-radius:9px;padding:9px 14px;font-size:13px;font-weight:700;cursor:pointer">参加</button>',
          '</div>',
        '</div>',
        '<div id="_rtControlMsg" style="margin-top:8px;font-size:12px;color:#64748b"></div>',
      '</div>'
    ].join('');
    wrap.parentElement ? wrap.parentElement.insertBefore(div, wrap.nextSibling) : wrap.appendChild(div);
    console.log('[RT] controls injected');
  }

  window._rtHostClick = async function () {
    const name = (document.querySelector('#playerNameDisplay,#userName,[id*="playerName"],[id*="userName"]')?.textContent || 'ホスト').trim();
    const area = document.getElementById('friendWildAreaSelect')?.value || 'rounding';
    const bt   = document.querySelector('[name="friendBattleType"]:checked')?.value || 'normal';
    document.getElementById('_rtControlMsg').textContent = 'ルーム作成中...';
    const id = await window.rtCreateRoom(name, [], area, bt);
    const msg = document.getElementById('_rtControlMsg');
    if (msg) msg.textContent = id ? ('ルームID: ' + id + ' を相手に伝えてSTARTを押してください') : '作成に失敗しました';
  };

  window._rtGuestClick = async function () {
    const rid = (document.getElementById('_rtJoinId')?.value || '').toUpperCase().trim();
    if (rid.length < 3) { alert('ルームIDを入力してください'); return; }
    const name = (document.querySelector('#playerNameDisplay,#userName,[id*="playerName"],[id*="userName"]')?.textContent || 'ゲスト').trim();
    document.getElementById('_rtControlMsg').textContent = '参加中...';
    const ok = await window.rtJoinRoom(rid, name, []);
    const msg = document.getElementById('_rtControlMsg');
    if (msg) msg.textContent = ok ? 'バトル開始を待っています！' : '参加に失敗しました';
  };

  // ===== 初期化 =====
  function init() {
    buildPanel();
    hookCalcDamage();
    hookStartBattle();
    injectRtControls();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
  // 遅延再試行（動的ロード対応）
  setTimeout(function () { hookCalcDamage(); hookStartBattle(); injectRtControls(); }, 1500);
  setTimeout(function () { hookCalcDamage(); hookStartBattle(); injectRtControls(); }, 4000);

  console.log('[RT Battle System] loaded');
})();
