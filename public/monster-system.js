/**
 * monster-system.js (v2 - 軽量版)
 * 図鑑・手持ち・ボックス・捕獲・ショップ・交換システム
 *
 * 修正点:
 *  - MutationObserver を廃止（全DOM変化監視で重大なフリーズを引き起こしていた）
 *  - setInterval を 2000ms に変更（800ms→2000ms）
 *  - apiSave をデバウンス化（3秒後にまとめて送信）
 */
(function () {
  'use strict';

  // ============================================================
  // 状態管理
  // ============================================================
  let MS = null;

  const DEFAULTS = {
    coins: 100,
    monsterBalls: 5,
    pokedex: [],   // 一度でも捕まえたモンスターID一覧
    party: [],     // [{id, level, name, emoji}] 最大3体
    box: [],       // [{id, level, name, emoji}] 上限なし
  };

  async function apiLoad() {
    try {
      const res = await fetch('/api/student/progress');
      if (!res.ok) return null;
      const data = await res.json();
      if (!data.ok || !data.progress) return null;
      const obj = JSON.parse(data.progress.stateJson);
      return obj.state || obj;
    } catch (e) { return null; }
  }

  // デバウンス付きAPIセーブ（3秒間隔にまとめて送信）
  let _saveTimer = null;
  let _saving = false;
  async function apiSave(s) {
    clearTimeout(_saveTimer);
    _saveTimer = setTimeout(async () => {
      if (_saving) return;
      _saving = true;
      try {
        await fetch('/api/student/progress', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ state: s }),
        });
      } catch (e) {}
      _saving = false;
    }, 3000);
  }

  async function init() {
    const s = await apiLoad();
    if (!s) {
      // ゲストモード: localStorageにフォールバック
      const saved = localStorage.getItem('ms_ext');
      MS = saved ? JSON.parse(saved) : { ...DEFAULTS };
    } else {
      // 既存 monsters を party/box に移行（初回のみ）
      if (!('monsterBalls' in s)) {
        Object.assign(s, DEFAULTS);
        const existingMonsters = s.monsters || {};
        const list = Object.entries(existingMonsters)
          .map(([id, m]) => ({ id, level: m.level || 1, name: id, emoji: '👾' }));
        s.party = list.slice(0, 3);
        s.box   = list.slice(3);
        s.pokedex = list.map(m => m.id);
        await apiSave(s);
      }
      MS = s;
    }
    buildUI();
    startBattleWatcher();
    interceptNetwork();
  }

  function saveMS() {
    if (!MS) return;
    apiSave(MS);
    try { localStorage.setItem('ms_ext', JSON.stringify(MS)); } catch(e) {}
  }

  // ============================================================
  // バトル監視（MutationObserver廃止・setIntervalのみ）
  // ============================================================
  let inBattle = false;
  let captureShown = false;
  let enemyHpPct = 100;

  function startBattleWatcher() {
    // ▼ MutationObserver は 5MB のゲームでは重大なフリーズを引き起こすため廃止
    // ▼ 2秒ごとのポーリングのみに変更
    setInterval(checkBattle, 2000);
  }

  function checkBattle() {
    // 野生バトル判定: HPバーイ敵表示要素を探す
    const hpEls = document.querySelectorAll(
      '[class*="hp-bar"], [class*="hpBar"], [class*="enemy-hp"], ' +
      '[class*="oppHp"], [id*="enemy-hp"], [id*="opp-hp"]'
    );

    const battleEl =
      document.querySelector('[class*="wild-battle"], [class*="wildBattle"]') ||
      document.querySelector('[data-scene="battle"], [data-mode="wild"]') ||
      (hpEls.length > 0 ? hpEls[0] : null);

    const nowInBattle = !!battleEl;

    if (nowInBattle !== inBattle) {
      inBattle = nowInBattle;
      if (inBattle) {
        enemyHpPct = 100;
        captureShown = false;
        onBattleStart();
      } else {
        onBattleEnd();
      }
    }

    if (inBattle) {
      updateEnemyHp(hpEls);
      if (!captureShown) {
        const btn = document.getElementById('ms-capture-btn');
        if (btn) { btn.style.display = 'block'; captureShown = true; }
      }
      refreshCaptureBtn();
    }
  }

  function updateEnemyHp(hpEls) {
    for (const el of hpEls) {
      const style = el.getAttribute('style') || '';
      const m = style.match(/width\s*:\s*(\d+(?:\.\d+)?)\s*%/);
      if (m) { enemyHpPct = parseFloat(m[1]); return; }
    }
    const bar = document.querySelector('[role="progressbar"][aria-valuenow]');
    if (bar) {
      const v   = parseFloat(bar.getAttribute('aria-valuenow'));
      const max = parseFloat(bar.getAttribute('aria-valuemax') || '100');
      if (!isNaN(v)) enemyHpPct = (v / max) * 100;
    }
  }

  function captureRate() {
    return Math.min(0.95, 0.15 + (1 - enemyHpPct / 100) * 0.80);
  }

  function onBattleStart() {
    const btn = document.getElementById('ms-capture-btn');
    if (btn) btn.style.display = 'block';
  }

  function onBattleEnd() {
    const btn = document.getElementById('ms-capture-btn');
    if (btn) btn.style.display = 'none';
    captureShown = false;
  }

  function refreshCaptureBtn() {
    const btn = document.getElementById('ms-capture-btn');
    if (!btn || !MS) return;
    const balls = MS.monsterBalls || 0;
    const rate  = Math.round(captureRate() * 100);
    btn.disabled = balls <= 0;
    btn.textContent = balls > 0
      ? `⚾ ボールを投げる！（成功率 ${rate}% / 残り ${balls}個）`
      : '⚾ モンスターボールがありません';
  }

  // 捕獲実行
  window.msThrowBall = function () {
    if (!MS || !inBattle) return;
    if ((MS.monsterBalls || 0) <= 0) {
      toast('モンスターボールがありません！', 'error'); return;
    }
    MS.monsterBalls--;

    const roll  = Math.random();
    const rate  = captureRate();
    const enemy = detectEnemy();

    if (roll < rate) {
      if (!MS.pokedex.includes(enemy.id)) MS.pokedex.push(enemy.id);
      const mon = { id: enemy.id, level: 1, name: enemy.name, emoji: enemy.emoji };
      if (MS.party.length < 3) {
        MS.party.push(mon);
        toast(`${enemy.emoji} ${enemy.name} を手持ちに加えた！`, 'success');
      } else {
        MS.box.push(mon);
        toast(`${enemy.emoji} ${enemy.name} をボックスに送った！`, 'success');
      }
    } else {
      toast(`${enemy.emoji} ${enemy.name} は逃げてしまった…`, 'fail');
      if (enemyHpPct > 50) toast('もっよ弱らせると捕まえやすくなるよ！', 'hint');
    }

    saveMS();
    refreshCaptureBtn();
    updateHUD();
  };

  function detectEnemy() {
    const selectors = [
      '[class*="enemy-name"]', '[class*="enemyName"]',
      '[class*="wild-name"]',  '[id*="enemy-name"]',
      '[class*="opp-name"]',   '[class*="oppName"]',
    ];
    let name = '???', emoji = '👾';
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el && el.textContent.trim()) { name = el.textContent.trim(); break; }
    }
    const emojiSels = ['[class*="enemy-emoji"]', '[class*="enemyEmoji"]'];
    for (const sel of emojiSels) {
      const el = document.querySelector(sel);
      if (el && el.textContent.trim()) { emoji = el.textContent.trim().slice(0, 2); break; }
    }
    return { id: name.replace(/\s+/g, '_').toLowerCase(), name, emoji };
  }

  // ============================================================
  // ネットワーク傍受（コイン獲得）
  // ============================================================
  function interceptNetwork() {
    const origFetch = window.fetch.bind(window);
    window.fetch = async function (url, opts) {
      opts = opts || {};
      const res = await origFetch(url, opts);
      const urlStr = (typeof url === 'string') ? url : (url && url.url) || '';

      // 問題正解 → コイン付与（/api/student/progress へのPUTは除外）
      if (
        urlStr.includes('/api/student/results') &&
        opts.method === 'POST'
      ) {
        try {
          const body = JSON.parse(opts.body || '{}');
          if (body.correct && MS) {
            MS.coins = (MS.coins || 0) + 10;
            saveMS();
            updateHUD();
            toast('+10コイン！', 'coin');
          }
        } catch (e) {}
      }
      return res;
    };
  }

  // ============================================================
  // ショップ
  // ============================================================
  window.msBuy = function (count) {
    if (!MS) return;
    const price = count === 1 ? 50 : 200;
    if ((MS.coins || 0) < price) { toast('コインが足りません！', 'error'); return; }
    MS.coins -= price;
    MS.monsterBalls = (MS.monsterBalls || 0) + count;
    toast(`モンスターボール×${count} を購入しました！`, 'success');
    saveMS(); updateHUD();
  };

  // ============================================================
  // 手持ち↔ボックス 交換
  // ============================================================
  let swapSrc = null;

  window.msSelectForSwap = function (type, idx) {
    if (!swapSrc) {
      swapSrc = { type, idx };
      toast(type === 'party' ? 'ボックスの交換したいキャラを選んでね' : '手持ちの交換したいキャラを選んでね', 'hint');
      renderParty(); renderBox();
    } else {
      if (swapSrc.type === type) {
        swapSrc = null; toast('交換をキ�Σ9¸しました', ''); renderParty(); renderBox(); return;
      }
      const partyIdx = swapSrc.type === 'party' ? swapSrc.idx : idx;
      const boxIdx   = swapSrc.type === 'box'   ? swapSrc.idx : idx;
      const tmp = MS.party[partyIdx];
      MS.party[partyIdx] = MS.box[boxIdx];
      MS.box[boxIdx] = tmp;
      swapSrc = null;
      toast('交換しました！', 'success');
      saveMS(); renderParty(); renderBox();
    }
  };

  // ============================================================
  // UI 構築
  // ============================================================
  function buildUI() {
    const wrap = document.createElement('div');
    wrap.id = 'ms-root';
    wrap.innerHTML = `
<style>
#ms-root *{box-sizing:border-box;}
#ms-hud{
  position:fixed;top:10px;right:10px;
  background:rgba(15,15,35,0.93);color:#fff;
  border-radius:14px;padding:7px 14px;font-size:13px;
  z-index:9900;display:flex;gap:10px;align-items:center;
  box-shadow:0 2px 14px rgba(0,0,0,0.5);
  border:1px solid rgba(255,255,255,0.08);
}
#ms-hud span{white-space:nowrap;}
.ms-btn{
  background:rgba(255,255,255,0.1);border:1px solid rgba(255,255,255,0.25);
  color:#fff;border-radius:8px;padding:4px 10px;cursor:pointer;font-size:12px;
}
.ms-btn:hover{background:rgba(255,255,255,0.22);}
#ms-capture-btn{
  position:fixed;bottom:110px;left:50%;transform:translateX(-50%);
  background:linear-gradient(135deg,#f59e0b,#d97706);color:#fff;
  border:none;border-radius:24px;padding:12px 28px;
  font-size:15px;font-weight:bold;cursor:pointer;z-index:9905;
  box-shadow:0 4px 18px rgba(245,158,11,0.55);display:none;
  transition:transform .15s,box-shadow .15s;
}
#ms-capture-btn:hover:not(:disabled){transform:translateX(-50%) scale(1.05);box-shadow:0 6px 24px rgba(245,158,11,0.7);}
#ms-capture-btn:disabled{background:#666;box-shadow:none;cursor:not-allowed;}
#ms-overlay{
  display:none;position:fixed;inset:0;background:rgba(0,0,0,0.72);
  z-index:10000;justify-content:center;align-items:center;
}
#ms-overlay.open{display:flex;}
#ms-panel{
  background:#111827;border-radius:18px;padding:20px;
  width:min(520px,92vw);max-height:80vh;overflow-y:auto;
  color:#fff;box-shadow:0 8px 40px rgba(0,0,0,0.7);
  border:1px solid rgba(255,255,255,0.08);
}
.ms-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;}
.ms-header h2{margin:0;font-size:17px;color:#f59e0b;}
.ms-close{background:none;border:none;color:#aaa;font-size:22px;cursor:pointer;line-height:1;}
.ms-tabs{display:flex;gap:5px;margin-bottom:14px;}
.ms-tab{
  flex:1;padding:7px 4px;background:rgba(255,255,255,0.07);
  border:none;color:#bbb;border-radius:8px;cursor:pointer;font-size:12px;
}
.ms-tab.on{background:#f59e0b;color:#000;font-weight:bold;}
.ms-pane{display:none;}
.ms-pane.on{display:block;}
.ms-sub{font-size:11px;color:#888;margin-bottom:10px;}
.ms-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;}
.ms-card{
  background:rgba(255,255,255,0.07);border-radius:10px;
  padding:10px 6px;text-align:center;position:relative;
}
.ms-card.selected{outline:2px solid #f59e0b;}
.ms-card .ms-em{font-size:26px;}
.ms-card .ms-nm{font-size:11px;color:#ccc;margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.ms-card .ms-lv{font-size:10px;color:#f59e0b;}
.ms-card .ms-swap{
  margin-top:5px;width:100%;background:rgba(100,160,255,0.2);
  border:1px solid rgba(100,160,255,0.4);color:#adf;
  border-radius:6px;padding:2px;font-size:10px;cursor:pointer;
}
.ms-empty{
  background:rgba(255,255,255,0.03);border:2px dashed rgba(255,255,255,0.12);
  border-radius:10px;padding:18px 6px;text-align:center;
  color:rgba(255,255,255,0.2);font-size:22px;
}
.ms-dex{display:grid;grid-template-columns:repeat(4,1fr);gap:7px;}
.ms-dex-card{background:rgba(255,255,255,0.06);border-radius:8px;padding:8px;text-align:center;}
.ms-dex-card .ms-em{font-size:22px;}
.ms-dex-card .ms-nm{font-size:10px;color:#ccc;}
.ms-shop-row{
  display:flex;justify-content:space-between;align-items:center;
  background:rgba(255,255,255,0.06);border-radius:10px;padding:12px;margin-bottom:8px;
}
.ms-buy{
  background:#10b981;border:none;color:#fff;
  border-radius:8px;padding:6px 14px;cursor:pointer;font-weight:bold;font-size:13px;
}
.ms-buy:hover{background:#059669;}
#ms-toast{
  position:fixed;bottom:70px;left:50%;transform:translateX(-50%);
  background:rgba(15,15,35,0.95);color:#fff;
  padding:9px 20px;border-radius:20px;font-size:13px;
  z-index:10010;opacity:0;transition:opacity .3s;
  pointer-events:none;white-space:nowrap;max-width:90vw;
  border-left:3px solid transparent;
}
#ms-toast.show{opacity:1;}
#ms-toast.success{border-color:#10b981;}
#ms-toast.error{border-color:#ef4444;}
#ms-toast.fail{border-color:#f59e0b;}
#ms-toast.coin{border-color:#facc15;}
</style>

<!-- HUD -->
<div id="ms-hud">
  <span>🪙<span id="ms-c">0</span></span>
  <span>⚾<span id="ms-b">0</span></span>
  <button class="ms-btn" onclick="msOpen('party')">手持ち</button>
  <button class="ms-btn" onclick="msOpen('box')">ボックス</button>
  <button class="ms-btn" onclick="msOpen('pokedex')">図鑑</button>
  <button class="ms-btn" onclick="msOpen('shop')">ショップ</button>
</div>

<!-- 捕獲ボタン -->
<button id="ms-capture-btn" onclick="msThrowBall()">⚾ ボールを投げる！</button>

<!-- モーダル -->
<div id="ms-overlay" onclick="if(event.target===this)msClose()">
  <div id="ms-panel">
    <div class="ms-header">
      <h2 id="ms-title">手持ち</h2>
      <button class="ms-close" onclick="msClose()">✕</button>
    </div>
    <div class="ms-tabs">
      <button class="ms-tab on" data-p="party"   onclick="msTab('party')">🤝手持ち</button>
      <button class="ms-tab"    data-p="box"     onclick="msTab('box')">📦ボックス</button>
      <button class="ms-tab"    data-p="pokedex" onclick="msTab('pokedex')">📖図鑑</button>
      <button class="ms-tab"    data-p="shop"    onclick="msTab('shop')">🏪ショップ</button>
    </div>
    <div class="ms-pane on" id="ms-p-party">
      <p class="ms-sub">今一緒にいるキャラ（最大3体）</p>
      <div class="ms-grid" id="ms-party-grid"></div>
    </div>
    <div class="ms-pane" id="ms-p-box">
      <p class="ms-sub">4体目以降のキャラ。手持ちと入れ替えできます。</p>
      <div class="ms-grid" id="ms-box-grid"></div>
    </div>
    <div class="ms-pane" id="ms-p-pokedex">
      <p class="ms-sub">これまでに捕まえたキャラ: <span id="ms-dex-n">0</span>種類</p>
      <div class="ms-dex" id="ms-dex-grid"></div>
    </div>
    <div class="ms-pane" id="ms-p-shop">
      <p class="ms-sub">コインを使ってアイテムを購入しよう（問題正解で+10コイン）</p>
      <div class="ms-shop-row">
        <div>
          <div style="font-size:15px">⚾ モンスターボール</div>
          <div style="font-size:11px;color:#888">野生キャラを捕まえるボール</div>
        </div>
        <div style="text-align:center">
          <div style="font-size:12px;color:#f59e0b;margin-bottom:4px">50コイン</div>
          <button class="ms-buy" onclick="msBuy(1)">1個買う</button>
        </div>
      </div>
      <div class="ms-shop-row">
        <div>
          <div style="font-size:15px">⚾×5 まとめ買い</div>
          <div style="font-size:11px;color:#888">1個あたり40コインでお得</div>
        </div>
        <div style="text-align:center">
          <div style="font-size:12px;color:#f59e0b;margin-bottom:4px">200コイン</div>
          <button class="ms-buy" onclick="msBuy(5)">5個買う</button>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- トースト -->
<div id="ms-toast"></div>
`;
    document.body.appendChild(wrap);
    updateHUD();
  }

  // ============================================================
  // HUD
  // ============================================================
  function updateHUD() {
    if (!MS) return;
    const c = document.getElementById('ms-c');
    const b = document.getElementById('ms-b');
    if (c) c.textContent = MS.coins || 0;
    if (b) b.textContent = MS.monsterBalls || 0;
  }

  // ============================================================
  // モーダル操作
  // ============================================================
  const TITLES = { party: '手持ち', box: 'ボックス', pokedex: '図鑑', shop: 'ショップ' };

  window.msOpen = function (pane) {
    const o = document.getElementById('ms-overlay');
    if (o) o.classList.add('open');
    msTab(pane || 'party');
  };

  window.msClose = function () {
    const o = document.getElementById('ms-overlay');
    if (o) o.classList.remove('open');
    swapSrc = null;
    renderParty(); renderBox();
  };

  window.msTab = function (pane) {
    document.querySelectorAll('.ms-tab').forEach(t =>
      t.classList.toggle('on', t.dataset.p === pane));
    document.querySelectorAll('.ms-pane').forEach(p =>
      p.classList.toggle('on', p.id === 'ms-p-' + pane));
    const t = document.getElementById('ms-title');
    if (t) t.textContent = TITLES[pane] || pane;
    if (pane === 'party')   renderParty();
    if (pane === 'box')     renderBox();
    if (pane === 'pokedex') renderDex();
  };

  // ============================================================
  // 手持ちレンダリング
  // ============================================================
  function renderParty() {
    const g = document.getElementById('ms-party-grid');
    if (!g || !MS) return;
    g.innerHTML = '';
    for (let i = 0; i < 3; i++) {
      const m = MS.party[i];
      if (m) {
        const d = document.createElement('div');
        d.className = 'ms-card' + (swapSrc && swapSrc.type === 'party' && swapSrc.idx === i ? ' selected' : '');
        d.innerHTML = `
          <div class="ms-em">${m.emoji || '👾'}</div>
          <div class="ms-nm">${m.name || m.id}</div>
          <div class="ms-lv">Lv.${m.level || 1}</div>
          <button class="ms-swap" onclick="msSelectForSwap('party',${i})">
            ${swapSrc && swapSrc.type === 'party' && swapSrc.idx === i ? '✓選択中' : '↔ボックスと交換'}
          </button>`;
        g.appendChild(d);
      } else {
        const d = document.createElement('div');
        d.className = 'ms-empty';
        d.textContent = '＋';
        g.appendChild(d);
      }
    }
  }

  // ============================================================
  // ボックスレンダリング
  // ============================================================
  function renderBox() {
    const g = document.getElementById('ms-box-grid');
    if (!g || !MS) return;
    g.innerHTML = '';
    if (MS.box.length === 0) {
      g.innerHTML = '<p style="color:#666;font-size:12px;grid-column:1/-1;text-align:center">ボックスは空です</p>';
      return;
    }
    MS.box.forEach((m, i) => {
      const d = document.createElement('div');
      d.className = 'ms-card' + (swapSrc && swapSrc.type === 'box' && swapSrc.idx === i ? ' selected' : '');
      const waiting = swapSrc && swapSrc.type === 'party';
      d.innerHTML = `
        <div class="ms-em">${m.emoji || '👾'}</div>
        <div class="ms-nm">${m.name || m.id}</div>
        <div class="ms-lv">Lv.${m.level || 1}</div>
        <button class="ms-swap" style="${waiting ? 'background:rgba(255,200,0,0.2);border-color:rgba(255,200,0,0.5)' : ''}"
          onclick="msSelectForSwap('box',${i})">
          ${swapSrc && swapSrc.type === 'box' && swapSrc.idx === i ? '✓選択中' : waiting ? '↔ここと交換' : '↔手持ちと交換'}
        </button>`;
      g.appendChild(d);
    });
  }

  // ============================================================
  // 図鑑レンダリング
  // ============================================================
  function renderDex() {
    const g = document.getElementById('ms-dex-grid');
    const n = document.getElementById('ms-dex-n');
    if (!g || !MS) return;
    const dex = MS.pokedex || [];
    if (n) n.textContent = dex.length;
    g.innerHTML = '';
    if (dex.length === 0) {
      g.innerHTML = '<p style="color:#666;font-size:12px;grid-column:1/-1;text-align:center">まだ捕まえていません</p>';
      return;
    }
    const allMons = [...(MS.party || []), ...(MS.box || [])];
    dex.forEach(id => {
      const m = allMons.find(x => x.id === id);
      const d = document.createElement('div');
      d.className = 'ms-dex-card';
      d.innerHTML = `
        <div class="ms-em">${m?.emoji || '👾'}</div>
        <div class="ms-nm">${m?.name || id}</div>`;
      g.appendChild(d);
    });
  }

  // ============================================================
  // トースト通知
  // ============================================================
  let toastTmr;
  function toast(msg, type) {
    const el = document.getElementById('ms-toast');
    if (!el) return;
    el.textContent = msg;
    el.className = 'show ' + (type || '');
    clearTimeout(toastTmr);
    toastTmr = setTimeout(() => { el.className = ''; }, 2800);
  }

  // ============================================================
  // 起動（1秒後に初期化）
  // ============================================================
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(init, 1000));
  } else {
    setTimeout(init, 1000);
  }
})();
