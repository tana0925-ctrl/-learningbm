/**
 * monster-system.js (v4 -（性見、手持、捕獲、ショップ）
 * 國卸会フィロー・-ボックーペャンセハビデャアデュ
 *
 * ���nӚZÖ>���h(�������
ϒⷎ��rϖ2[�ⷎ���������
K��ךZc��#�&/�2���
��[��{�^���c��.��(���������ώ
�
���s����VÎ
K�^���c�
ώ
��Ϣ���������������*�(�������s��
���#���g������nϦFG�s��
��
�
K����*�(��(���Xx~i�Nik�
��
��
����[��[ۈ

H	�\�H��X�	����OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOB���9b'y�"x�����8��g,9� ���OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOB�]T�H�[]��]�QX��[��U\�H�[��[��[ۈ[�]

H�YT�
N�Z[RJ
N[�\��\�]�ܚ�
N�Y��\��\\�P��
N�][�\��[
�X�И]K�
NB���[��[ۈ�YT�
H�H�ۜ��]�H��[�ܘY�K��]][J	�[ۜ�\��\�[I�NT�H�]����Ӌ�\��J�]�H��[H�]�
JH�T�H�[�B�Y�
ST�HT�H�\�N��K����K��Y^��K[ۜ�\��[Έ���[�ΈNY�
ST˜\�JHT˜\�HH�NY�
ST˘��
HT˘��H�NY�
ST˜��Y^
HT˜��Y^H�NY�
T˛[ۜ�\��[�OOH[�Y�[�Y
HT˛[ۜ�\��[�H�Y�
T˘��[��OOH[�Y�[�Y
HT˘��[��HB���[��[ۈ�]�ST�
H�X\�[Y[�]
��]�QX��[��U\�N��]�QX��[��U\�H�][Y[�]


HO��H��[�ܘY�K��]][J	�[ۜ�\��\�[I���Ӌ���[��Y�JT�JNH�]�
JH�B��H�ۜ���HH�]N�[ۜ�\��[ΈT˛[ۜ�\��[��[ۜ�\�Έ�K�\�N�T˜\�K����T˘�����Y^�T˜��Y^���[�ΈT˘��[�B�Nˋ��T˜\�H�JK���T˘���JWK��ܑXX�
HO�Y�
K�Y
H��K��]K�[ۜ�\���K�YHH�]�[�K�]�[NJN�]�
	��\K��Y[����ܙ\����Y]��	�U	�XY\�Έ�	��۝[�U\IΈ	�\X�][ۋڜ�ۉ�K��N���Ӌ���[��Y�J��JHJK��]�


HO��JNH�]�
JH�B�K�
NB����OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOB���9�ey�l���8�����8��8��8���H9���b�ybcB���OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOB��[��[ۈ�X�И]J
H�Y��\��\\�P��
NB���[��[ۈ\��[�]J
H�ۜ�[�X�]ܜ�H	���\�ʏH��[X�]H�I�	���\�ʏH��[�]H�I��	��Y
�H��[X�]H�I�	��Y
�H��[�]H�I��	���\�ʏH��]K\��[�H�I�	���\�ʏH��]T��[�H�I��	���\�ʏH�[�[^KX\�XH�I�	���\�ʏH�[�[^P\�XH�I��N�܈
�ۜ��[و[�X�]ܜ�H�ۜ�[H��[Y[��]Y\�T�[X�܊�[
NY�
[
H�]\���YNB��]\���[�NB���[��[ۈ�Y��\��\\�P��
H�ۜ���H��[Y[���][[Y[��RY
	�\�X�\\�KX���NY�
X��H�]\���ۜ�[��]H\��[�]J
N����[K�\�^HH[��]�	؛�����	ۛۙI�Y�
Z[��]
H�]\���ۜ�\И[�H
T˛[ۜ�\��[�
H����\�X�YHZ\И[����^�۝[�H\И[�8���8��8��8���ह��x�d���� J9� 8ࢻ�&��T˛[ۜ�\��[�JX��	����8��8��8����8�k��c9bc�� I�B����OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOB���9��x�d���a�y/&����OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOB��[��˛\���И[H�[��[ۈ

HY�
ST�H�]\��Y�

T˛[ۜ�\��[�
HH
H��\�
	���8��8���c8�`�ࢸ�o��f���� I�	�\��܉�N��]\���B�Y�
Z\��[�]J
JH��\�
	�g��oex��8��8�껺(c8�i��k�/oえません！', 'error'); return; }

    MS.monsterBalls--;
    const enemyHpPct = (() => {
      const sels = ['[class*="enemy-hp"]', '[class*="enemyHP"]', '[class*="opp-hp"]'];
      for (const s of sels) {
        const el = document.querySelector(s);
        if (el) {
          const w = parseFloat(el.style.width);
          if (!isNaN(w)) return w;
        }
      }
      return 50;
    })();

    const rate = Math.min(0.9, (100 - enemyHpPct) / 100 * 0.8 + 0.1);
    const roll = Math.random();
    const enemy = detectEnemy();
    const Z = enemy = detectEnemy();

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
      if (enemyHpPct > 50) toast('もっと弱らせると捕まえやすくなるよ！', 'hint');
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

      if (urlStr.includes('/api/student/results') && opts.method === 'POST') {
        try {
          const body = JSON.parse(opts.body || '{}');
          if (body.correct && MS) {
            MS.coins = (MS.coins || 0) + 10;
            saveMS();
            updateHUD();
            toast('+10コイン（モンスターボール購入に使えます）', 'coin');
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
  // ボックス→パーティへ移動
  // ============================================================
  window.msMoveToParty = function (boxIdx) {
    if (!MS) return;
    if ((MS.party || []).length >= 3) {
      toast('手持ちが満員です（3体まで）', 'error');
      return;
    }
    const mon = MS.box.splice(boxIdx, 1)[0];
    MS.party.push(mon);
    toast(`${mon.emoji || '👾'} ${mon.name || mon.id} を手持ちに加えました！`, 'success');
    saveMS(); renderBox();
  };

  // ============================================================
  // UI 構築（既存ゲームUIに統合）
  // ============================================================
  function buildUI() {
    // 1. モンスターボール数を既存コイン表示の横に追加
    const coinEl = document.getElementById('coinCount');
    if (coinEl && !document.getElementById('ms-b')) {
      const ballWrap = document.createElement('span');
      ballWrap.style.cssText = 'margin-left:8px;';
      ballWrap.innerHTML = '⚾<span id="ms-b" style="font-weight:bold;">0</span>';
      coinEl.parentElement.appendChild(ballWrap);
    }

    // 2. 左navにボタン追加（ボックス・捕獲図鑑・ボール購入）
    const nav = document.querySelector('nav.flex.flex-col');
    if (nav && !document.getElementById('ms-nav-box')) {
      // ボックスボタン
      const boxBtn = document.createElement('button');
      boxBtn.id = 'ms-nav-box';
      boxBtn.className = 'py-3 px-3 rounded-lg bg-purple-500 text-white hover:bg-purple-600 transition shadow text-sm font-bold flex items-center gap-1 w-full text-left';
      boxBtn.innerHTML = '📦<span class="ml-1">ボックス</span>';
      boxBtn.onclick = () => window.msOpen('box');
      nav.appendChild(boxBtn);

      // 捕獲図鑑ボタン
      const dexBtn = document.createElement('button');
      dexBtn.id = 'ms-nav-dex';
      dexBtn.className = 'py-3 px-3 rounded-lg bg-teal-500 text-white hover:bg-teal-600 transition shadow text-sm font-bold flex items-center gap-1 w-full text-left';
      dexBtn.innerHTML = '🔮<span class="ml-1">捕獲図鑑</span>';
      dexBtn.onclick = () => window.msOpen('pokedex');
      nav.appendChild(dexBtn);

      // ボール購入ボタン
      const ballBtn = document.createElement('button');
      ballBtn.id = 'ms-nav-shop';
      ballBtn.className = 'py-3 px-3 rounded-lg bg-amber-500 text-white hover:bg-amber-600 transition shadow text-sm font-bold flex items-center gap-1 w-full text-left';
      ballBtn.innerHTML = '⚾<span class="ml-1">ボール購入</span>';
      ballBtn.onclick = () => window.msOpen('shop');
      nav.appendChild(ballBtn);
    }

    // 3. モーダル・捕獲ボタン・トーストの作成（HUDなし）
    const wrap = document.createElement('div');
    wrap.id = 'ms-root';
    wrap.innerHTML = `
<style>
#ms-root *{box-sizing:border-box;}

/* 捕獲ボタン（バトル中のみ表示） */
#ms-capture-btn{
  position:fixed;bottom:110px;left:50%;transform:translateX(-50%);
  background:linear-gradient(135deg,#f59e0b,#d97706);color:#fff;
  border:none;border-radius:24px;padding:12px 28px;
  font-size:15px;font-weight:bold;cursor:pointer;z-index:9905;
  box-shadow:0 4px 18px rgba(245,158,11,0.55);display:none;
  transition:transform .15s,box-shadow .15s;
}
#ms-capture-btn:hover:not(:disabled){transform:translateX(-50%) scale(1.05);}
#ms-capture-btn:disabled{background:#888;box-shadow:none;cursor:not-allowed;}

/* モーダル */
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

/* モンスターグリッド */
.ms-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;}
.ms-card{
  background:rgba(255,255,255,0.07);border-radius:10px;
  padding:10px 6px;text-align:center;
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

/* コイン表示（ショップ内） */
.ms-coins-row{
  background:rgba(250,204,21,0.1);border:1px solid rgba(250,204,21,0.3);
  border-radius:10px;padding:10px 14px;margin-bottom:12px;
  font-size:14px;color:#facc15;font-weight:bold;
}
.ms-shop-row{
  display:flex;justify-content:space-between;align-items:center;
  background:rgba(255,255,255,0.06);border-radius:10px;padding:12px;margin-bottom:8px;
}
.ms-buy{
  background:#10b981;border:none;color:#fff;
  border-radius:8px;padding:6px 14px;cursor:pointer;font-weight:bold;font-size:13px;
}
.ms-buy:hover{background:#059669;}

/* トースト */
#ms-toast{
  position:fixed;bottom:70px;left:50%;transform:translateX(-50%);
  background:rgba(15,15,35,0.95);color:#fff;
  padding:9px 20px;border-radius:20px;font-size:13px;
  z-index:10010;opacity:0;transition:opacity .3s;
  pointer-events:none;white-space:nowraw;max-width:90vw;
  border-left:3px solid transparent;
}
#ms-toast.show{opacity:1;}
#ms-toast.success{border-color:#10b981;}
#ms-toast.error{border-color:#ef4444;}
#ms-toast.fail{border-color:#f59e0b;}
#ms-toast.coin{border-color:#facc15;}
</style>

<!-- 捕獲ボタン（バトル中のみ表示） -->
<button id="ms-capture-btn" onclick="msThrowBall()">⚾ ボールを投げる！</button>

<!-- モーダル -->
<div id="ms-overlay" onclick="if(event.target===this)msClose()">
  <div id="ms-panel">
    <div class="ms-header">
      <h2 id="ms-title">手持ち</h2>
      <button class="ms-close" onclick="msClose()">✕</button>
    </div>
    <div class="ms-tabs">
      <button class="ms-tab on" data-p="box"     onclick="msTab('box')">📦ボックス</button>
      <button class="ms-tab"    data-p="pokedex" onclick="msTab('pokedex')">🔮捕獲図鑑</button>
      <button class="ms-tab"    data-p="shop"    onclick="msTab('shop')">⚾ボール購入</button>
    </div>
    <!-- ボックス -->
    <div class="ms-pane on" id="ms-p-box">
      <p class="ms-sub">4体目以降のキャラ。手持ちが空きなら手持ちに加えられます。</p>
      <div class="ms-grid" id="ms-box-grid"></div>
    </div>
    <!-- 捕獲図鑑 -->
    <div class="ms-pane" id="ms-p-pokedex">
      <p class="ms-sub">これまでに捕まえたキャラ: <span id="ms-dex-n">0</span>種類</p>
      <div class="ms-dex" id="ms-dex-grid"></div>
    </div>
    <!-- ボール購入 -->
    <div class="ms-pane" id="ms-p-shop">
      <div class="ms-coins-row">💰 所持コイン: <span id="ms-c">0</span>コイン<br><small style="color:#aaa;font-weight:normal;">問題に正解するたびに+10コイン獲得</small></div>
      <p class="ms-sub">モンスターボールを買って野生キャラを捕まえよう</p>
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
          <div style="font-size:15px">⚾×5 まとめ買う</div>
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
  // HUD更新（モンスターボール数のみ）
  // ============================================================
  function updateHUD() {
    if (!MS) return;
    const b = document.getElementById('ms-b');
    const c = document.getElementById('ms-c');
    if (b) b.textContent = MS.monsterBalls || 0;
    if (c) c.textContent = MS.coins || 0;
  }

  // ============================================================
  // モーダル操作
  // ============================================================
  const TITLES = { box: 'ボックス', pokedex: '捕獲図鑑', shop: 'ボール購入' };

  window.msOpen = function (pane) {
    const o = document.getElementById('ms-overlay');
    if (o) o.classList.add('open');
    msTab(pane || 'box');
  };

  window.msClose = function () {
    const o = document.getElementById('ms-overlay');
    if (o) o.classList.remove('open');
    renderBox();
  };

  window.msTab = function (pane) {
    document.querySelectorAll('.ms-tab').forEach(t =>
      t.classList.toggle('on', t.dataset.p === pane));
    document.querySelectorAll('.ms-pane').forEach(p =>
      p.classList.toggle('on', p.id === 'ms-p-' + pane));
    const t = document.getElementById('ms-title');
    if (t) t.textContent = TITLES[pane] || pane;
    if (pane === 'box')     renderBox();
    if (pane === 'pokedex') renderDex();
  };

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
    const partyFull = (MS.party || []).length >= 3;
    MS.box.forEach((m, i) => {
      const d = document.createElement('div');
      d.className = 'ms-card';
      d.innerHTML = `
        <div class="ms-em">${m.emoji || '👾'}</div>
        <div class="ms-nm">${m.name || m.id}</div>
        <div class="ms-lv">Lv.${m.level || 1}</div>
        <button class="ms-swap" ${partyFull ? 'disabled style="opacity:0.4;cursor:not-allowed"' : ''}
          onclick="msMoveToParty(${i})">
          ${partyFull ? '手持ち満員' : '→手持ちへ'}
        </button>`;
      g.appendChild(d);
    });
  }

  // ============================================================
  // 捕獲図鑑レンダリング
  // ============================================================
  function renderDex() {
    const g = document.getElementById('ms-dex-grid');
    const n = document.getElementById('ms-dex-n');
    if (!g || !MS) return;
    const dex = MS.pokedex || [];
    if (n) n.textContent = dex.length;
    g.innerHTML = '';
    if (dex.length === 0) {
      g.innerHTML = '<p style="color:#666;font-size:12px;grid-column:1/-1;text-align:center">まだ捕まえていません<br>野生バトリ今にボールを投げて捕まえよう！</p>';
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
  // 起動（1秒後）
  // ============================================================
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(init, 1000));
  } else {
    setTimeout(init, 1000);
  }
})();
