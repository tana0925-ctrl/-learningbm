/* ===================================================================
   kahoot_ticket.js : 「カフート券」ショップUI（サーバー権威）
   - index.html 無編集。sticker.js とまったく同じ形で配信・注入する。
   - この券は「クラスのみんながそろって初めて発動する」協力の商品。
   - ★いちばん大事な約束★
     子どもの画面には「何人が買ったか」も「だれが買っていないか」も出さない。
     サーバが返すのは 0〜5 の段階ゲージだけで、人数はそもそも送られてこない。
     ゲージは 1 段が数人ぶんなので、だれか 1 人が買っても普通は動かない。
     「今わたしが買ったら数字が増えた＝さっき買ったのは◯◯くん」という
     つきとめ方ができないようにするため。
   - 正当性（1回だけ／800消費／返金）はすべてサーバー(/api/shop/kahoot/*)で担保する。
   =================================================================== */
(function(global){
  'use strict';

  var PRICE = 800;
  var S = { loaded:false, enabled:false, bought:false, gauge:0, reached:false, daysLeft:null, round:0 };
  var _busy = false;

  // app側の player は `let player`（window非公開）。lexicalなグローバルを安全に取得。
  function curP(){ try{ if(typeof player!=='undefined' && player) return player; }catch(e){} return global.player || null; }

  function jpost(path){
    return fetch(path, { method:'POST', headers:{'content-type':'application/json'}, credentials:'same-origin' })
      .then(function(r){ return r.json().then(function(j){ j=j||{}; j.__status=r.status; return j; }).catch(function(){ return {ok:false,__status:r.status}; }); })
      .catch(function(){ return {ok:false,__status:0}; });
  }
  function jget(path){
    return fetch(path, { credentials:'same-origin' })
      .then(function(r){ return r.json().then(function(j){ j=j||{}; j.__status=r.status; return j; }).catch(function(){ return {ok:false,__status:r.status}; }); })
      .catch(function(){ return {ok:false,__status:0}; });
  }

  /* サーバが確定させたコインを画面に映すだけ。クライアントでは引き算しない。 */
  function applyCoins(newCoins){
    if(typeof newCoins !== 'number' || !isFinite(newCoins)) return;
    var p = curP();
    if(p){ try{ p.coins = newCoins; }catch(e){} }
    try{ if(typeof updateStatusView==='function') updateStatusView(); }catch(e){}
    ['coinCount','trainingCoinCount','coins','newCoins'].forEach(function(id){
      var el=document.getElementById(id); if(el){ try{ el.innerText = newCoins; }catch(e){} }
    });
    try{ if(typeof renderShopItems==='function') renderShopItems(); }catch(e){}
  }

  /* ---------- 段階ゲージ（数字は一切出さない） ---------- */
  var LABELS = [
    'まだ はじまったばかり',
    'あつまってきたよ',
    'はんぶんくらい',
    'だいぶ そろってきた',
    'あと ちょっと！',
    'ぜんいん そろったよ！'
  ];
  function gaugeHtml(g, reached){
    var i, on, h = '<div style="display:flex;gap:3px;margin-top:7px">';
    for(i=1;i<=5;i++){
      on = (i<=g);
      h += '<div style="flex:1;height:9px;border-radius:5px;background:'+(on?(reached?'#22c55e':'#f97316'):'#e5e7eb')+'"></div>';
    }
    return h + '</div>';
  }

  /* ---------- ショップのカード ---------- */
  function removeCard(){ var c0=document.getElementById('kahootShopCard'); if(c0&&c0.parentNode) c0.parentNode.removeChild(c0); }

  function refreshState(){
    return jget('/api/shop/kahoot/current').then(function(res){
      if(res && res.ok){
        S.loaded = true;
        S.enabled = !!res.enabled;
        S.bought = !!res.bought;
        S.gauge = Math.max(0, Math.min(5, Math.floor(Number(res.gauge)||0)));
        S.reached = !!res.reached;
        S.daysLeft = (typeof res.daysLeft === 'number') ? res.daysLeft : null;
        S.round = Number(res.round)||0;
      }
      ensureCard();
      updateCard();
      return res;
    });
  }

  function updateCard(){
    var card = document.getElementById('kahootShopCard'); if(!card) return;
    var g = card.querySelector('.kht-gauge');
    var lbl = card.querySelector('.kht-label');
    var cta = card.querySelector('.kht-cta');
    var note = card.querySelector('.kht-note');
    if(g) g.innerHTML = gaugeHtml(S.gauge, S.reached);
    if(lbl) lbl.textContent = LABELS[S.reached ? 5 : S.gauge] || LABELS[0];
    if(cta){
      if(S.reached){
        cta.textContent = '🎉 そろったよ！ 先生からの おしらせを まってね';
        cta.style.background = '#16a34a';
      } else if(S.bought){
        cta.textContent = '✅ こうにゅう ずみ｜みんなを まっているよ';
        cta.style.background = '#0ea5e9';
      } else {
        cta.textContent = '🎫 ' + PRICE + 'コインで こうにゅう';
        cta.style.background = '#7c3aed';
      }
    }
    if(note){
      if(S.reached){
        note.textContent = 'クラスのみんなが そろいました。';
      } else if(S.daysLeft !== null){
        note.textContent = 'そろわないまま ' + S.daysLeft + '日 たつと、コインは ぜんいんに もどってきます。';
      } else {
        note.textContent = 'そろわなかったときは、コインは もどってきます。';
      }
    }
  }

  function doBuy(){
    if(_busy) return;
    if(S.bought || S.reached){ return; }
    var p = curP();
    var have = p ? (Number(p.coins)||0) : null;
    if(have !== null && have < PRICE){ alert('コインが たりないよ（' + PRICE + 'コイン ひつよう）'); return; }
    if(!confirm('カフート券を ' + PRICE + 'コインで かいますか？\n\nクラスの みんなが そろうと、先生が カフートを やってくれます。\nそろわなかったときは、コインは もどってきます。')) return;
    _busy = true;
    jpost('/api/shop/kahoot/buy').then(function(res){
      _busy = false;
      if(res && res.ok){
        if(typeof res.coins === 'number') applyCoins(res.coins);
        S.bought = true;
        if(typeof res.gauge === 'number') S.gauge = res.gauge;
        S.reached = !!res.reached;
        updateCard();
        alert('カフート券を かいました！\nクラスの みんなが そろうのを まとう。');
        refreshState();
        return;
      }
      var r = (res && res.error) || (res && res.reason) || '';
      if(r === 'not_enough_coins') alert('コインが たりないよ（' + PRICE + 'コイン ひつよう）');
      else if(r === 'already_bought') { S.bought = true; updateCard(); alert('もう かってあるよ。'); }
      else if(r === 'already_reached') { S.reached = true; updateCard(); alert('もう ぜんいん そろっているよ！'); }
      else if(r === 'kahoot_disabled') { S.enabled = false; ensureCard(); }
      else if(r === 'busy_retry') alert('こんでいます。すこし まって、もういちど おしてね。');
      else alert('うまく いきませんでした。もういちど ためしてね。');
      refreshState();
    });
  }

  function ensureCard(){
    var container = document.getElementById('shopItemsContainer');
    if(!container) return;
    /* 先生がこのクラスでOFFにしている間は、カードそのものを出さない。
       ただし買ってある子には出す（買った券の行方が分からなくなるのを防ぐため）。 */
    if(!S.loaded) return;
    if(!S.enabled && !S.bought){ removeCard(); return; }
    if(document.getElementById('kahootShopCard')) return;

    var card = document.createElement('button');
    card.id = 'kahootShopCard';
    card.className = 'rounded-xl p-4 shadow-sm border border-purple-300 text-left flex flex-col gap-1 relative';
    card.style.cssText = 'background:#faf5ff;';
    card.innerHTML = ''
      + '<div class="flex items-center gap-3">'
      + '  <div class="text-3xl">🎫</div>'
      + '  <div class="flex-1"><div class="font-bold text-base">カフート券</div>'
      + '  <div class="text-xs text-gray-600">クラスの ぜんいんが そろうと、先生が カフートを やってくれる券。</div></div>'
      + '</div>'
      + '<div class="mt-1 bg-purple-100 text-purple-800 text-xs px-2 py-1 rounded-full w-fit">💰 ' + PRICE + ' コイン</div>'
      + '<div class="kht-gauge"></div>'
      + '<div class="kht-label" style="font-size:12px;color:#6b21a8;font-weight:700;margin-top:4px"></div>'
      + '<div class="kht-note" style="font-size:11px;color:#6b7280;margin-top:2px"></div>'
      + '<div class="kht-cta" style="margin-top:8px;color:#fff;background:#7c3aed;border-radius:10px;padding:8px 10px;font-weight:800;font-size:13px;text-align:center"></div>';
    card.addEventListener('click', function(ev){ ev.preventDefault(); ev.stopPropagation(); doBuy(); });
    container.appendChild(card);
    updateCard();
  }

  /* ショップが作り直されてもカードが残るように見張る（sticker.js と同じ形） */
  function start(){
    var container = document.getElementById('shopItemsContainer');
    if(!container){ setTimeout(start, 800); return; }
    try{ var mo = new MutationObserver(function(){ ensureCard(); }); mo.observe(container, {childList:true}); }catch(e){}
    refreshState();
    setInterval(function(){ ensureCard(); }, 1500);
    setInterval(function(){ refreshState(); }, 30000);
  }
  if(document.readyState !== 'loading') start();
  else document.addEventListener('DOMContentLoaded', start);

  global.__kahootRefresh = refreshState; // debug/manual
})(typeof window!=='undefined'?window:globalThis);
