def a():
    if 1:
        return 2
x = 1
# -*- coding: utf-8 -*-
# DEF_PROG_UX_V1_PATCH
# 防衛戦の「プログラムをつくるところ」を なおす。
#   ① 出陣ボタンの上に出す（いままでは ボタンより下に落ちていた）
#   ② つくったプログラムを ほぞんする（つぎの日も つづきから なおせる）
#   ③ 「いつも」より下のルールは うごかないことを その場で知らせる
# 触るのは public/defense2.js と src/index.tsx の2つだけ。
# public/index.html は手で編集しない。チェーンの本数は増やさない。
# アンカーが1件でなければ 1文字も書かずに異常終了する（fail-closed）。
import io
import sys

D2 = 'public/defense2.js'
TSX = 'src/index.tsx'
MARK = 'DEF_PROG_UX_V1'

HEAD = '/* ---- program authoring state ---- */'
TAIL = 'anchor.appendChild(box); renderEditor();'

CHAIN_START = "app.get('/', async (c) => {"
CHAIN_END = "app.get('/logout'"
CHAIN_N = 78

OLD_SRC = '/defense2.js?v=5'
NEW_SRC = '/defense2.js?v=6'

NEW_BLOCK = u"""/* ---- program authoring state ---- */
  /* DEF_PROG_UX_V1
     プログラムづくりが 防衛戦の学びの中心。だから
     ①出陣ボタンの上に置く ②ほぞんする ③うごかない行を その場で知らせる。 */
  var _progRules = null;
  var _progLoaded = false;
  var _progTouched = false;
  var _progTimer = null;

  function progPlayer(){
    try{ if(window.player && typeof window.player === 'object') return window.player; }catch(e){}
    try{
      var p = new Function('try{ return (typeof player !== "undefined") ? player : null; }catch(e){ return null; }')();
      if(p && typeof p === 'object') return p;
    }catch(e){}
    return null;
  }
  function progClean(list){
    if(!Array.isArray(list) || !list.length) return null;
    var out = [];
    for(var i=0; i<list.length && out.length<12; i++){
      var r = list[i] || {};
      var cd = COND.filter(function(x){ return x.v === r.c; })[0];
      var ac = ACT.filter(function(x){ return x.v === r.a; })[0];
      if(!cd || !ac) continue;
      out.push({ c: cd.v, cn: (cd.num ? Number(r.cn != null ? r.cn : (cd.dflt || 0)) : null), a: ac.v });
    }
    return out.length ? out : null;
  }
  function progLoadOnce(){
    /* player は loadData で まるごと入れかわるので、
       見つかるまで 何度でも さがす。子が さわったら もう上書きしない。 */
    if(_progLoaded || _progTouched) return;
    var p = progPlayer(); if(!p) return;
    var saved = progClean(p.defProgram);
    if(saved){ _progLoaded = true; _progRules = saved; }
  }
  function progSaveNow(){
    try{
      var p = progPlayer(); if(!p) return;
      p.defProgram = JSON.parse(JSON.stringify(ensureRules()));
      if(typeof window.saveData === 'function') window.saveData();
    }catch(e){}
  }
  function progSaveSoon(){
    _progTouched = true;
    try{ if(_progTimer) clearTimeout(_progTimer); }catch(e){}
    _progTimer = setTimeout(progSaveNow, 700);
  }
  function ensureRules(){
    progLoadOnce();
    if(!Array.isArray(_progRules) || !_progRules.length){ _progRules = [{c:'always',cn:null,a:'attackBase'}]; }
    return _progRules;
  }
  function progDeadFrom(){
    var rs = ensureRules();
    for(var i=0; i<rs.length; i++){ if(rs[i].c === 'always') return i + 1; }
    return -1;
  }
  function progFromRules(){ return ensureRules().map(function(r){ var o={c:r.c,a:r.a}; var cd=COND.filter(function(x){return x.v===r.c;})[0]; if(cd&&cd.num){ o.cn=Number(r.cn!=null?r.cn:(cd.dflt||0)); } return o; }); }
  function optionsHtml(list,cur){ return list.map(function(o){ return '<option value="'+o.v+'"'+(o.v===cur?' selected':'')+'>'+esc(o.label)+'</option>'; }).join(''); }
  function renderEditor(){
    var box=document.getElementById('def2ProgBox'); if(!box) return; ensureRules();
    var dead=progDeadFrom();
    var rows=_progRules.map(function(r,i){
      var cd=COND.filter(function(x){return x.v===r.c;})[0]; var showNum=cd&&cd.num;
      var isDead=(dead>=0 && i>=dead);
      var note=(dead>=0 && i===dead)
        ? '<div style="margin:7px 0 5px;padding:6px 8px;background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;font-size:11px;color:#9a3412;line-height:1.6;">⬇ この下は うごきません<br>「いつも」は どんなときも あてはまるので、ここで とまります。下の ルールも うごかしたいときは、▲▼で 「いつも」を いちばん下に うつしてね。</div>'
        : '';
      return note
        +'<div style="display:flex;gap:4px;align-items:center;margin-bottom:4px;flex-wrap:wrap;'+(isDead?'opacity:0.45;background:#f1f5f9;border-radius:8px;padding:3px 4px;':'')+'">'
        +'<span style="font-size:11px;color:#94a3b8;min-width:12px;">'+(i+1)+'</span>'
        +'<span style="font-size:11px;color:#64748b;">もし</span>'
        +'<select data-i="'+i+'" data-k="c" class="def2sel" style="font-size:12px;padding:2px;border:1px solid #cbd5e1;border-radius:6px;">'+optionsHtml(COND,r.c)+'</select>'
        +(showNum?'<input data-i="'+i+'" data-k="cn" type="number" value="'+esc(r.cn!=null?r.cn:(cd.dflt||0))+'" style="width:52px;font-size:12px;padding:2px;border:1px solid #cbd5e1;border-radius:6px;">%':'')
        +'<span style="font-size:11px;color:#64748b;">なら</span>'
        +'<select data-i="'+i+'" data-k="a" class="def2sel" style="font-size:12px;padding:2px;border:1px solid #cbd5e1;border-radius:6px;">'+optionsHtml(ACT,r.a)+'</select>'
        +'<button data-i="'+i+'" class="def2up" style="font-size:11px;color:#475569;background:#fff;border:1px solid #cbd5e1;border-radius:6px;padding:1px 5px;cursor:pointer;">▲</button>'
        +'<button data-i="'+i+'" class="def2dn" style="font-size:11px;color:#475569;background:#fff;border:1px solid #cbd5e1;border-radius:6px;padding:1px 5px;cursor:pointer;">▼</button>'
        +'<button data-i="'+i+'" class="def2del" style="font-size:11px;color:#dc2626;background:none;border:0;cursor:pointer;">✕</button>'
        +(isDead?'<span style="font-size:10px;color:#9a3412;font-weight:700;">うごきません</span>':'')
        +'</div>';
    }).join('');
    box.innerHTML='<div style="font-weight:800;font-size:12px;color:#334155;">🧩 ③ うごきかたを プログラムする</div>'
      +'<div style="font-size:11px;color:#64748b;margin:2px 0 6px;">上から じゅんに チェックして、さいしょに あてはまった 1つだけ うごくよ。</div>'
      +rows
      +'<button id="def2add" style="font-size:12px;color:#2563eb;background:#eff6ff;border:1px solid #bfdbfe;border-radius:6px;padding:3px 8px;cursor:pointer;">＋ ルールを追加</button>'
      +'<span style="font-size:10px;color:#94a3b8;margin-left:8px;">じどうで ほぞんされるよ</span>';
    box.querySelectorAll('.def2sel').forEach(function(sel){ sel.addEventListener('change',function(){ var i=+this.getAttribute('data-i'),k=this.getAttribute('data-k'); _progRules[i][k]=this.value; if(k==='c'){ var v=this.value; var cd=COND.filter(function(x){return x.v===v;})[0]; _progRules[i].cn=(cd&&cd.num)?(cd.dflt||0):null; } progSaveSoon(); renderEditor(); }); });
    box.querySelectorAll('input[data-k="cn"]').forEach(function(inp){ inp.addEventListener('input',function(){ var i=+this.getAttribute('data-i'); _progRules[i].cn=Number(this.value); progSaveSoon(); }); });
    box.querySelectorAll('.def2del').forEach(function(b){ b.addEventListener('click',function(){ var i=+this.getAttribute('data-i'); if(_progRules.length>1){ _progRules.splice(i,1); progSaveSoon(); renderEditor(); } }); });
    box.querySelectorAll('.def2up').forEach(function(b){ b.addEventListener('click',function(){ var i=+this.getAttribute('data-i'); if(i>0){ var t=_progRules[i]; _progRules[i]=_progRules[i-1]; _progRules[i-1]=t; progSaveSoon(); renderEditor(); } }); });
    box.querySelectorAll('.def2dn').forEach(function(b){ b.addEventListener('click',function(){ var i=+this.getAttribute('data-i'); if(i<_progRules.length-1){ var t=_progRules[i]; _progRules[i]=_progRules[i+1]; _progRules[i+1]=t; progSaveSoon(); renderEditor(); } }); });
    var add=box.querySelector('#def2add'); if(add) add.addEventListener('click',function(){ if(_progRules.length>=12) return; _progRules.push({c:'always',cn:null,a:'attackBase'}); progSaveSoon(); renderEditor(); });
  }
  function tryMountEditor(){
    if(document.getElementById('def2ProgBox')) return;
    var anchor=document.getElementById('defenseBody')||document.getElementById('defenseModal');
    if(!anchor) return;
    var btn=null;
    try{ btn=anchor.querySelector('button[onclick*="_defDoSubmit"]'); }catch(e){}
    if(!btn||!btn.parentNode) return;
    var box=document.createElement('div'); box.id='def2ProgBox'; box.style.cssText='background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:8px;margin:8px 0;';
    btn.parentNode.insertBefore(box, btn); renderEditor();"""



def chain_count(s):
    i = s.index(CHAIN_START)
    j = s.index(CHAIN_END, i)
    return s[i:j].count('.replace(')


def main():
    d = io.open(D2, encoding='utf-8').read()
    s = io.open(TSX, encoding='utf-8').read()

    if MARK in d:
        print('already applied: ' + MARK + ' / 何もしない')
        return 0

    for label, text, target in (
        ('状態のはじまり', HEAD, d),
        ('組みこみの行', TAIL, d),
        ('よみこみ', OLD_SRC, s),
        ('root', CHAIN_START, s),
        ('logout', CHAIN_END, s),
        ("配る道", "app.get('/defense2.js'", s),
    ):
        n = target.count(text)
        if n != 1:
            print('NG: アンカー %s が %d 件（期待 1）' % (label, n))
            return 1

    before = chain_count(s)
    if before != CHAIN_N:
        print('NG: チェーンが %d 件（期待 %d）' % (before, CHAIN_N))
        return 1

    i = d.index(HEAD)
    j = d.index(TAIL) + len(TAIL)
    if j <= i:
        print('NG: アンカーの前後がおかしい')
        return 1

    region = d[i:j]
    for need in ('function renderEditor()', 'function tryMountEditor()',
                 'def2ProgBox', 'progFromRules', 'optionsHtml', '_progRules'):
        if need not in region:
            print('NG: 置きかえる範囲に %s が無い' % need)
            return 1

    rest = d[:i] + d[j:]
    for gone in ('function renderEditor()', 'function tryMountEditor()',
                 'def2ProgBox', 'optionsHtml', '_progRules'):
        if gone in rest:
            print('NG: %s が置きかえる範囲の外にもある' % gone)
            return 1

    nd = d[:i] + NEW_BLOCK + d[j:]
    ns = s.replace(OLD_SRC, NEW_SRC)

    ok = True
    for label, got, want in (
        ('目じるし', nd.count(MARK), 1),
        ('ボタンの上に入れる', nd.count('btn.parentNode.insertBefore(box, btn)'), 1),
        ('出陣ボタンをさがす', nd.count('button[onclick*="_defDoSubmit"]'), 1),
        ('_defDoSubmit の参照', nd.count('_defDoSubmit'), 5),
        ('末尾に落ちる書き方が消えた', nd.count('anchor.appendChild(box)'), 0),
        ('ほぞん先', nd.count('p.defProgram'), 2),
        ('ほぞんの呼び出し', nd.count('window.saveData()'), 1),
        ('おしらせ', nd.count('この下は うごきません'), 1),
        ('灰色の目じるし', nd.count('うごきません'), 2),
        ('progFromRules', nd.count('function progFromRules()'), 1),
        ('renderEditor', nd.count('function renderEditor()'), 1),
        ('tryMountEditor', nd.count('function tryMountEditor()'), 1),
        ('ensureRules', nd.count('function ensureRules()'), 1),
        ('optionsHtml', nd.count('function optionsHtml('), 1),
        ('早期抜け', nd.count('__DEF2_SKIP_LOCAL_V1__'), 1),
        ('makeResolve', nd.count('function makeResolve(o'), 1),
        ('新しいよみこみ', ns.count(NEW_SRC), 1),
        ('古いよみこみ', ns.count(OLD_SRC), 0),
        ('チェーン', chain_count(ns), CHAIN_N),
    ):
        if got != want:
            print('NG: %s が %d 件（期待 %d）' % (label, got, want))
            ok = False

    if nd == d or ns == s:
        print('NG: 中身が変わっていない')
        ok = False

    if not ok:
        print('NG: 自己点検に落ちたので書き込まない')
        return 1

    io.open(D2, 'w', encoding='utf-8').write(nd)
    io.open(TSX, 'w', encoding='utf-8').write(ns)
    print('OK: ' + MARK + ' を適用した（チェーンは %d 件のまま）' % CHAIN_N)
    return 0


if __name__ == '__main__':
    sys.exit(main())
