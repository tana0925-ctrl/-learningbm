import { JSDOM } from 'jsdom';
import fs from 'fs';
const html=fs.readFileSync('public/index.html','utf8');
const i=html.indexOf('const CURRICULUM = {'); let d=0,k=html.indexOf('{',i);
for(;;k++){ if(html[k]=='{')d++; else if(html[k]=='}'){d--; if(!d)break;} }
const cur=html.slice(i+'const CURRICULUM = '.length,k+1);
const dom=new JSDOM('<!doctype html><body><div id="training-subject-select"><div class="grid"></div></div></body>',{runScripts:'outside-only',url:'https://x.test/'});
const w=dom.window; w.eval('window.CURRICULUM='+cur); w.__userGrade=6;
// add g6x units
w.CURRICULUM.math.grades[6].units.push({id:'m6-scale',name:'拡大図と縮図'},{id:'m6-prism',name:'角柱と円柱の体積'},{id:'m6-data',name:'データの調べ方'});
w.fetch=async()=>({ok:true,json:async()=>({ok:true,manual:'',memo:[],classUnits:[{unit:'m6-ratio',users:2,n:99,users7:2,n7:99}],mine:[{unit:'m6-ratio',n:5}],unitProgress:null})});
w.eval(fs.readFileSync('public/hscheck.js','utf8'));
const H=w.HSCHECK; let bad=0;
for(const s of H.S){ for(let t=0;t<150;t++){ const Q=s.gen(); let A;
  if(Q.type==='num')A={x:Q.ans}; else if(Q.type==='rem')A={q:Q.ans[0],r:Q.ans[1]}; else if(Q.type==='ratio')A={a:Q.ans[0],b:Q.ans[1]}; else if(Q.type==='hm'||Q.type==='pair')A={h:Q.ans[0],m:Q.ans[1]};
  else { const [N,D]=Q.ans; const g=(a,b)=>b?g(b,a%b):a; const G=g(N,D); let n=N/G,dd=D/G; if(Q.mixedForm&&n>=dd&&n%dd){A={w:Math.floor(n/dd),n:n%dd,d:dd};} else if(n%dd===0&&!Q.improperForm){A={w:n/dd,n:0,d:1,only:true};} else A={w:0,n,d:dd}; }
  if(!H._t.judge(Q,A)){bad++; if(bad<5)console.log('BAD',s.id,JSON.stringify(Q).slice(0,200));}
}}
console.log('gen check bad=',bad);
for(const [u,g] of Object.entries(H.UNIT2GOAL)) if(!H.S.find(s=>s.id===g)) console.log('missing goal',u,g);
for(const s of H.S) if(!(s.id in H.SK2UNIT)) console.log('missing map',s.id);
// flow
await new Promise(r=>setTimeout(r,1500));
const e=w.document.querySelector('.hkEntry'); console.log('entry:',e&&e.textContent);
H.open(''); await new Promise(r=>setTimeout(r,50));
const st=H._t.state(); console.log(st.log.map(x=>x.t).join(' / '));
w.document.querySelector('#hkFoot [data-i="0"]').click();
// answer everything wrong via わからない
for(let n=0;n<60 && H._t.state() && H._t.state().step==='quiz';n++){ const f=w.document.getElementById('hkFoot'); const b=f.querySelector('[data-i]'); if(H._t.state().answered) b.click(); else f.querySelectorAll('[data-i]')[1].click(); }
const s2=H._t.state(); console.log(s2.step, s2.log.filter(x=>!x.html||x.t.indexOf('<')<0).slice(-8).map(x=>x.t).join('\n'));
console.log("go",s2.go); process.exit(bad||!s2.go.length?1:0);
