/* 🔍 HSCHECK_V1 阪神マンと 理解度チェック（子どもの画面・算数）— 2026-11-10
 *  ・「今『比』の学習してるんやろ？ 必要な技が 身についてるか 理解度チェック してみるか？」と 阪神マンが 聞く。
 *    いまの単元は カルテの「いまの単元」と同じ順（先生が選んだ → 授業メモ → クラスの記録 → 標準の進み方）。/api/student/check-now
 *  ・問題は「学びのどうぐ箱」の「ここはできてる？チェック」と同じ技・同じ問題づくり（2問正解で⭕、2問まちがいで❌）。
 *    ❌のときは その前に学ぶ技（前の学年）へ さかのぼる。いちばん根っこの❌を「ここから修行に もどると ええで」と伝え、
 *    LearningBM の 修行の単元へ そのまま 行ける ボタンを 出す。修行に ない技は やり方だけ 伝える。
 *  ・入口：修行の「科目を選べ」画面と 算数の単元えらびの上（小1〜小6）。コインは 出さない。index.html は 手で 編集しない。
 */
(function () {
'use strict';
if (window.__HSCHECK_V1__) return; window.__HSCHECK_V1__ = 1;
const ri=(a,b)=>a+Math.floor(Math.random()*(b-a+1));
const pick=a=>a[Math.floor(Math.random()*a.length)];
const fm=x=>String(Math.round(x*100000)/100000);
const fr=(n,d)=>`<span class="frac" data-say="${d}分の${n}"><span>${n}</span><span>${d}</span></span>`;
const mx=(w,n,d)=>`<span data-say="${w}と${d}分の${n}">${w}${fr(n,d)}</span>`;
const red=(n,d)=>{const g=gcd(n,d);return [n/g,d/g];};
function copair(max){let m,n;do{m=ri(1,max);n=ri(1,max);}while(m===n||gcd(m,n)!==1);return [m,n];}
function properCo(d){let n;do{n=ri(1,d-1);}while(gcd(n,d)!==1);return n;}
function gcd(a,b){a=Math.abs(a);b=Math.abs(b);while(b){[a,b]=[b,a%b];}return a;}
function lcm(a,b){return a/gcd(a,b)*b;}
function clockSVG(h,m,o){o=o||{};const R=100;let s=`<svg viewBox="-${o.labels?128:108} -${o.labels?128:108} ${o.labels?256:216} ${o.labels?256:216}" class="clocksvg" ${o.size?`width="${o.size}" height="${o.size}"`:''}>`;
 s+=`<circle r="${R}" fill="#fffdf6" stroke="#333" stroke-width="5"/>`;
 for(let i=0;i<60;i++){const a=i*6*Math.PI/180,l=i%5===0?14:6,w=i%5===0?3:1.5;s+=`<line x1="${Math.sin(a)*(R-l)}" y1="${-Math.cos(a)*(R-l)}" x2="${Math.sin(a)*(R-2)}" y2="${-Math.cos(a)*(R-2)}" stroke="#333" stroke-width="${w}"/>`;}
 for(let i=1;i<=12;i++){const a=i*30*Math.PI/180;s+=`<text x="${Math.sin(a)*72}" y="${-Math.cos(a)*72+7}" text-anchor="middle" font-size="20" font-weight="bold" fill="#333">${i}</text>`;}
 if(o.labels)for(let i=0;i<12;i++){const a=i*30*Math.PI/180;s+=`<text x="${Math.sin(a)*116}" y="${-Math.cos(a)*116+5}" text-anchor="middle" font-size="13" fill="#2f6fdb" font-weight="bold">${i*5}</text>`;}
 const ha=((h%12)*30+m*0.5)*Math.PI/180,ma=m*6*Math.PI/180;
 s+=`<line x1="0" y1="0" x2="${Math.sin(ha)*52}" y2="${-Math.cos(ha)*52}" stroke="#d9473b" stroke-width="8" stroke-linecap="round"/>`;
 s+=`<line class="mhand" x1="0" y1="0" x2="${Math.sin(ma)*84}" y2="${-Math.cos(ma)*84}" stroke="#2f6fdb" stroke-width="5" stroke-linecap="round"/>`;
 s+=`<circle r="6" fill="#333"/></svg>`;return s;}
function numlineSVG(o){/* o:{n,label(i),long(i),mid(i),mark,hl,top(i)} */
 const W=1000,x0=40,x1=960,y=70;const X=i=>x0+i*(x1-x0)/o.n;let s=`<svg viewBox="0 0 ${W} 130" class="nlsvg" preserveAspectRatio="xMidYMid meet">`;
 s+=`<line x1="${x0-20}" y1="${y}" x2="${x1+25}" y2="${y}" stroke="#333" stroke-width="3"/><polygon points="${x1+25},${y-7} ${x1+38},${y} ${x1+25},${y+7}" fill="#333"/>`;
 for(let i=0;i<=o.n;i++){const L=o.long&&o.long(i)?22:(o.mid&&o.mid(i)?15:9);const x=X(i);
  if(o.hl===i)s+=`<rect x="${x-12}" y="${y-30}" width="24" height="60" rx="6" fill="#fff1bf"/>`;
  s+=`<line x1="${x}" y1="${y-L}" x2="${x}" y2="${y+L}" stroke="#333" stroke-width="${L>20?3:2}"/>`;
  const lb=o.label&&o.label(i);if(lb!=null)s+=fracText(lb,x,y+48,22,'#333');
  const tp=o.top&&o.top(i);if(tp!=null)s+=fracText(tp,x,y-36,15,'#2f6fdb');}
 if(o.mark!=null){const x=X(o.mark);s+=`<polygon points="${x-11},${y-44} ${x+11},${y-44} ${x},${y-26}" fill="#d9473b"/>`;}
 return s+'</svg>';}
function protractorSVG(a,baseLeft,o){o=o||{};const R=100;const P=(r,t)=>[r*Math.cos(t*Math.PI/180),-r*Math.sin(t*Math.PI/180)];
 let s=`<svg viewBox="-125 -122 250 140" class="protsvg">`;
 s+=`<path d="M -${R} 0 A ${R} ${R} 0 0 1 ${R} 0 Z" fill="#eef6ff" stroke="#6b8fc7" stroke-width="1.5"/>`;
 for(let t=0;t<=180;t++){const l=t%10===0?11:(t%5===0?7:4);const [xa,ya]=P(R,t),[xb,yb]=P(R-l,t);s+=`<line x1="${xa}" y1="${ya}" x2="${xb}" y2="${yb}" stroke="#335" stroke-width="${t%10===0?1.2:.6}"/>`;}
 const okOuter=!baseLeft;const cO=okOuter?'#d9473b':'#9aa',cI=okOuter?'#9aa':'#d9473b';
 for(let t=0;t<=180;t+=10){const [x1,y1]=P(R-19,t),[x2,y2]=P(R-34,t);
  s+=`<text x="${x1}" y="${y1+3}" text-anchor="middle" font-size="8.5" font-weight="${okOuter?'bold':'normal'}" fill="${cO}">${t}</text>`;
  s+=`<text x="${x2}" y="${y2+3}" text-anchor="middle" font-size="8" font-weight="${okOuter?'normal':'bold'}" fill="${cI}">${180-t}</text>`;}
 const base=baseLeft?180:0,ray=baseLeft?180-a:a;const [bx,by]=P(118,base),[rx,ry]=P(118,ray);
 if(o.arc!==false){const [ax,ay]=P(24,base),[cx,cy]=P(24,ray);s+=`<path d="M ${ax} ${ay} A 24 24 0 0 ${baseLeft?1:0} ${cx} ${cy}" fill="none" stroke="#f39c12" stroke-width="3"/>`;}
 s+=`<line x1="0" y1="0" x2="${bx}" y2="${by}" stroke="#222" stroke-width="3"/>`;
 s+=`<line class="ray" x1="0" y1="0" x2="${rx}" y2="${ry}" stroke="#1e9e5a" stroke-width="3"/>`;
 if(o.handle)s+=`<circle cx="${rx}" cy="${ry}" r="7" fill="#1e9e5a"/>`;
 s+=`<circle r="3" fill="#d9473b"/></svg>`;return s;}
function barSVG(o){const L=78,R=600,T=34,B=310;const n=o.cats.length,max=o.unit*o.ticks;const Y=v=>B-(v/max)*(B-T);
 let s=`<svg viewBox="0 0 620 360" class="grsvg">`;s+=`<text x="${L-8}" y="20" text-anchor="end" font-size="15" fill="#555">（${o.uname}）</text>`;
 const lstep=o.ticks>10?5:1;
 for(let k=0;k<=o.ticks;k++){const y=Y(k*o.unit);s+=`<line x1="${L}" y1="${y}" x2="${R}" y2="${y}" stroke="${k%5===0?'#999':'#ddd'}" stroke-width="${k%5===0?1.5:1}"/>`;if(k%lstep===0)s+=`<text x="${L-8}" y="${y+5}" text-anchor="end" font-size="15" fill="#333">${k*o.unit}</text>`;}
 const cw=(R-L)/n;o.vals.forEach((v,i)=>{const x=L+i*cw+cw*0.22;s+=`<rect data-i="${i}" x="${x}" y="${Y(v)}" width="${cw*0.56}" height="${B-Y(v)}" fill="${o.hl===i?'#f39c12':'#5b8def'}" style="cursor:pointer"/>`;
  s+=`<text x="${L+i*cw+cw/2}" y="${B+24}" text-anchor="middle" font-size="15" fill="#333">${o.cats[i]}</text>`;});
 s+=`<line x1="${L}" y1="${T-6}" x2="${L}" y2="${B}" stroke="#333" stroke-width="2"/><line x1="${L}" y1="${B}" x2="${R}" y2="${B}" stroke="#333" stroke-width="2"/>`;
 return s+`<text x="340" y="352" text-anchor="middle" font-size="16" font-weight="bold">${o.title}</text></svg>`;}
function lineSVG(o){const L=78,R=600,T=34,B=300;const n=o.cats.length;const base=o.base,max=base+o.unit*o.ticks;const Y=v=>B-((v-base)/(max-base))*(B-T);
 let s=`<svg viewBox="0 0 620 360" class="grsvg">`;s+=`<text x="${L-8}" y="20" text-anchor="end" font-size="15" fill="#555">（${o.uname}）</text>`;
 for(let k=0;k<=o.ticks;k++){const v=base+k*o.unit,y=Y(v);s+=`<line x1="${L}" y1="${y}" x2="${R}" y2="${y}" stroke="${v%5===0?'#999':'#ddd'}"/>`;if(v%5===0)s+=`<text x="${L-8}" y="${y+5}" text-anchor="end" font-size="15">${v}</text>`;}
 const cw=(R-L)/(n-1+0.6),X=i=>L+cw*(i+0.3);
 s+=`<line x1="${L}" y1="${T-6}" x2="${L}" y2="${B+30}" stroke="#333" stroke-width="2"/><line x1="${L}" y1="${B+30}" x2="${R}" y2="${B+30}" stroke="#333" stroke-width="2"/>`;
 if(base>0){s+=`<text x="${L-8}" y="${B+35}" text-anchor="end" font-size="15">0</text><path d="M ${L-9} ${B+10} q 4.5 -5 9 0 t 9 0 M ${L-9} ${B+17} q 4.5 -5 9 0 t 9 0" fill="none" stroke="#d9473b" stroke-width="2"/>`;}
 let d='';o.vals.forEach((v,i)=>{d+=(i?'L':'M')+X(i)+' '+Y(v)+' ';});s+=`<path d="${d}" fill="none" stroke="#2f6fdb" stroke-width="3"/>`;
 o.vals.forEach((v,i)=>{s+=`<circle data-i="${i}" cx="${X(i)}" cy="${Y(v)}" r="${o.hl===i?9:6}" fill="${o.hl===i?'#f39c12':'#2f6fdb'}" style="cursor:pointer"/><text x="${X(i)}" y="${B+52}" text-anchor="middle" font-size="15">${o.cats[i]}</text>`;});
 return s+`<text x="340" y="356" text-anchor="middle" font-size="0">.</text></svg>`;}
function rulerSVG(o){const x0=30,k=6,Y=40;let s=`<svg viewBox="0 0 990 140" class="rulsvg">`;
 s+=`<rect x="10" y="${Y}" width="${x0+150*k}" height="80" rx="6" fill="#fff6d6" stroke="#b8963c" stroke-width="2"/>`;
 for(let m=0;m<=150;m++){const x=x0+m*k,l=m%10===0?32:(m%5===0?22:13);s+=`<line x1="${x}" y1="${Y}" x2="${x}" y2="${Y+l}" stroke="#333" stroke-width="${m%10===0?2:1}"/>`;if(m%10===0)s+=`<text x="${x}" y="${Y+52}" text-anchor="middle" font-size="16">${m/10}</text>`;}
 s+=`<text x="${x0+150*k-8}" y="${Y+74}" text-anchor="end" font-size="13" fill="#555">cm</text>`;
 const a=x0+o.s*k,b=x0+o.e*k;s+=`<rect x="${a}" y="${Y-26}" width="${b-a}" height="22" fill="#5b8def" rx="3"/>`;
 if(o.handle)s+=`<circle class="hd" cx="${b}" cy="${Y-15}" r="11" fill="#d9473b"/>`;
 return s+'</svg>';}
function scaleSVG(o){/* o:{max,unit,step,w} */const R=105,n=o.max/o.unit;let s=`<svg viewBox="-130 -130 260 260" class="scsvg">`;
 s+=`<circle r="122" fill="#e6e6e6" stroke="#888" stroke-width="3"/><circle r="${R+6}" fill="#fff" stroke="#333" stroke-width="2"/>`;
 const per=o.step/o.unit;
 for(let i=0;i<n;i++){const a=i*360/n*Math.PI/180;const l=i%per===0?14:((per%2===0&&i%(per/2)===0)?10:(i%5===0?7:4));
  s+=`<line x1="${Math.sin(a)*R}" y1="${-Math.cos(a)*R}" x2="${Math.sin(a)*(R-l)}" y2="${-Math.cos(a)*(R-l)}" stroke="#333" stroke-width="${i%per===0?2:.8}"/>`;
  if(i%per===0){const v=i*o.unit;const t=v%1000===0?(v===0?'0':`${v/1000}kg`):String(v%1000);s+=`<text x="${Math.sin(a)*(R-30)}" y="${-Math.cos(a)*(R-30)+5}" text-anchor="middle" font-size="${t.length>3?11:13}" font-weight="bold">${t}</text>`;}}
 s+=`<text x="0" y="40" text-anchor="middle" font-size="12" fill="#555">${o.max/1000}kgまで</text>`;
 const a=(o.w/o.max*360)*Math.PI/180;s+=`<line class="needle" x1="0" y1="0" x2="${Math.sin(a)*(R-4)}" y2="${-Math.cos(a)*(R-4)}" stroke="#d9473b" stroke-width="3" stroke-linecap="round"/><circle r="6" fill="#d9473b"/>`;
 return s+'</svg>';}
function bandSVG(o){const L=40,R=580,y=110,h=56;const C=['#ffb347','#79a8f0','#7fd3a3','#f5a0b8','#c9b3f2'];let s=`<svg viewBox="0 0 620 220" class="grsvg">`;
 s+=`<text x="310" y="30" text-anchor="middle" font-size="16" font-weight="bold">${o.title}</text>`;
 for(let k=0;k<=100;k+=10){const x=L+(R-L)*k/100;s+=`<line x1="${x}" y1="${y-10}" x2="${x}" y2="${y}" stroke="#333"/><text x="${x}" y="${y-16}" text-anchor="middle" font-size="13">${k}</text>`;}
 for(let k=0;k<=100;k++){const x=L+(R-L)*k/100;s+=`<line x1="${x}" y1="${y-4}" x2="${x}" y2="${y}" stroke="#666" stroke-width=".6"/>`;}
 let acc=0;o.vals.forEach((v,i)=>{const x=L+(R-L)*acc/100,w=(R-L)*v/100;s+=`<rect data-i="${i}" x="${x}" y="${y}" width="${w}" height="${h}" fill="${o.hl===i?'#f39c12':C[i%5]}" stroke="#333" style="cursor:pointer"/><text x="${x+w/2}" y="${y+h/2+6}" text-anchor="middle" font-size="${w<45?12:15}" pointer-events="none">${o.cats[i]}</text>`;acc+=v;});
 return s+`<text x="${R}" y="${y+h+26}" text-anchor="end" font-size="14" fill="#555">（%）　全体 ${o.total}${o.uname}</text></svg>`;}
function fracText(t,x,y,fs,col){t=String(t);const m=t.match(/^(\d+)\/(\d+)$/);if(!m)return `<text x="${x}" y="${y}" text-anchor="middle" font-size="${fs}" font-weight="bold" fill="${col}">${t}</text>`;
 return `<text x="${x}" y="${y-fs*0.55}" text-anchor="middle" font-size="${fs*0.8}" font-weight="bold" fill="${col}">${m[1]}</text><line x1="${x-fs*0.5}" y1="${y-fs*0.4}" x2="${x+fs*0.5}" y2="${y-fs*0.4}" stroke="${col}" stroke-width="2"/><text x="${x}" y="${y+fs*0.45}" text-anchor="middle" font-size="${fs*0.8}" font-weight="bold" fill="${col}">${m[2]}</text>`;}
const GR_TOPICS=[['すきなくだもの','人',['りんご','みかん','バナナ','いちご','ぶどう']],['図書室でかりた本','さつ',['物語','図かん','伝記','まんが','詩']],['通った車の数','台',['乗用車','トラック','バス','バイク','自転車']],['集めたキャップ','こ',['1組','2組','3組','4組','5組']]];
const S=[
{id:'g1_count',g:1,name:'10までの数（いくつといくつ）',pre:[],tool:'block',how:'10までの数を2つに分けて考えるよ。ブロックやおはじきを分けてみよう。',
 gen:()=>{const n=ri(5,10),a=ri(1,n-1);return {q:`${n} は ${a} と □`,type:'num',ans:n-a};}},
{id:'g1_add1',g:1,name:'たし算（くり上がりなし）',pre:['g1_count'],tool:'block',how:'大きい方の数から、のこりの数だけ数えていこう。',
 gen:()=>{const a=ri(1,8),b=ri(1,10-a);return {q:`${a} + ${b}`,type:'num',ans:a+b};}},
{id:'g1_sub1',g:1,name:'ひき算（くり下がりなし）',pre:['g1_count'],tool:'block',how:'「いくつといくつ」を使うよ。7−3 は「7は3と4」だから 4。',
 gen:()=>{const a=ri(3,10),b=ri(1,a-1);return {q:`${a} − ${b}`,type:'num',ans:a-b};}},
{id:'g1_add_carry',g:1,name:'くり上がりのあるたし算',pre:['g1_add1'],tool:'block',how:'10のまとまりを作ろう。9+4 は、4を1と3に分けて、9+1=10、10+3=13。',
 gen:()=>{const a=ri(2,9),b=ri(Math.max(2,11-a),9);return {q:`${a} + ${b}`,type:'num',ans:a+b};}},
{id:'g1_sub_borrow',g:1,name:'くり下がりのあるひき算',pre:['g1_sub1'],tool:'block',how:'13−8 は、13を10と3に分けて、10−8=2、2+3=5。',
 gen:()=>{const x=ri(1,8),b=ri(x+1,9);return {q:`${10+x} − ${b}`,type:'num',ans:10+x-b};}},

{id:'g1_clock',g:1,name:'時計（何時・何時半）',pre:['g1_count'],tool:'clock',how:'短いはりで「何時」を読む。長いはりが 12 なら「ちょうど」、6 なら「半（30分）」。',
 gen:()=>{const h=ri(1,12),m=pick([0,30]);return {q:`<div class="qclk">${clockSVG(h,m,{size:170})}</div>何時何分？`,type:'hm',ans:[h,m]};}},
{id:'g2_place',g:2,name:'3けたの数のしくみ',pre:['g1_count'],tool:'place',how:'百の位・十の位・一の位に、こ数をならべて書くよ。0このところは0を書く。',
 gen:()=>{const h=ri(1,9),t=ri(0,9),o=ri(0,9);return {q:`100を ${h}こ、10を ${t}こ、1を ${o}こ あわせた数は？`,type:'num',ans:h*100+t*10+o};}},
{id:'g2_mm',g:2,name:'長さの単位（cm・mm）',pre:['g2_place'],tool:'unit',how:'1cm = 10mm。3cm5mm は 30mm と 5mm で 35mm。',
 gen:()=>{const c=ri(1,15),m=ri(1,9);return {q:`${c}cm ${m}mm = □ mm`,type:'num',ans:c*10+m};}},
{id:'g2_ruler',g:2,name:'ものさしの読み方',pre:['g2_mm'],tool:'ruler',how:'数字の目もりが1cm、小さい目もり1つが1mm。まん中の少し長い目もりは5mm。',
 gen:()=>{const L=ri(12,140);return {q:`<div class="qrul">${rulerSVG({s:0,e:L})}</div>青いテープの長さは？`,type:'pair',labels:['cm','mm'],ans:[Math.floor(L/10),L%10]};}},
{id:'g2_kasa',g:2,name:'かさの単位（L・dL・mL）',pre:['g2_place'],tool:'unit',how:'1L = 10dL、1L = 1000mL、1dL = 100mL。',
 gen:()=>{const f=ri(1,3);if(f===1){const a=ri(1,9),b=ri(1,9);return {q:`${a}L ${b}dL = □dL`,type:'num',ans:a*10+b};}if(f===2){const a=ri(1,9);return {q:`${a}L = □mL`,type:'num',ans:a*1000};}const a=ri(1,5),b=ri(1,9);return {q:`${a*10+b}dL = □L ${b}dL`,type:'num',ans:a};}},
{id:'g2_add2',g:2,name:'2けたのたし算（筆算）',pre:['g1_add_carry','g2_place'],tool:['hissan','block'],how:'一の位からたすよ。10をこえたら、十の位に1くり上げる。',
 gen:()=>{const a=ri(15,79),b=ri(15,89);return {q:`${a} + ${b}`,type:'num',ans:a+b};}},
{id:'g2_sub2',g:2,name:'2けたのひき算（筆算）',pre:['g1_sub_borrow','g2_place'],tool:['hissan','block'],how:'一の位からひくよ。ひけないときは、十の位から10をかりてくる（くり下がり）。',
 gen:()=>{const ao=ri(0,8),bo=ri(ao+1,9),at=ri(2,9),bt=ri(1,at-1);return {q:`${at*10+ao} − ${bt*10+bo}`,type:'num',ans:(at-bt)*10+ao-bo};}},
{id:'g2_kuku_25',g:2,name:'九九（2・5・3・4の段）',pre:['g1_add1'],tool:'kuku',how:'段の数ずつふえていくよ。九九表で見て、となえて覚えよう。',
 gen:()=>{const d=pick([2,5,3,4]),k=ri(2,9);return {q:`${d} × ${k}`,type:'num',ans:d*k};}},
{id:'g2_kuku_all',g:2,name:'九九（6・7・8・9の段）',pre:['g2_kuku_25'],tool:'kuku',how:'6×7 は 7×6 と同じ。知っている九九から考えてもいいよ。九九表で練習しよう。',
 gen:()=>{const d=pick([6,7,8,9]),k=ri(2,9);return {q:`${d} × ${k}`,type:'num',ans:d*k};}},

{id:'g2_clock',g:2,name:'時計（何時何分）',pre:['g1_clock','g2_kuku_25'],tool:'clock',how:'長いはりは、数字1つで5分。5とびで数えて、のこりの小さい目もりをたす。短いはりは、小さい方の数字を読む。',
 gen:()=>{const h=ri(1,12),m=ri(1,59);return {q:`<div class="qclk">${clockSVG(h,m,{size:170})}</div>何時何分？`,type:'hm',ans:[h,m]};}},
{id:'g2_time_calc',g:2,name:'時こくと時間',pre:['g2_clock'],tool:'clock',how:'ちょうどの時こく（○時）をはさんで考えよう。8時40分の30分後は、9時まで20分、のこり10分で 9時10分。',
 gen:()=>{const h=ri(1,10),m=ri(2,11)*5,x=ri(2,11)*5;if(Math.random()<.5){const t=h*60+m+x;return {q:`${h}時${m}分 の ${x}分後は？`,type:'hm',ans:[Math.floor(t/60),t%60]};}const m2=ri(0,11)*5;return {q:`${h}時${m}分 から ${h+1}時${m2}分 まで 何分？`,type:'num',ans:60-m+m2};}},
{id:'g3_large_num',g:3,name:'大きな数（万の位）',pre:['g2_place'],tool:'place',how:'一・十・百・千のつぎは、一万・十万・百万・千万。4けたごとに区切ると読みやすいよ。',
 gen:()=>{const f=ri(1,3);if(f===1){const a=ri(1,9),b=ri(1,9),c=ri(0,9);return {q:`1万を ${a}こ、1000を ${b}こ、100を ${c}こ あわせた数は？`,type:'num',ans:a*10000+b*1000+c*100};}if(f===2){const n=ri(11,99);return {q:`${n*1000} は、1000を □こ 集めた数`,type:'num',ans:n};}const n=ri(12,999);return {q:`${n} を10倍した数は？`,type:'num',ans:n*10};}},
{id:'g3_dec_place',g:3,name:'小数のしくみ（0.1の位）',pre:['g2_place'],tool:'place',how:'1を10こに分けた1こ分が 0.1。2.3 は 0.1 が 23こ。',
 gen:()=>{let n=ri(11,99);if(n%10===0)n++;if(Math.random()<.5)return {q:`0.1を ${n}こ 集めた数は？`,type:'num',ans:n/10};return {q:`${fm(n/10)} は、0.1を □こ 集めた数`,type:'num',ans:n};}},
{id:'g3_numline',g:3,name:'数直線の読み方',pre:['g3_dec_place','g2_place'],tool:'numline',how:'まず1目もりの大きさを見つける。数字の書いてある目もりの間が、いくつに分かれているかを数えよう。',
 gen:()=>{let i;do{i=ri(1,19);}while(i===10);if(Math.random()<.5){const svg=numlineSVG({n:20,label:j=>j%10===0?String(j/10):null,long:j=>j%10===0,mid:j=>j%5===0,mark:i});return {q:`<div class="qnl">${svg}</div>▼の目もりが表す数は？`,type:'num',ans:i/10};}
  const st=pick([10,100]);const svg=numlineSVG({n:20,label:j=>j%10===0?String(j*st):null,long:j=>j%10===0,mid:j=>j%5===0,mark:i});return {q:`<div class="qnl">${svg}</div>▼の目もりが表す数は？`,type:'num',ans:i*st};}},
{id:'g3_bargraph',g:3,name:'棒グラフの読み方',pre:['g2_kuku_25','g3_numline'],tool:'graph',how:'まず1目もりの大きさを見つける。数字が書いてある目もりの間が、何目もりに分かれているかを数えよう。',
 gen:()=>{const t=pick(GR_TOPICS);const unit=pick([2,5,10,20,50]);const ticks=pick([10,15,20]);const n=4;const vals=[];for(let i=0;i<n;i++)vals.push(unit*ri(1,ticks));const i=ri(0,n-1);return {q:`<div class="qgr">${barSVG({title:t[0],uname:t[1],cats:t[2].slice(0,n),vals,unit,ticks})}</div>${t[2][i]}は何${t[1]}？`,type:'num',ans:vals[i]};}},
{id:'g3_add3',g:3,name:'3けたのたし算',pre:['g2_add2'],tool:['hissan','block'],how:'位をそろえて、一の位からじゅんにたす。くり上がりに気をつけよう。',
 gen:()=>{const a=ri(105,789),b=ri(105,999-a);return {q:`${a} + ${b}`,type:'num',ans:a+b};}},
{id:'g3_sub3',g:3,name:'3けたのひき算',pre:['g2_sub2'],tool:['hissan','block'],how:'位をそろえて、一の位からじゅんにひく。くり下がりに気をつけよう。',
 gen:()=>{const a=ri(300,999),b=ri(101,a-100);return {q:`${a} − ${b}`,type:'num',ans:a-b};}},
{id:'g3_div_basic',g:3,name:'わり算（九九で答えが出る）',pre:['g2_kuku_all'],tool:'div',how:'わる数の段の九九で、答えがわられる数になるものをさがすよ。24÷6 → 6×4=24 だから 4。',
 gen:()=>{const d=ri(2,9),q=ri(2,9);return {q:`${d*q} ÷ ${d}`,type:'num',ans:q};}},
{id:'g3_div_rem',g:3,name:'あまりのあるわり算',pre:['g3_div_basic','g1_sub_borrow'],tool:'div',how:'わる数の段で、わられる数をこえない一番大きい九九を見つける。のこりがあまり。あまりは、わる数より小さいよ。',
 gen:()=>{const d=ri(3,9),q=ri(2,9),r=ri(1,d-1);return {q:`${d*q+r} ÷ ${d}`,type:'rem',ans:[q,r]};}},
{id:'g3_mul_2x1',g:3,name:'かけ算（2・3けた×1けた）',pre:['g2_kuku_all','g2_add2'],tool:['hissan','mularea','kuku'],how:'位ごとに分けてかけて、あとでたす。23×4 = 20×4 + 3×4 = 80 + 12 = 92。',
 gen:()=>{const a=Math.random()<.6?ri(12,99):ri(102,489),b=ri(2,9);return {q:`${a} × ${b}`,type:'num',ans:a*b};}},
{id:'g3_mul_2x2',g:3,name:'かけ算（2けた×2けた）',pre:['g3_mul_2x1','g3_add3'],tool:['hissan','mularea'],how:'23×45 は、23×5 と 23×40 を計算してたす（筆算で2だんになる）。',
 gen:()=>{const a=ri(12,98),b=ri(12,98);return {q:`${a} × ${b}`,type:'num',ans:a*b};}},
{id:'g3_dec_add',g:3,name:'小数のたし算・ひき算（0.1の位）',pre:['g2_add2','g2_sub2','g3_dec_place'],tool:'place',how:'小数点の位置をそろえて、整数と同じように計算。答えにも小数点をうつよ。',
 gen:()=>{let a=ri(11,99),b=ri(11,99);if(a%10===0)a++;if(b%10===0)b++;if(Math.random()<.5)return {q:`${fm(a/10)} + ${fm(b/10)}`,type:'num',ans:(a+b)/10};if(a<b)[a,b]=[b,a];if(a===b)a+=1;return {q:`${fm(a/10)} − ${fm(b/10)}`,type:'num',ans:(a-b)/10};}},
{id:'g3_frac_add',g:3,name:'分数のたし算・ひき算（分母が同じ）',pre:['g1_add1','g1_sub1'],tool:'frac',how:'分母が同じなら、分子だけをたす（ひく）。分母はそのまま。',
 gen:()=>{const d=ri(4,9);if(Math.random()<.5){const a=ri(1,d-2),b=ri(1,d-1-a);return {q:`${fr(a,d)} + ${fr(b,d)}`,type:'frac',ans:[a+b,d]};}const a=ri(2,d-1),b=ri(1,a-1);return {q:`${fr(a,d)} − ${fr(b,d)}`,type:'frac',ans:[a-b,d]};}},

{id:'g3_len_weight',g:3,name:'長さ・重さの単位（km・m・kg・g）',pre:['g2_mm','g3_large_num'],tool:'unit',how:'1km = 1000m、1kg = 1000g。1000ずつで単位がかわるよ。',
 gen:()=>{const a=ri(1,9),b=ri(1,999),f=ri(1,3);if(f===1)return {q:`${a}km ${b}m = □m`,type:'num',ans:a*1000+b};if(f===2)return {q:`${a}kg ${b}g = □g`,type:'num',ans:a*1000+b};return {q:`${a*1000+b}g = □kg ${b}g`,type:'num',ans:a};}},
{id:'g3_scale',g:3,name:'はかりの読み方',pre:['g3_len_weight','g3_numline'],tool:'scale',how:'まず1目もりの大きさを見つける。数字と数字の間が何目もりに分かれているかを数えよう。1kg = 1000g。',
 gen:()=>{const M=pick([1000,2000,4000]);const t={1000:[5,100],2000:[10,200],4000:[20,500]}[M];const w=t[0]*ri(3,M/t[0]-2);return {q:`<div class="qsc">${scaleSVG({max:M,unit:t[0],step:t[1],w})}</div>何g？`,type:'num',ans:w};}},
{id:'g3_time',g:3,name:'時間の単位（分・秒）',pre:['g2_time_calc','g2_kuku_all'],tool:'unit',how:'1分 = 60秒、1時間 = 60分。60でくり上がるよ。',
 gen:()=>{const a=ri(1,4),b=ri(1,59);if(Math.random()<.5)return {q:`${a}分 ${b}秒 = □秒`,type:'num',ans:a*60+b};return {q:`${a*60+b}秒 = □分 ${b}秒`,type:'num',ans:a};}},

{id:'g4_large_num',g:4,name:'大きな数（億・兆）',pre:['g3_large_num'],tool:'place',how:'千万のつぎは一億。4けたごとに 万・億・兆 と名前がかわる。10倍すると位が1つ上がる。',
 gen:()=>{const f=ri(1,3);if(f===1){const a=ri(2,9);return {q:`${a}億 は、1万を □こ 集めた数`,type:'num',ans:a*10000};}if(f===2){const a=ri(12,99);return {q:`${a}億 を10倍すると □億`,type:'num',ans:a*10};}const a=ri(2,9),b=ri(1,9);return {q:`1億を ${a}こ、1000万を ${b}こ あわせた数は □万`,type:'num',ans:a*10000+b*1000};}},
{id:'g4_dec_place',g:4,name:'小数のしくみ（0.01・0.001の位）',pre:['g3_dec_place'],tool:'place',how:'0.1を10こに分けた1こ分が 0.01。3.45 は 0.01 が 345こ。',
 gen:()=>{const f=ri(1,3);let n=ri(101,999);if(n%10===0)n++;if(f===1)return {q:`0.01を ${n}こ 集めた数は？`,type:'num',ans:n/100};if(f===2)return {q:`${fm(n/100)} は、0.01を □こ 集めた数`,type:'num',ans:n};return {q:`${fm(n/100)} を10倍した数は？`,type:'num',ans:n/10};}},
{id:'g4_div_1digit',g:4,name:'わり算の筆算（÷1けた）',pre:['g3_div_rem','g3_mul_2x1','g2_sub2'],tool:['hissan','div'],how:'大きい位から「たてる → かける → ひく → おろす」をくりかえすよ。',
 gen:()=>{const d=ri(2,9),q=ri(12,99);if(Math.random()<.5)return {q:`${d*q} ÷ ${d}`,type:'num',ans:q};const r=ri(1,d-1);return {q:`${d*q+r} ÷ ${d}`,type:'rem',ans:[q,r]};}},
{id:'g4_div_2digit',g:4,name:'わり算の筆算（÷2けた）',pre:['g4_div_1digit','g3_mul_2x1'],tool:['hissan','div'],how:'わる数を何十とみて、商の見当をつけよう（仮の商）。大きすぎたら1小さくする。',
 gen:()=>{const d=ri(12,39),q=ri(2,25),r=Math.random()<.5?0:ri(1,d-1);return {q:`${d*q+r} ÷ ${d}`,type:'rem',ans:[q,r]};}},
{id:'g4_dec_add2',g:4,name:'小数のたし算・ひき算（0.01の位）',pre:['g3_dec_add','g4_dec_place'],tool:'place',how:'小数点をそろえて書く。けたが足りないところは0があると考えよう。3.45+1.7 → 3.45+1.70。',
 gen:()=>{let a=ri(101,999),b=Math.random()<.5?ri(11,99)*10:ri(101,999);if(Math.random()<.5)return {q:`${fm(a/100)} + ${fm(b/100)}`,type:'num',ans:(a+b)/100};if(a<b)[a,b]=[b,a];if(a===b)a+=7;return {q:`${fm(a/100)} − ${fm(b/100)}`,type:'num',ans:(a-b)/100};}},
{id:'g4_dec_mul_int',g:4,name:'小数×整数',pre:['g3_mul_2x1','g3_dec_add'],tool:'place',how:'小数を10倍して整数としてかけ、さいごに10でわる。2.3×4 → 23×4=92 → 9.2。',
 gen:()=>{let a=ri(11,99);if(a%10===0)a++;const b=ri(2,9);return {q:`${fm(a/10)} × ${b}`,type:'num',ans:a*b/10};}},
{id:'g4_dec_div_int',g:4,name:'小数÷整数',pre:['g4_div_1digit','g3_dec_add'],tool:'div',how:'整数と同じようにわって、商の小数点は、わられる数の小数点にそろえてうつよ。',
 gen:()=>{let q=ri(11,99);if(q%10===0)q++;const d=ri(2,9);return {q:`${fm(q*d/10)} ÷ ${d}`,type:'num',ans:q/10};}},
{id:'g4_frac_mixed',g:4,name:'帯分数と仮分数',pre:['g3_frac_add','g3_div_rem'],tool:'frac',how:'仮分数→帯分数：分子÷分母の商が整数、あまりが分子。帯分数→仮分数：整数×分母＋分子 が新しい分子。',
 gen:()=>{const w=ri(1,4),d=ri(2,9),n=ri(1,d-1);if(Math.random()<.5)return {q:`${fr(w*d+n,d)} を帯分数に`,type:'frac',ans:[w*d+n,d],whole:true,mixedForm:true};return {q:`${mx(w,n,d)} を仮分数に`,type:'frac',ans:[w*d+n,d],whole:true,improperForm:true};}},
{id:'g4_frac_add',g:4,name:'分数のたし算・ひき算（帯分数をふくむ）',pre:['g4_frac_mixed'],tool:'frac',how:'分母が同じなら、整数どうし・分子どうしを計算。分子が分母以上になったら整数にくり上げる。',
 gen:()=>{const d=ri(3,9),f=ri(1,3);if(f===1){const a=ri(1,d-1),b=ri(d-a,d-1);return {q:`${fr(a,d)} + ${fr(b,d)}`,type:'frac',ans:[a+b,d],whole:true};}
  const w1=ri(1,3),n1=ri(1,d-1),n2=ri(1,d-1);if(f===2){const w2=ri(1,2);return {q:`${mx(w1,n1,d)} + ${mx(w2,n2,d)}`,type:'frac',ans:[(w1+w2)*d+n1+n2,d],whole:true};}
  return {q:`${mx(w1,n1,d)} − ${fr(n2,d)}`,type:'frac',ans:[w1*d+n1-n2,d],whole:true};}},
{id:'g4_area_rect',g:4,name:'長方形・正方形の面積',pre:['g3_mul_2x1'],tool:'area',how:'長方形の面積 ＝ たて × よこ。正方形は 1辺 × 1辺。',
 gen:()=>{const w=ri(3,15),h=ri(3,15);return {q:`たて ${h}cm、よこ ${w}cm の長方形の面積は？（cm²）`,type:'num',ans:w*h};}},
{id:'g4_area_unit',g:4,name:'面積の単位（m²・a・ha・km²）',pre:['g4_area_rect','g3_large_num'],tool:'unit',how:'1a = 100m²、1ha = 100a = 10000m²、1km² = 100ha。100ずつで単位がかわるよ。',
 gen:()=>{const a=ri(2,9);return pick([{q:`${a}a = □m²`,type:'num',ans:a*100},{q:`${a}ha = □a`,type:'num',ans:a*100},{q:`${a}ha = □m²`,type:'num',ans:a*10000},{q:`${a}km² = □ha`,type:'num',ans:a*100},{q:`${a}m² = □cm²`,type:'num',ans:a*10000}]);}},
{id:'g4_angle',g:4,name:'角の大きさ（分度器）',pre:['g3_numline'],tool:'angle',how:'もとの線（黒）が 0 になっている方の目もりを読む。数字が2つならんでいるので、まちがえやすいよ。',
 gen:()=>{const a=5*ri(3,33);return {q:`<div class="qprot">${protractorSVG(a,Math.random()<.5,{})}</div>黒い線と緑の線の角は何度？`,type:'num',ans:a};}},
{id:'g4_linegraph',g:4,name:'折れ線グラフの読み方',pre:['g3_bargraph'],tool:'graph',how:'1目もりの大きさを見つけて読む。線が右上がりなら上がっている。かたむきが急なほど、変わり方が大きい。',
 gen:()=>{const cats=[];for(let i=0;i<7;i++)cats.push(`${9+i}時`);let v=ri(8,18);const vals=[];for(let i=0;i<7;i++){vals.push(v);v+=i<4?ri(1,4):ri(-3,1);}const mn=Math.min(...vals),mx=Math.max(...vals);const base=Math.floor((mn-1)/5)*5;const ticks=Math.ceil((mx-base+1)/5)*5;
  const svg=lineSVG({cats,vals,unit:1,ticks,base,uname:'度'});const i=ri(0,6);if(Math.random()<.5)return {q:`<div class="qgr">${svg}</div>${cats[i]}の気温は何度？`,type:'num',ans:vals[i]};const k=ri(1,3);return {q:`<div class="qgr">${svg}</div>${cats[k]}から${cats[k+1]}の間に、気温は何度上がった？`,type:'num',ans:vals[k+1]-vals[k]};}},
{id:'g4_order',g:4,name:'計算のじゅんじょ（( )、×÷が先）',pre:['g3_mul_2x1','g3_div_basic','g2_add2','g2_sub2'],tool:null,how:'( ) の中を先に計算。× と ÷ は、+ と − より先に計算するよ。',
 gen:()=>{const f=ri(1,4);if(f===1){const a=ri(2,20),b=ri(2,9),c=ri(2,9);return {q:`${a} + ${b} × ${c}`,type:'num',ans:a+b*c};}
  if(f===2){const a=ri(2,20),b=ri(2,20),c=ri(2,6);return {q:`(${a} + ${b}) × ${c}`,type:'num',ans:(a+b)*c};}
  if(f===3){const b=ri(2,6),c=ri(2,6),a=b*c+ri(1,30);return {q:`${a} − ${b} × ${c}`,type:'num',ans:a-b*c};}
  const c=ri(2,9),b=c*ri(2,9),a=ri(2,30);return {q:`${a} + ${b} ÷ ${c}`,type:'num',ans:a+b/c};}},

{id:'g5_dec_mul',g:5,name:'小数×小数',pre:['g4_dec_mul_int','g3_mul_2x2'],tool:null,how:'小数点がないものとして整数でかけ、かけられる数とかける数の小数点の下のけた数をあわせた分だけ、答えの小数点をうつ。',
 gen:()=>{let a=ri(11,99),b=ri(11,49);if(a%10===0)a++;if(b%10===0)b++;return {q:`${fm(a/10)} × ${fm(b/10)}`,type:'num',ans:a*b/100};}},
{id:'g5_dec_div',g:5,name:'小数÷小数',pre:['g4_dec_div_int','g4_div_2digit'],tool:'div',how:'わる数が整数になるように、わる数とわられる数の小数点を、同じけた数だけ右にうつしてから計算。',
 gen:()=>{let b=ri(2,25);if(b%10===0)b++;if(Math.random()<.5){const q=ri(2,30);return {q:`${fm(b*q/10)} ÷ ${fm(b/10)}`,type:'num',ans:q};}let q=ri(11,60);if(q%10===0)q++;return {q:`${fm(b*q/100)} ÷ ${fm(b/10)}`,type:'num',ans:q/10};}},
{id:'g5_multiple',g:5,name:'倍数・最小公倍数',pre:['g2_kuku_all','g3_div_basic'],tool:'kuku',how:'大きい方の数の倍数を順に書いて、小さい方の数でもわりきれる、最初の数をさがす。',
 gen:()=>{let a,b;do{a=ri(2,9);b=ri(2,9);}while(a===b||lcm(a,b)===Math.max(a,b)&&Math.random()<.7);return {q:`${a} と ${b} の最小公倍数は？`,type:'num',ans:lcm(a,b)};}},
{id:'g5_divisor',g:5,name:'約数・最大公約数',pre:['g3_div_rem'],tool:'yaku',how:'小さい方の数の約数を書き出して、大きい方の数もわりきれる、一番大きい数をさがす。',
 gen:()=>{const g=ri(2,9),[m,n]=copair(7);return {q:`${g*m} と ${g*n} の最大公約数は？`,type:'num',ans:g};}},
{id:'g5_frac_eq',g:5,name:'約分',pre:['g5_divisor','g3_div_basic'],tool:['frac','yaku'],how:'分子と分母を、両方わりきれる数（公約数）でわる。最大公約数でわると1回でできる。',
 gen:()=>{const d=ri(3,9),n=properCo(d),g=ri(2,6);return {q:`${fr(n*g,d*g)} を約分すると？`,type:'frac',ans:[n,d],simplest:true};}},
{id:'g5_frac_common',g:5,name:'通分',pre:['g5_multiple','g3_div_basic'],tool:['frac','kuku'],how:'分母どうしの最小公倍数を、共通の分母にする。分母を何倍かしたら、分子も同じだけ倍にする。',
 gen:()=>{let b,d;do{b=ri(2,9);d=ri(2,9);}while(b===d);const a=properCo(b),c=properCo(d);if(Math.random()<.5)return {q:`${fr(a,b)} と ${fr(c,d)} を通分するとき、分母はいくつにする？（一番小さい数で）`,type:'num',ans:lcm(b,d)};const L=b*ri(2,4);return {q:`${fr(a,b)} = ${fr('□',L)}　□は？`,type:'num',ans:a*L/b};}},
{id:'g5_frac_add',g:5,name:'分数のたし算・ひき算（分母がちがう）',pre:['g5_frac_eq','g5_frac_common','g4_frac_add'],tool:'frac',how:'通分して分母をそろえてから、分子をたす（ひく）。答えが約分できたら約分する。',
 gen:()=>{let b,d,a,c;do{b=ri(2,9);d=ri(2,9);}while(b===d);a=properCo(b);c=properCo(d);const L=lcm(b,d);
  if(Math.random()<.5)return {q:`${fr(a,b)} + ${fr(c,d)}`,type:'frac',ans:red(a*L/b+c*L/d,L),whole:true,simplest:true};
  if(a*d<c*b){[a,b,c,d]=[c,d,a,b];}return {q:`${fr(a,b)} − ${fr(c,d)}`,type:'frac',ans:red(a*L/b-c*L/d,L),whole:true,simplest:true};}},
{id:'g5_avg',g:5,name:'平均',pre:['g3_add3','g4_div_1digit'],tool:'div',how:'平均 ＝ 合計 ÷ 個数。まず全部たして、こ数でわる。',
 gen:()=>{const n=ri(3,5),m=ri(6,20);const v=[];let s=0;for(let i=0;i<n-1;i++){const x=m+ri(-5,5);v.push(x);s+=x;}const last=m*n-s;if(last<1)return S_by.g5_avg.gen();v.push(last);return {q:`${v.join('、')} の平均は？`,type:'num',ans:m};}},
{id:'g5_per',g:5,name:'割合',pre:['g5_dec_mul','g5_dec_div'],tool:'wari',how:'比べる量 ＝ もとにする量 × 割合　／　割合 ＝ 比べる量 ÷ もとにする量　／　もとにする量 ＝ 比べる量 ÷ 割合',
 gen:()=>{const rn=pick([10,20,25,30,40,50,60,75,80,120,150]),base=pick([20,40,60,80,100,120,200,300,400,500]),cmp=base*rn/100,r=fm(rn/100),f=ri(1,3);
  if(f===1)return {q:`${base}円の ${r}倍は何円？`,type:'num',ans:cmp};
  if(f===2)return {q:`${cmp}m は、${base}m の何倍？`,type:'num',ans:rn/100};
  return {q:`□人の ${r}倍が ${cmp}人です。□は何人？`,type:'num',ans:base};}},
{id:'g5_percent',g:5,name:'百分率と歩合',pre:['g5_per'],tool:'wari',how:'割合の 1 が 100%。小数の割合を100倍すると百分率。歩合は 0.1 が1割、0.01 が1分。',
 gen:()=>{const rn=pick([5,8,12,15,24,30,45,60,75,80,125,150]);const f=ri(1,3);if(f===1)return {q:`${fm(rn/100)} を百分率で表すと何%？`,type:'num',ans:rn};if(f===2)return {q:`${rn}% を小数で表すと？`,type:'num',ans:rn/100};const base=pick([200,400,500,800,1000]);return {q:`${base}円の ${rn}% は何円？`,type:'num',ans:base*rn/100};}},
{id:'g5_area_tri',g:5,name:'三角形・平行四辺形の面積',pre:['g4_area_rect','g3_div_basic'],tool:'area',how:'平行四辺形 ＝ 底辺 × 高さ。三角形 ＝ 底辺 × 高さ ÷ 2。',
 gen:()=>{const b=ri(3,14),h=ri(2,12);if(Math.random()<.5){const hh=(b*h)%2?h+1:h;return {q:`底辺 ${b}cm、高さ ${hh}cm の三角形の面積は？（cm²）`,type:'num',ans:b*hh/2};}return {q:`底辺 ${b}cm、高さ ${h}cm の平行四辺形の面積は？（cm²）`,type:'num',ans:b*h};}},
{id:'g5_area_trap',g:5,name:'台形・ひし形の面積',pre:['g5_area_tri'],tool:'area',how:'台形 ＝ (上底＋下底) × 高さ ÷ 2。ひし形 ＝ 対角線 × 対角線 ÷ 2。同じ形を2つくっつけたり、長方形でかこんだりして考えよう。',
 gen:()=>{if(Math.random()<.5){let a=ri(2,8),b=ri(a+1,12),h=ri(2,10);if((a+b)*h%2)h++;return {q:`上底 ${a}cm、下底 ${b}cm、高さ ${h}cm の台形の面積は？（cm²）`,type:'num',ans:(a+b)*h/2};}let d1=ri(3,12),d2=ri(3,12);if(d1*d2%2)d1++;return {q:`対角線が ${d1}cm と ${d2}cm のひし形の面積は？（cm²）`,type:'num',ans:d1*d2/2};}},
{id:'g5_circum',g:5,name:'円周の長さ',pre:['g4_dec_mul_int'],tool:'area',how:'円周 ＝ 直径 × 3.14。半径が分かっているときは、まず2倍して直径にする。',
 gen:()=>{if(Math.random()<.5){const d=ri(2,20);return {q:`直径 ${d}cm の円の円周は？（円周率3.14）`,type:'num',ans:d*314/100};}const r=ri(2,10);return {q:`半径 ${r}cm の円の円周は？（円周率3.14）`,type:'num',ans:r*2*314/100};}},
{id:'g5_volume',g:5,name:'直方体の体積',pre:['g4_area_rect','g3_mul_2x1'],tool:null,how:'直方体の体積 ＝ たて × よこ × 高さ。',
 gen:()=>{const a=ri(2,10),b=ri(2,10),c=ri(2,10);return {q:`たて ${a}cm、よこ ${b}cm、高さ ${c}cm の直方体の体積は？（cm³）`,type:'num',ans:a*b*c};}},
{id:'g5_vol_unit',g:5,name:'体積の単位（cm³・m³・L）',pre:['g5_volume','g2_kasa'],tool:'unit',how:'1L = 1000cm³、1m³ = 1000L、1mL = 1cm³。',
 gen:()=>{const a=ri(2,9);return pick([{q:`${a}L = □cm³`,type:'num',ans:a*1000},{q:`${a}m³ = □L`,type:'num',ans:a*1000},{q:`${a*100}cm³ = □dL`,type:'num',ans:a},{q:`${a*1000}cm³ = □L`,type:'num',ans:a}]);}},
{id:'g5_speed',g:5,name:'速さ',pre:['g4_div_1digit','g3_mul_2x1'],tool:'wari',how:'速さ ＝ 道のり ÷ 時間　／　道のり ＝ 速さ × 時間　／　時間 ＝ 道のり ÷ 速さ',
 gen:()=>{const v=ri(3,9)*10,t=ri(2,5),f=ri(1,3);if(f===1)return {q:`${v*t}km を ${t}時間で走る車の時速は？（km）`,type:'num',ans:v};if(f===2)return {q:`時速 ${v}km で ${t}時間走ると、何km進む？`,type:'num',ans:v*t};return {q:`時速 ${v}km で ${v*t}km 進むのに、何時間かかる？`,type:'num',ans:t};}},

{id:'g6_frac_mul',g:6,name:'分数×分数',pre:['g5_frac_eq','g2_kuku_all'],tool:'yaku',how:'分子どうし、分母どうしをかける。とちゅうで約分すると計算がかんたん。',
 gen:()=>{const b=ri(2,9),d=ri(2,9),a=ri(1,b-1)||1,c=ri(1,d-1)||1;return {q:`${fr(a,b)} × ${fr(c,d)}`,type:'frac',ans:red(a*c,b*d),whole:true,simplest:true};}},
{id:'g6_frac_div',g:6,name:'分数÷分数',pre:['g6_frac_mul'],tool:'yaku',how:'わる数の分母と分子を入れかえて（逆数にして）かける。',
 gen:()=>{const b=ri(2,9),d=ri(2,9),a=ri(1,b-1),c=ri(1,d-1);return {q:`${fr(a,b)} ÷ ${fr(c,d)}`,type:'frac',ans:red(a*d,b*c),whole:true,simplest:true};}},
{id:'g6_ratio_simplify',g:6,name:'比をかんたんにする（整数）',pre:['g5_divisor','g3_div_basic'],tool:'ratio',how:'両方を同じ数（公約数）でわる。最大公約数でわると1回でできる。',
 gen:()=>{const g=ri(2,12),[m,n]=copair(9);return {q:`${g*m} : ${g*n} をかんたんにすると？`,type:'ratio',ans:[m,n]};}},
{id:'g6_ratio_dec_frac',g:6,name:'比をかんたんにする（小数・分数）',pre:['g6_ratio_simplify','g5_frac_common','g4_dec_mul_int'],tool:'ratio',how:'小数は10倍・100倍、分数は分母の最小公倍数をかけて整数の比にしてから、かんたんにする。',
 gen:()=>{if(Math.random()<.5){let m,n,g,an,bn;do{[m,n]=copair(9);g=ri(2,9);an=m*g;bn=n*g;}while(an%10===0&&bn%10===0);return {q:`${fm(an/10)} : ${fm(bn/10)} をかんたんにすると？`,type:'ratio',ans:red(an,bn)};}
  let b,d;do{b=ri(2,9);d=ri(2,9);}while(b===d);const a=properCo(b),c=properCo(d),L=lcm(b,d);return {q:`${fr(a,b)} : ${fr(c,d)} をかんたんにすると？`,type:'ratio',ans:red(a*L/b,c*L/d)};}},
{id:'g6_ratio_value',g:6,name:'等しい比（□をもとめる）',pre:['g6_ratio_simplify','g3_mul_2x1','g3_div_basic'],tool:'ratio',how:'比の両方に同じ数をかけても同じ比。何倍になっているかを見つけて、もう一方にもかける。',
 gen:()=>{const [m,n]=copair(9),k=ri(2,9);if(Math.random()<.5)return {q:`${m} : ${n} = ${m*k} : □`,type:'num',ans:n*k};return {q:`${m} : ${n} = □ : ${n*k}`,type:'num',ans:m*k};}},
{id:'g6_circle',g:6,name:'円の面積',pre:['g5_circum','g4_area_rect'],tool:'area',how:'円の面積 ＝ 半径 × 半径 × 3.14。直径が分かっているときは、まず半分にして半径にする。',
 gen:()=>{const r=ri(2,10);return {q:`半径 ${r}cm の円の面積は？（円周率は3.14、cm²）`,type:'num',ans:r*r*314/100};}},
{id:'g6_prop',g:6,name:'比例',pre:['g3_div_basic','g3_mul_2x1'],tool:null,how:'比例では、x が2倍、3倍…になると、y も2倍、3倍…になる。y ÷ x はいつも同じ数（きまった数）。',
 gen:()=>{const k=ri(2,9),x1=ri(2,5),x2=ri(6,12);return {q:`y は x に比例します。x が ${x1} のとき y は ${k*x1}。x が ${x2} のとき y は？`,type:'num',ans:k*x2};}},
{id:'g6_letters',g:6,name:'文字と式（x をもとめる）',pre:['g3_div_basic','g3_sub3'],tool:null,how:'x × 4 = 28 なら x = 28 ÷ 4。x + 15 = 40 なら x = 40 − 15。反対の計算でもとめるよ。',
 gen:()=>{const x=ri(2,9),a=ri(2,9);if(Math.random()<.5)return {q:`x × ${a} = ${x*a}　x は？`,type:'num',ans:x};const y=ri(12,90),b=ri(11,60);return {q:`x + ${b} = ${y+b}　x は？`,type:'num',ans:y};}},
{id:'g6_metric',g:6,name:'単位のしくみ（小数で単位をかえる）',pre:['g3_len_weight','g2_kasa','g4_dec_place'],tool:'unit',how:'k（キロ）は1000倍、c（センチ）は100分の1、m（ミリ）は1000分の1。大きい単位→小さい単位は かける、小さい→大きいは わる。',
 gen:()=>{let n=ri(101,999);if(n%10===0)n++;return pick([{q:`${fm(n/100)}m = □cm`,type:'num',ans:n},{q:`${n*10}g = □kg`,type:'num',ans:n/100},{q:`${fm(n/1000)}kg = □g`,type:'num',ans:n},{q:`${n}mL = □L`,type:'num',ans:n/1000},{q:`${fm(n/10)}cm = □mm`,type:'num',ans:n},{q:`${n*10}m = □km`,type:'num',ans:n/100}]);}},
];

const S_by = {}; S.forEach(function (s) { S_by[s.id] = s; });

// ───────── LearningBM の 修行 とのつながり ─────────
// いまの単元（修行の単元）→ チェックで さいしょに 調べる技
var UNIT2GOAL = {
  'm1-add-no': 'g1_add1', 'm1-sub-no': 'g1_sub1', 'm1-add-cy': 'g1_add_carry', 'm1-sub-bo': 'g1_sub_borrow', 'm1-3num': 'g1_add_carry',
  'm2-add2': 'g2_add2', 'm2-sub2': 'g2_sub2', 'm2-kuku': 'g2_kuku_all', 'm2-length': 'g2_mm',
  'm3-mul1': 'g3_mul_2x1', 'm3-div0': 'g3_div_basic', 'm3-divR': 'g3_div_rem', 'm3-large': 'g3_large_num', 'm3-weight': 'g3_len_weight',
  'rounding': 'g4_large_num', 'division': 'g3_div_rem', 'fraction-mixed': 'g4_frac_mixed', 'decimal': 'g4_dec_mul_int', 'long-division': 'g4_div_1digit', 'area': 'g4_area_rect', 'brackets': 'g4_order',
  'm5-frac-eq': 'g5_frac_eq', 'm5-percent': 'g5_percent', 'm5-volume': 'g5_volume', 'm5-avg': 'g5_avg', 'm5-dec-mul': 'g5_dec_mul', 'm5-dec-div': 'g5_dec_div', 'm5-speed': 'g5_speed', 'm5-unit-qty': 'g5_dec_div',
  'm6-frac-mul': 'g6_frac_mul', 'm6-frac-div': 'g6_frac_div', 'm6-frac-int': 'g6_frac_mul', 'm6-frac-mixed': 'g6_frac_div', 'm6-frac-triple': 'g6_frac_div', 'm6-frac-dec': 'g6_frac_div',
  'm6-ratio': 'g6_ratio_value', 'm6-circle': 'g6_circle', 'm6-proportion': 'g6_prop', 'm6-expression': 'g6_letters', 'm6-scale': 'g6_ratio_value', 'm6-prism': 'g6_circle', 'm6-data': 'g5_avg'
};
// 🛤 UNIT_PATH_V1（2026-11-13 先生の指示）単元ごとの「もどる道」。
//   単元の技（goal）が ❌ のとき、その単元に 本当に 関係する 前の技だけを、近い順に 1本ずつ たどる。
//   1本の 道は ⭕ が 出たら そこで 止まり、その すぐ手前の ❌ が「もどる場所（根っこ）」。
//   関係の うすい技（ひとつ前の 単元・ほかの 単元）へは 行かない。道が 2本 ある 単元は 2本とも 見る。
var UNIT_PATHS = {
  'm1-add-no': [['g1_count']], 'm1-sub-no': [['g1_count']], 'm1-add-cy': [['g1_add1', 'g1_count']], 'm1-sub-bo': [['g1_sub1', 'g1_count']], 'm1-3num': [['g1_add1', 'g1_count']],
  'm2-add2': [['g1_add_carry', 'g1_add1', 'g1_count'], ['g2_place']], 'm2-sub2': [['g1_sub_borrow', 'g1_sub1', 'g1_count'], ['g2_place']],
  'm2-kuku': [['g2_kuku_25', 'g1_add1']], 'm2-length': [['g2_place', 'g1_count']],
  'm3-mul1': [['g2_kuku_all', 'g2_kuku_25'], ['g2_add2', 'g1_add_carry']], 'm3-div0': [['g2_kuku_all', 'g2_kuku_25']],
  'm3-divR': [['g3_div_basic', 'g2_kuku_all', 'g2_kuku_25'], ['g1_sub_borrow', 'g1_sub1']], 'm3-large': [['g2_place', 'g1_count']], 'm3-weight': [['g2_mm', 'g2_place']],
  'rounding': [['g3_large_num', 'g2_place']], 'division': [['g3_div_basic', 'g2_kuku_all', 'g2_kuku_25'], ['g1_sub_borrow']],
  'long-division': [['g3_div_rem', 'g3_div_basic', 'g2_kuku_all'], ['g3_mul_2x1', 'g2_kuku_all'], ['g2_sub2', 'g1_sub_borrow']],
  'fraction-mixed': [['g3_div_rem', 'g3_div_basic', 'g2_kuku_all'], ['g3_frac_add']],
  'decimal': [['g3_mul_2x1', 'g2_kuku_all'], ['g4_dec_place', 'g3_dec_place']], 'area': [['g3_mul_2x1', 'g2_kuku_all']],
  'brackets': [['g3_mul_2x1', 'g2_kuku_all'], ['g3_div_basic', 'g2_kuku_all'], ['g2_sub2', 'g1_sub_borrow']],
  'm5-frac-eq': [['g5_divisor', 'g3_div_basic', 'g2_kuku_all'], ['g5_frac_common', 'g5_multiple', 'g2_kuku_all']],
  'm5-percent': [['g5_per', 'g5_dec_div', 'g4_dec_div_int', 'g4_div_1digit', 'g3_div_basic'], ['g5_dec_mul', 'g4_dec_mul_int', 'g3_mul_2x1']],
  'm5-volume': [['g4_area_rect', 'g3_mul_2x1', 'g2_kuku_all']], 'm5-avg': [['g4_div_1digit', 'g3_div_rem', 'g3_div_basic'], ['g3_add3', 'g2_add2']],
  'm5-dec-mul': [['g4_dec_mul_int', 'g3_mul_2x1', 'g2_kuku_all'], ['g4_dec_place', 'g3_dec_place']],
  'm5-dec-div': [['g4_dec_div_int', 'g4_div_1digit', 'g3_div_rem', 'g3_div_basic'], ['g4_dec_place', 'g3_dec_place']],
  'm5-speed': [['g4_div_1digit', 'g3_div_basic', 'g2_kuku_all'], ['g3_mul_2x1', 'g2_kuku_all']], 'm5-unit-qty': [['g4_dec_div_int', 'g4_div_1digit', 'g3_div_basic', 'g2_kuku_all']],
  'm6-frac-mul': [['g5_frac_eq', 'g5_divisor', 'g3_div_basic', 'g2_kuku_all'], ['g4_frac_mixed', 'g3_div_rem']],
  'm6-frac-int': [['g5_frac_eq', 'g5_divisor', 'g3_div_basic', 'g2_kuku_all']],
  'm6-frac-div': [['g6_frac_mul', 'g5_frac_eq', 'g5_divisor', 'g3_div_basic', 'g2_kuku_all'], ['g4_frac_mixed', 'g3_div_rem']],
  'm6-frac-mixed': [['g4_frac_mixed', 'g3_div_rem', 'g3_div_basic'], ['g6_frac_mul', 'g5_frac_eq', 'g5_divisor', 'g2_kuku_all']],
  'm6-frac-triple': [['g6_frac_mul', 'g5_frac_eq', 'g5_divisor', 'g3_div_basic', 'g2_kuku_all']],
  'm6-frac-dec': [['g6_frac_mul', 'g5_frac_eq', 'g5_divisor', 'g3_div_basic'], ['g4_dec_place', 'g3_dec_place']],
  'm6-ratio': [['g6_ratio_simplify', 'g5_divisor', 'g3_div_basic', 'g2_kuku_all']],
  'm6-scale': [['g4_dec_mul_int', 'g3_mul_2x1', 'g2_kuku_all'], ['g6_metric', 'g3_len_weight']],
  'm6-circle': [['g5_circum', 'g4_dec_mul_int', 'g3_mul_2x1', 'g2_kuku_all'], ['g4_area_rect']],
  'm6-prism': [['g6_circle', 'g5_circum', 'g4_dec_mul_int'], ['g5_volume', 'g4_area_rect', 'g3_mul_2x1']],
  'm6-proportion': [['g3_div_basic', 'g2_kuku_all'], ['g4_dec_div_int', 'g4_div_1digit']],
  'm6-expression': [['g3_div_basic', 'g2_kuku_all'], ['g3_sub3', 'g2_sub2']],
  'm6-data': [['g4_div_1digit', 'g3_div_rem', 'g3_div_basic'], ['g3_add3', 'g2_add2']]
};
// 単元の 道を ことばに（例：約分 → 約数 → わり算 → 九九）
function pathText(unitId) {
  var ps = UNIT_PATHS[unitId]; if (!ps) return '';
  return ps.map(function (p) { return p.map(function (id) { var s = S_by[id]; return s ? s.name.replace(/（.*?）/g, '') : id; }).join(' → '); }).join(' ／ ');
}
// 技 → もどる 修行（ないものは null：やり方だけ伝える）
var SK2UNIT = {
  g1_count: 'm1-add-no', g1_add1: 'm1-add-no', g1_sub1: 'm1-sub-no', g1_add_carry: 'm1-add-cy', g1_sub_borrow: 'm1-sub-bo', g1_clock: null,
  g2_place: 'm3-large', g2_mm: 'm2-length', g2_ruler: 'm2-length', g2_kasa: null, g2_add2: 'm2-add2', g2_sub2: 'm2-sub2', g2_kuku_25: 'm2-kuku', g2_kuku_all: 'm2-kuku', g2_clock: null, g2_time_calc: null,
  g3_large_num: 'm3-large', g3_dec_place: null, g3_numline: null, g3_bargraph: null, g3_add3: 'm2-add2', g3_sub3: 'm2-sub2', g3_div_basic: 'm3-div0', g3_div_rem: 'm3-divR', g3_mul_2x1: 'm3-mul1', g3_mul_2x2: 'm3-mul1',
  g3_dec_add: 'decimal', g3_frac_add: 'fraction-mixed', g3_len_weight: 'm3-weight', g3_scale: 'm3-weight', g3_time: null,
  g4_large_num: 'm3-large', g4_dec_place: null, g4_div_1digit: 'long-division', g4_div_2digit: 'long-division', g4_dec_add2: 'decimal', g4_dec_mul_int: 'decimal', g4_dec_div_int: 'decimal',
  g4_frac_mixed: 'fraction-mixed', g4_frac_add: 'fraction-mixed', g4_area_rect: 'area', g4_area_unit: 'area', g4_angle: null, g4_linegraph: null, g4_order: 'brackets',
  g5_dec_mul: 'm5-dec-mul', g5_dec_div: 'm5-dec-div', g5_multiple: 'm5-frac-eq', g5_divisor: 'm5-frac-eq', g5_frac_eq: 'm5-frac-eq', g5_frac_common: 'm5-frac-eq', g5_frac_add: 'm5-frac-eq',
  g5_avg: 'm5-avg', g5_per: 'm5-percent', g5_percent: 'm5-percent', g5_area_tri: 'area', g5_area_trap: 'area', g5_circum: 'm6-circle', g5_volume: 'm5-volume', g5_vol_unit: 'm5-volume', g5_speed: 'm5-speed',
  g6_frac_mul: 'm6-frac-mul', g6_frac_div: 'm6-frac-div', g6_ratio_simplify: 'm6-ratio', g6_ratio_dec_frac: 'm6-ratio', g6_ratio_value: 'm6-ratio', g6_circle: 'm6-circle', g6_prop: 'm6-proportion', g6_letters: 'm6-expression', g6_metric: null
};
var MATH_PACE_MONTH = {
  1: { 4: 'm1-add-no', 5: 'm1-add-no', 6: 'm1-add-no', 7: 'm1-sub-no', 8: 'm1-sub-no', 9: 'm1-sub-no', 10: 'm1-3num', 11: 'm1-add-cy', 12: 'm1-sub-bo', 1: 'm1-sub-bo', 2: 'm1-sub-bo', 3: 'm1-sub-bo' },
  2: { 4: 'm2-add2', 5: 'm2-sub2', 6: 'm2-length', 7: 'm2-length', 8: 'm2-length', 9: 'm2-length', 10: 'm2-kuku', 11: 'm2-kuku', 12: 'm2-kuku', 1: 'm2-kuku', 2: 'm2-kuku', 3: 'm2-kuku' },
  3: { 4: 'm3-div0', 5: 'm3-div0', 6: 'm3-divR', 7: 'm3-large', 8: 'm3-large', 9: 'm3-mul1', 10: 'm3-mul1', 11: 'm3-weight', 12: 'm3-weight', 1: 'm3-weight', 2: 'm3-weight', 3: 'm3-weight' },
  4: { 4: 'division', 5: 'long-division', 6: 'long-division', 7: 'long-division', 8: 'long-division', 9: 'long-division', 10: 'rounding', 11: 'brackets', 12: 'area', 1: 'decimal', 2: 'decimal', 3: 'fraction-mixed' },
  5: { 4: 'm5-volume', 5: 'm5-dec-mul', 6: 'm5-dec-div', 7: 'm5-polygon', 8: 'm5-polygon', 9: 'm5-frac-eq', 10: 'm5-avg', 11: 'm5-unit-qty', 12: 'm5-speed', 1: 'm5-percent', 2: 'm5-percent', 3: 'm5-percent' },
  6: { 4: 'm6-expression', 5: 'm6-expression', 6: 'm6-frac-mul', 7: 'm6-frac-div', 8: 'm6-frac-div', 9: 'm6-ratio', 10: 'm6-circle', 11: 'm6-proportion', 12: 'm6-proportion', 1: 'm6-proportion', 2: 'm6-proportion', 3: 'm6-proportion' }
};
var MAX_SKILLS = 10;

function curr() { try { return window.CURRICULUM || null; } catch (e) { return null; } }
function unitObj(id) {
  var C = curr(); if (!C || !C.math) return null;
  var gs = C.math.grades || {};
  for (var g in gs) { var us = (gs[g] && gs[g].units) || []; for (var i = 0; i < us.length; i++) if (us[i].id === id) return { u: us[i], grade: Number(g) }; }
  return null;
}
function unitName(id) { var o = unitObj(id); return o ? o.u.name : id; }
function gradeUnits(g) { var C = curr(); var gd = C && C.math && C.math.grades && C.math.grades[g]; return ((gd && gd.units) || []).map(function (u) { return u.id; }); }
function myGrade() { var g = Number(window.__userGrade || 0); return g >= 1 && g <= 6 ? g : 0; }
function jstMonth() { return new Date(Date.now() + 9 * 3600000).getUTCMonth() + 1; }
function normName(s) { return String(s || '').replace(/[（(][^）)]*[）)]/g, '').replace(/[\s　・「」『』、。．.:：]/g, '').replace(/の/g, ''); }
function matchTheme(g, theme) {
  var t = normName(theme); if (!t) return '';
  var best = '', bs = 0;
  gradeUnits(g).forEach(function (id) {
    var n = normName(unitName(id)); if (!n) return;
    var sc = 0;
    if (t.indexOf(n) >= 0 || (t.length >= 2 && n.indexOf(t) >= 0)) sc = Math.min(n.length, t.length) + 0.5;
    else if (n.length >= 3) {
      var cov = {}, hit = 0, ng = n.length - 1;
      for (var i = 0; i + 1 < n.length; i++) if (t.indexOf(n.slice(i, i + 2)) >= 0) { hit++; cov[i] = 1; cov[i + 1] = 1; }
      if (hit >= 2 && hit / ng >= 0.6) sc = Object.keys(cov).length;
    }
    if (sc > bs) { bs = sc; best = id; }
  });
  return best;
}
// いまの単元：①先生が選んだ ②授業メモ ③クラスの記録 ④標準の進み方（カルテの「いまの単元」と同じ順）
function resolveNow(d, g) {
  if (!g) return null;
  var gu = gradeUnits(g), ok = function (id) { return gu.indexOf(id) >= 0; };
  var up = d && d.unitProgress && d.unitProgress.units;
  var taught = function (id) { return !(up && up[id] === false); };
  if (d && d.manual && ok(d.manual)) return { id: d.manual, src: 'manual' };
  var mt = (d && d.memo) || [];
  if (mt.length) { var mid = matchTheme(g, mt[0].theme); if (mid) return { id: mid, src: 'memo' }; }
  var nu = ((d && d.classUnits) || []).filter(function (x) { return ok(x.unit) && taught(x.unit); });
  var p7 = nu.filter(function (x) { return x.users7 >= 3 && x.n7 >= 15; }).sort(function (a, b) { return b.users7 - a.users7 || gu.indexOf(b.unit) - gu.indexOf(a.unit); })[0];
  if (p7) return { id: p7.unit, src: 'auto' };
  var p14 = nu.filter(function (x) { return x.users >= 3 && x.n >= 30; }).sort(function (a, b) { return b.users - a.users || gu.indexOf(b.unit) - gu.indexOf(a.unit); })[0];
  if (p14) return { id: p14.unit, src: 'auto' };
  var cur = (MATH_PACE_MONTH[g] || {})[jstMonth()];
  if (cur && ok(cur)) return { id: cur, src: 'std' };
  return null;
}

// ───────── 答えの 読みとり（学びのどうぐ箱と同じ） ─────────
function nz(s) { return String(s || '').replace(/[０-９]/g, function (c) { return String.fromCharCode(c.charCodeAt(0) - 0xFEE0); }).replace(/[．。]/g, '.').replace(/\s/g, ''); }
function pNum(s) { s = nz(s); return /^\d+(\.\d+)?$/.test(s) ? parseFloat(s) : NaN; }
function pInt(s) { s = nz(s); return /^\d+$/.test(s) ? parseInt(s, 10) : NaN; }
function readAns(Q, v) {
  if (Q.type === 'num') { var x = pNum(v('k1')); return isNaN(x) ? null : { x: x }; }
  if (Q.type === 'rem') { var q = pInt(v('k1')); var rs = nz(v('k2')); var r = rs === '' ? 0 : pInt(rs); return isNaN(q) || isNaN(r) ? null : { q: q, r: r }; }
  if (Q.type === 'ratio') { var a = pInt(v('k1')), b = pInt(v('k2')); return isNaN(a) || isNaN(b) || !a || !b ? null : { a: a, b: b }; }
  if (Q.type === 'hm' || Q.type === 'pair') { var h = pInt(v('k1')); var ms = nz(v('k2')); var m = ms === '' ? 0 : pInt(ms); return isNaN(h) || isNaN(m) ? null : { h: h, m: m }; }
  var ws = nz(v('kW')), ns = nz(v('k1')), ds = nz(v('k2')); var w = ws === '' ? 0 : pInt(ws);
  if (isNaN(w)) return null;
  if (ns === '' && ds === '') { if (ws === '') return null; return { w: w, n: 0, d: 1, only: true }; }
  var n = pInt(ns), d = pInt(ds); if (isNaN(n) || isNaN(d) || d === 0) return null; return { w: w, n: n, d: d };
}
function judge(Q, A) {
  if (Q.type === 'num') return Math.abs(A.x - Q.ans) < 1e-9;
  if (Q.type === 'rem') return A.q === Q.ans[0] && A.r === Q.ans[1];
  if (Q.type === 'ratio') return A.a === Q.ans[0] && A.b === Q.ans[1];
  if (Q.type === 'hm' || Q.type === 'pair') return A.h === Q.ans[0] && A.m === Q.ans[1];
  var N = Q.ans[0], D = Q.ans[1]; if ((A.w * A.d + A.n) * D !== N * A.d) return false;
  if (Q.simplest && A.n > 0 && gcd(A.n, A.d) !== 1) return false;
  if (Q.mixedForm && !(A.w >= 1 && (A.only || A.n < A.d))) return false;
  if (Q.improperForm && A.w !== 0) return false;
  return true;
}
function ansText(Q) {
  if (Q.type === 'num') return fm(Q.ans);
  if (Q.type === 'rem') return Q.ans[1] ? Q.ans[0] + ' あまり ' + Q.ans[1] : Q.ans[0] + '（あまりなし）';
  if (Q.type === 'ratio') return Q.ans[0] + ' : ' + Q.ans[1];
  if (Q.type === 'hm') return Q.ans[0] + '時' + Q.ans[1] + '分';
  if (Q.type === 'pair') return Q.ans[0] + Q.labels[0] + Q.ans[1] + Q.labels[1];
  var N = Q.ans[0], D = Q.ans[1]; if (N % D === 0) return String(N / D);
  if (Q.improperForm || N < D) return fr(N, D);
  var w = Math.floor(N / D), n = N % D; return Q.mixedForm ? mx(w, n, D) : mx(w, n, D) + '（' + fr(N, D) + ' でもOK）';
}

// ───────── ことば（NGWORD_V1：責めない） ─────────
var SAY = {
  askNow: { manual: '今 授業で「{u}」の学習してるんやろ？', memo: '今 授業で「{u}」の学習してるんやろ？', auto: '今 クラスのみんな「{u}」の学習してるんやろ？', std: '今ごろは「{u}」の学習してるんちゃう？' },
  askCheck: 'この学習に 必要な技を 身につけてるか、理解度チェック してみるか？',
  askNone: '理解度チェック しよか！ どの単元の 技を 調べる？',
  pick: 'どの単元の 技を 調べる？',
  start: 'よっしゃ！ 問題を 出すで。わからへんかったら「わからない」を おしてええで。むずかしかったら、前の学年の技まで さかのぼって いっしょに さがすからな！',
  where: '【{g}年「{n}」】の技やで',
  ok: ['⭕ せいかい！', '⭕ ええやん！', '⭕ ばっちりや！'],
  ng: '答えは {a} やで。',
  skip: 'だいじょうぶ！ 答えは {a} やで。',
  pass: '「{n}」は ばっちりやな！',
  passTri: '「{n}」は だいたい できてるで！',
  back: '「{n}」は ちょっと むずかしかったな。その前に 学ぶ技を 見てみよか！',
  backPath: '「{n}」も むずかしかったな。この道を もう1つ 前へ さかのぼるで！',
  backEnd: '「{n}」が 根っこ みたいやな。よう がんばった！',
  unitSelf: '前に 習った技は ちゃんと できてるで！ つまずきは「{n}」の 中にあるみたいや。修行で「{n}」を ゆっくり 練習しよな。💡 わからん時は ヒントを 見てな',
  backNone: '「{n}」は ちょっと むずかしかったな。ここが 練習のしどころや！',
  goalOk: '🎉 「{n}」に 必要な技は 身についてるで！ この調子で 修行して 腕を みがこか！',
  goalHint: '🙂 ヒントが あれば できるな！ つぎは ヒントなしでも できるか、修行で ためしてみよか！',
  roots: '🌱 ここから 修行に もどると ええで！',
  rootUnit: '{g}年「{n}」→ ⚔ 修行「{u}」',
  rootNoUnit: '{g}年「{n}」→ 修行には まだ ないから、ノートで 練習しよか',
  after: 'ここが できるように なったら、もう一回「{n}」を チェックしてみよな！ 応援してるで！',
  quit: 'ここまでの けっかを 見てみよか。',
  bye: 'また いつでも チェックしよな！'
};
function fill(t, o) { return String(t).replace(/\{(\w+)\}/g, function (_, k) { return o[k] == null ? '' : o[k]; }); }
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }

// ───────── 対話の 状態 ─────────
var C = null;        // { log:[], step, goal, goalUnit, queue, res, order, cur, Q, hinted, now }
var _data = null, _loading = null;
function load(force) {
  if (_data && !force) return Promise.resolve(_data);
  if (_loading) return _loading;
  _loading = fetch('/api/student/check-now', { credentials: 'include', cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : null; })
    .then(function (j) { _data = (j && j.ok) ? j : { ok: false }; _loading = null; return _data; })
    .catch(function () { _loading = null; _data = { ok: false }; return _data; });
  return _loading;
}
function nowUnit() { var g = myGrade(); var r = resolveNow(_data, g); return r && UNIT2GOAL[r.id] ? r : null; }

function say(w, t, html) { C.log.push({ w: w, t: t, html: !!html }); }
function face() { var f = '🐯'; try { if (typeof window.monSpriteHtml === 'function') f = window.monSpriteHtml(154, '🐯'); } catch (e) {} return f; }

function open(unitId, opt) {
  ensureCss();
  C = { log: [], step: 'ask', res: {}, order: [], queue: [] };
  var root = document.getElementById('hkChat');
  if (!root) {
    root = document.createElement('div'); root.id = 'hkChat';
    root.innerHTML = '<div class="hk-box"><div class="hk-head"><span class="hk-face">' + face() + '</span><span>阪神マンと 理解度チェック</span><button type="button" class="hk-x">とじる</button></div><div class="hk-log" id="hkLog"></div><div class="hk-foot" id="hkFoot"></div></div>';
    document.body.appendChild(root);
    root.querySelector('.hk-x').onclick = function () { if (C && C.step === 'quiz' && Object.keys(C.res).length) { say('m', 'やめる'); say('b', SAY.quit); result(true); } else close(); };
  }
  root.style.display = 'flex';
  C.src = (opt && opt.src) ? String(opt.src) : 'self';   // SAKANOBORI_V1 だれが ひらいたか（auto＝修行で つまずいて 阪神マンが さそった）
  if (unitId && UNIT2GOAL[unitId]) { C.now = { id: unitId, src: 'pick' }; begin(unitId); draw(); return; }
  draw();
  load(false).then(function () {
    if (!C) return;
    var r = nowUnit();
    C.now = r;
    if (r) { say('b', fill(SAY.askNow[r.src] || SAY.askNow.std, { u: unitName(r.id) })); say('b', SAY.askCheck); }
    else say('b', SAY.askNone), C.step = 'pick';
    draw();
  });
}
function close() { var r = document.getElementById('hkChat'); if (r) r.style.display = 'none'; C = null; }

function pickList() {
  var g = myGrade() || 6, out = [], seen = {};
  var add = function (id) { if (!id || seen[id] || !UNIT2GOAL[id] || !unitObj(id)) return; seen[id] = 1; out.push(id); };
  ((_data && _data.mine) || []).forEach(function (x) { var o = unitObj(x.unit); if (o && o.grade <= g) add(x.unit); });
  if (C && C.now) add(C.now.id);
  for (var gg = g; gg >= 1 && out.length < 12; gg--) gradeUnits(gg).forEach(add);
  return out.slice(0, 12);
}

function begin(unitId) {
  var goal = UNIT2GOAL[unitId];
  C.goalUnit = unitId; C.goal = goal; C.queue = [goal]; C.res = {}; C.order = []; C.step = 'quiz';
  C.paths = UNIT_PATHS[unitId] ? UNIT_PATHS[unitId].map(function (p) { return p.filter(function (id) { return !!S_by[id] && id !== goal; }); }).filter(function (p) { return p.length; }) : null;
  C.walk = null;   // UNIT_PATH_V1 道ごとの いま いる場所
  say('b', SAY.start);
  nextSkill();
}
function nextSkill() {
  while (C.queue.length && C.res[C.queue[0]]) C.queue.shift();
  if (!C.queue.length || C.order.length >= MAX_SKILLS) { result(false); return; }
  var id = C.queue.shift();
  C.cur = { id: id, right: 0, n: 0 }; C.order.push(id);
  var s = S_by[id];
  say('b', fill(SAY.where, { g: s.g, n: s.name }));
  newQ();
}
function newQ() {
  var s = S_by[C.cur.id], Q, k = 0;
  do { Q = s.gen(); k++; } while (C.lastQ && Q.q === C.lastQ && k < 8);
  C.Q = Q; C.lastQ = Q.q; C.hinted = false; C.answered = false;
  say('b', Q.q, true);
}
function answer(skip) {
  var Q = C.Q, ok = false;
  if (!skip) {
    var foot = document.getElementById('hkFoot');
    var v = function (id) { var e = foot && foot.querySelector('[data-k="' + id + '"]'); return e ? e.value : ''; };
    var A = readAns(Q, v);
    if (!A) { C.note = Q.type === 'frac' ? '分子と分母に 数を 入れてな' : '数を 入れてな'; draw(); return; }
    ok = judge(Q, A);
    say('m', meText(Q, A));
    if (!ok && Q.type === 'frac' && Q.simplest) { var N = Q.ans[0], D = Q.ans[1]; if ((A.w * A.d + A.n) * D === N * A.d) { say('b', 'おしい！ 大きさは 合ってるで。でも まだ 約分できるな。答えは ' + ansText(Q) + ' やで。', true); finish(false); return; } }
  } else say('m', 'わからない');
  if (ok) say('b', SAY.ok[C.cur.n % SAY.ok.length]);
  else say('b', fill(skip ? SAY.skip : SAY.ng, { a: ansText(Q) }) + '\n💡 やり方：' + S_by[C.cur.id].how, true);
  finish(ok);
}
function meText(Q, A) {
  if (Q.type === 'num') return String(A.x);
  if (Q.type === 'rem') return A.q + (A.r ? ' あまり ' + A.r : '');
  if (Q.type === 'ratio') return A.a + ' : ' + A.b;
  if (Q.type === 'hm') return A.h + '時' + A.m + '分';
  if (Q.type === 'pair') return A.h + Q.labels[0] + A.m + Q.labels[1];
  return (A.w ? A.w + ' と ' : '') + (A.only ? '' : A.d + '分の' + A.n);
}
function finish(ok) {
  var c = C.cur; c.n++; if (ok) c.right++; if (ok && C.hinted) c.hintOk = (c.hintOk || 0) + 1;
  C.answered = true; C.note = '';
  draw();
}
function next() {
  var c = C.cur, wrong = c.n - c.right, st = null, s = S_by[c.id];
  if (c.right >= 2) st = (c.n === 2 && !c.hintOk) ? 'ok' : 'tri'; else if (wrong >= 2) st = 'x';
  if (!st) { newQ(); draw(); return; }
  C.res[c.id] = { st: st, right: c.right, n: c.n, hint: !!c.hintOk };
  if (C.paths) {   // UNIT_PATH_V1 単元の 道を たどる
    if (c.id === C.goal) {
      if (st === 'x') {
        C.walk = C.paths.map(function (p) { return { p: p, i: 0, done: false }; });
        say('b', fill(SAY.back, { n: s.name }) + '\n🛤 この単元の もどる道：' + pathText(C.goalUnit));
      } else say('b', fill(st === 'ok' ? SAY.pass : SAY.passTri, { n: s.name }));
    } else {
    }
    walkAdvance();
    if (c.id !== C.goal) say('b', fill(st === 'x' ? (C.queue.length ? SAY.backPath : SAY.backEnd) : (st === 'ok' ? SAY.pass : SAY.passTri), { n: s.name }));
    nextSkill(); draw(); return;
  }
  if (st === 'x') {
    var pre = s.pre.filter(function (p) { return !C.res[p] && C.queue.indexOf(p) < 0; });
    say('b', fill(pre.length ? SAY.back : SAY.backNone, { n: s.name }));
    C.queue = pre.concat(C.queue);
  } else say('b', fill(st === 'ok' ? SAY.pass : SAY.passTri, { n: s.name }));
  nextSkill(); draw();
}
// UNIT_PATH_V1 道を すすめる：いまの 技が ❌ なら その道の つぎへ、⭕🔺 なら その道は おしまい
function walkAdvance() {
  if (!C.walk) return;
  C.queue = [];
  C.walk.forEach(function (w) {
    while (!w.done) {
      var id = w.p[w.i];
      if (id == null) { w.done = true; break; }
      var r = C.res[id];
      if (!r) { if (C.queue.indexOf(id) < 0) C.queue.push(id); break; }
      if (r.st === 'x') { w.i++; continue; }
      w.done = true;
    }
  });
}
// UNIT_PATH_V1 根っこ＝道ごとに いちばん 奥の ❌（つぎが ⭕🔺 か 道の おわり）。どの道も 1つめが ⭕ なら 単元そのものが 練習の しどころ
function pathRoots() {
  var out = [];
  (C.walk || []).forEach(function (w) {
    var deepest = null;
    for (var i = 0; i < w.p.length; i++) { var r = C.res[w.p[i]]; if (!r) break; if (r.st === 'x') deepest = w.p[i]; else break; }
    if (deepest && out.indexOf(deepest) < 0) out.push(deepest);
  });
  return out.sort(function (a, b) { return S_by[a].g - S_by[b].g; });
}
function hint() { var s = S_by[C.cur.id]; C.hinted = true; say('m', '💡 ヒント'); say('b', '💡 ' + s.how); draw(); }

function result(quit) {
  C.step = 'result';
  var res = C.res, ids = Object.keys(res), goal = C.goal, gs = S_by[goal];
  var gr = res[goal];
  var roots = C.paths ? pathRoots() : ids.filter(function (id) { return res[id].st === 'x' && S_by[id].pre.every(function (p) { return !res[p] || res[p].st !== 'x'; }); })
    .sort(function (a, b) { return S_by[a].g - S_by[b].g; });
  // UNIT_PATH_V1 単元の技は ❌ でも、道の 1つめが ぜんぶ ⭕ なら「単元そのもの」を 練習（前に もどらなくて ええ）
  var unitSelf = !!(C.paths && gr && gr.st === 'x' && !roots.length);
  // さかのぼりきれなかった（上限）ときは、まだ調べていない前の技も ある
  var lad = ids.slice().sort(function (a, b) { return S_by[b].g - S_by[a].g; })
    .map(function (id) { var r = res[id]; return (r.st === 'ok' ? '⭕' : r.st === 'tri' ? '🔺' : '❌') + ' ' + S_by[id].g + '年 ' + S_by[id].name + '（' + r.right + '/' + r.n + '）'; });
  if (lad.length) say('b', '🪜 しらべた技\n' + lad.join('\n'));
  C.go = [];
  if (gr && gr.st !== 'x') {
    say('b', gr.hint ? SAY.goalHint : fill(SAY.goalOk, { n: unitName(C.goalUnit) }));
    C.go.push(C.goalUnit);
  } else if (unitSelf) {
    say('b', fill(SAY.unitSelf, { n: unitName(C.goalUnit) }));
    C.go.push(C.goalUnit);
  } else if (roots.length) {
    say('b', SAY.roots);
    roots.forEach(function (id) {
      var s = S_by[id], u = SK2UNIT[id];
      if (u && unitObj(u)) { say('b', fill(SAY.rootUnit, { g: s.g, n: s.name, u: unitName(u) }) + '\n💡 ' + s.how); if (C.go.indexOf(u) < 0) C.go.push(u); }
      else say('b', fill(SAY.rootNoUnit, { g: s.g, n: s.name }) + '\n💡 ' + s.how);
    });
    say('b', fill(SAY.after, { n: unitName(C.goalUnit) }));
  } else if (!ids.length) { say('b', SAY.bye); }
  else { say('b', SAY.bye); }
  saveLast(roots);
  draw();
}
function saveLast(roots) {
  try {
    var k = 'hsCheckV1:' + String((window.player && (player.id || player.name)) || '');
    localStorage.setItem(k, JSON.stringify({ at: Date.now(), unit: C.goalUnit, go: C.go, roots: roots }));
  } catch (e) {}
  // SAKANOBORI_V1 先生に のこす（技の 名前つき）。しらべた 技が 1つも ない ときは 送らない
  try {
    var ids = Object.keys(C.res || {}); if (!ids.length) return;
    var nm = function (id) { var s = S_by[id]; return s ? (s.g + '年 ' + s.name) : id; };
    var body = { unit: C.goalUnit, unitName: unitName(C.goalUnit), src: C.src || 'self',
      roots: roots.map(nm),
      res: ids.map(function (id) { var r = C.res[id]; return { s: nm(id), st: r.st, r: r.right, n: r.n }; }) };
    fetch('/api/student/check-log', { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).catch(function () {});
  } catch (e) {}
}
function goUnit(id) {
  var o = unitObj(id); if (!o) return;
  close();
  try { if (typeof window.setMode === 'function') window.setMode('training'); } catch (e) {}
  try { if (typeof window.showSubjectModes === 'function') window.showSubjectModes('math'); } catch (e) {}
  try { window.__currUnit = o.u; if (typeof window.selectTrainingMode === 'function') window.selectTrainingMode(o.u.id); } catch (e) {}
}

// ───────── 描く ─────────
function bubble(x) {
  var body = (x.html ? String(x.t) : esc(x.t)).replace(/\n/g, '<br>');
  if (x.w === 'm') return '<div class="hk-row me"><div class="hk-b">' + body + '</div></div>';
  return '<div class="hk-row bot"><span class="hk-face">' + face() + '</span><div class="hk-b">' + body + '</div></div>';
}
function btns(list, cls) { return '<div class="hk-ch ' + (cls || '') + '">' + list.map(function (b, i) { return '<button type="button" class="hk-btn ' + (b.cls || '') + '" data-i="' + i + '">' + esc(b.label) + '</button>'; }).join('') + '</div>'; }
function bind(el, fns) { if (!el) return; var bs = el.querySelectorAll('[data-i]'); for (var i = 0; i < bs.length; i++) (function (b) { b.onclick = function () { var f = fns[Number(b.getAttribute('data-i'))]; if (f) f(); }; })(bs[i]); }
function inp(k, ph) { return '<input data-k="' + k + '" inputmode="decimal" autocomplete="off"' + (ph ? ' placeholder="' + ph + '"' : '') + '>'; }
function inputHtml(Q) {
  if (Q.type === 'num') return '答え ' + inp('k1');
  if (Q.type === 'rem') return inp('k1') + ' あまり ' + inp('k2');
  if (Q.type === 'ratio') return inp('k1') + ' <b class="hk-big">:</b> ' + inp('k2');
  if (Q.type === 'hm') return inp('k1') + ' 時 ' + inp('k2') + ' 分';
  if (Q.type === 'pair') return inp('k1') + ' ' + Q.labels[0] + ' ' + inp('k2') + ' ' + Q.labels[1];
  return (Q.whole ? '<span class="hk-w">整数<br>（なければ空らん）' + inp('kW') + '</span>' : '') + '<span class="frac"><span>' + inp('k1', '分子') + '</span><span>' + inp('k2', '分母') + '</span></span>';
}
function draw() {
  var logEl = document.getElementById('hkLog'), foot = document.getElementById('hkFoot');
  if (!logEl || !foot || !C) return;
  logEl.innerHTML = C.log.map(bubble).join('') || bubble({ w: 'b', t: 'ちょっと まってな…' });
  logEl.scrollTop = logEl.scrollHeight;
  if (C.step === 'ask') {
    if (!C.now) { foot.innerHTML = ''; return; }
    var l = [{ label: '🔍 やってみる！', cls: 'main' }, { label: '📚 ほかの単元にする' }, { label: 'また こんど', cls: 'sub' }];
    foot.innerHTML = btns(l, 'three');
    bind(foot, [function () { say('m', 'やってみる！'); begin(C.now.id); draw(); }, function () { say('m', 'ほかの単元にする'); say('b', SAY.pick); C.step = 'pick'; draw(); }, function () { close(); }]);
  } else if (C.step === 'pick') {
    var ids = pickList();
    var bl = ids.map(function (id) { var o = unitObj(id); return { label: (o.grade !== myGrade() ? o.grade + '年 ' : '') + o.u.name }; }).concat([{ label: 'また こんど', cls: 'sub' }]);
    foot.innerHTML = '<div class="hk-scroll">' + btns(bl) + '</div>';
    bind(foot, ids.map(function (id) { return function () { say('m', unitName(id)); C.now = { id: id, src: 'pick' }; begin(id); draw(); }; }).concat([close]));
  } else if (C.step === 'quiz') {
    if (C.answered) {
      foot.innerHTML = btns([{ label: 'つぎへ ▶', cls: 'main' }], 'one');
      bind(foot, [next]);
      setTimeout(function () { var b = foot.querySelector('.hk-btn'); if (b) try { b.focus(); } catch (e) {} }, 30);
      return;
    }
    foot.innerHTML = '<div class="hk-in">' + inputHtml(C.Q) + '</div>' + (C.note ? '<div class="hk-note">' + esc(C.note) + '</div>' : '')
      + btns([{ label: 'こたえる', cls: 'main' }, { label: 'わからない', cls: 'sub' }, { label: '💡 ヒント', cls: 'sub' }], 'three');
    bind(foot, [function () { answer(false); }, function () { answer(true); }, C.hinted ? null : hint]);
    var ins = foot.querySelectorAll('input');
    for (var i = 0; i < ins.length; i++) ins[i].onkeydown = function (e) { if (e.key === 'Enter') { e.preventDefault(); answer(false); } };
    if (C.hinted) { var hb = foot.querySelectorAll('.hk-btn')[2]; if (hb) hb.disabled = true; }
    setTimeout(function () { var f = foot.querySelector('input'); if (f) try { f.focus(); } catch (e) {} }, 30);
  } else if (C.step === 'result') {
    var go = (C.go || []).map(function (id) { return { label: '⚔ ' + unitName(id) + ' の修行へ', cls: 'main' }; });
    var l2 = go.concat([{ label: '🔁 もう一回 チェック' }, { label: 'とじる', cls: 'sub' }]);
    foot.innerHTML = btns(l2, l2.length === 2 ? '' : 'one');
    bind(foot, (C.go || []).map(function (id) { return function () { goUnit(id); }; }).concat([function () { var u = C.goalUnit; C.log = []; C.step = 'quiz'; C.now = { id: u, src: 'pick' }; begin(u); draw(); }, close]));
  }
}

var _css = false;
function ensureCss() {
  if (_css) return; _css = true;
  var st = document.createElement('style');
  st.textContent = '#hkChat{position:fixed;inset:0;z-index:9991;background:rgba(15,23,42,.45);display:flex;justify-content:center;align-items:stretch;font-family:inherit}'
    + '#hkChat .hk-box{width:100%;max-width:780px;background:#f0f9ff;display:flex;flex-direction:column;height:100%;box-shadow:0 0 30px rgba(0,0,0,.25)}'
    + '#hkChat .hk-head{display:flex;align-items:center;gap:10px;padding:10px 14px;background:#facc15;color:#1f2937;font-weight:900;font-size:18px}'
    + '#hkChat .hk-x{margin-left:auto;background:#fff;border:2px solid #a16207;border-radius:12px;padding:8px 14px;font-size:15px;font-weight:800;color:#713f12;min-height:44px}'
    + '#hkChat .hk-log{flex:1;overflow-y:auto;padding:14px 14px 6px;-webkit-overflow-scrolling:touch}'
    + '#hkChat .hk-row{display:flex;gap:8px;margin:8px 0;align-items:flex-end}'
    + '#hkChat .hk-row.me{justify-content:flex-end}'
    + '#hkChat .hk-face{width:44px;height:44px;flex:0 0 44px;display:flex;align-items:center;justify-content:center;font-size:30px;background:#fff;border-radius:50%;border:2px solid #fde68a;overflow:hidden}'
    + '#hkChat .hk-face img{max-width:40px;max-height:40px}'
    + '#hkChat .hk-b{max-width:78%;padding:10px 14px;border-radius:18px;font-size:18px;line-height:1.6;word-break:break-word}'
    + '#hkChat .bot .hk-b{background:#fff;border:2px solid #bae6fd;border-bottom-left-radius:6px;color:#1f2937}'
    + '#hkChat .me .hk-b{background:#86efac;border-bottom-right-radius:6px;color:#14532d;font-weight:700}'
    + '#hkChat .hk-b svg{max-width:100%;height:auto;display:block;margin:4px auto}'
    + '#hkChat .hk-foot{border-top:2px solid #bae6fd;background:#fff;padding:10px 12px 14px}'
    + '#hkChat .hk-scroll{max-height:42vh;overflow-y:auto}'
    + '#hkChat .hk-ch{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px}'
    + '#hkChat .hk-ch.one{grid-template-columns:1fr}#hkChat .hk-ch.three{grid-template-columns:1fr 1fr 1fr}'
    + '#hkChat .hk-btn{min-height:54px;border-radius:16px;border:2px solid #0ea5e9;background:#fff;color:#075985;font-size:16px;font-weight:800;padding:8px 10px;cursor:pointer;touch-action:manipulation}'
    + '#hkChat .hk-btn.main{background:#0284c7;border-color:#075985;color:#fff}'
    + '#hkChat .hk-btn.sub{background:#f1f5f9;border-color:#cbd5e1;color:#334155}'
    + '#hkChat .hk-btn:disabled{opacity:.4}'
    + '#hkChat .hk-in{display:flex;flex-wrap:wrap;align-items:center;justify-content:center;gap:8px;font-size:20px;font-weight:800}'
    + '#hkChat .hk-in input{width:96px;min-height:50px;border:2px solid #0ea5e9;border-radius:12px;padding:0 8px;font-size:22px;text-align:center;background:#fff}'
    + '#hkChat .hk-w{display:inline-flex;flex-direction:column;align-items:center;font-size:11px;color:#475569}'
    + '#hkChat .hk-big{font-size:28px}'
    + '#hkChat .hk-note{text-align:center;color:#b45309;font-weight:800;margin-top:4px}'
    + '#hkChat .frac{display:inline-flex;flex-direction:column;vertical-align:middle;text-align:center;line-height:1.15;margin:0 2px}'
    + '#hkChat .frac>span:first-child{border-bottom:2px solid currentColor;padding:0 4px}'
    + '#hkChat .hk-in .frac input{margin:2px 0}'
    + '.hkEntry{display:flex;align-items:center;gap:10px;width:100%;max-width:48rem;margin:0 auto 10px;padding:10px 14px;border-radius:16px;border:3px solid #0284c7;background:linear-gradient(135deg,#e0f2fe,#fef9c3);color:#0c4a6e;font-weight:900;font-size:15px;text-align:left;cursor:pointer;box-shadow:0 4px 12px rgba(2,132,199,.2)}'
    + '.hkEntry .hk-e1{font-size:30px}.hkEntry small{display:block;font-weight:700;color:#475569;font-size:12px}'
    + '.hkEntry .hk-go{margin-left:auto;background:#0284c7;color:#fff;border-radius:999px;padding:8px 12px;white-space:nowrap;font-size:14px}';
  document.head.appendChild(st);
}

// ───────── 入口：修行の「科目を選べ」と 算数の単元えらびの上 ─────────
function entryText() {
  var r = nowUnit();
  if (r) return { t: fill(SAY.askNow[r.src] || SAY.askNow.std, { u: unitName(r.id) }), s: '必要な技が 身についてるか 理解度チェック してみるか？', id: r.id };
  return { t: '🔍 理解度チェック', s: '今の学習に 必要な技が 身についてるか、阪神マンと 調べよか', id: '' };
}
function entryHtml() { var e = entryText(); return '<span class="hk-e1">🐯</span><span>' + esc(e.t) + '<small>' + esc(e.s) + '</small></span><span class="hk-go">🔍 チェック</span>'; }
function placeEntry(host, before, key) {
  if (!host) return;
  var b = host.querySelector('.hkEntry[data-k="' + key + '"]');
  if (!b) {
    ensureCss();
    b = document.createElement('button'); b.type = 'button'; b.className = 'hkEntry'; b.setAttribute('data-k', key);
    b.onclick = function () { open(''); };
    host.insertBefore(b, before || host.firstChild);
  }
  var h = entryHtml(); if (b._h !== h) { b.innerHTML = h; b._h = h; }
}
function tick() {
  if (!myGrade() || !curr()) return;
  var ss = document.getElementById('training-subject-select');
  if (ss && ss.offsetParent) { load(false); var grid = ss.querySelector('.grid'); placeEntry(ss, grid, 'subj'); }
  var ms = document.getElementById('training-mode-select'), ct = document.getElementById('training-modes-container');
  var isMath = String(window.currentTrainingSubject || '') === 'math' || /算数/.test(String((document.getElementById('mode-select-title') || {}).textContent || ''));
  if (ms && ct && ms.offsetParent && isMath) { load(false); placeEntry(ct.parentNode, ct, 'math'); }
  else if (ct && ct.parentNode) { var o = ct.parentNode.querySelector('.hkEntry[data-k="math"]'); if (o && !isMath) o.remove(); }
}
setInterval(function () { try { tick(); } catch (e) {} }, 1200);
window.HSCHECK = { open: open, UNIT_PATHS: UNIT_PATHS, pathText: pathText, resolveNow: resolveNow, S: S, UNIT2GOAL: UNIT2GOAL, SK2UNIT: SK2UNIT, _t: { readAns: readAns, judge: judge, ansText: ansText, state: function () { return C; }, setData: function (d) { _data = d; } } };

})();
