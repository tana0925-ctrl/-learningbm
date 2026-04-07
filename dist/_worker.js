var Ft=Object.defineProperty;var rt=e=>{throw TypeError(e)};var Wt=(e,t,s)=>t in e?Ft(e,t,{enumerable:!0,configurable:!0,writable:!0,value:s}):e[t]=s;var k=(e,t,s)=>Wt(e,typeof t!="symbol"?t+"":t,s),Qe=(e,t,s)=>t.has(e)||rt("Cannot "+s);var u=(e,t,s)=>(Qe(e,t,"read from private field"),s?s.call(e):t.get(e)),I=(e,t,s)=>t.has(e)?rt("Cannot add the same private member more than once"):t instanceof WeakSet?t.add(e):t.set(e,s),E=(e,t,s,n)=>(Qe(e,t,"write to private field"),n?n.call(e,s):t.set(e,s),s),S=(e,t,s)=>(Qe(e,t,"access private method"),s);var ot=(e,t,s,n)=>({set _(a){E(e,t,a,s)},get _(){return u(e,t,n)}});var it=(e,t,s)=>(n,a)=>{let r=-1;return o(0);async function o(i){if(i<=r)throw new Error("next() called multiple times");r=i;let l,c=!1,p;if(e[i]?(p=e[i][0][0],n.req.routeIndex=i):p=i===e.length&&a||void 0,p)try{l=await p(n,()=>o(i+1))}catch(h){if(h instanceof Error&&t)n.error=h,l=await t(h,n),c=!0;else throw h}else n.finalized===!1&&s&&(l=await s(n));return l&&(n.finalized===!1||c)&&(n.res=l),n}},Ut=Symbol(),Jt=async(e,t=Object.create(null))=>{const{all:s=!1,dot:n=!1}=t,r=(e instanceof kt?e.raw.headers:e.headers).get("Content-Type");return r!=null&&r.startsWith("multipart/form-data")||r!=null&&r.startsWith("application/x-www-form-urlencoded")?Kt(e,{all:s,dot:n}):{}};async function Kt(e,t){const s=await e.formData();return s?$t(s,t):{}}function $t(e,t){const s=Object.create(null);return e.forEach((n,a)=>{t.all||a.endsWith("[]")?zt(s,a,n):s[a]=n}),t.dot&&Object.entries(s).forEach(([n,a])=>{n.includes(".")&&(Vt(s,n,a),delete s[n])}),s}var zt=(e,t,s)=>{e[t]!==void 0?Array.isArray(e[t])?e[t].push(s):e[t]=[e[t],s]:t.endsWith("[]")?e[t]=[s]:e[t]=s},Vt=(e,t,s)=>{let n=e;const a=t.split(".");a.forEach((r,o)=>{o===a.length-1?n[r]=s:((!n[r]||typeof n[r]!="object"||Array.isArray(n[r])||n[r]instanceof File)&&(n[r]=Object.create(null)),n=n[r])})},yt=e=>{const t=e.split("/");return t[0]===""&&t.shift(),t},Gt=e=>{const{groups:t,path:s}=Yt(e),n=yt(s);return Qt(n,t)},Yt=e=>{const t=[];return e=e.replace(/\{[^}]+\}/g,(s,n)=>{const a=`@${n}`;return t.push([a,s]),a}),{groups:t,path:e}},Qt=(e,t)=>{for(let s=t.length-1;s>=0;s--){const[n]=t[s];for(let a=e.length-1;a>=0;a--)if(e[a].includes(n)){e[a]=e[a].replace(n,t[s][1]);break}}return e},Pe={},Xt=(e,t)=>{if(e==="*")return"*";const s=e.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);if(s){const n=`${e}#${t}`;return Pe[n]||(s[2]?Pe[n]=t&&t[0]!==":"&&t[0]!=="*"?[n,s[1],new RegExp(`^${s[2]}(?=/${t})`)]:[e,s[1],new RegExp(`^${s[2]}$`)]:Pe[n]=[e,s[1],!0]),Pe[n]}return null},Ve=(e,t)=>{try{return t(e)}catch{return e.replace(/(?:%[0-9A-Fa-f]{2})+/g,s=>{try{return t(s)}catch{return s}})}},Zt=e=>Ve(e,decodeURI),xt=e=>{const t=e.url,s=t.indexOf("/",t.indexOf(":")+4);let n=s;for(;n<t.length;n++){const a=t.charCodeAt(n);if(a===37){const r=t.indexOf("?",n),o=t.indexOf("#",n),i=r===-1?o===-1?void 0:o:o===-1?r:Math.min(r,o),l=t.slice(s,i);return Zt(l.includes("%25")?l.replace(/%25/g,"%2525"):l)}else if(a===63||a===35)break}return t.slice(s,n)},es=e=>{const t=xt(e);return t.length>1&&t.at(-1)==="/"?t.slice(0,-1):t},me=(e,t,...s)=>(s.length&&(t=me(t,...s)),`${(e==null?void 0:e[0])==="/"?"":"/"}${e}${t==="/"?"":`${(e==null?void 0:e.at(-1))==="/"?"":"/"}${(t==null?void 0:t[0])==="/"?t.slice(1):t}`}`),vt=e=>{if(e.charCodeAt(e.length-1)!==63||!e.includes(":"))return null;const t=e.split("/"),s=[];let n="";return t.forEach(a=>{if(a!==""&&!/\:/.test(a))n+="/"+a;else if(/\:/.test(a))if(/\?/.test(a)){s.length===0&&n===""?s.push("/"):s.push(n);const r=a.replace("?","");n+="/"+r,s.push(n)}else n+="/"+a}),s.filter((a,r,o)=>o.indexOf(a)===r)},Xe=e=>/[%+]/.test(e)?(e.indexOf("+")!==-1&&(e=e.replace(/\+/g," ")),e.indexOf("%")!==-1?Ve(e,st):e):e,Et=(e,t,s)=>{let n;if(!s&&t&&!/[%+]/.test(t)){let o=e.indexOf("?",8);if(o===-1)return;for(e.startsWith(t,o+1)||(o=e.indexOf(`&${t}`,o+1));o!==-1;){const i=e.charCodeAt(o+t.length+1);if(i===61){const l=o+t.length+2,c=e.indexOf("&",l);return Xe(e.slice(l,c===-1?void 0:c))}else if(i==38||isNaN(i))return"";o=e.indexOf(`&${t}`,o+1)}if(n=/[%+]/.test(e),!n)return}const a={};n??(n=/[%+]/.test(e));let r=e.indexOf("?",8);for(;r!==-1;){const o=e.indexOf("&",r+1);let i=e.indexOf("=",r);i>o&&o!==-1&&(i=-1);let l=e.slice(r+1,i===-1?o===-1?void 0:o:i);if(n&&(l=Xe(l)),r=o,l==="")continue;let c;i===-1?c="":(c=e.slice(i+1,o===-1?void 0:o),n&&(c=Xe(c))),s?(a[l]&&Array.isArray(a[l])||(a[l]=[]),a[l].push(c)):a[l]??(a[l]=c)}return t?a[t]:a},ts=Et,ss=(e,t)=>Et(e,t,!0),st=decodeURIComponent,dt=e=>Ve(e,st),fe,P,V,It,St,tt,G,ht,kt=(ht=class{constructor(e,t="/",s=[[]]){I(this,V);k(this,"raw");I(this,fe);I(this,P);k(this,"routeIndex",0);k(this,"path");k(this,"bodyCache",{});I(this,G,e=>{const{bodyCache:t,raw:s}=this,n=t[e];if(n)return n;const a=Object.keys(t)[0];return a?t[a].then(r=>(a==="json"&&(r=JSON.stringify(r)),new Response(r)[e]())):t[e]=s[e]()});this.raw=e,this.path=t,E(this,P,s),E(this,fe,{})}param(e){return e?S(this,V,It).call(this,e):S(this,V,St).call(this)}query(e){return ts(this.url,e)}queries(e){return ss(this.url,e)}header(e){if(e)return this.raw.headers.get(e)??void 0;const t={};return this.raw.headers.forEach((s,n)=>{t[n]=s}),t}async parseBody(e){var t;return(t=this.bodyCache).parsedBody??(t.parsedBody=await Jt(this,e))}json(){return u(this,G).call(this,"text").then(e=>JSON.parse(e))}text(){return u(this,G).call(this,"text")}arrayBuffer(){return u(this,G).call(this,"arrayBuffer")}blob(){return u(this,G).call(this,"blob")}formData(){return u(this,G).call(this,"formData")}addValidatedData(e,t){u(this,fe)[e]=t}valid(e){return u(this,fe)[e]}get url(){return this.raw.url}get method(){return this.raw.method}get[Ut](){return u(this,P)}get matchedRoutes(){return u(this,P)[0].map(([[,e]])=>e)}get routePath(){return u(this,P)[0].map(([[,e]])=>e)[this.routeIndex].path}},fe=new WeakMap,P=new WeakMap,V=new WeakSet,It=function(e){const t=u(this,P)[0][this.routeIndex][1][e],s=S(this,V,tt).call(this,t);return s&&/\%/.test(s)?dt(s):s},St=function(){const e={},t=Object.keys(u(this,P)[0][this.routeIndex][1]);for(const s of t){const n=S(this,V,tt).call(this,u(this,P)[0][this.routeIndex][1][s]);n!==void 0&&(e[s]=/\%/.test(n)?dt(n):n)}return e},tt=function(e){return u(this,P)[1]?u(this,P)[1][e]:e},G=new WeakMap,ht),ns={Stringify:1},Ct=async(e,t,s,n,a)=>{typeof e=="object"&&!(e instanceof String)&&(e instanceof Promise||(e=e.toString()),e instanceof Promise&&(e=await e));const r=e.callbacks;return r!=null&&r.length?(a?a[0]+=e:a=[e],Promise.all(r.map(i=>i({phase:t,buffer:a,context:n}))).then(i=>Promise.all(i.filter(Boolean).map(l=>Ct(l,t,!1,n,a))).then(()=>a[0]))):Promise.resolve(e)},as="text/plain; charset=UTF-8",Ze=(e,t)=>({"Content-Type":e,...t}),Ce=(e,t)=>new Response(e,t),Oe,je,J,be,K,B,Ae,we,_e,ne,Be,Le,Y,he,gt,rs=(gt=class{constructor(e,t){I(this,Y);I(this,Oe);I(this,je);k(this,"env",{});I(this,J);k(this,"finalized",!1);k(this,"error");I(this,be);I(this,K);I(this,B);I(this,Ae);I(this,we);I(this,_e);I(this,ne);I(this,Be);I(this,Le);k(this,"render",(...e)=>(u(this,we)??E(this,we,t=>this.html(t)),u(this,we).call(this,...e)));k(this,"setLayout",e=>E(this,Ae,e));k(this,"getLayout",()=>u(this,Ae));k(this,"setRenderer",e=>{E(this,we,e)});k(this,"header",(e,t,s)=>{this.finalized&&E(this,B,Ce(u(this,B).body,u(this,B)));const n=u(this,B)?u(this,B).headers:u(this,ne)??E(this,ne,new Headers);t===void 0?n.delete(e):s!=null&&s.append?n.append(e,t):n.set(e,t)});k(this,"status",e=>{E(this,be,e)});k(this,"set",(e,t)=>{u(this,J)??E(this,J,new Map),u(this,J).set(e,t)});k(this,"get",e=>u(this,J)?u(this,J).get(e):void 0);k(this,"newResponse",(...e)=>S(this,Y,he).call(this,...e));k(this,"body",(e,t,s)=>S(this,Y,he).call(this,e,t,s));k(this,"text",(e,t,s)=>!u(this,ne)&&!u(this,be)&&!t&&!s&&!this.finalized?new Response(e):S(this,Y,he).call(this,e,t,Ze(as,s)));k(this,"json",(e,t,s)=>S(this,Y,he).call(this,JSON.stringify(e),t,Ze("application/json",s)));k(this,"html",(e,t,s)=>{const n=a=>S(this,Y,he).call(this,a,t,Ze("text/html; charset=UTF-8",s));return typeof e=="object"?Ct(e,ns.Stringify,!1,{}).then(n):n(e)});k(this,"redirect",(e,t)=>{const s=String(e);return this.header("Location",/[^\x00-\xFF]/.test(s)?encodeURI(s):s),this.newResponse(null,t??302)});k(this,"notFound",()=>(u(this,_e)??E(this,_e,()=>Ce()),u(this,_e).call(this,this)));E(this,Oe,e),t&&(E(this,K,t.executionCtx),this.env=t.env,E(this,_e,t.notFoundHandler),E(this,Le,t.path),E(this,Be,t.matchResult))}get req(){return u(this,je)??E(this,je,new kt(u(this,Oe),u(this,Le),u(this,Be))),u(this,je)}get event(){if(u(this,K)&&"respondWith"in u(this,K))return u(this,K);throw Error("This context has no FetchEvent")}get executionCtx(){if(u(this,K))return u(this,K);throw Error("This context has no ExecutionContext")}get res(){return u(this,B)||E(this,B,Ce(null,{headers:u(this,ne)??E(this,ne,new Headers)}))}set res(e){if(u(this,B)&&e){e=Ce(e.body,e);for(const[t,s]of u(this,B).headers.entries())if(t!=="content-type")if(t==="set-cookie"){const n=u(this,B).headers.getSetCookie();e.headers.delete("set-cookie");for(const a of n)e.headers.append("set-cookie",a)}else e.headers.set(t,s)}E(this,B,e),this.finalized=!0}get var(){return u(this,J)?Object.fromEntries(u(this,J)):{}}},Oe=new WeakMap,je=new WeakMap,J=new WeakMap,be=new WeakMap,K=new WeakMap,B=new WeakMap,Ae=new WeakMap,we=new WeakMap,_e=new WeakMap,ne=new WeakMap,Be=new WeakMap,Le=new WeakMap,Y=new WeakSet,he=function(e,t,s){const n=u(this,B)?new Headers(u(this,B).headers):u(this,ne)??new Headers;if(typeof t=="object"&&"headers"in t){const r=t.headers instanceof Headers?t.headers:new Headers(t.headers);for(const[o,i]of r)o.toLowerCase()==="set-cookie"?n.append(o,i):n.set(o,i)}if(s)for(const[r,o]of Object.entries(s))if(typeof o=="string")n.set(r,o);else{n.delete(r);for(const i of o)n.append(r,i)}const a=typeof t=="number"?t:(t==null?void 0:t.status)??u(this,be);return Ce(e,{status:a,headers:n})},gt),R="ALL",os="all",is=["get","post","put","delete","options","patch"],Dt="Can not add a route since the matcher is already built.",Tt=class extends Error{},ds="__COMPOSED_HANDLER",ls=e=>e.text("404 Not Found",404),lt=(e,t)=>{if("getResponse"in e){const s=e.getResponse();return t.newResponse(s.body,s)}return console.error(e),t.text("Internal Server Error",500)},q,N,Rt,F,te,Fe,We,ye,cs=(ye=class{constructor(t={}){I(this,N);k(this,"get");k(this,"post");k(this,"put");k(this,"delete");k(this,"options");k(this,"patch");k(this,"all");k(this,"on");k(this,"use");k(this,"router");k(this,"getPath");k(this,"_basePath","/");I(this,q,"/");k(this,"routes",[]);I(this,F,ls);k(this,"errorHandler",lt);k(this,"onError",t=>(this.errorHandler=t,this));k(this,"notFound",t=>(E(this,F,t),this));k(this,"fetch",(t,...s)=>S(this,N,We).call(this,t,s[1],s[0],t.method));k(this,"request",(t,s,n,a)=>t instanceof Request?this.fetch(s?new Request(t,s):t,n,a):(t=t.toString(),this.fetch(new Request(/^https?:\/\//.test(t)?t:`http://localhost${me("/",t)}`,s),n,a)));k(this,"fire",()=>{addEventListener("fetch",t=>{t.respondWith(S(this,N,We).call(this,t.request,t,void 0,t.request.method))})});[...is,os].forEach(r=>{this[r]=(o,...i)=>(typeof o=="string"?E(this,q,o):S(this,N,te).call(this,r,u(this,q),o),i.forEach(l=>{S(this,N,te).call(this,r,u(this,q),l)}),this)}),this.on=(r,o,...i)=>{for(const l of[o].flat()){E(this,q,l);for(const c of[r].flat())i.map(p=>{S(this,N,te).call(this,c.toUpperCase(),u(this,q),p)})}return this},this.use=(r,...o)=>(typeof r=="string"?E(this,q,r):(E(this,q,"*"),o.unshift(r)),o.forEach(i=>{S(this,N,te).call(this,R,u(this,q),i)}),this);const{strict:n,...a}=t;Object.assign(this,a),this.getPath=n??!0?t.getPath??xt:es}route(t,s){const n=this.basePath(t);return s.routes.map(a=>{var o;let r;s.errorHandler===lt?r=a.handler:(r=async(i,l)=>(await it([],s.errorHandler)(i,()=>a.handler(i,l))).res,r[ds]=a.handler),S(o=n,N,te).call(o,a.method,a.path,r)}),this}basePath(t){const s=S(this,N,Rt).call(this);return s._basePath=me(this._basePath,t),s}mount(t,s,n){let a,r;n&&(typeof n=="function"?r=n:(r=n.optionHandler,n.replaceRequest===!1?a=l=>l:a=n.replaceRequest));const o=r?l=>{const c=r(l);return Array.isArray(c)?c:[c]}:l=>{let c;try{c=l.executionCtx}catch{}return[l.env,c]};a||(a=(()=>{const l=me(this._basePath,t),c=l==="/"?0:l.length;return p=>{const h=new URL(p.url);return h.pathname=h.pathname.slice(c)||"/",new Request(h,p)}})());const i=async(l,c)=>{const p=await s(a(l.req.raw),...o(l));if(p)return p;await c()};return S(this,N,te).call(this,R,me(t,"*"),i),this}},q=new WeakMap,N=new WeakSet,Rt=function(){const t=new ye({router:this.router,getPath:this.getPath});return t.errorHandler=this.errorHandler,E(t,F,u(this,F)),t.routes=this.routes,t},F=new WeakMap,te=function(t,s,n){t=t.toUpperCase(),s=me(this._basePath,s);const a={basePath:this._basePath,path:s,method:t,handler:n};this.router.add(t,s,[n,a]),this.routes.push(a)},Fe=function(t,s){if(t instanceof Error)return this.errorHandler(t,s);throw t},We=function(t,s,n,a){if(a==="HEAD")return(async()=>new Response(null,await S(this,N,We).call(this,t,s,n,"GET")))();const r=this.getPath(t,{env:n}),o=this.router.match(a,r),i=new rs(t,{path:r,matchResult:o,env:n,executionCtx:s,notFoundHandler:u(this,F)});if(o[0].length===1){let c;try{c=o[0][0][0][0](i,async()=>{i.res=await u(this,F).call(this,i)})}catch(p){return S(this,N,Fe).call(this,p,i)}return c instanceof Promise?c.then(p=>p||(i.finalized?i.res:u(this,F).call(this,i))).catch(p=>S(this,N,Fe).call(this,p,i)):c??u(this,F).call(this,i)}const l=it(o[0],this.errorHandler,u(this,F));return(async()=>{try{const c=await l(i);if(!c.finalized)throw new Error("Context is not finalized. Did you forget to return a Response object or `await next()`?");return c.res}catch(c){return S(this,N,Fe).call(this,c,i)}})()},ye),Nt=[];function us(e,t){const s=this.buildAllMatchers(),n=((a,r)=>{const o=s[a]||s[R],i=o[2][r];if(i)return i;const l=r.match(o[0]);if(!l)return[[],Nt];const c=l.indexOf("",1);return[o[1][c],l]});return this.match=n,n(e,t)}var Je="[^/]+",Te=".*",Re="(?:|/.*)",ge=Symbol(),ps=new Set(".\\+*[^]$()");function ms(e,t){return e.length===1?t.length===1?e<t?-1:1:-1:t.length===1||e===Te||e===Re?1:t===Te||t===Re?-1:e===Je?1:t===Je?-1:e.length===t.length?e<t?-1:1:t.length-e.length}var ae,re,W,de,hs=(de=class{constructor(){I(this,ae);I(this,re);I(this,W,Object.create(null))}insert(t,s,n,a,r){if(t.length===0){if(u(this,ae)!==void 0)throw ge;if(r)return;E(this,ae,s);return}const[o,...i]=t,l=o==="*"?i.length===0?["","",Te]:["","",Je]:o==="/*"?["","",Re]:o.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);let c;if(l){const p=l[1];let h=l[2]||Je;if(p&&l[2]&&(h===".*"||(h=h.replace(/^\((?!\?:)(?=[^)]+\)$)/,"(?:"),/\((?!\?:)/.test(h))))throw ge;if(c=u(this,W)[h],!c){if(Object.keys(u(this,W)).some(w=>w!==Te&&w!==Re))throw ge;if(r)return;c=u(this,W)[h]=new de,p!==""&&E(c,re,a.varIndex++)}!r&&p!==""&&n.push([p,u(c,re)])}else if(c=u(this,W)[o],!c){if(Object.keys(u(this,W)).some(p=>p.length>1&&p!==Te&&p!==Re))throw ge;if(r)return;c=u(this,W)[o]=new de}c.insert(i,s,n,a,r)}buildRegExpStr(){const s=Object.keys(u(this,W)).sort(ms).map(n=>{const a=u(this,W)[n];return(typeof u(a,re)=="number"?`(${n})@${u(a,re)}`:ps.has(n)?`\\${n}`:n)+a.buildRegExpStr()});return typeof u(this,ae)=="number"&&s.unshift(`#${u(this,ae)}`),s.length===0?"":s.length===1?s[0]:"(?:"+s.join("|")+")"}},ae=new WeakMap,re=new WeakMap,W=new WeakMap,de),$e,Me,ft,gs=(ft=class{constructor(){I(this,$e,{varIndex:0});I(this,Me,new hs)}insert(e,t,s){const n=[],a=[];for(let o=0;;){let i=!1;if(e=e.replace(/\{[^}]+\}/g,l=>{const c=`@\\${o}`;return a[o]=[c,l],o++,i=!0,c}),!i)break}const r=e.match(/(?::[^\/]+)|(?:\/\*$)|./g)||[];for(let o=a.length-1;o>=0;o--){const[i]=a[o];for(let l=r.length-1;l>=0;l--)if(r[l].indexOf(i)!==-1){r[l]=r[l].replace(i,a[o][1]);break}}return u(this,Me).insert(r,t,n,u(this,$e),s),n}buildRegExp(){let e=u(this,Me).buildRegExpStr();if(e==="")return[/^$/,[],[]];let t=0;const s=[],n=[];return e=e.replace(/#(\d+)|@(\d+)|\.\*\$/g,(a,r,o)=>r!==void 0?(s[++t]=Number(r),"$()"):(o!==void 0&&(n[Number(o)]=++t),"")),[new RegExp(`^${e}`),s,n]}},$e=new WeakMap,Me=new WeakMap,ft),fs=[/^$/,[],Object.create(null)],Ue=Object.create(null);function Ot(e){return Ue[e]??(Ue[e]=new RegExp(e==="*"?"":`^${e.replace(/\/\*$|([.\\+*[^\]$()])/g,(t,s)=>s?`\\${s}`:"(?:|/.*)")}$`))}function bs(){Ue=Object.create(null)}function ws(e){var c;const t=new gs,s=[];if(e.length===0)return fs;const n=e.map(p=>[!/\*|\/:/.test(p[0]),...p]).sort(([p,h],[w,_])=>p?1:w?-1:h.length-_.length),a=Object.create(null);for(let p=0,h=-1,w=n.length;p<w;p++){const[_,f,y]=n[p];_?a[f]=[y.map(([x])=>[x,Object.create(null)]),Nt]:h++;let b;try{b=t.insert(f,h,_)}catch(x){throw x===ge?new Tt(f):x}_||(s[h]=y.map(([x,g])=>{const v=Object.create(null);for(g-=1;g>=0;g--){const[C,T]=b[g];v[C]=T}return[x,v]}))}const[r,o,i]=t.buildRegExp();for(let p=0,h=s.length;p<h;p++)for(let w=0,_=s[p].length;w<_;w++){const f=(c=s[p][w])==null?void 0:c[1];if(!f)continue;const y=Object.keys(f);for(let b=0,x=y.length;b<x;b++)f[y[b]]=i[f[y[b]]]}const l=[];for(const p in o)l[p]=s[o[p]];return[r,l,a]}function pe(e,t){if(e){for(const s of Object.keys(e).sort((n,a)=>a.length-n.length))if(Ot(s).test(t))return[...e[s]]}}var Q,X,ze,jt,bt,_s=(bt=class{constructor(){I(this,ze);k(this,"name","RegExpRouter");I(this,Q);I(this,X);k(this,"match",us);E(this,Q,{[R]:Object.create(null)}),E(this,X,{[R]:Object.create(null)})}add(e,t,s){var i;const n=u(this,Q),a=u(this,X);if(!n||!a)throw new Error(Dt);n[e]||[n,a].forEach(l=>{l[e]=Object.create(null),Object.keys(l[R]).forEach(c=>{l[e][c]=[...l[R][c]]})}),t==="/*"&&(t="*");const r=(t.match(/\/:/g)||[]).length;if(/\*$/.test(t)){const l=Ot(t);e===R?Object.keys(n).forEach(c=>{var p;(p=n[c])[t]||(p[t]=pe(n[c],t)||pe(n[R],t)||[])}):(i=n[e])[t]||(i[t]=pe(n[e],t)||pe(n[R],t)||[]),Object.keys(n).forEach(c=>{(e===R||e===c)&&Object.keys(n[c]).forEach(p=>{l.test(p)&&n[c][p].push([s,r])})}),Object.keys(a).forEach(c=>{(e===R||e===c)&&Object.keys(a[c]).forEach(p=>l.test(p)&&a[c][p].push([s,r]))});return}const o=vt(t)||[t];for(let l=0,c=o.length;l<c;l++){const p=o[l];Object.keys(a).forEach(h=>{var w;(e===R||e===h)&&((w=a[h])[p]||(w[p]=[...pe(n[h],p)||pe(n[R],p)||[]]),a[h][p].push([s,r-c+l+1]))})}}buildAllMatchers(){const e=Object.create(null);return Object.keys(u(this,X)).concat(Object.keys(u(this,Q))).forEach(t=>{e[t]||(e[t]=S(this,ze,jt).call(this,t))}),E(this,Q,E(this,X,void 0)),bs(),e}},Q=new WeakMap,X=new WeakMap,ze=new WeakSet,jt=function(e){const t=[];let s=e===R;return[u(this,Q),u(this,X)].forEach(n=>{const a=n[e]?Object.keys(n[e]).map(r=>[r,n[e][r]]):[];a.length!==0?(s||(s=!0),t.push(...a)):e!==R&&t.push(...Object.keys(n[R]).map(r=>[r,n[R][r]]))}),s?ws(t):null},bt),Z,$,wt,ys=(wt=class{constructor(e){k(this,"name","SmartRouter");I(this,Z,[]);I(this,$,[]);E(this,Z,e.routers)}add(e,t,s){if(!u(this,$))throw new Error(Dt);u(this,$).push([e,t,s])}match(e,t){if(!u(this,$))throw new Error("Fatal error");const s=u(this,Z),n=u(this,$),a=s.length;let r=0,o;for(;r<a;r++){const i=s[r];try{for(let l=0,c=n.length;l<c;l++)i.add(...n[l]);o=i.match(e,t)}catch(l){if(l instanceof Tt)continue;throw l}this.match=i.match.bind(i),E(this,Z,[i]),E(this,$,void 0);break}if(r===a)throw new Error("Fatal error");return this.name=`SmartRouter + ${this.activeRouter.name}`,o}get activeRouter(){if(u(this,$)||u(this,Z).length!==1)throw new Error("No active router has been determined yet.");return u(this,Z)[0]}},Z=new WeakMap,$=new WeakMap,wt),De=Object.create(null),xs=e=>{for(const t in e)return!0;return!1},ee,A,oe,xe,j,z,se,ve,vs=(ve=class{constructor(t,s,n){I(this,z);I(this,ee);I(this,A);I(this,oe);I(this,xe,0);I(this,j,De);if(E(this,A,n||Object.create(null)),E(this,ee,[]),t&&s){const a=Object.create(null);a[t]={handler:s,possibleKeys:[],score:0},E(this,ee,[a])}E(this,oe,[])}insert(t,s,n){E(this,xe,++ot(this,xe)._);let a=this;const r=Gt(s),o=[];for(let i=0,l=r.length;i<l;i++){const c=r[i],p=r[i+1],h=Xt(c,p),w=Array.isArray(h)?h[0]:c;if(w in u(a,A)){a=u(a,A)[w],h&&o.push(h[1]);continue}u(a,A)[w]=new ve,h&&(u(a,oe).push(h),o.push(h[1])),a=u(a,A)[w]}return u(a,ee).push({[t]:{handler:n,possibleKeys:o.filter((i,l,c)=>c.indexOf(i)===l),score:u(this,xe)}}),a}search(t,s){var p;const n=[];E(this,j,De);let r=[this];const o=yt(s),i=[],l=o.length;let c=null;for(let h=0;h<l;h++){const w=o[h],_=h===l-1,f=[];for(let b=0,x=r.length;b<x;b++){const g=r[b],v=u(g,A)[w];v&&(E(v,j,u(g,j)),_?(u(v,A)["*"]&&S(this,z,se).call(this,n,u(v,A)["*"],t,u(g,j)),S(this,z,se).call(this,n,v,t,u(g,j))):f.push(v));for(let C=0,T=u(g,oe).length;C<T;C++){const M=u(g,oe)[C],O=u(g,j)===De?{}:{...u(g,j)};if(M==="*"){const ce=u(g,A)["*"];ce&&(S(this,z,se).call(this,n,ce,t,u(g,j)),E(ce,j,O),f.push(ce));continue}const[Ge,at,Ie]=M;if(!w&&!(Ie instanceof RegExp))continue;const U=u(g,A)[Ge];if(Ie instanceof RegExp){if(c===null){c=new Array(l);let ue=s[0]==="/"?1:0;for(let Se=0;Se<l;Se++)c[Se]=ue,ue+=o[Se].length+1}const ce=s.substring(c[h]),Ye=Ie.exec(ce);if(Ye){if(O[at]=Ye[0],S(this,z,se).call(this,n,U,t,u(g,j),O),xs(u(U,A))){E(U,j,O);const ue=((p=Ye[0].match(/\//))==null?void 0:p.length)??0;(i[ue]||(i[ue]=[])).push(U)}continue}}(Ie===!0||Ie.test(w))&&(O[at]=w,_?(S(this,z,se).call(this,n,U,t,O,u(g,j)),u(U,A)["*"]&&S(this,z,se).call(this,n,u(U,A)["*"],t,O,u(g,j))):(E(U,j,O),f.push(U)))}}const y=i.shift();r=y?f.concat(y):f}return n.length>1&&n.sort((h,w)=>h.score-w.score),[n.map(({handler:h,params:w})=>[h,w])]}},ee=new WeakMap,A=new WeakMap,oe=new WeakMap,xe=new WeakMap,j=new WeakMap,z=new WeakSet,se=function(t,s,n,a,r){for(let o=0,i=u(s,ee).length;o<i;o++){const l=u(s,ee)[o],c=l[n]||l[R],p={};if(c!==void 0&&(c.params=Object.create(null),t.push(c),a!==De||r&&r!==De))for(let h=0,w=c.possibleKeys.length;h<w;h++){const _=c.possibleKeys[h],f=p[c.score];c.params[_]=r!=null&&r[_]&&!f?r[_]:a[_]??(r==null?void 0:r[_]),p[c.score]=!0}}},ve),ie,_t,Es=(_t=class{constructor(){k(this,"name","TrieRouter");I(this,ie);E(this,ie,new vs)}add(e,t,s){const n=vt(t);if(n){for(let a=0,r=n.length;a<r;a++)u(this,ie).insert(e,n[a],s);return}u(this,ie).insert(e,t,s)}match(e,t){return u(this,ie).search(e,t)}},ie=new WeakMap,_t),At=class extends cs{constructor(e={}){super(e),this.router=e.router??new ys({routers:[new _s,new Es]})}},ks=e=>{const s={...{origin:"*",allowMethods:["GET","HEAD","PUT","POST","DELETE","PATCH"],allowHeaders:[],exposeHeaders:[]},...e},n=(r=>typeof r=="string"?r==="*"?()=>r:o=>r===o?o:null:typeof r=="function"?r:o=>r.includes(o)?o:null)(s.origin),a=(r=>typeof r=="function"?r:Array.isArray(r)?()=>r:()=>[])(s.allowMethods);return async function(o,i){var p;function l(h,w){o.res.headers.set(h,w)}const c=await n(o.req.header("origin")||"",o);if(c&&l("Access-Control-Allow-Origin",c),s.credentials&&l("Access-Control-Allow-Credentials","true"),(p=s.exposeHeaders)!=null&&p.length&&l("Access-Control-Expose-Headers",s.exposeHeaders.join(",")),o.req.method==="OPTIONS"){s.origin!=="*"&&l("Vary","Origin"),s.maxAge!=null&&l("Access-Control-Max-Age",s.maxAge.toString());const h=await a(o.req.header("origin")||"",o);h.length&&l("Access-Control-Allow-Methods",h.join(","));let w=s.allowHeaders;if(!(w!=null&&w.length)){const _=o.req.header("Access-Control-Request-Headers");_&&(w=_.split(/\s*,\s*/))}return w!=null&&w.length&&(l("Access-Control-Allow-Headers",w.join(",")),o.res.headers.append("Vary","Access-Control-Request-Headers")),o.res.headers.delete("Content-Length"),o.res.headers.delete("Content-Type"),new Response(null,{headers:o.res.headers,status:204,statusText:"No Content"})}await i(),s.origin!=="*"&&o.header("Vary","Origin",{append:!0})}},Is=/^[\w!#$%&'*.^`|~+-]+$/,Ss=/^[ !#-:<-[\]-~]*$/,Cs=(e,t)=>{if(t&&e.indexOf(t)===-1)return{};const s=e.trim().split(";"),n={};for(let a of s){a=a.trim();const r=a.indexOf("=");if(r===-1)continue;const o=a.substring(0,r).trim();if(t&&t!==o||!Is.test(o))continue;let i=a.substring(r+1).trim();if(i.startsWith('"')&&i.endsWith('"')&&(i=i.slice(1,-1)),Ss.test(i)&&(n[o]=i.indexOf("%")!==-1?Ve(i,st):i,t))break}return n},Ds=(e,t,s={})=>{let n=`${e}=${t}`;if(e.startsWith("__Secure-")&&!s.secure)throw new Error("__Secure- Cookie must have Secure attributes");if(e.startsWith("__Host-")){if(!s.secure)throw new Error("__Host- Cookie must have Secure attributes");if(s.path!=="/")throw new Error('__Host- Cookie must have Path attributes with "/"');if(s.domain)throw new Error("__Host- Cookie must not have Domain attributes")}if(s&&typeof s.maxAge=="number"&&s.maxAge>=0){if(s.maxAge>3456e4)throw new Error("Cookies Max-Age SHOULD NOT be greater than 400 days (34560000 seconds) in duration.");n+=`; Max-Age=${s.maxAge|0}`}if(s.domain&&s.prefix!=="host"&&(n+=`; Domain=${s.domain}`),s.path&&(n+=`; Path=${s.path}`),s.expires){if(s.expires.getTime()-Date.now()>3456e7)throw new Error("Cookies Expires SHOULD NOT be greater than 400 days (34560000 seconds) in the future.");n+=`; Expires=${s.expires.toUTCString()}`}if(s.httpOnly&&(n+="; HttpOnly"),s.secure&&(n+="; Secure"),s.sameSite&&(n+=`; SameSite=${s.sameSite.charAt(0).toUpperCase()+s.sameSite.slice(1)}`),s.priority&&(n+=`; Priority=${s.priority.charAt(0).toUpperCase()+s.priority.slice(1)}`),s.partitioned){if(!s.secure)throw new Error("Partitioned Cookie must have Secure attributes");n+="; Partitioned"}return n},et=(e,t,s)=>(t=encodeURIComponent(t),Ds(e,t,s)),Bt=(e,t,s)=>{const n=e.req.raw.headers.get("Cookie");{if(!n)return;let a=t;return s==="secure"?a="__Secure-"+t:s==="host"&&(a="__Host-"+t),Cs(n,a)[a]}},Ts=(e,t,s)=>{let n;return(s==null?void 0:s.prefix)==="secure"?n=et("__Secure-"+e,t,{path:"/",...s,secure:!0}):(s==null?void 0:s.prefix)==="host"?n=et("__Host-"+e,t,{...s,path:"/",secure:!0,domain:void 0}):n=et(e,t,{path:"/",...s}),n},Lt=(e,t,s,n)=>{const a=Ts(t,s,n);e.header("Set-Cookie",a,{append:!0})},Ne=(e,t,s)=>{const n=Bt(e,t,s==null?void 0:s.prefix);return Lt(e,t,"",{...s,maxAge:0}),n};const m=new At;m.onError((e,t)=>{console.error("Unhandled error:",e);const s=e instanceof Error?`${e.name}: ${e.message}`:String(e);return t.text(`Internal Error
${s}`,500)});m.use("/api/*",ks({origin:e=>e?e.endsWith(".pages.dev")||e==="http://localhost:8788"||e==="http://127.0.0.1:8788"?e:null:"*",credentials:!0}));const qe=new Map;let ct=0;function Mt(e,t,s){const n=Date.now();if(n-ct>6e4){ct=n;for(const[r,o]of qe)n>o.resetAt&&qe.delete(r)}let a=qe.get(e);return(!a||n>a.resetAt)&&(a={count:0,resetAt:n+s*1e3},qe.set(e,a)),a.count++,!(a.count>t)}function d(e,t,s){return e.json({ok:!1,error:s},t)}function nt(e){const t=new Uint8Array(e);let s="";for(let n=0;n<t.length;n++)s+=String.fromCharCode(t[n]);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}function Ht(e){for(e=e.replace(/-/g,"+").replace(/_/g,"/");e.length%4;)e+="=";const t=atob(e),s=new Uint8Array(t.length);for(let n=0;n<t.length;n++)s[n]=t.charCodeAt(n);return s}async function Rs(e,t){const s=new TextEncoder,n=await crypto.subtle.importKey("raw",s.encode(e),{name:"HMAC",hash:"SHA-256"},!1,["sign"]),a=await crypto.subtle.sign("HMAC",n,s.encode(t));return nt(a)}async function Ns(e,t,s){const n=new TextEncoder,a=await crypto.subtle.importKey("raw",n.encode(e),{name:"HMAC",hash:"SHA-256"},!1,["verify"]);return crypto.subtle.verify("HMAC",a,Ht(s),n.encode(t))}function Ee(e=16){const t=new Uint8Array(e);return crypto.getRandomValues(t),[...t].map(s=>s.toString(16).padStart(2,"0")).join("")}async function le(e,t,s=1e5){const n=new TextEncoder,a=new Uint8Array(t.match(/.{1,2}/g).map(i=>parseInt(i,16))),r=await crypto.subtle.importKey("raw",n.encode(e),"PBKDF2",!1,["deriveBits"]),o=await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:a,iterations:s},r,256);return nt(o)}async function Os(e,t){const s=nt(new TextEncoder().encode(JSON.stringify(t))),n=await Rs(e,s);return`v1.${s}.${n}`}async function js(e,t){const s=t.split(".");if(s.length!==3||s[0]!=="v1")return null;const n=s[1],a=s[2];if(!await Ns(e,n,a))return null;const o=new TextDecoder().decode(Ht(n));return JSON.parse(o)}m.use("*",async(e,t)=>{const s=e.env.ADMIN_LOGIN_ID||"",n=e.env.ADMIN_PASSWORD||"",a=e.env.SESSION_SECRET;if(!s||!n||!a)return t();if(!await e.env.DB.prepare("SELECT id FROM users WHERE role='admin' AND login_id=? LIMIT 1").bind(s).first()){const o=crypto.randomUUID(),i=Ee(16),l=await le(n,i);await e.env.DB.prepare(`INSERT INTO users (id, role, login_id, password_hash, password_salt, name, grade, class_name, is_active)
       VALUES (?, 'admin', ?, ?, ?, 'admin', 0, '-', 1)`).bind(o,s,l,i).run()}return t()});m.use("/api/*",async(e,t)=>{const s=Bt(e,"session");if(!s)return t();const n=e.env.SESSION_SECRET;if(!n)return t();const a=await js(n,s);if(!(a!=null&&a.id))return t();const r=720*60*60;return a.iat&&Math.floor(Date.now()/1e3)-a.iat>r?(Ne(e,"session",{path:"/"}),t()):(e.set("user",{id:a.id,role:a.role,loginId:a.loginId,isActive:!!a.isActive}),t())});const As=[/[ちチﾁ][んンﾝ][こコﾞぽポ]/i,/[まマ][んンﾝ][こコ]/i,/[おオ][っッ][ぱパ][いイ]/i,/[ちチ][んンﾝ][ちチ][んンﾝ]/i,/[うウ][んンﾝ][こコ][ちチ]/i,/[うウ][んンﾝ][ちチ]/i,/[きキ][んンﾝ][たタ][まマ]/i,/[おオ][なナ][にニ]/i,/[しシ][ねネ]/,/[こコ][ろロ][すス]/,/死ね/,/殺す/,/殺/,/糞/,/クソ/,/ころす/,/しね[よ！]?$/,/ばか[やァ]?ろう/,/あほ/,/セックス/,/sex/i,/fuck/i,/shit/i,/dick/i,/pussy/i,/bitch/i,/エロ/,/えろ/,/ペニス/,/ヴァギナ/,/レイプ/,/うんこ/,/ウンコ/,/おしり/,/ケツ/];function Bs(e){const t=(e||"").trim();return As.some(s=>s.test(t))}m.post("/api/auth/signup",async e=>{const t=await e.req.json().catch(()=>null);if(!t)return d(e,400,"invalid_json");const s=String(t.loginId||"").trim(),n=String(t.password||""),a=String(t.name||"").trim(),r=Number(t.grade),o=String(t.className||"").trim();if(!s||s.length<3)return d(e,400,"loginId_too_short");if(!n||n.length<6)return d(e,400,"password_too_short");if(!a)return d(e,400,"name_required");if(Bs(a))return d(e,400,"name_inappropriate");if(!Number.isFinite(r)||r<1||r>12)return d(e,400,"grade_invalid");const i=crypto.randomUUID(),l=Ee(16),c=await le(n,l);try{await e.env.DB.prepare(`INSERT INTO users (id, role, login_id, password_hash, password_salt, name, grade, class_name, is_active)
       VALUES (?, 'student', ?, ?, ?, ?, ?, ?, 0)`).bind(i,s,c,l,a,r,o).run()}catch{return d(e,409,"loginId_taken")}return e.json({ok:!0,status:"ok"})});m.post("/api/auth/login",async e=>{const t=await e.req.json().catch(()=>null);if(!t)return d(e,400,"invalid_json");const s=String(t.loginId||"").trim(),n=String(t.password||"");if(!s||!n)return d(e,400,"missing_credentials");let a=await e.env.DB.prepare(`SELECT id, role, login_id as loginId, password_hash as hash, password_salt as salt, is_active as isActive,
            must_change_password as mustChangePassword
     FROM users WHERE login_id = ? LIMIT 1`).bind(s).first();if(!a){const i=await e.env.DB.prepare(`SELECT id, 'teacher' as role, login_id as loginId, password_hash as hash, password_salt as salt,
              is_active as isActive, 0 as mustChangePassword
       FROM teacher_accounts WHERE login_id = ? LIMIT 1`).bind(s).first();i&&(a=i)}if(!a||await le(n,a.salt)!==a.hash)return d(e,401,"invalid_credentials");if((a.role==="student"||a.role==="teacher")&&!a.isActive)return d(e,403,"pending_approval");a.role==="student"&&a.mustChangePassword;const o=await Os(e.env.SESSION_SECRET,{id:a.id,role:a.role,loginId:a.loginId,isActive:!!a.isActive,iat:Math.floor(Date.now()/1e3)});return Lt(e,"session",o,{httpOnly:!0,secure:!0,sameSite:"Lax",path:"/",maxAge:3600*24*30}),e.json({ok:!0,role:a.role,mustChangePassword:!!a.mustChangePassword})});m.post("/api/auth/logout",async e=>{const t={secure:!0,sameSite:"Lax",httpOnly:!0};return Ne(e,"session",{...t,path:"/"}),Ne(e,"session",{...t,path:"/api"}),e.json({ok:!0})});m.get("/api/auth/me",async e=>{const t=e.get("user");if(!t)return e.json({ok:!0,user:null});if(t.role==="teacher"){const n=await e.env.DB.prepare("SELECT name, school FROM teacher_accounts WHERE id = ? LIMIT 1").bind(t.id).first();return e.json({ok:!0,user:{...t,name:n==null?void 0:n.name,school:n==null?void 0:n.school,grade:null}})}let s=null;try{const n=await e.env.DB.prepare("SELECT grade, created_at FROM users WHERE id = ? LIMIT 1").bind(t.id).first();if(n&&(s=n.grade??null,s!==null&&s<6&&t.role==="student")){const a=new Date,r=a.getUTCFullYear(),o=a.getUTCMonth()+1,i=new Date(n.created_at),l=i.getUTCFullYear(),p=i.getUTCMonth()+1>=4?l:l-1,w=(o>=4?r:r-1)-p;if(w>0){const _=Math.min(6,n.grade+w);_!==n.grade&&(await e.env.DB.prepare("UPDATE users SET grade=? WHERE id=?").bind(_,t.id).run(),s=_)}}}catch{}return e.json({ok:!0,user:{...t,grade:s}})});function ke(e){const t=e.get("user");return!t||t.role!=="student"&&t.role!=="admin"&&t.role!=="teacher"?null:t}m.get("/api/student/progress",async e=>{const t=ke(e);if(!t)return d(e,401,"unauthorized");const s=await e.env.DB.prepare("SELECT state_json as stateJson, updated_at as updatedAt FROM progress WHERE user_id = ?").bind(t.id).first();return e.json({ok:!0,progress:s?{stateJson:s.stateJson,updatedAt:s.updatedAt}:null})});m.put("/api/student/progress",async e=>{const t=ke(e);if(!t)return d(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return d(e,400,"invalid_json");const n=JSON.stringify(s.state??s);if(t.role==="teacher")return e.json({ok:!0});if(n.length>1e6)return e.json({ok:!0});try{await e.env.DB.prepare(`INSERT INTO progress (user_id, state_json, updated_at)
       VALUES (?, ?, datetime('now'))
       ON CONFLICT(user_id) DO UPDATE SET state_json=excluded.state_json, updated_at=datetime('now')`).bind(t.id,n).run()}catch(a){return console.error("[progress] DB error:",(a==null?void 0:a.message)||a),d(e,500,"db_error")}try{const a=await e.env.DB.prepare("SELECT name, grade FROM users WHERE id=? LIMIT 1").bind(t.id).first(),r=Ls(n,(a==null?void 0:a.name)||""),o=Number((a==null?void 0:a.grade)||0),i=Pt(),l=await e.env.DB.prepare("SELECT week_start, correct_count, total_level, battle_power, pokedex_count, wild_win_streak, ranking_points FROM ranking_stats WHERE user_id=? LIMIT 1").bind(t.id).first();let c=0,p=0,h=0,w=0,_=0,f=0;l&&l.week_start===i||l&&(c=Number(l.correct_count||0),p=Number(l.total_level||0),h=Number(l.battle_power||0),w=Number(l.pokedex_count||0),_=Number(l.wild_win_streak||0),f=Number(l.ranking_points||0)),l?l.week_start!==i?await e.env.DB.prepare(`UPDATE ranking_stats SET
           display_name=?, total_level=?, monster_count=?, correct_count=?, ranking_points=?,
           grade=?, battle_power=?, pokedex_count=?, wild_win_streak=?,
           week_start=?, week_base_correct_count=?, week_base_total_level=?, week_base_battle_power=?, week_base_pokedex_count=?, week_base_wild_win_streak=?, week_base_ranking_points=?,
           updated_at=datetime('now')
         WHERE user_id=?`).bind(r.displayName,r.totalLevel,r.monsterCount,r.correctCount,r.rankingPoints,o,r.battlePower,r.pokedexCount,r.wildWinStreak,i,c,p,h,w,_,f,t.id).run():await e.env.DB.prepare(`UPDATE ranking_stats SET
           display_name=?, total_level=?, monster_count=?, correct_count=?, ranking_points=?,
           grade=?, battle_power=?, pokedex_count=?, wild_win_streak=?,
           updated_at=datetime('now')
         WHERE user_id=?`).bind(r.displayName,r.totalLevel,r.monsterCount,r.correctCount,r.rankingPoints,o,r.battlePower,r.pokedexCount,r.wildWinStreak,t.id).run():await e.env.DB.prepare(`INSERT INTO ranking_stats (user_id, display_name, total_level, monster_count, correct_count, ranking_points,
           grade, battle_power, pokedex_count, wild_win_streak,
           week_start, week_base_correct_count, week_base_total_level, week_base_battle_power, week_base_pokedex_count, week_base_wild_win_streak, week_base_ranking_points,
           updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`).bind(t.id,r.displayName,r.totalLevel,r.monsterCount,r.correctCount,r.rankingPoints,o,r.battlePower,r.pokedexCount,r.wildWinStreak,i,r.correctCount,r.totalLevel,r.battlePower,r.pokedexCount,r.wildWinStreak,r.rankingPoints).run()}catch{}return e.json({ok:!0})});m.post("/api/student/results",async e=>{const t=ke(e);if(!t)return d(e,401,"unauthorized");if(!Mt(`results:${t.id}`,30,60))return d(e,429,"too_many_requests");const s=await e.req.json().catch(()=>null);if(!s)return d(e,400,"invalid_json");const n=String(s.unit||"").trim(),a=s.questionId!=null?String(s.questionId):null,r=s.isCorrect?1:0,o=s.timeMs!=null?Number(s.timeMs):null,i=s.answeredAt?String(s.answeredAt):null,l=s.meta?JSON.stringify(s.meta):null;return n?(await e.env.DB.prepare(`INSERT INTO learning_results (user_id, unit, question_id, is_correct, time_ms, answered_at, meta_json)
     VALUES (?, ?, ?, ?, ?, COALESCE(?, datetime('now')), ?)`).bind(t.id,n,a,r,o,i,l).run(),e.json({ok:!0})):d(e,400,"unit_required")});function Ls(e,t){try{const s=JSON.parse(e),n=s.state||s,a=Number(n.level||1),r=n.monsters||{},o=Object.keys(r).length,i=Object.values(r).reduce((x,g)=>x+Number((g==null?void 0:g.level)||1),0),l=a+i,c=n.trainingProgress||{},p=Object.values(c).reduce((x,g)=>x+Number((g==null?void 0:g.correctCount)??(g==null?void 0:g.count)??0),0),h=Object.values(c).reduce((x,g)=>(g==null?void 0:g.rankingPoints)!=null?x+Number(g.rankingPoints):x+Number((g==null?void 0:g.correctCount)??(g==null?void 0:g.count)??0),0),w=Array.isArray(n.party)?n.party:[];let _=0;for(const x of w){const g=r[String(x)];if(g){const v=Number(g.level||1),C=Number(g.atk||0),T=Number(g.def||0),M=Number(g.hp||0),O=Number(g.spd||0);_+=C+T+M+O}}const f=Array.isArray(n.pokedex)?n.pokedex.length:0,y=n.max||n.M&&n.M.max||{},b=Number(y.winStreak||0);return{displayName:String(n.name||t).slice(0,30),totalLevel:l,monsterCount:o,correctCount:p,rankingPoints:h,battlePower:_,pokedexCount:f,wildWinStreak:b}}catch{return{displayName:t,totalLevel:0,monsterCount:0,correctCount:0,rankingPoints:0,battlePower:0,pokedexCount:0,wildWinStreak:0}}}function Pt(){const e=new Date,t=e.getUTCDay(),s=t===0?6:t-1,n=new Date(e);return n.setUTCDate(e.getUTCDate()-s),n.toISOString().slice(0,10)}function D(e){const t=e.get("user");return!t||t.role!=="admin"?null:t}m.get("/api/admin/pending",async e=>{if(!D(e))return d(e,401,"unauthorized");const s=await e.env.DB.prepare(`SELECT id, login_id as loginId, name, grade, class_name as className, created_at as createdAt, disabled_reason as disabledReason
     FROM users WHERE role='student' AND is_active=0
     ORDER BY created_at DESC`).all();return e.json({ok:!0,users:s.results})});m.get("/api/admin/users",async e=>{if(!D(e))return d(e,401,"unauthorized");const s=e.req.query("grade"),n=e.req.query("class"),a=["role='student'"],r=[];s&&(a.push("grade = ?"),r.push(Number(s))),n&&(a.push("class_name = ?"),r.push(String(n)));const o=`SELECT id, login_id as loginId, name, grade, class_name as className, is_active as isActive, disabled_reason as disabledReason, created_at as createdAt
               FROM users WHERE ${a.join(" AND ")} ORDER BY grade ASC, class_name ASC, name ASC`,i=await e.env.DB.prepare(o).bind(...r).all();return e.json({ok:!0,users:i.results})});m.post("/api/admin/approve/:id",async e=>{if(!D(e))return d(e,401,"unauthorized");const s=e.req.param("id");return await e.env.DB.prepare("UPDATE users SET is_active=1, disabled_reason=NULL WHERE id=? AND role='student'").bind(s).run(),e.json({ok:!0})});m.post("/api/admin/disable/:id",async e=>{if(!D(e))return d(e,401,"unauthorized");const s=e.req.param("id"),n=await e.req.json().catch(()=>({})),a=n!=null&&n.reason?String(n.reason).slice(0,200):null;return await e.env.DB.prepare("UPDATE users SET is_active=0, disabled_reason=? WHERE id=? AND role='student'").bind(a,s).run(),e.json({ok:!0})});m.post("/api/admin/reset-password/:id",async e=>{if(!D(e))return d(e,401,"unauthorized");const s=e.req.param("id"),n=Ee(4),a=Ee(16),r=await le(n,a);return await e.env.DB.prepare(`UPDATE users
       SET password_hash=?, password_salt=?, password_updated_at=datetime('now'), must_change_password=1
       WHERE id=? AND role='student'`).bind(r,a,s).run(),e.json({ok:!0,tempPassword:n})});m.delete("/api/admin/delete/:id",async e=>{const t=D(e);if(!t)return d(e,401,"unauthorized");const s=e.req.param("id");if(s===t.id)return d(e,400,"cannot_delete_self");const n=await e.env.DB.prepare("SELECT role FROM users WHERE id=? LIMIT 1").bind(s).first();return n?n.role!=="student"?d(e,400,"cannot_delete_admin"):(await e.env.DB.prepare("DELETE FROM progress WHERE user_id=?").bind(s).run(),await e.env.DB.prepare("DELETE FROM learning_results WHERE user_id=?").bind(s).run(),await e.env.DB.prepare("DELETE FROM battle_answers WHERE user_id=?").bind(s).run(),await e.env.DB.prepare("DELETE FROM users WHERE id=? AND role='student'").bind(s).run(),e.json({ok:!0})):d(e,404,"user_not_found")});m.post("/api/admin/change-password",async e=>{const t=D(e);if(!t)return d(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return d(e,400,"invalid_json");const n=String(s.oldPassword||""),a=String(s.newPassword||"");if(!n||!a)return d(e,400,"missing_fields");if(a.length<8)return d(e,400,"new_password_too_short");const r=await e.env.DB.prepare("SELECT id, password_hash as hash, password_salt as salt FROM users WHERE id=? AND role='admin' LIMIT 1").bind(t.id).first();if(!r)return d(e,404,"admin_not_found");if(await le(n,r.salt)!==r.hash)return d(e,401,"invalid_old_password");const i=Ee(16),l=await le(a,i);return await e.env.DB.prepare("UPDATE users SET password_hash=?, password_salt=?, password_updated_at=datetime('now'), must_change_password=0 WHERE id=?").bind(l,i,t.id).run(),e.json({ok:!0})});m.get("/api/admin/results",async e=>{if(!D(e))return d(e,401,"unauthorized");const s=Math.min(500,Math.max(1,Number(e.req.query("limit")||100))),n=e.req.query("from"),a=e.req.query("to"),r=e.req.query("grade"),o=e.req.query("class"),i=[],l=[];n&&(i.push("r.answered_at >= ?"),l.push(n)),a&&(i.push("r.answered_at <= ?"),l.push(a)),r&&(i.push("u.grade = ?"),l.push(Number(r))),o&&(i.push("u.class_name = ?"),l.push(String(o)));const c=i.length?`WHERE ${i.join(" AND ")}`:"",p=await e.env.DB.prepare(`SELECT r.id, r.answered_at as answeredAt, r.unit, r.question_id as questionId, r.is_correct as isCorrect, r.time_ms as timeMs,
            u.login_id as loginId, u.name, u.grade, u.class_name as className
     FROM learning_results r
     JOIN users u ON u.id = r.user_id
     ${c}
     ORDER BY r.answered_at DESC
     LIMIT ?`).bind(...l,s).all();return e.json({ok:!0,results:p.results})});m.get("/api/admin/results.csv",async e=>{if(!D(e))return d(e,401,"unauthorized");const s=e.req.query("from"),n=e.req.query("to"),a=e.req.query("grade"),r=e.req.query("class"),o=[],i=[];s&&(o.push("r.answered_at >= ?"),i.push(s)),n&&(o.push("r.answered_at <= ?"),i.push(n)),a&&(o.push("u.grade = ?"),i.push(Number(a))),r&&(o.push("u.class_name = ?"),i.push(String(r)));const l=o.length?`WHERE ${o.join(" AND ")}`:"",c=await e.env.DB.prepare(`SELECT r.answered_at as answeredAt, u.grade, u.class_name as className, u.name, u.login_id as loginId,
            r.unit, r.question_id as questionId, r.is_correct as isCorrect, r.time_ms as timeMs
     FROM learning_results r
     JOIN users u ON u.id = r.user_id
     ${l}
     ORDER BY r.answered_at DESC
     LIMIT 5000`).bind(...i).all(),p=["answeredAt","grade","class","name","loginId","unit","questionId","isCorrect","timeMs"],h=_=>{const f=_==null?"":String(_);return/[\n\r",]/.test(f)?'"'+f.replace(/"/g,'""')+'"':f},w=[p.join(",")];for(const _ of c.results)w.push([_.answeredAt,_.grade,_.className,_.name,_.loginId,_.unit,_.questionId,_.isCorrect,_.timeMs].map(h).join(","));return new Response(w.join(`
`),{headers:{"Content-Type":"text/csv; charset=utf-8","Content-Disposition":'attachment; filename="learning_results.csv"'}})});m.get("/api/admin/pending-teachers",async e=>{if(!D(e))return d(e,401,"unauthorized");const s=await e.env.DB.prepare("SELECT id, login_id as loginId, name, school, created_at as createdAt FROM teacher_accounts WHERE is_active=0 ORDER BY created_at DESC").all();return e.json({ok:!0,teachers:s.results})});m.post("/api/admin/approve-teacher/:id",async e=>D(e)?(await e.env.DB.prepare("UPDATE teacher_accounts SET is_active=1 WHERE id=?").bind(e.req.param("id")).run(),e.json({ok:!0})):d(e,401,"unauthorized"));m.delete("/api/admin/reject-teacher/:id",async e=>D(e)?(await e.env.DB.prepare("DELETE FROM teacher_accounts WHERE id=? AND is_active=0").bind(e.req.param("id")).run(),e.json({ok:!0})):d(e,401,"unauthorized"));m.get("/api/admin/settings",async e=>{if(!D(e))return d(e,401,"unauthorized");const s=await e.env.DB.prepare("SELECT key, value FROM admin_settings").all(),n={};for(const a of s.results)n[a.key]=a.value;return e.json({ok:!0,settings:n})});m.put("/api/admin/settings",async e=>{if(!D(e))return d(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return d(e,400,"invalid_json");for(const[n,a]of Object.entries(s))typeof a=="string"&&await e.env.DB.prepare(`INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
       ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now')`).bind(n,a).run();return e.json({ok:!0})});m.put("/api/admin/user-grade",async e=>{const t=e.get("user");if(!t||t.role!=="admin"&&t.role!=="teacher")return d(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return d(e,400,"invalid_json");const n=String(s.userId||""),a=Number(s.grade);return!n||!Number.isFinite(a)||a<1||a>6?d(e,400,"invalid_grade"):(await e.env.DB.prepare("UPDATE users SET grade=? WHERE id=? AND role='student'").bind(a,n).run(),e.json({ok:!0}))});function L(e){const t=e.get("user");return!t||t.role!=="teacher"&&t.role!=="admin"?null:t}function ut(){const e="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";let t="";const s=new Uint8Array(6);crypto.getRandomValues(s);for(let n=0;n<6;n++)t+=e[s[n]%e.length];return t}m.post("/api/auth/teacher-signup",async e=>{const t=await e.req.json().catch(()=>null);if(!t)return d(e,400,"invalid_json");const s=String(t.loginId||"").trim(),n=String(t.password||""),a=String(t.name||"").trim(),r=String(t.school||"").trim();if(!s||s.length<3)return d(e,400,"loginId_too_short");if(!n||n.length<6)return d(e,400,"password_too_short");if(!a)return d(e,400,"name_required");const o=crypto.randomUUID(),i=Ee(16),l=await le(n,i);try{await e.env.DB.prepare("INSERT INTO teacher_accounts (id, login_id, password_hash, password_salt, name, school) VALUES (?, ?, ?, ?, ?, ?)").bind(o,s,l,i,a,r).run()}catch{return d(e,409,"loginId_taken")}return e.json({ok:!0})});m.post("/api/teacher/class",async e=>{const t=L(e);if(!t)return d(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return d(e,400,"invalid_json");const n=String(s.name||"").trim();if(!n)return d(e,400,"name_required");let a=ut();for(let o=0;o<5&&await e.env.DB.prepare("SELECT id FROM classes WHERE class_code=? LIMIT 1").bind(a).first();o++)a=ut();const r=crypto.randomUUID();return await e.env.DB.prepare("INSERT INTO classes (id, class_code, name, teacher_id) VALUES (?, ?, ?, ?)").bind(r,a,n,t.id).run(),e.json({ok:!0,classId:r,classCode:a})});m.get("/api/teacher/classes",async e=>{const t=L(e);if(!t)return d(e,401,"unauthorized");const n=t.role==="admin"?await e.env.DB.prepare(`SELECT c.id, c.class_code as classCode, c.name, c.ranking_enabled as rankingEnabled, c.homework_enabled as homeworkEnabled, c.contact_enabled as contactEnabled, c.created_at as createdAt, t.name as teacherName
         FROM classes c LEFT JOIN teacher_accounts t ON t.id = c.teacher_id ORDER BY c.created_at DESC`).all():await e.env.DB.prepare("SELECT id, class_code as classCode, name, ranking_enabled as rankingEnabled, homework_enabled as homeworkEnabled, contact_enabled as contactEnabled, created_at as createdAt FROM classes WHERE teacher_id=? ORDER BY created_at DESC").bind(t.id).all();return e.json({ok:!0,classes:n.results})});m.delete("/api/teacher/class/:classId",async e=>{const t=L(e);if(!t)return d(e,401,"unauthorized");const s=e.req.param("classId");return await e.env.DB.prepare("DELETE FROM class_members WHERE class_id=?").bind(s).run(),t.role==="admin"?await e.env.DB.prepare("DELETE FROM classes WHERE id=?").bind(s).run():await e.env.DB.prepare("DELETE FROM classes WHERE id=? AND teacher_id=?").bind(s,t.id).run(),e.json({ok:!0})});m.put("/api/teacher/class/:classId/homework-toggle",async e=>{var o;const t=L(e);if(!t)return d(e,401,"unauthorized");const s=e.req.param("classId"),n=await e.req.json().catch(()=>null),a=n!=null&&n.enabled?1:0;return(o=(t.role==="admin"?await e.env.DB.prepare("UPDATE classes SET homework_enabled=? WHERE id=?").bind(a,s).run():await e.env.DB.prepare("UPDATE classes SET homework_enabled=? WHERE id=? AND teacher_id=?").bind(a,s,t.id).run()).meta)!=null&&o.changes?e.json({ok:!0,homeworkEnabled:a}):d(e,404,"class_not_found")});m.put("/api/teacher/class/:classId/contact-toggle",async e=>{var o;const t=L(e);if(!t)return d(e,401,"unauthorized");const s=e.req.param("classId"),n=await e.req.json().catch(()=>null),a=n!=null&&n.enabled?1:0;return(o=(t.role==="admin"?await e.env.DB.prepare("UPDATE classes SET contact_enabled=? WHERE id=?").bind(a,s).run():await e.env.DB.prepare("UPDATE classes SET contact_enabled=? WHERE id=? AND teacher_id=?").bind(a,s,t.id).run()).meta)!=null&&o.changes?e.json({ok:!0,contactEnabled:a}):d(e,404,"class_not_found")});m.put("/api/teacher/class/:classId/ranking-toggle",async e=>{var o;const t=L(e);if(!t)return d(e,401,"unauthorized");const s=e.req.param("classId"),n=await e.req.json().catch(()=>null),a=n!=null&&n.enabled?1:0;return(o=(t.role==="admin"?await e.env.DB.prepare("UPDATE classes SET ranking_enabled=? WHERE id=?").bind(a,s).run():await e.env.DB.prepare("UPDATE classes SET ranking_enabled=? WHERE id=? AND teacher_id=?").bind(a,s,t.id).run()).meta)!=null&&o.changes?e.json({ok:!0,rankingEnabled:a}):d(e,404,"class_not_found")});m.get("/api/teacher/class/:classId/ranking",async e=>{const t=L(e);if(!t)return d(e,401,"unauthorized");const s=e.req.param("classId"),n=t.role==="admin"?await e.env.DB.prepare("SELECT id, name, class_code as classCode FROM classes WHERE id=? LIMIT 1").bind(s).first():await e.env.DB.prepare("SELECT id, name, class_code as classCode FROM classes WHERE id=? AND teacher_id=? LIMIT 1").bind(s,t.id).first();if(!n)return d(e,404,"class_not_found");const a=await e.env.DB.prepare(`
    SELECT u.id, u.name, u.grade, u.class_name as className,
           COALESCE(rs.total_level, 0) as totalLevel,
           COALESCE(rs.monster_count, 0) as monsterCount,
           COALESCE(rs.correct_count, 0) as correctCount,
           COALESCE(rs.updated_at, '') as updatedAt
    FROM class_members cm
    JOIN users u ON u.id = cm.user_id
    LEFT JOIN ranking_stats rs ON rs.user_id = cm.user_id
    WHERE cm.class_id = ?
    ORDER BY rs.total_level DESC, rs.correct_count DESC
  `).bind(s).all();return e.json({ok:!0,class:n,members:a.results})});m.get("/api/teacher/class/:classId/unit-analytics",async e=>{var c,p,h,w,_;const t=L(e);if(!t)return d(e,401,"unauthorized");const s=e.req.param("classId"),n=t.role==="admin"?await e.env.DB.prepare("SELECT id, name FROM classes WHERE id=? LIMIT 1").bind(s).first():await e.env.DB.prepare("SELECT id, name FROM classes WHERE id=? AND teacher_id=? LIMIT 1").bind(s,t.id).first();if(!n)return d(e,404,"class_not_found");const a=await e.env.DB.prepare(`
    SELECT u.id, u.name, u.grade, p.state_json as stateJson
    FROM class_members cm
    JOIN users u ON u.id = cm.user_id
    LEFT JOIN progress p ON p.user_id = cm.user_id
    WHERE cm.class_id = ?
    ORDER BY u.name
  `).bind(s).all(),r=[],o=new Map;for(const f of a.results){let y={},b={},x=0;try{if(f.stateJson){const g=JSON.parse(f.stateJson);y=((p=(c=g==null?void 0:g.metrics)==null?void 0:c.learn)==null?void 0:p.byUnit)||{},b=((w=(h=g==null?void 0:g.metrics)==null?void 0:h.learn)==null?void 0:w.bySubject)||{};const v=((_=g==null?void 0:g.metrics)==null?void 0:_.daily)||{},C=Object.keys(v).filter(M=>{var O;return(((O=v[M])==null?void 0:O.training)||0)>=1}).sort();let T=0;for(let M=C.length-1;M>=0;M--){const O=new Date(C[M]+"T00:00:00+09:00");if(Math.round((Date.now()-O.getTime())/864e5)===C.length-1-M)T++;else break}x=T}}catch{}Object.keys(y).forEach(g=>{const v=y[g];!o.has(g)&&v.unitName&&o.set(g,{name:v.unitName,subject:v.subjectName||""})}),r.push({id:f.id,name:f.name||"",grade:f.grade||"",byUnit:y,bySubject:b,learnStreak:x})}const i=[];o.forEach((f,y)=>{r.some(b=>{var x;return(((x=b.byUnit[y])==null?void 0:x.total)||0)>=5})&&i.push(y)});const l=i.map(f=>{const y=o.get(f),b=r.filter(v=>{var C;return(((C=v.byUnit[f])==null?void 0:C.total)||0)>=5}),x=b.reduce((v,C)=>{const T=C.byUnit[f];return v+(T.total?T.correct/T.total:0)},0),g=b.length>0?Math.round(x/b.length*100):null;return{mode:f,name:y.name,subject:y.subject,classAvg:g,studentCount:b.length}}).sort((f,y)=>(f.classAvg??101)-(y.classAvg??101));return e.json({ok:!0,class:n,unitSummary:l,unitInfo:Object.fromEntries(o),students:r.map(f=>({id:f.id,name:f.name,grade:f.grade,learnStreak:f.learnStreak,bySubject:Object.fromEntries(Object.entries(f.bySubject).map(([y,b])=>[y,{total:b.total||0,correct:b.correct||0,acc:b.total?Math.round(b.correct/b.total*100):0}])),units:Object.fromEntries(i.map(y=>{const b=f.byUnit[y];return!b||(b.total||0)<5?[y,null]:[y,{total:b.total,correct:b.correct,acc:Math.round(b.correct/b.total*100)}]}))}))})});m.post("/api/student/join-class",async e=>{const t=ke(e);if(!t)return d(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return d(e,400,"invalid_json");const n=String(s.classCode||"").trim().toUpperCase();if(!n)return d(e,400,"code_required");const a=await e.env.DB.prepare("SELECT id, name FROM classes WHERE class_code=? LIMIT 1").bind(n).first();return a?(await e.env.DB.prepare("SELECT 1 FROM class_members WHERE user_id=? AND class_id=? LIMIT 1").bind(t.id,a.id).first()||(await e.env.DB.prepare("DELETE FROM class_members WHERE user_id=?").bind(t.id).run(),await e.env.DB.prepare("INSERT INTO class_members (user_id, class_id) VALUES (?, ?)").bind(t.id,a.id).run()),e.json({ok:!0,className:a.name})):d(e,404,"class_not_found")});m.get("/api/student/class-info",async e=>{const t=ke(e);if(!t)return d(e,401,"unauthorized");const s=await e.env.DB.prepare(`
    SELECT c.id, c.name, c.class_code as classCode, cm.joined_at as joinedAt,
           c.homework_enabled as homeworkEnabled, c.contact_enabled as contactEnabled
    FROM class_members cm JOIN classes c ON c.id = cm.class_id
    WHERE cm.user_id = ? LIMIT 1
  `).bind(t.id).first();return e.json({ok:!0,class:s||null})});m.post("/api/student/leave-class",async e=>{const t=ke(e);return t?(await e.env.DB.prepare("DELETE FROM class_members WHERE user_id=?").bind(t.id).run(),e.json({ok:!0})):d(e,401,"unauthorized")});m.get("/api/ranking",async e=>{const t=e.get("user");if(!t)return d(e,401,"unauthorized");const s=await e.env.DB.prepare("SELECT value FROM admin_settings WHERE key='ranking_scope' LIMIT 1").first(),n=await e.env.DB.prepare("SELECT value FROM admin_settings WHERE key='ranking_enabled' LIMIT 1").first(),a=(s==null?void 0:s.value)||"class",r=(n==null?void 0:n.value)!=="0";if(!r||a==="hidden")return e.json({ok:!0,ranking:[],scope:a,enabled:!1,hidden:!0});const o=e.req.query("type")||"overall",i=e.req.query("period")||"cumulative",l=Number(e.req.query("grade")||0),c=Pt();let p="rs.total_level",h="";switch(o){case"overall":p="rs.total_level";break;case"power":p="rs.battle_power";break;case"correct":p="rs.ranking_points";break;case"pokedex":p="rs.pokedex_count";break;case"wild":p="rs.wild_win_streak";break;case"grade":p="rs.ranking_points";break}if(i==="weekly")switch(o){case"overall":h=", (rs.total_level - rs.week_base_total_level) as weeklyScore",p="weeklyScore";break;case"power":h=", (rs.battle_power - rs.week_base_battle_power) as weeklyScore",p="weeklyScore";break;case"correct":case"grade":h=", (rs.ranking_points - rs.week_base_ranking_points) as weeklyScore",p="weeklyScore";break;case"pokedex":h=", (rs.pokedex_count - rs.week_base_pokedex_count) as weeklyScore",p="weeklyScore";break;case"wild":h=", (rs.wild_win_streak - rs.week_base_wild_win_streak) as weeklyScore",p="weeklyScore";break}const w=o==="grade"&&l>=1&&l<=6?` AND rs.grade = ${l}`:"",_=i==="weekly"?` AND rs.week_start = '${c}'`:"";let f="";const y=[],b=`rs.user_id as userId, rs.display_name as displayName,
    rs.total_level as totalLevel, rs.monster_count as monsterCount, rs.correct_count as correctCount,
    rs.ranking_points as rankingPoints,
    rs.grade, rs.battle_power as battlePower, rs.pokedex_count as pokedexCount, rs.wild_win_streak as wildWinStreak
    ${h}`;if(a==="global"||t.role==="admin")f=`SELECT ${b}
           FROM ranking_stats rs
           JOIN users u ON u.id = rs.user_id AND u.is_active=1
           JOIN class_members cm ON cm.user_id = rs.user_id
           JOIN classes cl ON cl.id = cm.class_id AND cl.ranking_enabled = 1
           WHERE 1=1 ${w} ${_}
           ORDER BY ${p} DESC, rs.correct_count DESC LIMIT 100`;else if(a==="class"){const v=await e.env.DB.prepare("SELECT cm.class_id, cl.ranking_enabled FROM class_members cm JOIN classes cl ON cl.id=cm.class_id WHERE cm.user_id=? LIMIT 1").bind(t.id).first();if(!v)return e.json({ok:!0,ranking:[],scope:a,enabled:r,message:"no_class"});if(!v.ranking_enabled)return e.json({ok:!0,ranking:[],scope:a,enabled:r,message:"ranking_not_allowed"});f=`SELECT ${b}
           FROM ranking_stats rs
           JOIN class_members cm ON cm.user_id = rs.user_id AND cm.class_id = ?
           JOIN users u ON u.id = rs.user_id AND u.is_active=1
           WHERE 1=1 ${w} ${_}
           ORDER BY ${p} DESC, rs.correct_count DESC LIMIT 100`,y.push(v.class_id)}else return e.json({ok:!0,ranking:[],scope:a,enabled:!1,hidden:!0});const g=(await e.env.DB.prepare(f).bind(...y).all()).results.map((v,C)=>({...v,rank:C+1,isMe:v.userId===t.id}));return e.json({ok:!0,ranking:g,scope:a,enabled:r,type:o,period:i})});function Ms(){const e=new Uint8Array(16);return crypto.getRandomValues(e),[...e].map(t=>t.toString(16).padStart(2,"0")).join("")}m.post("/api/homework/submit",async e=>{const t=e.get("user");if(!t||t.role!=="student")return d(e,403,"forbidden");const s=await e.req.json().catch(()=>null);if(!s)return d(e,400,"invalid_json");const n=String(s.dayKey||"").slice(0,10);if(!n)return d(e,400,"day_key_required");const a=await e.env.DB.prepare("SELECT id FROM homework_submissions WHERE user_id=? AND day_key=? LIMIT 1").bind(t.id,n).first();if(a)return e.json({ok:!0,alreadySubmitted:!0,id:a.id});const r=await e.env.DB.prepare("SELECT c.teacher_id FROM class_members cm JOIN classes c ON c.id=cm.class_id WHERE cm.user_id=? LIMIT 1").bind(t.id).first(),o=(r==null?void 0:r.teacher_id)||null,i=Ms();return await e.env.DB.prepare(`
    INSERT INTO homework_submissions
      (id, user_id, day_key, submitted_at, todo, why, aim, minutes, end_weather,
       weather_reason, next_improve, rest_day, streak_after,
       reward_kind, reward_coins, reward_shards, bonus_coins, bonus_shards, teacher_id,
       self_study_plan, weekly_plan, weekly_reflection)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).bind(i,t.id,n,Date.now(),String(s.todo||"").slice(0,500),String(s.why||"").slice(0,500),String(s.aim||"").slice(0,500),Number(s.minutes||0),String(s.endWeather||"sun"),String(s.weatherReason||"").slice(0,500),String(s.nextImprove||"").slice(0,500),s.restDay?1:0,Number(s.streakAfter||0),String(s.rewardKind||"coin"),Number(s.rewardCoins||0),Number(s.rewardShards||0),Number(s.bonusCoins||0),Number(s.bonusShards||0),o,String(s.selfStudyPlan||"").slice(0,500),String(s.weeklyPlan||"").slice(0,1e3),String(s.weeklyReflection||"").slice(0,1e3)).run(),e.json({ok:!0,id:i})});m.put("/api/homework/submit",async e=>{var r;const t=e.get("user");if(!t||t.role!=="student")return d(e,403,"forbidden");const s=await e.req.json().catch(()=>null);if(!s)return d(e,400,"invalid_json");const n=String(s.dayKey||"").slice(0,10);return n?(r=(await e.env.DB.prepare(`
    UPDATE homework_submissions
    SET todo=?, why=?, aim=?, minutes=?, end_weather=?, weather_reason=?, next_improve=?,
        self_study_plan=?, weekly_plan=?, weekly_reflection=?,
        updated_at=?
    WHERE user_id=? AND day_key=?
  `).bind(String(s.todo||"").slice(0,500),String(s.why||"").slice(0,500),String(s.aim||"").slice(0,500),Number(s.minutes||0),String(s.endWeather||"sun"),String(s.weatherReason||"").slice(0,500),String(s.nextImprove||"").slice(0,500),String(s.selfStudyPlan||"").slice(0,500),String(s.weeklyPlan||"").slice(0,1e3),String(s.weeklyReflection||"").slice(0,1e3),Date.now(),t.id,n).run()).meta)!=null&&r.changes?e.json({ok:!0}):d(e,404,"not_found"):d(e,400,"day_key_required")});m.get("/api/homework/my",async e=>{const t=e.get("user");if(!t||t.role!=="student")return d(e,403,"forbidden");const s=await e.env.DB.prepare(`
    SELECT id, day_key as dayKey, submitted_at as submittedAt, rest_day as restDay,
           teacher_comment as teacherComment, has_physical as hasPhysical,
           returned_at as returnedAt, reward_claimed as rewardClaimed,
           reward_kind as rewardKind, reward_coins as rewardCoins, reward_shards as rewardShards,
           bonus_coins as bonusCoins, bonus_shards as bonusShards
    FROM homework_submissions WHERE user_id=? ORDER BY submitted_at DESC LIMIT 30
  `).bind(t.id).all();return e.json({ok:!0,submissions:s.results})});m.post("/api/homework/:id/claim",async e=>{const t=e.get("user");if(!t||t.role!=="student")return d(e,403,"forbidden");const s=e.req.param("id"),n=await e.env.DB.prepare(`
    SELECT * FROM homework_submissions WHERE id=? AND user_id=? LIMIT 1
  `).bind(s,t.id).first();if(!n)return d(e,404,"not_found");if(!n.returned_at)return d(e,400,"not_returned_yet");if(n.reward_claimed)return d(e,400,"already_claimed");const a=n.has_physical?1:.5,r=Math.floor((Number(n.reward_coins||0)+Number(n.bonus_coins||0))*a),o=Math.floor((Number(n.reward_shards||0)+Number(n.bonus_shards||0))*a),i=String(n.reward_kind||"coin");return await e.env.DB.prepare(`
    UPDATE homework_submissions SET reward_claimed=1, reward_claimed_at=? WHERE id=?
  `).bind(Date.now(),s).run(),e.json({ok:!0,coins:r,shards:o,rewardKind:i,hasPhysical:!!n.has_physical})});m.get("/api/teacher/homework",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return d(e,403,"forbidden");const s=e.req.query("classId");let n=`
    SELECT hs.id, hs.day_key as dayKey, hs.submitted_at as submittedAt,
           hs.todo, hs.why, hs.aim, hs.minutes,
           hs.end_weather as endWeather, hs.weather_reason as weatherReason, hs.next_improve as nextImprove,
           hs.rest_day as restDay, hs.reward_kind as rewardKind,
           hs.reward_coins as rewardCoins, hs.reward_shards as rewardShards,
           hs.bonus_coins as bonusCoins, hs.bonus_shards as bonusShards,
           hs.teacher_comment as teacherComment, hs.has_physical as hasPhysical,
           hs.returned_at as returnedAt, hs.reward_claimed as rewardClaimed,
           hs.weekly_plan as weeklyPlan, hs.weekly_reflection as weeklyReflection,
           hs.self_study_plan as selfStudyPlan,
           u.id as userId, u.name as studentName, u.grade, u.class_name as className
    FROM homework_submissions hs
    JOIN users u ON u.id = hs.user_id
    JOIN class_members cm ON cm.user_id = hs.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
  `;const a=[t.id];s&&(n+=" AND cl.id = ?",a.push(s)),n+=" ORDER BY hs.submitted_at DESC LIMIT 100";const r=await e.env.DB.prepare(n).bind(...a).all();return e.json({ok:!0,submissions:r.results})});m.post("/api/teacher/homework/:id/return",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return d(e,403,"forbidden");const s=e.req.param("id"),n=await e.req.json().catch(()=>({}));return await e.env.DB.prepare(`
    SELECT hs.id FROM homework_submissions hs
    JOIN class_members cm ON cm.user_id = hs.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
    WHERE hs.id = ? LIMIT 1
  `).bind(t.id,s).first()?(await e.env.DB.prepare(`
    UPDATE homework_submissions
    SET teacher_id=?, teacher_comment=?, has_physical=?, returned_at=?
    WHERE id=?
  `).bind(t.id,String(n.comment||"").slice(0,500),n.hasPhysical?1:0,Date.now(),s).run(),e.json({ok:!0})):d(e,404,"not_found")});function He(e){const t=new Date,s=new Date(Date.UTC(t.getFullYear(),t.getMonth(),t.getDate()));s.setUTCDate(s.getUTCDate()+4-(s.getUTCDay()||7));const n=new Date(Date.UTC(s.getUTCFullYear(),0,1)),a=Math.ceil(((s.getTime()-n.getTime())/864e5+1)/7);return`${s.getUTCFullYear()}-W${String(a).padStart(2,"0")}`}m.post("/api/teacher/class/:classId/weekly-menu",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return d(e,403,"forbidden");const s=e.req.param("classId");if(!(t.role==="admin"?await e.env.DB.prepare("SELECT id FROM classes WHERE id=? LIMIT 1").bind(s).first():await e.env.DB.prepare("SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1").bind(s,t.id).first()))return d(e,404,"class_not_found");const r=await e.req.json().catch(()=>null);if(!r)return d(e,400,"invalid_json");const o=String(r.weekKey||He()).slice(0,8),i=String(r.kanjiPage||"").slice(0,100),l=String(r.keisanPage||"").slice(0,100),c=String(r.otherTasks||"").slice(0,500);return await e.env.DB.prepare(`
    INSERT INTO class_weekly_menu (class_id, week_key, kanji_page, keisan_page, other_tasks, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(class_id, week_key) DO UPDATE SET
      kanji_page=excluded.kanji_page, keisan_page=excluded.keisan_page,
      other_tasks=excluded.other_tasks, updated_at=excluded.updated_at
  `).bind(s,o,i,l,c,Date.now()).run(),e.json({ok:!0,weekKey:o})});m.get("/api/teacher/class/:classId/weekly-menu",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return d(e,403,"forbidden");const s=e.req.param("classId");if(!(t.role==="admin"?await e.env.DB.prepare("SELECT id FROM classes WHERE id=? LIMIT 1").bind(s).first():await e.env.DB.prepare("SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1").bind(s,t.id).first()))return d(e,404,"class_not_found");const r=e.req.query("weekKey")||He(),o=await e.env.DB.prepare("SELECT * FROM class_weekly_menu WHERE class_id=? AND week_key=? LIMIT 1").bind(s,r).first();return e.json({ok:!0,menu:o||null,weekKey:r})});m.get("/api/student/weekly-menu",async e=>{const t=e.get("user");if(!t)return d(e,403,"forbidden");const s=e.req.query("weekKey")||He(),n=await e.env.DB.prepare(`
    SELECT cwm.kanji_page as kanjiPage, cwm.keisan_page as keisanPage,
           cwm.other_tasks as otherTasks, cwm.week_key as weekKey
    FROM class_weekly_menu cwm
    JOIN class_members cm ON cm.class_id = cwm.class_id
    WHERE cm.user_id = ? AND cwm.week_key = ?
    LIMIT 1
  `).bind(t.id,s).first();return e.json({ok:!0,menu:n||null,weekKey:s})});m.get("/api/student/weekly-plan-status",async e=>{const t=e.get("user");if(!t)return d(e,403,"forbidden");const s=e.req.query("weekKey")||He(),n=await e.env.DB.prepare(`
    SELECT plan_approved as planApproved, plan_reward_coins as planRewardCoins,
           reflection_comment as reflectionComment, reflection_returned_at as reflectionReturnedAt,
           reflection_reward_coins as reflectionRewardCoins
    FROM student_weekly_plans WHERE user_id=? AND week_key=?
  `).bind(t.id,s).first();return e.json({ok:!0,status:n||null})});m.post("/api/student/weekly-plan",async e=>{const t=e.get("user");if(!t)return d(e,403,"forbidden");const s=await e.req.json().catch(()=>null);if(!s||!s.weekKey||!s.plans)return d(e,400,"invalid");const n=String(s.weekKey).slice(0,10),a=JSON.stringify(s.plans).slice(0,5e3);return await e.env.DB.prepare(`
    INSERT INTO student_weekly_plans (user_id, week_key, plans_json, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id, week_key) DO UPDATE SET plans_json=excluded.plans_json, updated_at=excluded.updated_at
  `).bind(t.id,n,a,Date.now()).run(),e.json({ok:!0})});m.get("/api/teacher/weekly-plans",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return d(e,403,"forbidden");const s=e.req.query("classId"),n=e.req.query("weekKey")||He();let a=`
    SELECT swp.id, swp.plans_json as plansJson, swp.updated_at as updatedAt, swp.week_key as weekKey,
           swp.plan_approved as planApproved, swp.plan_approved_at as planApprovedAt,
           swp.reflection_comment as reflectionComment, swp.reflection_returned_at as reflectionReturnedAt,
           u.id as userId, u.name as studentName, u.grade, u.class_name as className
    FROM student_weekly_plans swp
    JOIN users u ON u.id = swp.user_id
    JOIN class_members cm ON cm.user_id = swp.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
    WHERE swp.week_key = ?
  `;const r=[t.id,n];s&&(a+=" AND cl.id = ?",r.push(s)),a+=" ORDER BY u.grade, u.class_name, u.name";const o=await e.env.DB.prepare(a).bind(...r).all();return e.json({ok:!0,plans:o.results,weekKey:n})});m.post("/api/teacher/weekly-plan/:id/approve",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return d(e,403,"forbidden");const s=e.req.param("id"),n=await e.env.DB.prepare(`
    SELECT swp.*, cm.class_id FROM student_weekly_plans swp
    JOIN class_members cm ON cm.user_id = swp.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
    WHERE swp.id = ?
  `).bind(t.id,s).first();if(!n)return d(e,404,"not_found");if(n.plan_approved)return d(e,400,"already_approved");const a=300,r=5;return await e.env.DB.prepare("UPDATE student_weekly_plans SET plan_approved=1, plan_approved_at=?, plan_reward_coins=? WHERE id=?").bind(Date.now(),a,s).run(),e.json({ok:!0,coins:a,shards:r})});m.post("/api/teacher/weekly-plan/:id/return-reflection",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return d(e,403,"forbidden");const s=e.req.param("id"),n=await e.req.json().catch(()=>null);if(!n)return d(e,400,"invalid");const a=String(n.comment||"").slice(0,500),r=await e.env.DB.prepare(`
    SELECT swp.*, cm.class_id FROM student_weekly_plans swp
    JOIN class_members cm ON cm.user_id = swp.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
    WHERE swp.id = ?
  `).bind(t.id,s).first();if(!r)return d(e,404,"not_found");if(r.reflection_returned_at)return d(e,400,"already_returned");const o=300,i=5;return await e.env.DB.prepare("UPDATE student_weekly_plans SET reflection_comment=?, reflection_returned_at=?, reflection_reward_coins=? WHERE id=?").bind(a,Date.now(),o,s).run(),e.json({ok:!0,coins:o,shards:i})});function H(e){const t=e.get("user");return t||null}function Ke(){const e="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";let t="";const s=new Uint8Array(6);crypto.getRandomValues(s);for(let n=0;n<6;n++)t+=e[s[n]%e.length];return t}m.post("/api/battle/create",async e=>{const t=H(e);if(!t)return d(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return d(e,400,"invalid_json");const n=JSON.stringify(s.party||[]),a=String(s.name||"プレイヤー").slice(0,20),r=String(s.area||"rounding").slice(0,40),o=String(s.battleMode||"normal").slice(0,10);await e.env.DB.prepare("DELETE FROM battle_rooms WHERE host_user_id=? AND status='waiting'").bind(t.id).run();let i=Ke();for(let l=0;l<5&&await e.env.DB.prepare("SELECT id FROM battle_rooms WHERE id=?").bind(i).first();l++)i=Ke();return await e.env.DB.prepare(`
    INSERT INTO battle_rooms (id, host_user_id, host_name, host_party_json, area, battle_mode, status, host_hp, guest_hp, host_score, guest_score, question_index)
    VALUES (?, ?, ?, ?, ?, ?, 'waiting', 100, 100, 0, 0, 0)
  `).bind(i,t.id,a,n,r,o).run(),e.json({ok:!0,roomId:i})});m.post("/api/battle/join/:roomId",async e=>{const t=H(e);if(!t)return d(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.req.json().catch(()=>null);if(!n)return d(e,400,"invalid_json");const a=String(n.name||"プレイヤー").slice(0,20),r=JSON.stringify(n.party||[]),o=await e.env.DB.prepare("SELECT * FROM battle_rooms WHERE id=? LIMIT 1").bind(s).first();return o?o.status!=="waiting"?d(e,409,"room_not_available"):o.host_user_id===t.id?d(e,400,"cannot_join_own_room"):(await e.env.DB.prepare(`
    UPDATE battle_rooms SET guest_user_id=?, guest_name=?, guest_party_json=?, status='ready', updated_at=datetime('now')
    WHERE id=? AND status='waiting'
  `).bind(t.id,a,r,s).run(),e.json({ok:!0,roomId:s,hostName:o.host_name,area:o.area,battleMode:o.battle_mode,hostParty:JSON.parse(o.host_party_json||"[]")})):d(e,404,"room_not_found")});m.get("/api/battle/room/:roomId",async e=>{const t=H(e);if(!t)return d(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.env.DB.prepare("SELECT * FROM battle_rooms WHERE id=? LIMIT 1").bind(s).first();if(!n)return d(e,404,"room_not_found");const a=n.host_user_id===t.id,r=n.guest_user_id===t.id;if(!a&&!r)return d(e,403,"not_a_participant");const o=await e.env.DB.prepare(`
    SELECT user_id, question_index, is_correct, answered_at FROM battle_answers
    WHERE room_id=? AND question_index=?
  `).bind(s,n.question_index).all(),i=a?"host":"guest",l=a?n.guest_user_id:n.host_user_id,c=o.results.find(h=>h.user_id===t.id),p=o.results.find(h=>h.user_id===l);return e.json({ok:!0,room:{id:n.id,status:n.status,area:n.area,hostName:n.host_name,guestName:n.guest_name,questionIndex:n.question_index,questionJson:n.current_question_json,hostScore:n.host_score,guestScore:n.guest_score,hostHp:n.host_hp,guestHp:n.guest_hp,winner:n.winner,myRole:i,myAnswer:c?{isCorrect:!!c.is_correct}:null,oppAnswered:!!p,oppCorrect:p?!!p.is_correct:null,battleMode:n.battle_mode,opponentParty:a?n.guest_party_json?JSON.parse(n.guest_party_json):null:n.host_party_json?JSON.parse(n.host_party_json):null,opponentName:a?n.guest_name:n.host_name}})});m.post("/api/battle/set-question/:roomId",async e=>{const t=H(e);if(!t)return d(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.req.json().catch(()=>null);if(!n)return d(e,400,"invalid_json");const a=await e.env.DB.prepare("SELECT * FROM battle_rooms WHERE id=? LIMIT 1").bind(s).first();if(!a)return d(e,404,"room_not_found");if(a.host_user_id!==t.id)return d(e,403,"host_only");if(a.status!=="ready"&&a.status!=="playing")return d(e,409,"invalid_status");const r=JSON.stringify(n.question),o=Number(n.questionIndex??a.question_index);return await e.env.DB.prepare(`
    UPDATE battle_rooms
    SET current_question_json=?, question_index=?, status='playing', updated_at=datetime('now')
    WHERE id=?
  `).bind(r,o,s).run(),e.json({ok:!0})});m.post("/api/battle/answer/:roomId",async e=>{const t=H(e);if(!t)return d(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.req.json().catch(()=>null);if(!n)return d(e,400,"invalid_json");const a=await e.env.DB.prepare("SELECT * FROM battle_rooms WHERE id=? LIMIT 1").bind(s).first();if(!a)return d(e,404,"room_not_found");if(a.status!=="playing")return d(e,409,"not_playing");const r=a.host_user_id===t.id,o=a.guest_user_id===t.id;if(!r&&!o)return d(e,403,"not_a_participant");const i=n.isCorrect?1:0,l=String(n.answer||"").slice(0,100),c=a.question_index;if(await e.env.DB.prepare(`
    SELECT id FROM battle_answers WHERE room_id=? AND user_id=? AND question_index=?
  `).bind(s,t.id,c).first())return e.json({ok:!0,alreadyAnswered:!0});await e.env.DB.prepare(`
    INSERT INTO battle_answers (room_id, user_id, question_index, answer, is_correct)
    VALUES (?, ?, ?, ?, ?)
  `).bind(s,t.id,c,l,i).run();const h=await e.env.DB.prepare(`
    SELECT user_id, is_correct FROM battle_answers WHERE room_id=? AND question_index=?
  `).bind(s,c).all(),w=h.results.find(T=>T.user_id===a.host_user_id),_=h.results.find(T=>T.user_id===a.guest_user_id);let f=a.host_score,y=a.guest_score,b=a.host_hp,x=a.guest_hp,g=!1,v=a.status,C=a.winner;if(w&&_){g=!0;const T=!!w.is_correct,M=!!_.is_correct;T&&!M?(f++,x=Math.max(0,x-20)):!T&&M&&(y++,b=Math.max(0,b-20));const O=c+1;(b<=0||x<=0||O>=5)&&(v="finished",f>y?C="host":y>f?C="guest":C="draw"),await e.env.DB.prepare(`
      UPDATE battle_rooms
      SET host_score=?, guest_score=?, host_hp=?, guest_hp=?, status=?, winner=?, updated_at=datetime('now')
      WHERE id=?
    `).bind(f,y,b,x,v,C,s).run()}return e.json({ok:!0,bothAnswered:g,hostScore:f,guestScore:y,hostHp:b,guestHp:x,status:v,winner:C})});m.post("/api/battle/leave/:roomId",async e=>{const t=H(e);if(!t)return d(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.env.DB.prepare("SELECT * FROM battle_rooms WHERE id=? LIMIT 1").bind(s).first();return n?(n.host_user_id===t.id?await e.env.DB.prepare("DELETE FROM battle_rooms WHERE id=?").bind(s).run():await e.env.DB.prepare(`
      UPDATE battle_rooms SET guest_user_id=NULL, guest_name=NULL, guest_party_json=NULL,
      status='waiting', current_question_json=NULL, question_index=0,
      host_score=0, guest_score=0, host_hp=100, guest_hp=100, winner=NULL, updated_at=datetime('now')
      WHERE id=?
    `).bind(s).run(),e.json({ok:!0})):e.json({ok:!0})});m.delete("/api/battle/cleanup",async e=>H(e)?(await e.env.DB.prepare(`
    DELETE FROM battle_rooms WHERE created_at < datetime('now', '-2 hours')
  `).run(),e.json({ok:!0})):d(e,401,"unauthorized"));function pt(){const e="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";let t="";for(let s=0;s<6;s++)t+=e[Math.floor(Math.random()*e.length)];return t}m.post("/api/trade/offer",async e=>{const t=e.get("user");if(!t)return d(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!(s!=null&&s.monster))return d(e,400,"monster_required");await e.env.DB.prepare("UPDATE trade_offers SET status='cancelled' WHERE from_user_id=? AND status='pending'").bind(t.id).run();const n=crypto.randomUUID();let a=pt();for(let i=0;i<3&&await e.env.DB.prepare("SELECT id FROM trade_offers WHERE code=? AND status='pending' AND expires_at > ?").bind(a,Date.now()).first();i++)a=pt();const r=Date.now(),o=r+1440*60*1e3;return await e.env.DB.prepare(`
    INSERT INTO trade_offers (id, code, from_user_id, from_user_name, from_monster_json, status, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
  `).bind(n,a,t.id,t.name||t.username||"プレイヤー",JSON.stringify(s.monster),r,o).run(),e.json({ok:!0,code:a,expiresAt:o})});m.get("/api/trade/offer/:code",async e=>{const t=e.get("user");if(!t)return d(e,401,"unauthorized");const s=e.req.param("code").toUpperCase(),n=await e.env.DB.prepare("SELECT * FROM trade_offers WHERE code=? AND status='pending' AND expires_at > ?").bind(s,Date.now()).first();return n?n.from_user_id===t.id?d(e,400,"cannot_trade_with_yourself"):e.json({ok:!0,offer:{id:n.id,code:n.code,fromUserName:n.from_user_name,fromMonster:JSON.parse(n.from_monster_json),expiresAt:n.expires_at}}):d(e,404,"offer_not_found")});m.post("/api/trade/complete",async e=>{const t=e.get("user");if(!t)return d(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!(s!=null&&s.code)||!(s!=null&&s.monster))return d(e,400,"code_and_monster_required");const n=String(s.code).toUpperCase(),a=await e.env.DB.prepare("SELECT * FROM trade_offers WHERE code=? AND status='pending' AND expires_at > ?").bind(n,Date.now()).first();if(!a)return d(e,404,"offer_not_found");if(a.from_user_id===t.id)return d(e,400,"cannot_trade_with_yourself");const r=JSON.parse(a.from_monster_json),o=s.monster,i=await e.env.DB.prepare("SELECT state_json FROM progress WHERE user_id=?").bind(a.from_user_id).first();if(!i)return d(e,404,"from_user_progress_not_found");let l;try{l=JSON.parse(i.state_json)}catch{return d(e,500,"state_parse_error")}const c=await e.env.DB.prepare("SELECT state_json FROM progress WHERE user_id=?").bind(t.id).first();if(!c)return d(e,404,"to_user_progress_not_found");let p;try{p=JSON.parse(c.state_json)}catch{return d(e,500,"state_parse_error")}if(!Array.isArray(l.boxes))return d(e,400,"from_box_invalid");let h=-1,w=-1;e:for(let b=0;b<l.boxes.length;b++){const x=l.boxes[b];if(Array.isArray(x))for(let g=0;g<x.length;g++){const v=x[g];if(v&&(v.uid===r.uid||v.monsterId===r.monsterId&&v.level===r.level)){h=b,w=g;break e}}}if(h===-1)return d(e,400,"from_monster_not_in_box");if(l.boxes[h][w]=null,!Array.isArray(p.boxes))return d(e,400,"to_box_invalid");let _=-1,f=-1;e:for(let b=0;b<p.boxes.length;b++){const x=p.boxes[b];if(Array.isArray(x))for(let g=0;g<x.length;g++){const v=x[g];if(v&&(v.uid===o.uid||v.monsterId===o.monsterId&&v.level===o.level)){_=b,f=g;break e}}}if(_===-1)return d(e,400,"to_monster_not_in_box");p.boxes[_][f]=null;const y=(b,x)=>{for(let g=0;g<b.length;g++){Array.isArray(b[g])||(b[g]=[]);for(let v=0;v<100;v++)if(!b[g][v]){b[g][v]={...x,tradedAt:Date.now()};return}}b[0].push({...x,tradedAt:Date.now()})};return y(l.boxes,o),y(p.boxes,r),await e.env.DB.prepare("UPDATE progress SET state_json=?, updated_at=datetime('now') WHERE user_id=?").bind(JSON.stringify(l),a.from_user_id).run(),await e.env.DB.prepare("UPDATE progress SET state_json=?, updated_at=datetime('now') WHERE user_id=?").bind(JSON.stringify(p),t.id).run(),await e.env.DB.prepare("UPDATE trade_offers SET status='completed', to_user_id=?, to_monster_json=?, completed_at=? WHERE id=?").bind(t.id,JSON.stringify(o),Date.now(),a.id).run(),e.json({ok:!0,received:r,sent:o,fromUserName:a.from_user_name})});m.delete("/api/trade/offer",async e=>{const t=e.get("user");return t?(await e.env.DB.prepare("UPDATE trade_offers SET status='cancelled' WHERE from_user_id=? AND status='pending'").bind(t.id).run(),e.json({ok:!0})):d(e,401,"unauthorized")});m.post("/api/rt/create",async e=>{const t=H(e);if(!t)return d(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return d(e,400,"invalid_json");const n=String(s.name||"プレイヤー").slice(0,20),a=JSON.stringify(s.party||[]),r=String(s.area||"rounding").slice(0,40),o=s.battleType==="egg"?"egg":s.battleType==="gym"?"gym":"normal";await e.env.DB.prepare("DELETE FROM rt_rooms WHERE host_user_id=? AND status='waiting'").bind(t.id).run();const i=s.code?String(s.code).toUpperCase().replace(/[^A-Z0-9]/g,""):"";let l=i.length>=4?i:Ke();if(!i.length)for(let c=0;c<5&&await e.env.DB.prepare("SELECT id FROM rt_rooms WHERE id=?").bind(l).first();c++)l=Ke();return await e.env.DB.prepare(`
    INSERT INTO rt_rooms (id, host_user_id, host_name, host_party_json, host_area, host_hp, host_ready, guest_hp, guest_ready, battle_type, status)
    VALUES (?, ?, ?, ?, ?, 100, 0, 100, 0, ?, 'waiting')
  `).bind(l,t.id,n,a,r,o).run(),e.json({ok:!0,roomId:l})});m.post("/api/rt/join/:roomId",async e=>{const t=H(e);if(!t)return d(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.req.json().catch(()=>null);if(!n)return d(e,400,"invalid_json");const a=String(n.name||"プレイヤー").slice(0,20),r=JSON.stringify(n.party||[]),o=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();if(!o)return d(e,404,"room_not_found");if(o.status!=="waiting")return d(e,409,"room_not_available");if(o.host_user_id===t.id)return d(e,400,"cannot_join_own_room");await e.env.DB.prepare(`
    UPDATE rt_rooms SET guest_user_id=?, guest_name=?, guest_party_json=?, guest_ready=1, status='ready', updated_at=datetime('now')
    WHERE id=? AND status='waiting'
  `).bind(t.id,a,r,s).run();const i=JSON.parse(o.host_party_json||"[]");return e.json({ok:!0,roomId:s,hostName:o.host_name,area:o.host_area,battleType:o.battle_type,hostParty:i})});m.get("/api/rt/room/:roomId",async e=>{const t=H(e);if(!t)return d(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();if(!n)return d(e,404,"room_not_found");const a=n.host_user_id===t.id,r=n.guest_user_id===t.id;if(!a&&!r)return d(e,403,"not_a_participant");const o=Number(e.req.query("after")||0),i=await e.env.DB.prepare(`
    SELECT id, user_id, event_type, value, monster_id, meta_json, created_at FROM rt_events
    WHERE room_id=? AND id > ?
    ORDER BY id ASC LIMIT 50
  `).bind(s,o).all(),l=a?"host":"guest",c=a?n.guest_party_json?JSON.parse(n.guest_party_json):null:JSON.parse(n.host_party_json||"[]");return e.json({ok:!0,room:{id:n.id,status:n.status,battleType:n.battle_type,area:n.host_area,hostName:n.host_name,guestName:n.guest_name,hostHp:n.host_hp,guestHp:n.guest_hp,hostReady:!!n.host_ready,guestReady:!!n.guest_ready,winner:n.winner,myRole:l,opponentParty:c},events:i.results})});m.post("/api/rt/ready/:roomId",async e=>{const t=H(e);if(!t)return d(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();if(!n)return d(e,404,"room_not_found");const a=n.host_user_id===t.id,r=n.guest_user_id===t.id;if(!a&&!r)return d(e,403,"not_a_participant");a?await e.env.DB.prepare("UPDATE rt_rooms SET host_ready=1, updated_at=datetime('now') WHERE id=?").bind(s).run():await e.env.DB.prepare("UPDATE rt_rooms SET guest_ready=1, updated_at=datetime('now') WHERE id=?").bind(s).run();const o=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();return o&&o.host_ready&&o.guest_ready&&(o.status==="ready"||o.status==="waiting")&&await e.env.DB.prepare("UPDATE rt_rooms SET status='playing', updated_at=datetime('now') WHERE id=?").bind(s).run(),e.json({ok:!0})});m.post("/api/rt/damage/:roomId",async e=>{const t=H(e);if(!t)return d(e,401,"unauthorized");if(!Mt(`rtdmg:${t.id}`,20,10))return d(e,429,"too_many_requests");const s=e.req.param("roomId").toUpperCase(),n=await e.req.json().catch(()=>null);if(!n)return d(e,400,"invalid_json");const a=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();if(!a)return d(e,404,"room_not_found");if(a.status!=="playing")return d(e,409,"not_playing");const r=a.host_user_id===t.id,o=a.guest_user_id===t.id;if(!r&&!o)return d(e,403,"not_a_participant");const i=Math.max(0,Math.min(500,Number(n.damage||0)));if(!Number.isFinite(i))return d(e,400,"invalid_damage");const l=Math.max(0,Math.min(9999,Math.floor(Number(n.monsterId||0)))),c=n.meta?JSON.stringify(n.meta).slice(0,500):null,h=["damage","faint","win","lose"].includes(String(n.eventType))?String(n.eventType):"damage",_=(await e.env.DB.prepare(`
    INSERT INTO rt_events (room_id, user_id, event_type, value, monster_id, meta_json)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(s,t.id,h,i,l,c).run()).meta.last_row_id;let f=a.host_hp,y=a.guest_hp;h==="self_damage"?r?f=Math.max(0,f-i):y=Math.max(0,y-i):r?y=Math.max(0,y-i):f=Math.max(0,f-i);let b=a.status,x=a.winner;return h==="win"?(b="finished",x=r?"host":"guest"):h==="draw"&&(b="finished",x="draw"),await e.env.DB.prepare(`
    UPDATE rt_rooms SET host_hp=?, guest_hp=?, status=?, winner=?, updated_at=datetime('now') WHERE id=?
  `).bind(f,y,b,x,s).run(),e.json({ok:!0,eventId:_,hostHp:f,guestHp:y})});m.post("/api/rt/leave/:roomId",async e=>{const t=H(e);if(!t)return d(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();return n?(n.host_user_id===t.id?await e.env.DB.prepare("DELETE FROM rt_rooms WHERE id=?").bind(s).run():await e.env.DB.prepare(`
      UPDATE rt_rooms SET guest_user_id=NULL, guest_name=NULL, guest_party_json=NULL,
      status='waiting', host_hp=100, guest_hp=100, host_ready=0, guest_ready=0, winner=NULL,
      updated_at=datetime('now') WHERE id=?
    `).bind(s).run(),e.json({ok:!0})):e.json({ok:!0})});m.delete("/api/rt/cleanup",async e=>(await e.env.DB.prepare("DELETE FROM rt_rooms WHERE created_at < datetime('now', '-2 hours')").run(),await e.env.DB.prepare("DELETE FROM rt_events WHERE created_at < datetime('now', '-2 hours')").run(),e.json({ok:!0})));m.post("/api/report",async e=>{const t=e.get("user");if(!t)return d(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!(s!=null&&s.body)||typeof s.body!="string"||s.body.trim().length===0)return d(e,400,"body_required");const n=["bug","request","other"].includes(s.category)?s.category:"bug",a=s.body.trim().slice(0,1e3),r=await e.env.DB.prepare("SELECT name FROM users WHERE id=?").bind(t.id).first(),o=(r==null?void 0:r.name)||t.loginId||"unknown",i=crypto.randomUUID();return await e.env.DB.prepare("INSERT INTO reports (id, account_id, display_name, category, body) VALUES (?, ?, ?, ?, ?)").bind(i,t.id,o,n,a).run(),e.json({ok:!0,id:i})});m.get("/api/report/my",async e=>{const t=e.get("user");if(!t)return d(e,401,"unauthorized");const s=await e.env.DB.prepare(`SELECT id, category, body, status, admin_note as adminNote, created_at as createdAt
     FROM reports WHERE account_id=? ORDER BY created_at DESC LIMIT 20`).bind(t.id).all();return e.json({ok:!0,reports:s.results})});m.get("/api/admin/reports",async e=>{if(!(D(e)||L(e)))return d(e,401,"unauthorized");const s=e.req.query("status")||"all";let n="SELECT id, account_id as accountId, display_name as displayName, category, body, status, admin_note as adminNote, created_at as createdAt, updated_at as updatedAt FROM reports";const a=[];s!=="all"&&(n+=" WHERE status=?",a.push(s)),n+=" ORDER BY created_at DESC LIMIT 100";const o=await(a.length>0?e.env.DB.prepare(n).bind(...a):e.env.DB.prepare(n)).all();return e.json({ok:!0,reports:o.results})});m.put("/api/admin/report/:id",async e=>{if(!(D(e)||L(e)))return d(e,401,"unauthorized");const s=e.req.param("id"),n=await e.req.json().catch(()=>null);if(!n)return d(e,400,"invalid_body");const a=["open","in_progress","resolved","closed"],r=[],o=[];return n.status&&a.includes(n.status)&&(r.push("status=?"),o.push(n.status)),typeof n.adminNote=="string"&&(r.push("admin_note=?"),o.push(n.adminNote.slice(0,500))),r.length===0?d(e,400,"nothing_to_update"):(r.push("updated_at=datetime('now')"),o.push(s),await e.env.DB.prepare(`UPDATE reports SET ${r.join(", ")} WHERE id=?`).bind(...o).run(),e.json({ok:!0}))});m.delete("/api/admin/report/:id",async e=>D(e)||L(e)?(await e.env.DB.prepare("DELETE FROM reports WHERE id=?").bind(e.req.param("id")).run(),e.json({ok:!0})):d(e,401,"unauthorized"));m.post("/api/teacher/announcement",async e=>{const t=D(e);if(!t)return d(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return d(e,400,"invalid_json");const n=String(s.title||"").trim(),a=String(s.body||"").trim(),r=s.classId||null;if(!n||!a)return d(e,400,"title_and_body_required");const o=crypto.randomUUID();return await e.env.DB.prepare("INSERT INTO announcements (id, class_id, teacher_id, title, body) VALUES (?,?,?,?,?)").bind(o,r,t.id,n,a).run(),e.json({ok:!0,id:o})});m.get("/api/teacher/announcements",async e=>{if(!D(e))return d(e,401,"unauthorized");const s=await e.env.DB.prepare(`SELECT a.id, a.class_id as classId, a.title, a.body, a.created_at as createdAt, c.name as className
     FROM announcements a LEFT JOIN classes c ON c.id = a.class_id
     ORDER BY a.created_at DESC LIMIT 50`).all();return e.json({ok:!0,announcements:s.results})});m.delete("/api/teacher/announcement/:id",async e=>{if(!D(e))return d(e,401,"unauthorized");const s=e.req.param("id");return await e.env.DB.prepare("DELETE FROM announcement_reads WHERE announcement_id=?").bind(s).run(),await e.env.DB.prepare("DELETE FROM announcements WHERE id=?").bind(s).run(),e.json({ok:!0})});m.get("/api/student/announcements",async e=>{const t=e.get("user");if(!t)return d(e,401,"unauthorized");const s=await e.env.DB.prepare("SELECT class_id FROM class_members WHERE user_id=? LIMIT 1").bind(t.id).first(),n=(s==null?void 0:s.class_id)||null;let a;return n?a=await e.env.DB.prepare(`SELECT a.id, a.title, a.body, a.created_at as createdAt, a.class_id as classId,
              ar.read_at as readAt
       FROM announcements a
       LEFT JOIN announcement_reads ar ON ar.announcement_id = a.id AND ar.user_id = ?
       WHERE a.class_id IS NULL OR a.class_id = ?
       ORDER BY a.created_at DESC LIMIT 30`).bind(t.id,n).all():a=await e.env.DB.prepare(`SELECT a.id, a.title, a.body, a.created_at as createdAt, a.class_id as classId,
              ar.read_at as readAt
       FROM announcements a
       LEFT JOIN announcement_reads ar ON ar.announcement_id = a.id AND ar.user_id = ?
       WHERE a.class_id IS NULL
       ORDER BY a.created_at DESC LIMIT 30`).bind(t.id).all(),e.json({ok:!0,announcements:a.results})});m.post("/api/student/announcement/:id/read",async e=>{const t=e.get("user");if(!t)return d(e,401,"unauthorized");const s=e.req.param("id");return await e.env.DB.prepare("INSERT OR IGNORE INTO announcement_reads (user_id, announcement_id) VALUES (?,?)").bind(t.id,s).run(),e.json({ok:!0})});m.post("/api/teacher/contact-note",async e=>{const t=L(e);if(!t)return d(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return d(e,400,"invalid_json");const n=String(s.classId||"").trim(),a=String(s.body||"").trim(),r=String(s.dayKey||"").trim(),o=s.rewardDeadline||null,i=Number(s.rewardCoins)||5;if(!n||!a||!r)return d(e,400,"classId_body_dayKey_required");if(!await e.env.DB.prepare("SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1").bind(n,t.id).first())return d(e,403,"not_your_class");const c=crypto.randomUUID();return await e.env.DB.prepare("INSERT INTO contact_notes (id, class_id, teacher_id, day_key, body, reward_deadline, reward_coins) VALUES (?,?,?,?,?,?,?)").bind(c,n,t.id,r,a,o,i).run(),e.json({ok:!0,id:c})});m.get("/api/teacher/contact-notes",async e=>{const t=L(e);if(!t)return d(e,401,"unauthorized");const s=e.req.query("classId")||"",n=t.role==="admin";let a;return s?a=await e.env.DB.prepare(`SELECT cn.id, cn.class_id as classId, cn.day_key as dayKey, cn.body, cn.reward_deadline as rewardDeadline, cn.reward_coins as rewardCoins, cn.created_at as createdAt, c.name as className
       FROM contact_notes cn LEFT JOIN classes c ON c.id = cn.class_id
       WHERE cn.class_id = ? ${n?"":"AND cn.teacher_id = ?"}
       ORDER BY cn.created_at DESC LIMIT 30`).bind(...n?[s]:[s,t.id]).all():a=n?await e.env.DB.prepare(`SELECT cn.id, cn.class_id as classId, cn.day_key as dayKey, cn.body, cn.reward_deadline as rewardDeadline, cn.reward_coins as rewardCoins, cn.created_at as createdAt, c.name as className
           FROM contact_notes cn LEFT JOIN classes c ON c.id = cn.class_id
           ORDER BY cn.created_at DESC LIMIT 30`).all():await e.env.DB.prepare(`SELECT cn.id, cn.class_id as classId, cn.day_key as dayKey, cn.body, cn.reward_deadline as rewardDeadline, cn.reward_coins as rewardCoins, cn.created_at as createdAt, c.name as className
           FROM contact_notes cn LEFT JOIN classes c ON c.id = cn.class_id
           WHERE cn.teacher_id = ?
           ORDER BY cn.created_at DESC LIMIT 30`).bind(t.id).all(),e.json({ok:!0,notes:a.results})});m.delete("/api/teacher/contact-note/:id",async e=>{const t=L(e);if(!t)return d(e,401,"unauthorized");const s=e.req.param("id");return await e.env.DB.prepare("DELETE FROM contact_note_reads WHERE note_id=?").bind(s).run(),t.role==="admin"?await e.env.DB.prepare("DELETE FROM contact_notes WHERE id=?").bind(s).run():await e.env.DB.prepare("DELETE FROM contact_notes WHERE id=? AND teacher_id=?").bind(s,t.id).run(),e.json({ok:!0})});m.get("/api/teacher/contact-note/:id/reads",async e=>{if(!L(e))return d(e,401,"unauthorized");const s=e.req.param("id"),n=await e.env.DB.prepare(`SELECT cnr.user_id as userId, cnr.read_at as readAt, cnr.reward_claimed as rewardClaimed, u.name as studentName
     FROM contact_note_reads cnr JOIN users u ON u.id = cnr.user_id
     WHERE cnr.note_id = ? ORDER BY cnr.read_at ASC`).bind(s).all();return e.json({ok:!0,reads:n.results})});m.get("/api/student/contact-notes",async e=>{const t=e.get("user");if(!t)return d(e,401,"unauthorized");let s=null;if(t.role==="teacher"||t.role==="admin"){const a=t.role==="admin"?await e.env.DB.prepare("SELECT id FROM classes ORDER BY created_at DESC LIMIT 1").first():await e.env.DB.prepare("SELECT id FROM classes WHERE teacher_id=? ORDER BY created_at DESC LIMIT 1").bind(t.id).first();s=(a==null?void 0:a.id)||null}else{const a=await e.env.DB.prepare("SELECT class_id FROM class_members WHERE user_id=? LIMIT 1").bind(t.id).first();s=(a==null?void 0:a.class_id)||null}if(!s)return e.json({ok:!0,notes:[]});const n=await e.env.DB.prepare(`SELECT cn.id, cn.day_key as dayKey, cn.body, cn.reward_deadline as rewardDeadline, cn.reward_coins as rewardCoins, cn.created_at as createdAt,
            cnr.read_at as readAt, cnr.reward_claimed as rewardClaimed
     FROM contact_notes cn
     LEFT JOIN contact_note_reads cnr ON cnr.note_id = cn.id AND cnr.user_id = ?
     WHERE cn.class_id = ?
     ORDER BY cn.created_at DESC LIMIT 50`).bind(t.id,s).all();return e.json({ok:!0,notes:n.results})});m.post("/api/student/contact-note/:id/read",async e=>{const t=e.get("user");if(!t)return d(e,401,"unauthorized");const s=e.req.param("id");if(await e.env.DB.prepare("SELECT reward_claimed FROM contact_note_reads WHERE user_id=? AND note_id=? LIMIT 1").bind(t.id,s).first())return e.json({ok:!0,alreadyRead:!0,reward:0});const a=await e.env.DB.prepare("SELECT reward_deadline, reward_coins FROM contact_notes WHERE id=? LIMIT 1").bind(s).first();if(!a)return d(e,404,"not_found");const r=new Date().toISOString();let o=0,i=0;return a.reward_deadline?r<=a.reward_deadline&&(o=a.reward_coins||5,i=1):(o=a.reward_coins||5,i=1),await e.env.DB.prepare("INSERT OR IGNORE INTO contact_note_reads (user_id, note_id, reward_claimed) VALUES (?,?,?)").bind(t.id,s,i).run(),e.json({ok:!0,reward:o,rewardClaimed:!!i})});m.get("/",async e=>{var s;const t=await((s=e.env.ASSETS)==null?void 0:s.fetch(new Request(new URL("https://assets/index.html"))));return t||e.text("index.html not found",404)});m.get("/logout",async e=>{const t={secure:!0,sameSite:"Lax",httpOnly:!0};return Ne(e,"session",{...t,path:"/"}),Ne(e,"session",{...t,path:"/api"}),e.redirect("/login")});m.get("/login",e=>e.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>教材ログイン（LearningBM）</title><script src="https://cdn.tailwindcss.com"><\/script></head>
  <body class="min-h-screen bg-slate-100 p-4">
    <div class="max-w-md mx-auto bg-white rounded-xl shadow p-6">
      <h1 class="text-xl font-bold mb-1">教材ログイン</h1>
      <p class="text-xs text-slate-600 mb-4">学習記録のためにログインしてください。</p>
      <div class="space-y-3">
        <input id="loginId" class="w-full border p-2 rounded" placeholder="ログインID"/>
        <input id="password" type="password" class="w-full border p-2 rounded" placeholder="パスワード"/>
        <button id="btn" class="w-full bg-blue-600 text-white rounded p-2">ログイン</button>
        <p id="msg" class="text-sm text-red-600"></p>
        <a class="text-sm text-blue-700 underline" href="/signup">児童 新規登録</a>
        <span class="text-sm text-slate-400 mx-1">｜</span>
        <a class="text-sm text-emerald-700 underline" href="/teacher-signup">教師 アカウント申請</a>
      </div>
    </div>
    <script>
      const msg = document.getElementById('msg');
      document.getElementById('btn').onclick = async () => {
        msg.textContent='';
        const loginId = document.getElementById('loginId').value.trim();
        const password = document.getElementById('password').value;
        const r = await fetch('/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({loginId,password})});
        const j = await r.json().catch(()=>({}));
        if(!r.ok){
          const errMap = {
            invalid_credentials: 'IDまたはパスワードが間違っています',
            pending_approval: '承認待ちです。管理者の承認をお待ちください',
            missing_credentials: 'IDとパスワードを入力してください',
          };
          msg.textContent = errMap[j.error] || (j.error || 'ログインに失敗しました');
          return;
        }
        const me = await fetch('/api/auth/me').then(r=>r.json()).catch(()=>({}));
        if(me.user && me.user.role === 'teacher') { location.href = '/teacher'; }
        else { location.href = '/'; }
      };
    <\/script>
  </body></html>`));m.get("/signup",e=>e.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>新規登録</title><script src="https://cdn.tailwindcss.com"><\/script></head>
  <body class="min-h-screen bg-slate-100 p-4">
    <div class="max-w-md mx-auto bg-white rounded-xl shadow p-6">
      <h1 class="text-xl font-bold mb-4">児童 新規登録</h1>
      <div class="space-y-3">
        <div>
          <label class="text-sm font-bold text-gray-700 mb-1 block">名前</label>
          <input id="name" class="w-full border p-2 rounded" placeholder="例：山田 太郎"/>
        </div>
        <div class="flex gap-2">
          <div class="flex-1">
            <label class="text-sm font-bold text-gray-700 mb-1 block">学年</label>
            <select id="grade" class="w-full border p-2 rounded bg-white">
              <option value="">選択してください</option>
              <option value="1">1年</option>
              <option value="2">2年</option>
              <option value="3">3年</option>
              <option value="4">4年</option>
              <option value="5">5年</option>
              <option value="6">6年</option>
            </select>
          </div>
        </div>
        <div>
          <label class="text-sm font-bold text-gray-700 mb-1 block">ログインID（自分で決める）</label>
          <input id="loginId" class="w-full border p-2 rounded" placeholder="半角英数字 3文字以上"/>
        </div>
        <div>
          <label class="text-sm font-bold text-gray-700 mb-1 block">パスワード</label>
          <input id="password" type="password" class="w-full border p-2 rounded" placeholder="6文字以上"/>
        </div>
        <button id="btn" class="w-full bg-green-600 text-white rounded p-2 font-bold">登録する</button>
        <p id="msg" class="text-sm"></p>
        <a class="text-sm text-blue-700 underline" href="/login">ログインへ</a>
      </div>
    </div>
    <script>
      const msg = document.getElementById('msg');
      const errMap = {
        loginId_too_short: 'ログインIDは3文字以上にしてください',
        loginId_taken: 'このログインIDはすでに使われています',
        password_too_short: 'パスワードは6文字以上にしてください',
        name_required: '名前を入力してください',
        name_inappropriate: 'その名前は使えません',
        grade_invalid: '学年を選択してください',
        invalid_json: '入力内容に問題があります',
      };
      document.getElementById('btn').onclick = async () => {
        msg.textContent='';
        const gradeVal = document.getElementById('grade').value;
        const payload = {
          name: document.getElementById('name').value.trim(),
          grade: gradeVal ? Number(gradeVal) : NaN,
          loginId: document.getElementById('loginId').value.trim(),
          password: document.getElementById('password').value,
        };
        // クライアント側バリデーション
        if(!payload.name){ msg.textContent='名前を入力してください'; msg.className='text-sm text-red-600'; return; }
        if(!gradeVal){ msg.textContent='学年を選択してください'; msg.className='text-sm text-red-600'; return; }
        if(!payload.loginId || payload.loginId.length < 3){ msg.textContent='ログインIDは3文字以上にしてください'; msg.className='text-sm text-red-600'; return; }
        if(!payload.password || payload.password.length < 6){ msg.textContent='パスワードは6文字以上にしてください'; msg.className='text-sm text-red-600'; return; }

        document.getElementById('btn').disabled = true;
        const r = await fetch('/api/auth/signup',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
        const j = await r.json().catch(()=>({}));
        if(!r.ok){
          msg.textContent = errMap[j.error] || (j.error || '登録に失敗しました');
          msg.className='text-sm text-red-600';
          document.getElementById('btn').disabled = false;
          return;
        }
        // 登録成功 → 承認待ちメッセージを表示してログイン画面へ
        msg.textContent = '登録しました！先生が承認するまでお待ちください。';
        msg.className='text-sm text-green-700';
        setTimeout(()=>{ location.href='/login'; }, 3000);
      };
    <\/script>
  </body></html>`));m.get("/admin",e=>e.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>学習記録 管理（LearningBM）</title><script src="https://cdn.tailwindcss.com"><\/script></head>
  <body class="min-h-screen bg-slate-100 p-4">
    <div class="max-w-5xl mx-auto space-y-4">
      <div class="bg-white rounded-xl shadow p-6 flex items-center justify-between">
        <h1 class="text-xl font-bold">学習記録 管理</h1>
        <div class="flex items-center gap-3">
          <a href="/" class="text-sm px-3 py-1 rounded bg-indigo-100 hover:bg-indigo-200 text-indigo-700 font-bold transition">🌏 児童用ページへ</a>
          <button id="logout" class="text-sm px-3 py-1 rounded bg-gray-200 hover:bg-red-100 hover:text-red-700 text-gray-600 font-bold transition">ログアウト</button>
        </div>
      </div>

      <div class="grid md:grid-cols-2 gap-4">
        <div class="bg-white rounded-xl shadow p-6">
          <h2 class="font-bold mb-2">管理者パスワード変更</h2>
          <div class="space-y-2">
            <input id="oldAdminPw" type="password" class="w-full border p-2 rounded" placeholder="現在のパスワード" />
            <input id="newAdminPw" type="password" class="w-full border p-2 rounded" placeholder="新しいパスワード（8文字以上）" />
            <button id="changeAdminPwBtn" class="bg-indigo-600 text-white rounded px-3 py-2">変更</button>
            <p id="adminPwMsg" class="text-sm"></p>
          </div>
        </div>

        <div class="bg-white rounded-xl shadow p-6">
          <h2 class="font-bold mb-2">CSVエクスポート</h2>
          <div class="grid grid-cols-2 gap-2 text-sm">
            <input id="csvFrom" class="border p-2 rounded" placeholder="from (YYYY-MM-DD)" />
            <input id="csvTo" class="border p-2 rounded" placeholder="to (YYYY-MM-DD)" />
            <input id="csvGrade" class="border p-2 rounded" placeholder="学年(1-6)" />
            <input id="csvClass" class="border p-2 rounded" placeholder="クラス" />
          </div>
          <button id="csvBtn" class="mt-2 bg-emerald-600 text-white rounded px-3 py-2">CSVダウンロード</button>
        </div>
      </div>

      <!-- 教師承認 -->
      <div class="bg-white rounded-xl shadow p-6">
        <h2 class="font-bold mb-2">🍎 教師アカウント承認</h2>
        <div id="pendingTeachers" class="space-y-2 text-sm"></div>
      </div>

      <!-- ランキング設定 -->
      <div class="bg-white rounded-xl shadow p-6">
        <h2 class="font-bold mb-3">🏆 ランキング設定</h2>
        <div class="space-y-3 text-sm">
          <div class="flex items-center gap-3">
            <span class="font-bold">表示範囲：</span>
            <label class="flex items-center gap-1"><input type="radio" name="rankScope" value="global"/> 全体</label>
            <label class="flex items-center gap-1"><input type="radio" name="rankScope" value="class"/> クラス内のみ</label>
            <label class="flex items-center gap-1"><input type="radio" name="rankScope" value="hidden"/> 非表示</label>
          </div>
          <div class="flex items-center gap-3">
            <span class="font-bold">ランキング機能：</span>
            <label class="flex items-center gap-1"><input type="radio" name="rankEnabled" value="1"/> 有効</label>
            <label class="flex items-center gap-1"><input type="radio" name="rankEnabled" value="0"/> 無効</label>
          </div>
          <button id="saveRankingBtn" class="bg-indigo-600 text-white rounded px-3 py-2">設定を保存</button>
          <p id="rankingMsg" class="text-sm"></p>
        </div>
      </div>

      <div class="bg-white rounded-xl shadow p-6">
        <h2 class="font-bold mb-2">承認待ち / 停止中 児童</h2>
        <div id="pending" class="space-y-2 text-sm"></div>
      </div>

      <div class="bg-white rounded-xl shadow p-6">
        <h2 class="font-bold mb-2">児童一覧</h2>
        <div class="flex flex-wrap gap-2 mb-2 text-sm">
          <input id="filterGrade" class="border p-2 rounded" placeholder="学年" />
          <button id="filterBtn" class="bg-slate-700 text-white rounded px-3">絞り込み</button>
          <button id="reloadBtn" class="bg-slate-200 rounded px-3">更新</button>
        </div>
        <div id="users" class="space-y-2 text-sm"></div>
      </div>

      <div class="bg-white rounded-xl shadow p-6">
        <h2 class="font-bold mb-2">直近の学習ログ</h2>
        <div id="results" class="space-y-2 text-sm"></div>
      </div>
    </div>

    <script>
      async function api(path, opt){
        const r = await fetch(path, opt);
        const isCsv = String(path||'').includes('.csv');
        if(isCsv) return r;
        const j = await r.json().catch(()=>({}));
        if(!r.ok) throw new Error(j.error || 'error');
        return j;
      }

      document.getElementById('logout').onclick = async () => {
        await fetch('/api/auth/logout',{method:'POST'});
        location.href='/login';
      };

      document.getElementById('changeAdminPwBtn').onclick = async () => {
        const msg = document.getElementById('adminPwMsg');
        msg.textContent='';
        try{
          const oldPassword = document.getElementById('oldAdminPw').value;
          const newPassword = document.getElementById('newAdminPw').value;
          await api('/api/admin/change-password',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({oldPassword,newPassword})});
          msg.textContent='変更しました';
          msg.className='text-sm text-green-700';
          document.getElementById('oldAdminPw').value='';
          document.getElementById('newAdminPw').value='';
        }catch(e){
          msg.textContent=String(e.message||e);
          msg.className='text-sm text-red-700';
        }
      };

      document.getElementById('csvBtn').onclick = async () => {
        const from = document.getElementById('csvFrom').value.trim();
        const to = document.getElementById('csvTo').value.trim();
        const grade = document.getElementById('csvGrade').value.trim();
        const cls = document.getElementById('csvClass').value.trim();
        const qs = new URLSearchParams();
        if(from) qs.set('from', from);
        if(to) qs.set('to', to);
        if(grade) qs.set('grade', grade);
        if(cls) qs.set('class', cls);
        location.href = '/api/admin/results.csv?' + qs.toString();
      };

      async function renderPendingTeachers(){
        const wrap = document.getElementById('pendingTeachers');
        let data;
        try{ data = await api('/api/admin/pending-teachers'); }
        catch(e){ wrap.innerHTML='<p class="text-red-600">読み込みエラー</p>'; return; }
        wrap.innerHTML='';
        if(!data.teachers.length){ wrap.textContent='承認待ちの教師はいません'; return; }
        for(const t of data.teachers){
          const div = document.createElement('div');
          div.className='flex flex-col md:flex-row md:items-center md:justify-between border rounded p-2 gap-2';
          const left = document.createElement('div');
          left.textContent = t.name + '（' + t.loginId + '）' + (t.school ? ' ' + t.school : '');
          div.appendChild(left);
          const right = document.createElement('div');
          right.className='flex gap-2';
          const approve = document.createElement('button');
          approve.className='bg-emerald-600 text-white rounded px-3 py-1';
          approve.textContent='承認';
          approve.onclick = async ()=>{ await api('/api/admin/approve-teacher/'+t.id,{method:'POST'}); await renderPendingTeachers(); };
          right.appendChild(approve);
          const reject = document.createElement('button');
          reject.className='bg-red-600 text-white rounded px-3 py-1';
          reject.textContent='却下';
          reject.onclick = async ()=>{
            if(!confirm(t.name + 'の申請を却下・削除しますか？')){ return; }
            await api('/api/admin/reject-teacher/'+t.id,{method:'DELETE'}); await renderPendingTeachers();
          };
          right.appendChild(reject);
          div.appendChild(right);
          wrap.appendChild(div);
        }
      }

      async function loadRankingSettings(){
        try{
          const d = await api('/api/admin/settings');
          const scope = d.settings.ranking_scope || 'class';
          const enabled = d.settings.ranking_enabled !== '0';
          document.querySelectorAll('[name="rankScope"]').forEach(r=>{ r.checked = (r.value === scope); });
          document.querySelectorAll('[name="rankEnabled"]').forEach(r=>{ r.checked = (r.value === (enabled?'1':'0')); });
        }catch(e){ console.error('settings load error', e); }
      }

      document.getElementById('saveRankingBtn').onclick = async () => {
        const msg = document.getElementById('rankingMsg');
        msg.textContent=''; msg.className='text-sm';
        const scope = [...document.querySelectorAll('[name="rankScope"]')].find(r=>r.checked)?.value;
        const enabled = [...document.querySelectorAll('[name="rankEnabled"]')].find(r=>r.checked)?.value;
        try{
          await api('/api/admin/settings',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({ranking_scope:scope,ranking_enabled:enabled})});
          msg.textContent='保存しました'; msg.className='text-sm text-green-700';
        }catch(e){ msg.textContent=String(e.message||e); msg.className='text-sm text-red-600'; }
      };

      async function renderPending(){
        const p = await api('/api/admin/pending');
        const wrap = document.getElementById('pending');
        wrap.innerHTML='';
        if(!p.users.length){ wrap.textContent='承認待ち/停止中はありません'; return; }
        for(const u of p.users){
          const div = document.createElement('div');
          div.className='flex flex-col md:flex-row md:items-center md:justify-between border rounded p-2 gap-2';
          const left = document.createElement('div');
          left.textContent = u.grade + '年 ' + u.className + ' / ' + u.name + '（' + u.loginId + '）' + (u.disabledReason ? (' 停止理由: '+u.disabledReason) : '');
          div.appendChild(left);
          const right = document.createElement('div');
          right.className='flex gap-2';

          const approve = document.createElement('button');
          approve.className='bg-blue-600 text-white rounded px-3 py-1';
          approve.textContent='承認/再開';
          approve.onclick = async ()=>{ await api('/api/admin/approve/'+u.id,{method:'POST'}); await loadAll(); };
          right.appendChild(approve);

          const disable = document.createElement('button');
          disable.className='bg-amber-600 text-white rounded px-3 py-1';
          disable.textContent='停止';
          disable.onclick = async ()=>{ const reason=prompt('停止理由(任意)'); await api('/api/admin/disable/'+u.id,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({reason})}); await loadAll(); };
          right.appendChild(disable);

          const reset = document.createElement('button');
          reset.className='bg-slate-800 text-white rounded px-3 py-1';
          reset.textContent='PWリセット';
          reset.onclick = async ()=>{ const r=await api('/api/admin/reset-password/'+u.id,{method:'POST'}); alert('仮パスワード: '+r.tempPassword+'\\n(次回ログインで変更させてください)'); };
          right.appendChild(reset);

          const del = document.createElement('button');
          del.className='bg-red-600 text-white rounded px-3 py-1';
          del.textContent='削除';
          del.onclick = async ()=>{
            if(!confirm(u.name+'（'+u.loginId+'）のアカウントを完全に削除しますか？\\n学習記録もすべて削除されます。この操作は取り消せません。')) return;
            await api('/api/admin/delete/'+u.id,{method:'DELETE'});
            await loadAll();
          };
          right.appendChild(del);

          div.appendChild(right);
          wrap.appendChild(div);
        }
      }

      async function renderUsers(){
        const grade = document.getElementById('filterGrade').value.trim();
        const qs = new URLSearchParams();
        if(grade) qs.set('grade', grade);
        const u = await api('/api/admin/users?' + qs.toString());
        const wrap = document.getElementById('users');
        wrap.innerHTML='';
        if(!u.users.length){ wrap.textContent='該当なし'; return; }
        for(const x of u.users){
          const div = document.createElement('div');
          div.className='flex flex-col md:flex-row md:items-center md:justify-between border rounded p-2 gap-2';
          const left = document.createElement('div');
          left.textContent = x.grade + '年 / ' + x.name + '（' + x.loginId + '）' + (x.isActive? '' : ' [停止/未承認]');
          div.appendChild(left);
          const right = document.createElement('div');
          right.className='flex gap-2 flex-wrap';

          const gradeBtn = document.createElement('button');
          gradeBtn.className='bg-indigo-600 text-white rounded px-3 py-1';
          gradeBtn.textContent='学年変更';
          gradeBtn.onclick = async ()=>{
            const g = prompt(x.name + ' の学年を入力（1〜6）', x.grade);
            if(!g) return;
            const n = Number(g);
            if(!Number.isInteger(n)||n<1||n>6){ alert('1〜6の数字を入力してください'); return; }
            await api('/api/admin/user-grade',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({userId:x.id,grade:n})});
            await loadAll();
          };
          right.appendChild(gradeBtn);

          const toggle = document.createElement('button');
          toggle.className = x.isActive ? 'bg-amber-600 text-white rounded px-3 py-1' : 'bg-blue-600 text-white rounded px-3 py-1';
          toggle.textContent = x.isActive ? '停止' : '再開';
          toggle.onclick = async ()=>{
            if(x.isActive){ const reason=prompt('停止理由(任意)'); await api('/api/admin/disable/'+x.id,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({reason})}); }
            else { await api('/api/admin/approve/'+x.id,{method:'POST'}); }
            await loadAll();
          };
          right.appendChild(toggle);

          const reset = document.createElement('button');
          reset.className='bg-slate-800 text-white rounded px-3 py-1';
          reset.textContent='PWリセット';
          reset.onclick = async ()=>{ const r=await api('/api/admin/reset-password/'+x.id,{method:'POST'}); alert('仮パスワード: '+r.tempPassword+'\\n(次回ログインで変更させてください)'); };
          right.appendChild(reset);

          const del = document.createElement('button');
          del.className='bg-red-600 text-white rounded px-3 py-1';
          del.textContent='削除';
          del.onclick = async ()=>{
            if(!confirm(x.name+'（'+x.loginId+'）のアカウントを完全に削除しますか？\\n学習記録もすべて削除されます。この操作は取り消せません。')) return;
            await api('/api/admin/delete/'+x.id,{method:'DELETE'});
            await loadAll();
          };
          right.appendChild(del);

          div.appendChild(right);
          wrap.appendChild(div);
        }
      }

      async function renderResults(){
        const r = await api('/api/admin/results?limit=50');
        const rw = document.getElementById('results');
        rw.innerHTML='';
        if(!r.results.length){ rw.textContent='ログはまだありません'; return; }
        for(const x of r.results){
          const div = document.createElement('div');
          div.className='border rounded p-2';
          div.textContent = x.answeredAt + ' ' + x.grade + '年' + x.className + ' ' + x.name + '(' + x.loginId + ') unit=' + x.unit + ' q=' + (x.questionId ?? '') + ' correct=' + x.isCorrect + ' time=' + (x.timeMs ?? '');
          rw.appendChild(div);
        }
      }

      async function loadAll(){
        await renderPendingTeachers();
        await loadRankingSettings();
        await renderPending();
        await renderUsers();
        await renderResults();
      }

      document.getElementById('filterBtn').onclick = loadAll;
      document.getElementById('reloadBtn').onclick = loadAll;

      // auth check
      (async ()=>{
        const me = await fetch('/api/auth/me');
        const j = await me.json().catch(()=>({}));
        if(!j.user || j.user.role!=='admin'){ location.href='/login'; return; }
        loadAll();
      })();
    <\/script>
  </body></html>`));m.get("/teacher-signup",e=>e.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>教師 アカウント申請</title><script src="https://cdn.tailwindcss.com"><\/script></head>
  <body class="min-h-screen bg-emerald-50 p-4">
    <div class="max-w-md mx-auto bg-white rounded-xl shadow p-6">
      <h1 class="text-xl font-bold mb-1">教師 アカウント申請</h1>
      <p class="text-xs text-slate-500 mb-4">申請後、管理者が承認するとログインできるようになります。</p>
      <div class="space-y-3">
        <div>
          <label class="text-sm font-bold text-gray-700 mb-1 block">お名前</label>
          <input id="name" class="w-full border p-2 rounded" placeholder="例：田中 健一"/>
        </div>
        <div>
          <label class="text-sm font-bold text-gray-700 mb-1 block">学校名</label>
          <input id="school" class="w-full border p-2 rounded" placeholder="例：〇〇市立△△小学校"/>
        </div>
        <div>
          <label class="text-sm font-bold text-gray-700 mb-1 block">ログインID（自分で決める）</label>
          <input id="loginId" class="w-full border p-2 rounded" placeholder="半角英数字 3文字以上"/>
        </div>
        <div>
          <label class="text-sm font-bold text-gray-700 mb-1 block">パスワード</label>
          <input id="password" type="password" class="w-full border p-2 rounded" placeholder="6文字以上"/>
        </div>
        <button id="btn" class="w-full bg-emerald-600 text-white rounded p-2 font-bold">申請する</button>
        <p id="msg" class="text-sm"></p>
        <a class="text-sm text-blue-700 underline" href="/login">← ログインへ戻る</a>
      </div>
    </div>
    <script>
      const msg = document.getElementById('msg');
      document.getElementById('btn').onclick = async () => {
        msg.textContent=''; msg.className='text-sm';
        const name = document.getElementById('name').value.trim();
        const school = document.getElementById('school').value.trim();
        const loginId = document.getElementById('loginId').value.trim();
        const password = document.getElementById('password').value;
        if(!name){ msg.textContent='お名前を入力してください'; msg.className='text-sm text-red-600'; return; }
        if(!loginId || loginId.length < 3){ msg.textContent='ログインIDは3文字以上にしてください'; msg.className='text-sm text-red-600'; return; }
        if(!password || password.length < 6){ msg.textContent='パスワードは6文字以上にしてください'; msg.className='text-sm text-red-600'; return; }
        document.getElementById('btn').disabled = true;
        const r = await fetch('/api/auth/teacher-signup',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name,school,loginId,password})});
        const j = await r.json().catch(()=>({}));
        if(!r.ok){
          const errMap = { loginId_too_short:'IDは3文字以上', loginId_taken:'このIDはすでに使われています', password_too_short:'パスワードは6文字以上', name_required:'名前を入力してください' };
          msg.textContent = errMap[j.error] || (j.error || '申請に失敗しました');
          msg.className='text-sm text-red-600';
          document.getElementById('btn').disabled = false;
          return;
        }
        msg.textContent = '申請しました！管理者の承認をお待ちください。';
        msg.className='text-sm text-green-700';
        setTimeout(()=>{ location.href='/login'; }, 3000);
      };
    <\/script>
  </body></html>`));m.get("/teacher",e=>e.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>教師ダッシュボード</title><script src="https://cdn.tailwindcss.com"><\/script></head>
  <body class="min-h-screen bg-emerald-50 p-4">
    <div class="max-w-4xl mx-auto space-y-4">
      <div class="bg-white rounded-xl shadow p-4 flex items-center justify-between">
        <div>
          <h1 class="text-xl font-bold">教師ダッシュボード</h1>
          <p id="teacherInfo" class="text-sm text-slate-500"></p>
        </div>
        <div class="flex gap-2 items-center">
          <a href="/" class="text-sm px-3 py-1 rounded bg-emerald-100 hover:bg-emerald-200 text-emerald-700 font-bold transition">🎮 ゲーム画面へ</a>
          <button id="logout" class="text-sm px-3 py-1 rounded bg-gray-200 hover:bg-red-100 hover:text-red-700 text-gray-600 font-bold transition">ログアウト</button>
        </div>
      </div>

      <!-- クラス作成 -->
      <div class="bg-white rounded-xl shadow p-4">
        <h2 class="font-bold mb-3">クラス作成</h2>
        <div class="flex gap-2">
          <input id="newClassName" class="flex-1 border p-2 rounded" placeholder="クラス名（例：4年1組）"/>
          <button id="createClassBtn" class="bg-emerald-600 text-white rounded px-4 py-2 font-bold">作成</button>
        </div>
        <p id="createMsg" class="text-sm mt-1"></p>
      </div>

      <!-- タブナビ -->
      <div class="bg-white rounded-xl shadow p-1 flex gap-1">
        <button id="tabClasses" class="flex-1 py-2 rounded-lg text-sm font-bold bg-emerald-600 text-white" onclick="switchTab('classes')">📚 クラス管理</button>
        <button id="tabContact" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('contact')">📓 連絡帳</button>
        <button id="tabAnnouncements" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('announcements')">📢 おしらせ</button>
        <button id="tabHomework" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('homework')">📬 家庭学習</button>
        <button id="tabReports" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('reports')">📝 報告</button>
        <button id="tabAnalytics" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('analytics')">📊 学習分析</button>
      </div>

      <!-- クラス一覧タブ -->
      <div id="tabPaneClasses" class="space-y-4">
        <div id="classList" class="space-y-4"></div>
      </div>

      <!-- 学習分析タブ -->
      <div id="tabPaneAnalytics" class="hidden space-y-3">
        <div class="bg-white rounded-xl shadow p-4">
          <div class="flex gap-2 mb-3 flex-wrap items-center">
            <select id="analyticsClassFilter" class="border p-2 rounded text-sm bg-white">
              <option value="">クラスを選択...</option>
            </select>
            <button onclick="loadUnitAnalytics()" class="bg-purple-600 text-white rounded px-3 py-2 text-sm font-bold">📊 分析を表示</button>
            <span class="text-xs text-slate-400">※5問以上やった単元を表示します</span>
          </div>
          <div id="analyticsContent"></div>
        </div>
      </div>

      <!-- 家庭学習提出一覧タブ -->
      <div id="tabPaneHomework" class="hidden space-y-3">
        <!-- 先生メニュー（週の課題設定） -->
        <div class="bg-green-50 border border-green-200 rounded-xl p-4 space-y-3">
          <div class="font-bold text-sm text-green-800">📋 先生メニュー（今週の課題）</div>
          <div class="text-xs text-green-700 mb-2">クラス全体に出す漢字スキル・計算スキルのページ指示を設定します。生徒の家庭学習シートに表示されます。</div>
          <div class="flex gap-2 items-center flex-wrap">
            <select id="menuClassFilter" class="border p-2 rounded text-sm bg-white"></select>
            <span id="menuWeekLabel" class="text-xs text-slate-500 font-bold"></span>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <div>
              <label class="text-xs font-bold text-green-800">漢字スキル</label>
              <input id="menuKanjiPage" class="w-full border border-green-300 rounded-lg p-2 text-sm" placeholder="例：p.20まで"/>
            </div>
            <div>
              <label class="text-xs font-bold text-green-800">計算スキル</label>
              <input id="menuKeisanPage" class="w-full border border-green-300 rounded-lg p-2 text-sm" placeholder="例：p.15まで"/>
            </div>
            <div>
              <label class="text-xs font-bold text-green-800">その他</label>
              <input id="menuOtherTasks" class="w-full border border-green-300 rounded-lg p-2 text-sm" placeholder="例：音読3回"/>
            </div>
          </div>
          <div class="flex gap-2 items-center">
            <button onclick="saveWeeklyMenu()" class="bg-green-600 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:opacity-90">💾 保存</button>
            <span id="menuSaveMsg" class="text-xs text-green-700"></span>
          </div>
        </div>

        <!-- 生徒の今週の計画 -->
        <div class="bg-blue-50 border border-blue-200 rounded-xl p-3 space-y-3">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div class="font-bold text-sm text-blue-800">📝 生徒の今週の計画</div>
            <button onclick="loadStudentPlans()" class="bg-blue-600 text-white rounded-lg px-3 py-1 text-xs font-bold shadow hover:opacity-90">🔄 読み込む</button>
          </div>
          <div id="studentPlansList" class="space-y-2 text-sm text-slate-700">
            <p class="text-xs text-slate-400">「読み込む」を押すと表示されます</p>
          </div>
          <!-- 振り返り一括AI返却 -->
          <div id="bulkRefPanel" class="hidden border-t border-blue-200 pt-3 space-y-2">
            <div class="font-bold text-sm text-purple-800">🤖 振り返り一括コメント返却</div>
            <div class="flex items-center gap-2 flex-wrap">
              <span class="text-xs text-slate-500">①</span>
              <button onclick="copyWeeklyReflections()" class="bg-purple-500 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">📋 振り返りをコピー</button>
              <span class="text-xs text-slate-400">→ GeminiのGemに貼り付けてコメントを生成 →</span>
            </div>
            <div class="text-xs text-slate-500">② Geminiの返答をここに貼り付け</div>
            <textarea id="bulkRefComments" class="w-full border border-purple-300 rounded-lg p-2 text-xs" rows="3" placeholder='&#123;"comments":["よく頑張りました！","毎日続けてえらいね",...]}&#10;または番号付きリスト形式でもOK'></textarea>
            <button onclick="bulkReturnReflections()" class="bg-purple-600 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:opacity-90">✅ 貼り付けて一括返却</button>
            <div id="bulkRefMsg" class="text-xs text-purple-700"></div>
          </div>
        </div>

        <!-- Gemini連携パネル -->
        <div class="bg-amber-50 border border-amber-200 rounded-xl p-3 space-y-3">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div class="font-bold text-sm text-amber-800">🤖 Geminiで一括コメント返却</div>
            <button onclick="toggleGemPrompt()" class="text-xs text-amber-700 underline hover:no-underline">📝 Gem設定用プロンプトを表示</button>
          </div>
          <!-- Gemプロンプト表示エリア（初期非表示） -->
          <div id="gemPromptArea" class="hidden bg-white border border-amber-300 rounded-lg p-3 space-y-2">
            <div class="text-xs font-bold text-amber-800">Gemini の「Gem」に以下をシステムプロンプトとして設定してください</div>
            <pre id="gemPromptText" class="text-xs text-slate-700 whitespace-pre-wrap bg-slate-50 rounded p-2 border select-all">あなたは小学校の担任の先生の代わりにコメントを書くアシスタントです。

【ルール】
- 児童の「今日の振り返り」と「過去の振り返り」を読む
- 各児童への温かく具体的な先生コメントを30文字以内で考える
- その子の成長・課題・継続している努力を踏まえた個別最適な内容にする
- 必ずJSON形式だけで返答する（他のテキストは一切不要）

【返答形式】
{"comments":["コメント1","コメント2","コメント3",...]}

貼り付けられたテキストを読んだら、上記形式で即座に返答してください。</pre>
            <button onclick="copyGemPrompt()" class="bg-amber-500 text-white rounded px-3 py-1 text-xs font-bold">📋 このプロンプトをコピー</button>
            <div id="gemPromptCopyMsg" class="text-xs text-emerald-600"></div>
          </div>
          <div class="flex items-center gap-3 flex-wrap">
            <span class="text-xs text-amber-700 font-bold">① </span>
            <button onclick="copyReflections()" class="bg-amber-500 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:opacity-90">📋 振り返りをコピー</button>
            <span class="text-xs text-amber-600">→ GeminiのGemに貼り付けてコメントを生成 →</span>
          </div>
          <div class="space-y-1">
            <div class="text-xs font-bold text-amber-700">② Geminiの返答をここに貼り付け</div>
            <textarea id="aiPasteArea" rows="4" class="w-full border border-amber-300 rounded-lg p-2 text-xs bg-white focus:outline-none focus:border-amber-500" placeholder='&#123;"comments":["よく頑張りました！","毎日続けてえらいね",...]}&#10;または番号付きリスト形式でもOK'></textarea>
          </div>
          <button onclick="pasteAndBulkReturn()" class="w-full bg-emerald-600 text-white rounded-lg px-4 py-2.5 text-sm font-bold shadow hover:opacity-90">✅ ③ 貼り付けて一括返却</button>
          <div id="aiGenMsg" class="text-xs text-amber-700 min-h-[16px]"></div>
        </div>
        <div class="bg-white rounded-xl shadow p-4">
          <div class="flex gap-2 mb-3 flex-wrap items-center">
            <select id="hwClassFilter" class="border p-2 rounded text-sm bg-white"></select>
            <select id="hwStatusFilter" class="border p-2 rounded text-sm bg-white">
              <option value="">すべて</option>
              <option value="unreturned">未返却</option>
              <option value="returned">返却済み</option>
            </select>
            <button onclick="loadHomework()" class="bg-emerald-600 text-white rounded px-3 py-1 text-sm font-bold">絞り込み</button>
            <button onclick="loadHomework()" class="bg-slate-200 rounded px-3 py-1 text-sm">更新</button>
            <button onclick="bulkReturnNoComment()" class="ml-auto bg-blue-500 text-white rounded-lg px-4 py-1.5 text-sm font-bold shadow hover:opacity-90">✅ 未返却をまとめて返却（コメントなし）</button>
          </div>
          <div id="hwList" class="space-y-3 text-sm"></div>
        </div>
      </div>

      <!-- 連絡帳タブ -->
      <div id="tabPaneContact" class="hidden space-y-3">
        <div class="bg-white rounded-xl shadow p-4">
          <h3 class="font-bold mb-3">連絡帳を書く</h3>
          <div class="space-y-2">
            <select id="cnClassFilter" class="border p-2 rounded text-sm bg-white w-full"></select>
            <div class="flex gap-2">
              <div class="flex-1">
                <label class="text-xs font-bold text-gray-600">日付</label>
                <input id="cnDayKey" type="date" class="w-full border p-2 rounded text-sm"/>
              </div>
              <div class="flex-1">
                <label class="text-xs font-bold text-gray-600">報酬締切（任意）</label>
                <input id="cnDeadline" type="datetime-local" class="w-full border p-2 rounded text-sm"/>
              </div>
              <div class="w-20">
                <label class="text-xs font-bold text-gray-600">報酬コイン</label>
                <input id="cnCoins" type="number" value="5" min="0" max="100" class="w-full border p-2 rounded text-sm"/>
              </div>
            </div>
            <textarea id="cnBody" class="w-full border p-2 rounded text-sm" rows="4" placeholder="明日の持ち物や連絡事項を入力..."></textarea>
            <button onclick="sendContactNote()" class="bg-blue-500 hover:bg-blue-600 text-white rounded px-4 py-2 font-bold text-sm">📓 送信</button>
            <p id="cnMsg" class="text-sm"></p>
          </div>
        </div>
        <div class="bg-white rounded-xl shadow p-4">
          <h3 class="font-bold mb-3">送信済み連絡帳</h3>
          <div id="cnList" class="space-y-3 text-sm"></div>
        </div>
      </div>

      <!-- おしらせタブ -->
      <div id="tabPaneAnnouncements" class="hidden space-y-3">
        <div class="bg-white rounded-xl shadow p-4">
          <h3 class="font-bold mb-3">おしらせ作成</h3>
          <div class="space-y-2">
            <select id="annClassFilter" class="border p-2 rounded text-sm bg-white w-full">
              <option value="">全体（クラス関係なく全員）</option>
            </select>
            <input id="annTitle" class="w-full border p-2 rounded text-sm" placeholder="タイトル（例：イベント開催！）"/>
            <textarea id="annBody" class="w-full border p-2 rounded text-sm" rows="4" placeholder="内容を入力..."></textarea>
            <button id="annSendBtn" onclick="sendAnnouncement()" class="bg-orange-500 hover:bg-orange-600 text-white rounded px-4 py-2 font-bold text-sm">📢 送信</button>
            <p id="annMsg" class="text-sm"></p>
          </div>
        </div>
        <div class="bg-white rounded-xl shadow p-4">
          <h3 class="font-bold mb-3">送信済みおしらせ</h3>
          <div id="annList" class="space-y-3 text-sm"></div>
        </div>
      </div>

      <!-- 報告一覧タブ -->
      <div id="tabPaneReports" class="hidden space-y-3">
        <div class="bg-white rounded-xl shadow p-4">
          <div class="flex gap-2 mb-3 flex-wrap items-center">
            <select id="rptStatusFilter" class="border p-2 rounded text-sm bg-white">
              <option value="all">すべて</option>
              <option value="open">📬 受付中</option>
              <option value="in_progress">🔧 対応中</option>
              <option value="resolved">✅ 解決済み</option>
              <option value="closed">🗂️ 終了</option>
            </select>
            <button onclick="loadAdminReports()" class="bg-gray-600 text-white rounded px-3 py-1 text-sm font-bold">絞り込み</button>
            <span id="rptCount" class="text-xs text-gray-500 ml-auto"></span>
          </div>
          <div id="adminReportList" class="space-y-3 text-sm"></div>
        </div>
      </div>
    </div>

    <script>
      async function api(path, opt){
        const r = await fetch(path, opt);
        const j = await r.json().catch(()=>({}));
        if(!r.ok) throw new Error(j.error || 'error');
        return j;
      }

      function escH(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

      function switchTab(tab){
        ['classes','contact','announcements','homework','reports','analytics'].forEach(function(t){
          var pane = document.getElementById('tabPane' + t.charAt(0).toUpperCase() + t.slice(1));
          if(pane) pane.classList.toggle('hidden', tab !== t);
          var btn = document.getElementById('tab' + t.charAt(0).toUpperCase() + t.slice(1));
          if(btn) btn.className = tab===t
            ? 'flex-1 py-2 rounded-lg text-sm font-bold bg-emerald-600 text-white'
            : 'flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100';
        });
        if(tab === 'homework') { loadHomework(); loadWeeklyMenu(); }
        if(tab === 'reports') loadAdminReports();
        if(tab === 'announcements') loadAnnouncements();
        if(tab === 'contact') loadContactNotes();
      }

      async function loadUnitAnalytics(){
        const wrap = document.getElementById('analyticsContent');
        const classId = document.getElementById('analyticsClassFilter').value;
        if(!classId){ wrap.innerHTML='<p class="text-slate-400 text-sm">クラスを選択してください</p>'; return; }
        wrap.innerHTML='<p class="text-slate-400 text-sm">読み込み中... ⏳</p>';
        let data;
        try{ data = await api('/api/teacher/class/'+encodeURIComponent(classId)+'/unit-analytics'); }
        catch(e){ wrap.innerHTML='<p class="text-red-600 text-sm">読み込みエラー: '+escH(String(e.message||e))+'</p>'; return; }

        const students = data.students || [];
        const unitSummary = data.unitSummary || [];
        if(!students.length){ wrap.innerHTML='<p class="text-slate-400 text-sm">まだ生徒がいません</p>'; return; }

        // 教科別色
        const subjColor = {math:'bg-blue-100 text-blue-800', jp:'bg-pink-100 text-pink-800', soc:'bg-green-100 text-green-800', science:'bg-yellow-100 text-yellow-800'};
        const subjName = {math:'算数', jp:'国語', soc:'社会', science:'理科'};

        // ① クラス全体の教科別平均
        let html = '<div class="mb-4"><h3 class="font-bold text-slate-700 mb-2">📊 クラス全体 教科別正解率</h3>';
        html += '<div class="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-4">';
        ['math','jp','soc','science'].forEach(subj=>{
          const rows = students.filter(s=>s.bySubject[subj] && s.bySubject[subj].total >= 10);
          if(!rows.length){ html += '<div class="rounded-lg border p-3 text-center"><div class="text-xs text-slate-400">'+escH(subjName[subj]||subj)+'</div><div class="font-bold text-slate-400">データなし</div></div>'; return; }
          const avg = Math.round(rows.reduce((s,r)=>s+(r.bySubject[subj].acc||0),0)/rows.length);
          const color = avg>=80?'text-green-600':avg>=60?'text-yellow-600':'text-red-600';
          html += '<div class="rounded-lg border p-3 text-center"><div class="text-xs font-bold text-slate-500">'+escH(subjName[subj]||subj)+'</div>'
            +'<div class="text-2xl font-black '+color+'">'+avg+'%</div>'
            +'<div class="text-xs text-slate-400">'+rows.length+'人分</div></div>';
        });
        html += '</div></div>';

        // ② 単元別クラス平均（苦手順）
        if(unitSummary.length > 0){
          html += '<div class="mb-4"><h3 class="font-bold text-slate-700 mb-2">⚠️ 単元別クラス平均（苦手順）</h3>';
          html += '<div class="overflow-x-auto"><table class="w-full text-xs border-collapse">';
          html += '<thead><tr class="bg-slate-50"><th class="border px-2 py-1 text-left">教科</th><th class="border px-2 py-1 text-left">単元名</th><th class="border px-2 py-1 text-right">クラス平均</th><th class="border px-2 py-1 text-right">人数</th></tr></thead><tbody>';
          unitSummary.slice(0,15).forEach((u,i)=>{
            const avg = u.classAvg;
            const bar = avg!=null ? Math.round(avg) : null;
            const color = avg==null?'text-slate-400':avg>=80?'text-green-600':avg>=60?'text-yellow-600':'text-red-600 font-black';
            html += '<tr class="'+(i%2===0?'':'bg-slate-50')+'">'
              +'<td class="border px-2 py-1">'+escH(u.subject||'')+'</td>'
              +'<td class="border px-2 py-1 font-bold">'+escH(u.name||u.mode)+'</td>'
              +'<td class="border px-2 py-1 text-right '+color+'">'+(avg!=null?avg+'%':'−')+'</td>'
              +'<td class="border px-2 py-1 text-right">'+u.studentCount+'</td></tr>';
          });
          html += '</tbody></table></div></div>';
        }

        // ③ 生徒別一覧
        html += '<div><h3 class="font-bold text-slate-700 mb-2">👤 生徒別 学習状況</h3>';
        html += '<div class="overflow-x-auto"><table class="w-full text-xs border-collapse">';
        html += '<thead><tr class="bg-slate-50">'
          +'<th class="border px-2 py-1 text-left sticky left-0 bg-slate-50">名前</th>'
          +'<th class="border px-2 py-1 text-center">🔥連続</th>'
          +'<th class="border px-2 py-1 text-center">算数</th>'
          +'<th class="border px-2 py-1 text-center">国語</th>'
          +'<th class="border px-2 py-1 text-center">社会</th>'
          +'<th class="border px-2 py-1 text-center">理科</th>'
          +'</tr></thead><tbody>';
        students.forEach((s,i)=>{
          const row = '<tr class="'+(i%2===0?'':'bg-slate-50')+'">'
            +'<td class="border px-2 py-1 font-bold sticky left-0 '+(i%2===0?'bg-white':'bg-slate-50')+'">'+escH(s.name)+'</td>'
            +'<td class="border px-2 py-1 text-center">'+(s.learnStreak>0?'🔥'+s.learnStreak:'−')+'</td>'
            +['math','jp','soc','science'].map(subj=>{
              const d = s.bySubject[subj];
              if(!d||d.total<5) return '<td class="border px-2 py-1 text-center text-slate-300">−</td>';
              const c = d.acc>=80?'text-green-600':d.acc>=60?'text-yellow-600':'text-red-600 font-black';
              return '<td class="border px-2 py-1 text-center '+c+'">'+d.acc+'%<span class="text-slate-300 ml-0.5 text-[10px]">('+d.total+')</span></td>';
            }).join('')
            +'</tr>';
          html += row;
        });
        html += '</tbody></table></div>';
        html += '<p class="text-xs text-slate-400 mt-1">括弧内は解答数。5問未満は「−」表示。</p></div>';

        wrap.innerHTML = html;
      }

      document.getElementById('logout').onclick = async () => {
        await fetch('/api/auth/logout',{method:'POST'});
        location.href='/login';
      };

      document.getElementById('createClassBtn').onclick = async () => {
        const msg = document.getElementById('createMsg');
        msg.textContent=''; msg.className='text-sm';
        const name = document.getElementById('newClassName').value.trim();
        if(!name){ msg.textContent='クラス名を入力してください'; msg.className='text-sm text-red-600'; return; }
        try{
          await api('/api/teacher/class',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name})});
          document.getElementById('newClassName').value='';
          msg.textContent='クラスを作成しました';
          msg.className='text-sm text-green-700';
          await renderClasses();
        }catch(e){
          msg.textContent=String(e.message||e);
          msg.className='text-sm text-red-600';
        }
      };

      async function renderClasses(){
        const wrap = document.getElementById('classList');
        wrap.innerHTML='<p class="text-sm text-slate-400">読み込み中...</p>';
        let data;
        try{ data = await api('/api/teacher/classes'); }
        catch(e){ wrap.innerHTML='<p class="text-sm text-red-600">読み込みエラー</p>'; return; }
        wrap.innerHTML='';
        if(!data.classes.length){ wrap.innerHTML='<p class="text-sm text-slate-400 bg-white rounded-xl shadow p-4">クラスはまだありません。上から作成してください。</p>'; return; }

        // クラスフィルター選択肢を更新
        const sel = document.getElementById('hwClassFilter');
        sel.innerHTML = '<option value="">全クラス</option>';
        data.classes.forEach(c => { sel.innerHTML += '<option value="'+escH(c.id)+'">'+escH(c.name)+'</option>'; });
        // 学習分析タブのクラスフィルターも更新
        const analyticsSel = document.getElementById('analyticsClassFilter');
        if(analyticsSel){
          analyticsSel.innerHTML = '<option value="">クラスを選択...</option>';
          data.classes.forEach(c => { analyticsSel.innerHTML += '<option value="'+escH(c.id)+'">'+escH(c.name)+'</option>'; });
        }

        for(const cls of data.classes){
          const card = document.createElement('div');
          card.className='bg-white rounded-xl shadow p-4';
          const header = document.createElement('div');
          header.className='flex items-center justify-between mb-3';
          const title = document.createElement('div');
          title.innerHTML = '<span class="font-bold text-lg">' + escH(cls.name) + '</span>'
            + ' <span class="text-sm text-slate-400 ml-2 select-all font-mono bg-slate-100 px-2 py-0.5 rounded">参加コード: ' + escH(cls.classCode) + '</span>'
            + ' <span class="text-xs text-slate-400 ml-2">生徒数: ' + cls.memberCount + '人</span>';
          header.appendChild(title);
          const btnGroup = document.createElement('div');
          btnGroup.className='flex items-center gap-2';
          // ランキング参加トグルボタン
          const rankBtn = document.createElement('button');
          const isEnabled = !!cls.rankingEnabled;
          rankBtn.className = isEnabled
            ? 'text-xs px-2 py-1 rounded font-bold bg-emerald-100 text-emerald-700 border border-emerald-300 hover:bg-emerald-200'
            : 'text-xs px-2 py-1 rounded font-bold bg-slate-100 text-slate-500 border border-slate-300 hover:bg-slate-200';
          rankBtn.textContent = isEnabled ? '🏆 ランキング参加中' : '🏆 ランキング不参加';
          rankBtn.title = isEnabled ? 'クリックでランキング参加を停止' : 'クリックでランキング参加を許可';
          rankBtn.onclick = async ()=>{
            const newVal = !rankBtn.dataset.enabled;
            rankBtn.dataset.enabled = newVal ? '1' : '';
            try{
              await api('/api/teacher/class/'+cls.id+'/ranking-toggle',{
                method:'PUT', headers:{'content-type':'application/json'},
                body: JSON.stringify({enabled: newVal})
              });
              rankBtn.className = newVal
                ? 'text-xs px-2 py-1 rounded font-bold bg-emerald-100 text-emerald-700 border border-emerald-300 hover:bg-emerald-200'
                : 'text-xs px-2 py-1 rounded font-bold bg-slate-100 text-slate-500 border border-slate-300 hover:bg-slate-200';
              rankBtn.textContent = newVal ? '🏆 ランキング参加中' : '🏆 ランキング不参加';
              rankBtn.title = newVal ? 'クリックでランキング参加を停止' : 'クリックでランキング参加を許可';
            } catch(e){ alert(String(e.message||e)); }
          };
          rankBtn.dataset.enabled = isEnabled ? '1' : '';
          btnGroup.appendChild(rankBtn);
          // 家庭学習ON/OFFトグルボタン
          const hwBtn = document.createElement('button');
          const hwEnabled = cls.homeworkEnabled !== 0 && cls.homeworkEnabled !== '0';
          hwBtn.className = hwEnabled
            ? 'text-xs px-2 py-1 rounded font-bold bg-blue-100 text-blue-700 border border-blue-300 hover:bg-blue-200'
            : 'text-xs px-2 py-1 rounded font-bold bg-slate-100 text-slate-500 border border-slate-300 hover:bg-slate-200';
          hwBtn.textContent = hwEnabled ? '📝 家庭学習ON' : '📝 家庭学習OFF';
          hwBtn.title = hwEnabled ? 'クリックで家庭学習を非表示にする' : 'クリックで家庭学習を表示する';
          hwBtn.dataset.enabled = hwEnabled ? '1' : '';
          hwBtn.onclick = async ()=>{
            const newVal = !hwBtn.dataset.enabled;
            hwBtn.dataset.enabled = newVal ? '1' : '';
            try{
              await api('/api/teacher/class/'+cls.id+'/homework-toggle',{
                method:'PUT', headers:{'content-type':'application/json'},
                body: JSON.stringify({enabled: newVal})
              });
              hwBtn.className = newVal
                ? 'text-xs px-2 py-1 rounded font-bold bg-blue-100 text-blue-700 border border-blue-300 hover:bg-blue-200'
                : 'text-xs px-2 py-1 rounded font-bold bg-slate-100 text-slate-500 border border-slate-300 hover:bg-slate-200';
              hwBtn.textContent = newVal ? '📝 家庭学習ON' : '📝 家庭学習OFF';
              hwBtn.title = newVal ? 'クリックで家庭学習を非表示にする' : 'クリックで家庭学習を表示する';
            } catch(e){ alert(String(e.message||e)); }
          };
          btnGroup.appendChild(hwBtn);
          // 連絡帳ON/OFFトグルボタン
          const ctBtn = document.createElement('button');
          const ctEnabled = cls.contactEnabled !== 0 && cls.contactEnabled !== '0';
          ctBtn.className = ctEnabled
            ? 'text-xs px-2 py-1 rounded font-bold bg-cyan-100 text-cyan-700 border border-cyan-300 hover:bg-cyan-200'
            : 'text-xs px-2 py-1 rounded font-bold bg-slate-100 text-slate-500 border border-slate-300 hover:bg-slate-200';
          ctBtn.textContent = ctEnabled ? '📓 連絡帳ON' : '📓 連絡帳OFF';
          ctBtn.title = ctEnabled ? 'クリックで連絡帳を非表示にする' : 'クリックで連絡帳を表示する';
          ctBtn.dataset.enabled = ctEnabled ? '1' : '';
          ctBtn.onclick = async ()=>{
            const newVal = !ctBtn.dataset.enabled;
            ctBtn.dataset.enabled = newVal ? '1' : '';
            try{
              await api('/api/teacher/class/'+cls.id+'/contact-toggle',{
                method:'PUT', headers:{'content-type':'application/json'},
                body: JSON.stringify({enabled: newVal})
              });
              ctBtn.className = newVal
                ? 'text-xs px-2 py-1 rounded font-bold bg-cyan-100 text-cyan-700 border border-cyan-300 hover:bg-cyan-200'
                : 'text-xs px-2 py-1 rounded font-bold bg-slate-100 text-slate-500 border border-slate-300 hover:bg-slate-200';
              ctBtn.textContent = newVal ? '📓 連絡帳ON' : '📓 連絡帳OFF';
              ctBtn.title = newVal ? 'クリックで連絡帳を非表示にする' : 'クリックで連絡帳を表示する';
            } catch(e){ alert(String(e.message||e)); }
          };
          btnGroup.appendChild(ctBtn);
          const delBtn = document.createElement('button');
          delBtn.className='text-xs text-red-500 hover:text-red-700 border border-red-200 rounded px-2 py-1';
          delBtn.textContent='削除';
          delBtn.onclick = async ()=>{
            if(!confirm(cls.name + ' を削除しますか？\\n生徒のクラス参加も解除されます。')){ return; }
            try{ await api('/api/teacher/class/'+cls.id,{method:'DELETE'}); await renderClasses(); }
            catch(e){ alert(String(e.message||e)); }
          };
          btnGroup.appendChild(delBtn);
          header.appendChild(btnGroup);
          card.appendChild(header);

          const rankDiv = document.createElement('div');
          rankDiv.innerHTML='<p class="text-xs text-slate-400">ランキングを読み込み中...</p>';
          card.appendChild(rankDiv);
          wrap.appendChild(card);

          api('/api/teacher/class/'+cls.id+'/ranking').then(rd=>{
            if(!rd.members.length){ rankDiv.innerHTML='<p class="text-xs text-slate-400">まだ生徒がいません</p>'; return; }
            let html = '<div class="overflow-x-auto"><table class="w-full text-xs border-collapse"><thead><tr class="bg-slate-50">'
              + '<th class="border px-2 py-1 text-left">順位</th><th class="border px-2 py-1 text-left">名前</th>'
              + '<th class="border px-2 py-1 text-right">総合Lv</th><th class="border px-2 py-1 text-right">モンスター数</th><th class="border px-2 py-1 text-right">正解数</th>'
              + '</tr></thead><tbody>';
            rd.members.forEach((m,i)=>{
              html += '<tr class="'+(i%2===0?'bg-white':'bg-slate-50')+'">'
                +'<td class="border px-2 py-1 text-center font-bold">'+(i+1)+'</td>'
                +'<td class="border px-2 py-1">'+escH(m.displayName||m.userId)+'</td>'
                +'<td class="border px-2 py-1 text-right">'+(m.totalLevel||0)+'</td>'
                +'<td class="border px-2 py-1 text-right">'+(m.monsterCount||0)+'</td>'
                +'<td class="border px-2 py-1 text-right">'+(m.correctCount||0)+'</td></tr>';
            });
            html += '</tbody></table></div>';
            rankDiv.innerHTML = html;
          }).catch(()=>{ rankDiv.innerHTML='<p class="text-xs text-red-400">ランキング取得エラー</p>'; });
        }
      }

      // 家庭学習提出一覧
      // ISO週番号キーを返す
      function getWeekKeyLocal(date){
        var d = date || new Date();
        var tmp = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
        tmp.setUTCDate(tmp.getUTCDate() + 4 - (tmp.getUTCDay() || 7));
        var yearStart = new Date(Date.UTC(tmp.getUTCFullYear(), 0, 1));
        var weekNo = Math.ceil((((tmp.getTime() - yearStart.getTime()) / 86400000) + 1) / 7);
        return tmp.getUTCFullYear() + '-W' + String(weekNo).padStart(2, '0');
      }

      async function loadWeeklyMenu(){
        try{
          var classFilter = document.getElementById('menuClassFilter');
          var weekLabel = document.getElementById('menuWeekLabel');
          var wk = getWeekKeyLocal(new Date());
          if(weekLabel) weekLabel.textContent = '今週: ' + wk;

          // クラス一覧をメニューフィルターにも反映
          if(classFilter && classFilter.options.length <= 1){
            var cdata = await api('/api/teacher/classes');
            var classes = (cdata && cdata.classes) || [];
            classFilter.innerHTML = '';
            classes.forEach(function(cls){
              var opt = document.createElement('option');
              opt.value = cls.id;
              opt.textContent = cls.name;
              classFilter.appendChild(opt);
            });
          }

          var classId = classFilter ? classFilter.value : '';
          if(!classId) return;

          var data = await api('/api/teacher/class/' + encodeURIComponent(classId) + '/weekly-menu?weekKey=' + encodeURIComponent(wk));
          var menu = (data && data.menu) || {};
          document.getElementById('menuKanjiPage').value = menu.kanji_page || menu.kanjiPage || '';
          document.getElementById('menuKeisanPage').value = menu.keisan_page || menu.keisanPage || '';
          document.getElementById('menuOtherTasks').value = menu.other_tasks || menu.otherTasks || '';
        }catch(e){ console.warn('loadWeeklyMenu error:', e); }
      }

      async function saveWeeklyMenu(){
        var msg = document.getElementById('menuSaveMsg');
        try{
          var classId = document.getElementById('menuClassFilter').value;
          if(!classId){ if(msg) msg.textContent = 'クラスを選択してください'; return; }
          var wk = getWeekKeyLocal(new Date());
          var body = {
            weekKey: wk,
            kanjiPage: document.getElementById('menuKanjiPage').value || '',
            keisanPage: document.getElementById('menuKeisanPage').value || '',
            otherTasks: document.getElementById('menuOtherTasks').value || '',
          };
          await api('/api/teacher/class/' + encodeURIComponent(classId) + '/weekly-menu', {
            method: 'POST',
            headers: {'content-type':'application/json'},
            body: JSON.stringify(body),
          });
          if(msg) msg.textContent = '✅ 保存しました（' + wk + '）';
          setTimeout(function(){ if(msg) msg.textContent = ''; }, 3000);
        }catch(e){
          if(msg) msg.textContent = '⚠️ 保存に失敗しました';
        }
      }

      async function loadStudentPlans(){
        const wrap = document.getElementById('studentPlansList');
        if(!wrap) return;
        wrap.innerHTML='<p class="text-slate-400">読み込み中...</p>';
        const classId = document.getElementById('hwClassFilter')?.value || '';
        const wk = getWeekKeyLocal();
        let qs = '?weekKey='+encodeURIComponent(wk);
        if(classId) qs += '&classId='+encodeURIComponent(classId);
        try{
          const data = await api('/api/teacher/weekly-plans'+qs);
          const plans = data.plans || [];
          if(!plans.length){ wrap.innerHTML='<p class="text-slate-400">まだ計画が提出されていません</p>'; return; }
          const dayLabels = ['月','火','水','木','金'];
          wrap.innerHTML = '';
          window._weeklyRefData = []; // 一括用データ
          for(const p of plans){
            let parsed = {};
            try{ parsed = JSON.parse(p.plansJson || '{}'); }catch(_){}
            const modified = parsed._modified || {};
            const card = document.createElement('div');
            card.className = 'border rounded-lg p-2 bg-white space-y-1';

            // ヘッダー + 承認バッジ
            const approvedBadge = p.planApproved
              ? '<span class="bg-green-100 text-green-700 text-xs px-1.5 rounded font-bold">✅ 承認済(+300coin+5かけら)</span>'
              : '';
            let html = '<div class="flex items-center justify-between flex-wrap gap-1">'
              + '<div class="font-bold text-sm">'+escH(p.studentName)+' <span class="text-xs text-slate-400 font-normal">'+escH(p.grade+'年'+p.className)+'</span> '+approvedBadge+'</div>'
              + '<div class="text-[10px] text-slate-400">'+new Date(p.updatedAt).toLocaleString('ja-JP',{month:'numeric',day:'numeric',hour:'2-digit',minute:'2-digit'})+'</div>'
              + '</div>';

            // 5曜日グリッド
            html += '<div class="grid grid-cols-5 gap-1 text-xs">';
            const keys = Object.keys(parsed).filter(k => k !== '_modified');
            for(let i = 0; i < 5; i++){
              const k = keys[i] || '';
              const val = k ? parsed[k] : '';
              const planText = typeof val === 'object' ? (val.free || '') : (val || '');
              const isMod = k && modified[k];
              html += '<div class="border rounded p-1 '+(isMod ? 'bg-orange-50 border-orange-200' : 'bg-slate-50 border-slate-200')+'">'
                + '<div class="font-bold text-center '+(i===0?'text-green-700':i===4?'text-orange-700':'text-slate-600')+'">'+dayLabels[i]+'</div>'
                + '<div class="text-[11px] text-slate-700 break-words">'+(planText ? escH(planText) : '<span class="text-slate-300">—</span>')+'</div>'
                + (isMod ? '<div class="text-[9px] text-orange-500 text-center">✎変更</div>' : '')
                + '</div>';
            }
            html += '</div>';

            // 計画承認ボタン（未承認の場合のみ）
            if(!p.planApproved){
              html += '<div class="flex justify-end"><button class="bg-green-600 text-white rounded px-3 py-1 text-xs font-bold hover:opacity-90" onclick="approvePlan('+p.id+',this)">✅ 計画OK (+300coin+5かけら)</button></div>';
            }

            // 金曜の振り返り
            const friKey = keys[4] || '';
            const friVal = friKey ? parsed[friKey] : '';
            const reflection = typeof friVal === 'object' ? (friVal.reflection || '') : '';
            if(reflection){
              html += '<div class="text-xs mt-1 p-1.5 bg-orange-50 rounded border border-orange-200 space-y-1">'
                + '<div><span class="font-bold text-orange-700">🔄 振り返り：</span>'+escH(reflection)+'</div>';
              if(p.reflectionReturnedAt){
                html += '<div class="text-emerald-700 bg-emerald-50 rounded p-1 border border-emerald-200">💬 '+escH(p.reflectionComment)+' <span class="text-[10px] text-slate-400">(返却済+300coin+5かけら)</span></div>';
              } else {
                window._weeklyRefData.push({ id: p.id, name: p.studentName, reflection: reflection });
                html += '<div class="flex items-center gap-1">'
                  + '<textarea id="refComment_'+p.id+'" class="flex-1 border rounded p-1.5 text-xs" rows="1" placeholder="コメント（一括AIも可）"></textarea>'
                  + '<button class="bg-orange-500 text-white rounded px-2 py-1 text-[11px] font-bold hover:opacity-90 shrink-0" onclick="returnReflection('+p.id+',this)">返却</button>'
                  + '</div>';
              }
              html += '</div>';
            }

            card.innerHTML = html;
            wrap.appendChild(card);
          }
          // 一括パネル表示
          const bulkPanel = document.getElementById('bulkRefPanel');
          if(bulkPanel) bulkPanel.classList.toggle('hidden', window._weeklyRefData.length === 0);
        }catch(e){
          wrap.innerHTML='<p class="text-red-600">読み込みエラー</p>';
        }
      }

      function copyWeeklyReflections(){
        const data = window._weeklyRefData || [];
        if(!data.length){ alert('未返却の振り返りがありません'); return; }
        let text = '以下は小学生の今週の家庭学習の振り返りです。それぞれに温かく励ましつつ具体的に褒める短いコメント（1〜2文）を書いてください。
JSON形式 ' + '{"comments":["コメント1","コメント2",...]}' + ' で返してください。

';
        data.forEach(function(d, i){
          text += (i+1) + '. ' + d.name + '「' + d.reflection + '」
';
        });
        navigator.clipboard.writeText(text).then(function(){
          alert('📋 '+data.length+'人分の振り返りをコピーしました！
Gemini等に貼り付けてコメントを生成してください。');
        }).catch(function(){
          prompt('コピーに失敗しました。手動でコピーしてください:', text);
        });
      }

      async function bulkReturnReflections(){
        const data = window._weeklyRefData || [];
        if(!data.length){ alert('未返却の振り返りがありません'); return; }
        const raw = (document.getElementById('bulkRefComments') || {}).value || '';
        const msg = document.getElementById('bulkRefMsg');

        // パース：JSON or 番号付きリスト
        let comments = [];
        try{
          const parsed = JSON.parse(raw);
          comments = parsed.comments || parsed;
        }catch(_){
          // 番号付きリスト形式をパース
          comments = raw.split(/
/).map(function(line){
            return line.replace(/^d+[.)：:]s*/, '').trim();
          }).filter(function(l){ return l.length > 0; });
        }

        if(comments.length < data.length){
          if(msg) msg.textContent = '⚠️ コメント数('+comments.length+')が振り返り数('+data.length+')より少ないです';
          return;
        }

        if(msg) msg.textContent = '返却中...';
        let ok = 0, fail = 0;
        for(let i = 0; i < data.length; i++){
          try{
            await api('/api/teacher/weekly-plan/'+data[i].id+'/return-reflection', {
              method:'POST', headers:{'content-type':'application/json'},
              body: JSON.stringify({ comment: comments[i] || '' })
            });
            ok++;
          }catch(e){ fail++; }
        }
        if(msg) msg.textContent = '✅ '+ok+'人に返却完了' + (fail ? ' ('+fail+'人失敗)' : '');
        await loadStudentPlans();
      }

      async function approvePlan(planId, btn){
        btn.disabled = true;
        try{
          await api('/api/teacher/weekly-plan/'+planId+'/approve', {method:'POST',headers:{'content-type':'application/json'},body:'{}'});
          await loadStudentPlans();
        }catch(e){ btn.disabled=false; alert('エラー: '+String(e.message||e)); }
      }

      async function returnReflection(planId, btn){
        btn.disabled = true;
        const comment = (document.getElementById('refComment_'+planId)||{}).value || '';
        if(!comment.trim()){ alert('コメントを入力してください'); btn.disabled=false; return; }
        try{
          await api('/api/teacher/weekly-plan/'+planId+'/return-reflection', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({comment})});
          await loadStudentPlans();
        }catch(e){ btn.disabled=false; alert('エラー: '+String(e.message||e)); }
      }

      async function loadHomework(){
        const wrap = document.getElementById('hwList');
        wrap.innerHTML='<p class="text-slate-400">読み込み中...</p>';
        const classId = document.getElementById('hwClassFilter').value;
        const status = document.getElementById('hwStatusFilter').value;
        let qs = classId ? '?classId='+encodeURIComponent(classId) : '';
        let data;
        try{ data = await api('/api/teacher/homework'+qs); }
        catch(e){ wrap.innerHTML='<p class="text-red-600">読み込みエラー</p>'; return; }
        let list = data.submissions || [];
        if(status === 'unreturned') list = list.filter(s => !s.returnedAt);
        if(status === 'returned')   list = list.filter(s => !!s.returnedAt);
        if(!list.length){ wrap.innerHTML='<p class="text-slate-400">提出がありません</p>'; return; }
        wrap.innerHTML='';
        for(const s of list){
          const card = document.createElement('div');
          const returned = !!s.returnedAt;
          card.className='border rounded-xl p-3 space-y-2 ' + (returned ? 'bg-slate-50' : 'bg-yellow-50 border-yellow-300');
          card.dataset.hwId = s.id;
          card.dataset.hwUserId = s.userId||'';
          card.dataset.hwName = s.studentName||'';
          card.dataset.hwDayKey = s.dayKey||'';
          const weatherEmoji = {sun:'☀️', cloud:'☁️', rain:'🌧️'}[s.endWeather] || '😊';
          const physicalBadge = s.hasPhysical
            ? '<span class="bg-yellow-200 text-yellow-800 text-xs px-1 rounded">成果物あり⭐</span>'
            : '';
          const returnedBadge = returned
            ? '<span class="bg-green-100 text-green-700 text-xs px-1 rounded">返却済み</span>'
            : '<span class="bg-red-100 text-red-600 text-xs px-1 rounded font-bold">未返却</span>';

          card.innerHTML = '<div class="flex items-center justify-between flex-wrap gap-1">'
            + '<div class="font-bold">' + escH(s.studentName||'') + ' <span class="text-xs text-slate-400 font-normal">'+escH(s.grade+'年'+s.className)+'</span></div>'
            + '<div class="flex gap-1 items-center text-xs">' + returnedBadge + physicalBadge + '<span class="text-slate-400">'+escH(s.dayKey)+'</span></div>'
            + '</div>'
            + '<div class="text-xs space-y-0.5 text-slate-700">'
            + '<div><b>今日やること：</b>'+escH(s.todo)+'</div>'
            + '<div><b>なんで：</b>'+escH(s.why)+'</div>'
            + '<div><b>めあて：</b>'+escH(s.aim)+'</div>'
            + '<div><b>'+s.minutes+'分</b> 学習 / 学びの天気: '+weatherEmoji+'</div>'
            + (s.weatherReason ? '<div><b>天気の理由：</b>'+escH(s.weatherReason)+'</div>' : '')
            + (s.nextImprove  ? '<div><b>次にするには：</b>'+escH(s.nextImprove)+'</div>' : '')
            + (s.selfStudyPlan ? '<div class="mt-1 p-1.5 bg-blue-50 rounded border border-blue-200"><b>📖 自主学習：</b>'+escH(s.selfStudyPlan)+'</div>' : '')
            + (s.weeklyPlan ? '<div class="mt-1 p-1.5 bg-purple-50 rounded border border-purple-200"><b>📝 週の計画：</b>'+escH(s.weeklyPlan)+'</div>' : '')
            + (s.weeklyReflection ? '<div class="mt-1 p-1.5 bg-amber-50 rounded border border-amber-200"><b>🔄 週の振り返り：</b>'+escH(s.weeklyReflection)+'</div>' : '')
            + '</div>';

          if(!returned){
            // 返却フォーム
            const formDiv = document.createElement('div');
            formDiv.className='space-y-2 border-t pt-2';
            formDiv.innerHTML = '<div class="text-xs font-bold text-slate-600">先生コメント（任意）</div>'
              + '<textarea class="w-full border rounded p-2 text-xs" rows="2" placeholder="よく頑張りました！など" id="hwComment_'+s.id+'"></textarea>'
              + '<label class="flex items-center gap-2 text-xs cursor-pointer"><input type="checkbox" id="hwPhysical_'+s.id+'"/> <span>成果物（ノートなど）も提出あり ⭐</span></label>'
              + '<button class="bg-emerald-600 text-white rounded px-3 py-1 text-xs font-bold" onclick="returnHomework(&#39;'+escH(s.id)+'&#39;, this)">✅ 返却する</button>';
            card.appendChild(formDiv);
          } else if(s.teacherComment) {
            const commentDiv = document.createElement('div');
            commentDiv.className='text-xs text-emerald-700 bg-emerald-50 rounded p-2 border border-emerald-200';
            commentDiv.textContent = '💬 ' + s.teacherComment;
            card.appendChild(commentDiv);
          }
          wrap.appendChild(card);
        }
      }

      async function returnHomework(id, btn){
        btn.disabled = true;
        const comment = (document.getElementById('hwComment_'+id)||{}).value || '';
        const hasPhysical = (document.getElementById('hwPhysical_'+id)||{}).checked || false;
        try{
          await api('/api/teacher/homework/'+id+'/return',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({comment,hasPhysical})});
          await loadHomework();
        }catch(e){
          btn.disabled=false;
          alert('エラー: '+String(e.message||e));
        }
      }

      async function copyReflections(){
        const msgEl = document.getElementById('aiGenMsg');
        msgEl.textContent='⏳ 履歴を取得中...';

        // 全提出データを取得（返却済み含む）
        const classId = document.getElementById('hwClassFilter').value;
        var qs = classId ? '?classId='+encodeURIComponent(classId) : '';
        var allData;
        try{ allData = await api('/api/teacher/homework'+qs); }
        catch(e){ msgEl.textContent='❌ データ取得失敗: '+String(e.message||e); return; }
        var all = allData.submissions||[];

        // userId → 過去の返却済み提出（最新3件）にグループ化
        var history = {};
        for(var i=0;i<all.length;i++){
          var s = all[i];
          if(!s.returnedAt) continue; // 返却済みのみ過去履歴に使う
          if(!history[s.userId]) history[s.userId]=[];
          history[s.userId].push(s);
        }
        // 各ユーザーの履歴を日付降順にソートして最新3件に絞る
        Object.keys(history).forEach(function(uid){
          history[uid].sort(function(a,b){ return (b.submittedAt||0)-(a.submittedAt||0); });
          history[uid]=history[uid].slice(0,5);
        });

        // 未返却カードを収集
        var cards = document.querySelectorAll('#hwList [data-hw-id]');
        var items = [];
        var idx = 1;
        for(var ci=0;ci<cards.length;ci++){
          var card = cards[ci];
          var id = card.dataset.hwId;
          if(!document.getElementById('hwComment_'+id)) continue;
          // 対応する提出データをallから探す
          var sub = null;
          for(var si=0;si<all.length;si++){ if(all[si].id===id){ sub=all[si]; break; } }
          if(!sub) continue;
          var w = {sun:'☀晴れ',cloud:'☁くもり',rain:'☂あめ'}[sub.endWeather]||'';
          var today = idx+'. 【'+sub.studentName+'】（'+sub.dayKey+'）';
          today += '\\n  やったこと: '+(sub.todo||'―');
          today += '\\n  なんで: '+(sub.why||'―');
          today += '\\n  めあて: '+(sub.aim||'―');
          today += '\\n  学習時間: '+(sub.minutes||0)+'分 / 学びの天気: '+w;
          today += '\\n  振り返り: '+(sub.weatherReason||'―');
          today += '\\n  次どうする: '+(sub.nextImprove||'―');
          var hist = history[sub.userId]||[];
          if(hist.length){
            today += '\\n  ── 過去の振り返り（参考）──';
            for(var hi=0;hi<hist.length;hi++){
              var h = hist[hi];
              var hw = {sun:'☀',cloud:'☁',rain:'☂'}[h.endWeather]||'';
              today += '\\n    ['+h.dayKey+']';
              today += '\\n      やること: '+(h.todo||'―');
              today += '\\n      理由: '+(h.why||'―');
              today += '\\n      めあて: '+(h.aim||'―');
              today += '\\n      時間: '+(h.minutes||0)+'分';
              today += '\\n      天気: '+hw+' 「'+(h.weatherReason||'―')+'」';
              today += '\\n      次どうする: '+(h.nextImprove||'―');
            }
          }
          items.push(today);
          idx++;
        }
        if(!items.length){ msgEl.textContent='未返却の提出がありません'; return; }

        var nl = String.fromCharCode(10);
        var header = '小学校の担任の先生として、以下の児童の家庭学習の振り返りを読み、各児童への個別最適なコメントを30文字以内で考えてください。'+nl
          +'過去の振り返りも参考にして、その子の成長や課題に合わせてください。'+nl
          +'必ずJSON形式だけで返答してください（番号は不要）：{"comments":["コメント1","コメント2",...]}'+nl+nl
          +'=== 児童の振り返り ==='+nl;
        var text = header + items.join(nl+nl);

        navigator.clipboard.writeText(text).then(function(){
          msgEl.textContent='✅ '+items.length+'件（過去履歴付き）をコピーしました！GeminiのGemに貼り付けてください。';
        }).catch(function(){
          var ta = document.createElement('textarea');
          ta.value=text; ta.style.position='fixed'; ta.style.opacity='0';
          document.body.appendChild(ta); ta.select(); document.execCommand('copy');
          document.body.removeChild(ta);
          msgEl.textContent='✅ '+items.length+'件コピーしました！';
        });
      }

      function toggleGemPrompt(){
        var el = document.getElementById('gemPromptArea');
        if(el) el.classList.toggle('hidden');
      }
      function copyGemPrompt(){
        var el = document.getElementById('gemPromptText');
        var msg = document.getElementById('gemPromptCopyMsg');
        if(!el) return;
        navigator.clipboard.writeText(el.textContent||'').then(function(){
          msg.textContent='✅ コピーしました！Geminiの「Gem」→「システムプロンプト」に貼り付けてください';
        }).catch(function(){
          var ta=document.createElement('textarea');
          ta.value=el.textContent||''; ta.style.position='fixed'; ta.style.opacity='0';
          document.body.appendChild(ta); ta.select(); document.execCommand('copy');
          document.body.removeChild(ta);
          msg.textContent='✅ コピーしました！';
        });
      }

      async function bulkReturnNoComment(){
        const cards = document.querySelectorAll('#hwList [data-hw-id]');
        const targets = [];
        for(var i=0;i<cards.length;i++){
          var id = cards[i].dataset.hwId;
          var commentEl = document.getElementById('hwComment_'+id);
          if(!commentEl) continue; // 返却済みはスキップ
          var comment = commentEl.value||'';
          targets.push({id:id, comment:comment});
        }
        if(!targets.length){ alert('未返却の提出がありません'); return; }
        if(!confirm(targets.length+'件まとめて返却します。よろしいですか？')) return;
        var ok=0, ng=0;
        for(var ti=0;ti<targets.length;ti++){
          try{
            await api('/api/teacher/homework/'+targets[ti].id+'/return',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({comment:targets[ti].comment,hasPhysical:false})});
            ok++;
          }catch(e){ ng++; }
        }
        alert((ng===0?'✅ ':('⚠️ '+ng+'件失敗 / '))+ok+'件返却しました！');
        await loadHomework();
      }

      async function pasteAndBulkReturn(){
        const msgEl = document.getElementById('aiGenMsg');
        const raw = (document.getElementById('aiPasteArea')||{value:''}).value||'';
        if(!raw.trim()){ msgEl.textContent='⚠️ Geminiのコメントをテキストエリアにペーストしてからボタンを押してください'; return; }

        // コメント解析（JSON形式 or 番号付きリスト）
        let comments = [];
        try{
          const start = raw.indexOf('{'); const end = raw.lastIndexOf('}');
          if(start>=0 && end>start){ const j = JSON.parse(raw.slice(start, end+1)); comments = j.comments||[]; }
        }catch(_){}
        if(!comments.length){
          var nl = String.fromCharCode(10);
          comments = raw.split(nl).map(function(l){ return l.replace(/^[0-9]+[.)] */,'').trim(); }).filter(function(l){ return l.length>0; });
        }
        if(!comments.length){ msgEl.textContent='⚠️ コメントを解析できませんでした。JSON形式または番号付きリストで貼り付けてください'; return; }

        // 未返却の提出を収集
        const cards = document.querySelectorAll('#hwList [data-hw-id]');
        const targets = [];
        for(const card of cards){
          const id = card.dataset.hwId;
          if(!document.getElementById('hwComment_'+id)) continue; // 返却済みはスキップ
          targets.push(id);
        }
        if(!targets.length){ msgEl.textContent='未返却の提出がありません'; return; }
        if(!confirm(targets.length+'件まとめて返却します。よろしいですか？')) return;

        msgEl.textContent='⏳ 返却中...';
        let ok=0, ng=0;
        for(let i=0;i<targets.length;i++){
          const id = targets[i];
          const comment = (i < comments.length) ? comments[i] : '';
          try{
            await api('/api/teacher/homework/'+id+'/return',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({comment:comment,hasPhysical:false})});
            ok++;
          }catch(e){ ng++; }
        }
        document.getElementById('aiPasteArea').value='';
        msgEl.textContent=(ng===0?'✅ ':('⚠️ '+ng+'件失敗 / '))+ok+'件返却しました！';
        await loadHomework();
      }

      // 報告一覧
      async function loadAdminReports(){
        const wrap = document.getElementById('adminReportList');
        const countEl = document.getElementById('rptCount');
        wrap.innerHTML='<p class="text-slate-400">読み込み中...</p>';
        const status = document.getElementById('rptStatusFilter').value;
        try {
          const data = await api('/api/admin/reports?status='+encodeURIComponent(status));
          const list = data.reports || [];
          if(countEl) countEl.textContent = list.length + '件';
          if(!list.length){ wrap.innerHTML='<p class="text-slate-400">報告はありません</p>'; return; }
          var catLabels = {bug:'🐛 バグ', request:'💡 要望', other:'💬 その他'};
          var statusLabels = {open:'📬 受付中', in_progress:'🔧 対応中', resolved:'✅ 解決済み', closed:'🗂️ 終了'};
          wrap.innerHTML='';
          list.forEach(function(r){
            var card = document.createElement('div');
            card.className = 'border rounded-xl p-3 space-y-2 ' + (r.status==='open' ? 'bg-yellow-50 border-yellow-300' : 'bg-white');
            card.innerHTML = '<div class="flex items-center justify-between flex-wrap gap-1">'
              + '<div class="font-bold text-sm">' + escH(r.displayName) + ' <span class="text-xs text-slate-400 font-normal">'+(catLabels[r.category]||r.category)+'</span></div>'
              + '<div class="flex gap-1 items-center text-xs"><span class="px-2 py-0.5 rounded-full bg-gray-100">'+(statusLabels[r.status]||r.status)+'</span><span class="text-slate-400">'+escH(r.createdAt)+'</span></div>'
              + '</div>'
              + '<div class="text-sm text-slate-700">'+escH(r.body)+'</div>'
              + (r.adminNote ? '<div class="text-xs bg-emerald-50 border border-emerald-200 rounded p-2 text-emerald-800">💬 返信: '+escH(r.adminNote)+'</div>' : '')
              + '<div class="flex gap-2 items-center flex-wrap">'
              + '<select class="border p-1 rounded text-xs" id="rptSt_'+r.id+'">'
              + '<option value="open"'+(r.status==='open'?' selected':'')+'>受付中</option>'
              + '<option value="in_progress"'+(r.status==='in_progress'?' selected':'')+'>対応中</option>'
              + '<option value="resolved"'+(r.status==='resolved'?' selected':'')+'>解決済み</option>'
              + '<option value="closed"'+(r.status==='closed'?' selected':'')+'>終了</option>'
              + '</select>'
              + '<input class="border p-1 rounded text-xs flex-1" id="rptNote_'+r.id+'" placeholder="返信メモ" value="'+escH(r.adminNote)+'" />'
              + '<button class="bg-emerald-600 text-white rounded px-2 py-1 text-xs font-bold" onclick="updateReport(&#39;'+r.id+'&#39;)">更新</button>'
              + '<button class="bg-red-100 text-red-600 rounded px-2 py-1 text-xs" onclick="deleteReport(&#39;'+r.id+'&#39;)">削除</button>'
              + '</div>';
            wrap.appendChild(card);
          });
        } catch(e) {
          wrap.innerHTML='<p class="text-red-600">読み込みエラー: '+escH(String(e.message||e))+'</p>';
        }
      }

      async function updateReport(id){
        var st = document.getElementById('rptSt_'+id).value;
        var note = document.getElementById('rptNote_'+id).value;
        try{
          await api('/api/admin/report/'+id,{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({status:st,adminNote:note})});
          loadAdminReports();
        }catch(e){ alert('更新エラー: '+String(e.message||e)); }
      }

      async function deleteReport(id){
        if(!confirm('この報告を削除しますか？')) return;
        try{
          await api('/api/admin/report/'+id,{method:'DELETE'});
          loadAdminReports();
        }catch(e){ alert('削除エラー: '+String(e.message||e)); }
      }

      // ===== 連絡帳機能 =====
      async function loadContactNotes(){
        // クラスセレクター更新
        try{
          var clsData = await api('/api/teacher/classes');
          var sel = document.getElementById('cnClassFilter');
          sel.innerHTML = '';
          (clsData.classes||[]).forEach(function(c,i){ sel.innerHTML += '<option value="'+escH(c.id)+'"'+(i===0?' selected':'')+'>'+escH(c.name)+'</option>'; });
        }catch(e){}
        // 今日の日付をデフォルトに
        var today = new Date();
        var tmrw = new Date(today); tmrw.setDate(tmrw.getDate()+1);
        var dk = document.getElementById('cnDayKey');
        if(dk && !dk.value) dk.value = tmrw.toISOString().slice(0,10);
        // 一覧
        var wrap = document.getElementById('cnList');
        wrap.innerHTML = '<p class="text-slate-400 text-xs">読み込み中...</p>';
        try{
          var classId = document.getElementById('cnClassFilter').value||'';
          var data = await api('/api/teacher/contact-notes?classId='+encodeURIComponent(classId));
          wrap.innerHTML = '';
          if(!data.notes.length){ wrap.innerHTML='<p class="text-xs text-slate-400">まだ連絡がありません</p>'; return; }
          for(var i=0;i<data.notes.length;i++){
            var n = data.notes[i];
            var card = document.createElement('div');
            card.className = 'border rounded-lg p-3 bg-blue-50 border-blue-200';
            var deadlineStr = n.rewardDeadline ? '<span class="text-xs text-orange-600">報酬締切: '+escH(n.rewardDeadline).slice(0,16)+'</span>' : '';
            card.innerHTML = '<div class="flex items-center justify-between mb-1">'
              + '<div class="font-bold text-sm">'+escH(n.dayKey)+' <span class="text-xs text-slate-400">'+escH(n.className||'')+'</span></div>'
              + '<div class="flex items-center gap-2">'
              + '<span class="text-xs bg-blue-100 text-blue-700 px-1 rounded">💰 '+n.rewardCoins+'コイン</span>'
              + deadlineStr
              + '<button class="text-xs text-slate-500 underline" onclick="viewContactReads(&#39;'+escH(n.id)+'&#39;)">既読状況</button>'
              + '<button class="text-xs text-red-400 hover:text-red-600" onclick="deleteContactNote(&#39;'+escH(n.id)+'&#39;)">削除</button>'
              + '</div></div>'
              + '<div class="text-xs text-slate-700 whitespace-pre-wrap">'+escH(n.body)+'</div>'
              + '<div class="hidden text-xs mt-2 border-t pt-2" id="cnReads_'+escH(n.id)+'"></div>';
            wrap.appendChild(card);
          }
        }catch(e){ wrap.innerHTML='<p class="text-xs text-red-600">読み込みエラー</p>'; }
      }

      async function sendContactNote(){
        var msg = document.getElementById('cnMsg');
        msg.textContent=''; msg.className='text-sm';
        var classId = document.getElementById('cnClassFilter').value;
        var dayKey = document.getElementById('cnDayKey').value;
        var body = document.getElementById('cnBody').value.trim();
        var deadline = document.getElementById('cnDeadline').value || null;
        var coins = parseInt(document.getElementById('cnCoins').value) || 5;
        if(!classId){ msg.textContent='クラスを選択してください'; msg.className='text-sm text-red-600'; return; }
        if(!dayKey){ msg.textContent='日付を入力してください'; msg.className='text-sm text-red-600'; return; }
        if(!body){ msg.textContent='連絡内容を入力してください'; msg.className='text-sm text-red-600'; return; }
        var rewardDeadline = deadline ? new Date(deadline).toISOString() : null;
        try{
          await api('/api/teacher/contact-note',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({classId:classId,dayKey:dayKey,body:body,rewardDeadline:rewardDeadline,rewardCoins:coins})});
          msg.textContent='送信しました！'; msg.className='text-sm text-green-700';
          document.getElementById('cnBody').value='';
          loadContactNotes();
        }catch(e){ msg.textContent='送信エラー: '+String(e.message||e); msg.className='text-sm text-red-600'; }
      }

      async function deleteContactNote(id){
        if(!confirm('この連絡を削除しますか？')) return;
        try{
          await api('/api/teacher/contact-note/'+id,{method:'DELETE'});
          loadContactNotes();
        }catch(e){ alert('削除エラー: '+String(e.message||e)); }
      }

      async function viewContactReads(id){
        var wrap = document.getElementById('cnReads_'+id);
        if(!wrap) return;
        if(!wrap.classList.contains('hidden')){ wrap.classList.add('hidden'); return; }
        wrap.classList.remove('hidden');
        wrap.innerHTML = '<span class="text-slate-400">読み込み中...</span>';
        try{
          var data = await api('/api/teacher/contact-note/'+id+'/reads');
          if(!data.reads.length){ wrap.innerHTML='<span class="text-slate-400">まだ誰も読んでいません</span>'; return; }
          var html = '<div class="font-bold mb-1">既読: '+data.reads.length+'人</div>';
          data.reads.forEach(function(r){
            var reward = r.rewardClaimed ? '<span class="text-green-600">💰</span>' : '<span class="text-slate-400">-</span>';
            html += '<div class="flex gap-2 items-center">'
              + '<span>'+escH(r.studentName)+'</span>'
              + '<span class="text-xs text-slate-400">'+escH((r.readAt||'').slice(0,16))+'</span>'
              + reward + '</div>';
          });
          wrap.innerHTML = html;
        }catch(e){ wrap.innerHTML='<span class="text-red-500">エラー</span>'; }
      }

      // ===== おしらせ機能 =====
      async function loadAnnouncements(){
        // クラスセレクター更新
        try{
          var clsData = await api('/api/teacher/classes');
          var sel = document.getElementById('annClassFilter');
          sel.innerHTML = '<option value="">全体（クラス関係なく全員）</option>';
          (clsData.classes||[]).forEach(function(c){ sel.innerHTML += '<option value="'+escH(c.id)+'">'+escH(c.name)+'</option>'; });
        }catch(e){}
        // 送信済み一覧
        var wrap = document.getElementById('annList');
        wrap.innerHTML = '<p class="text-slate-400 text-xs">読み込み中...</p>';
        try{
          var data = await api('/api/teacher/announcements');
          wrap.innerHTML = '';
          if(!data.announcements.length){ wrap.innerHTML='<p class="text-xs text-slate-400">まだおしらせがありません</p>'; return; }
          data.announcements.forEach(function(a){
            var card = document.createElement('div');
            card.className = 'border rounded-lg p-3 bg-orange-50 border-orange-200';
            var target = a.classId ? escH(a.className||'クラス') : '<span class="text-orange-600 font-bold">全体</span>';
            card.innerHTML = '<div class="flex items-center justify-between mb-1">'
              + '<div class="font-bold text-sm">'+escH(a.title)+'</div>'
              + '<div class="flex items-center gap-2">'
              + '<span class="text-xs text-slate-400">'+escH(a.createdAt||'').slice(0,10)+'</span>'
              + '<span class="text-xs bg-orange-100 text-orange-700 px-1 rounded">'+target+'</span>'
              + '</div></div>'
              + '<div class="text-xs text-slate-700 whitespace-pre-wrap">'+escH(a.body)+'</div>'
              + '<button class="text-xs text-red-400 hover:text-red-600 mt-1" onclick="deleteAnnouncement(&#39;'+escH(a.id)+'&#39;)">削除</button>';
            wrap.appendChild(card);
          });
        }catch(e){ wrap.innerHTML='<p class="text-xs text-red-600">読み込みエラー</p>'; }
      }

      async function sendAnnouncement(){
        var msg = document.getElementById('annMsg');
        msg.textContent=''; msg.className='text-sm';
        var title = document.getElementById('annTitle').value.trim();
        var body = document.getElementById('annBody').value.trim();
        var classId = document.getElementById('annClassFilter').value || null;
        if(!title){ msg.textContent='タイトルを入力してください'; msg.className='text-sm text-red-600'; return; }
        if(!body){ msg.textContent='内容を入力してください'; msg.className='text-sm text-red-600'; return; }
        try{
          await api('/api/teacher/announcement',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({title:title,body:body,classId:classId})});
          msg.textContent='送信しました！'; msg.className='text-sm text-green-700';
          document.getElementById('annTitle').value='';
          document.getElementById('annBody').value='';
          loadAnnouncements();
        }catch(e){ msg.textContent='送信エラー: '+String(e.message||e); msg.className='text-sm text-red-600'; }
      }

      async function deleteAnnouncement(id){
        if(!confirm('このおしらせを削除しますか？')) return;
        try{
          await api('/api/teacher/announcement/'+id,{method:'DELETE'});
          loadAnnouncements();
        }catch(e){ alert('削除エラー: '+String(e.message||e)); }
      }

      (async ()=>{
        const me = await fetch('/api/auth/me').then(r=>r.json()).catch(()=>({}));
        if(!me.user || (me.user.role !== 'teacher' && me.user.role !== 'admin')){ location.href='/login'; return; }
        document.getElementById('teacherInfo').textContent = me.user.name + '（' + (me.user.school||'') + '）';
        // おしらせタブは管理者のみ表示
        if(me.user.role !== 'admin'){
          var annTab = document.getElementById('tabAnnouncements');
          if(annTab) annTab.style.display = 'none';
          var annPane = document.getElementById('tabPaneAnnouncements');
          if(annPane) annPane.style.display = 'none';
        }
        await renderClasses();
      })();
    <\/script>
  </body></html>`));const mt=new At,Hs=Object.assign({"/src/index.tsx":m});let qt=!1;for(const[,e]of Object.entries(Hs))e&&(mt.all("*",t=>{let s;try{s=t.executionCtx}catch{}return e.fetch(t.req.raw,t.env,s)}),mt.notFound(t=>{let s;try{s=t.executionCtx}catch{}return e.fetch(t.req.raw,t.env,s)}),qt=!0);if(!qt)throw new Error("Can't import modules from ['/src/index.ts','/src/index.tsx','/app/server.ts']");export{mt as default};
