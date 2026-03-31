var Pt=Object.defineProperty;var at=e=>{throw TypeError(e)};var qt=(e,t,s)=>t in e?Pt(e,t,{enumerable:!0,configurable:!0,writable:!0,value:s}):e[t]=s;var E=(e,t,s)=>qt(e,typeof t!="symbol"?t+"":t,s),Ge=(e,t,s)=>t.has(e)||at("Cannot "+s);var u=(e,t,s)=>(Ge(e,t,"read from private field"),s?s.call(e):t.get(e)),I=(e,t,s)=>t.has(e)?at("Cannot add the same private member more than once"):t instanceof WeakSet?t.add(e):t.set(e,s),y=(e,t,s,n)=>(Ge(e,t,"write to private field"),n?n.call(e,s):t.set(e,s),s),k=(e,t,s)=>(Ge(e,t,"access private method"),s);var rt=(e,t,s,n)=>({set _(a){y(e,t,a,s)},get _(){return u(e,t,n)}});var ot=(e,t,s)=>(n,a)=>{let r=-1;return o(0);async function o(i){if(i<=r)throw new Error("next() called multiple times");r=i;let d,c=!1,p;if(e[i]?(p=e[i][0][0],n.req.routeIndex=i):p=i===e.length&&a||void 0,p)try{d=await p(n,()=>o(i+1))}catch(m){if(m instanceof Error&&t)n.error=m,d=await t(m,n),c=!0;else throw m}else n.finalized===!1&&s&&(d=await s(n));return d&&(n.finalized===!1||c)&&(n.res=d),n}},Ft=Symbol(),Wt=async(e,t=Object.create(null))=>{const{all:s=!1,dot:n=!1}=t,r=(e instanceof Et?e.raw.headers:e.headers).get("Content-Type");return r!=null&&r.startsWith("multipart/form-data")||r!=null&&r.startsWith("application/x-www-form-urlencoded")?Ut(e,{all:s,dot:n}):{}};async function Ut(e,t){const s=await e.formData();return s?Jt(s,t):{}}function Jt(e,t){const s=Object.create(null);return e.forEach((n,a)=>{t.all||a.endsWith("[]")?$t(s,a,n):s[a]=n}),t.dot&&Object.entries(s).forEach(([n,a])=>{n.includes(".")&&(zt(s,n,a),delete s[n])}),s}var $t=(e,t,s)=>{e[t]!==void 0?Array.isArray(e[t])?e[t].push(s):e[t]=[e[t],s]:t.endsWith("[]")?e[t]=[s]:e[t]=s},zt=(e,t,s)=>{let n=e;const a=t.split(".");a.forEach((r,o)=>{o===a.length-1?n[r]=s:((!n[r]||typeof n[r]!="object"||Array.isArray(n[r])||n[r]instanceof File)&&(n[r]=Object.create(null)),n=n[r])})},wt=e=>{const t=e.split("/");return t[0]===""&&t.shift(),t},Vt=e=>{const{groups:t,path:s}=Kt(e),n=wt(s);return Yt(n,t)},Kt=e=>{const t=[];return e=e.replace(/\{[^}]+\}/g,(s,n)=>{const a=`@${n}`;return t.push([a,s]),a}),{groups:t,path:e}},Yt=(e,t)=>{for(let s=t.length-1;s>=0;s--){const[n]=t[s];for(let a=e.length-1;a>=0;a--)if(e[a].includes(n)){e[a]=e[a].replace(n,t[s][1]);break}}return e},Me={},Gt=(e,t)=>{if(e==="*")return"*";const s=e.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);if(s){const n=`${e}#${t}`;return Me[n]||(s[2]?Me[n]=t&&t[0]!==":"&&t[0]!=="*"?[n,s[1],new RegExp(`^${s[2]}(?=/${t})`)]:[e,s[1],new RegExp(`^${s[2]}$`)]:Me[n]=[e,s[1],!0]),Me[n]}return null},Ve=(e,t)=>{try{return t(e)}catch{return e.replace(/(?:%[0-9A-Fa-f]{2})+/g,s=>{try{return t(s)}catch{return s}})}},Qt=e=>Ve(e,decodeURI),_t=e=>{const t=e.url,s=t.indexOf("/",t.indexOf(":")+4);let n=s;for(;n<t.length;n++){const a=t.charCodeAt(n);if(a===37){const r=t.indexOf("?",n),o=t.indexOf("#",n),i=r===-1?o===-1?void 0:o:o===-1?r:Math.min(r,o),d=t.slice(s,i);return Qt(d.includes("%25")?d.replace(/%25/g,"%2525"):d)}else if(a===63||a===35)break}return t.slice(s,n)},Xt=e=>{const t=_t(e);return t.length>1&&t.at(-1)==="/"?t.slice(0,-1):t},me=(e,t,...s)=>(s.length&&(t=me(t,...s)),`${(e==null?void 0:e[0])==="/"?"":"/"}${e}${t==="/"?"":`${(e==null?void 0:e.at(-1))==="/"?"":"/"}${(t==null?void 0:t[0])==="/"?t.slice(1):t}`}`),yt=e=>{if(e.charCodeAt(e.length-1)!==63||!e.includes(":"))return null;const t=e.split("/"),s=[];let n="";return t.forEach(a=>{if(a!==""&&!/\:/.test(a))n+="/"+a;else if(/\:/.test(a))if(/\?/.test(a)){s.length===0&&n===""?s.push("/"):s.push(n);const r=a.replace("?","");n+="/"+r,s.push(n)}else n+="/"+a}),s.filter((a,r,o)=>o.indexOf(a)===r)},Qe=e=>/[%+]/.test(e)?(e.indexOf("+")!==-1&&(e=e.replace(/\+/g," ")),e.indexOf("%")!==-1?Ve(e,tt):e):e,xt=(e,t,s)=>{let n;if(!s&&t&&!/[%+]/.test(t)){let o=e.indexOf("?",8);if(o===-1)return;for(e.startsWith(t,o+1)||(o=e.indexOf(`&${t}`,o+1));o!==-1;){const i=e.charCodeAt(o+t.length+1);if(i===61){const d=o+t.length+2,c=e.indexOf("&",d);return Qe(e.slice(d,c===-1?void 0:c))}else if(i==38||isNaN(i))return"";o=e.indexOf(`&${t}`,o+1)}if(n=/[%+]/.test(e),!n)return}const a={};n??(n=/[%+]/.test(e));let r=e.indexOf("?",8);for(;r!==-1;){const o=e.indexOf("&",r+1);let i=e.indexOf("=",r);i>o&&o!==-1&&(i=-1);let d=e.slice(r+1,i===-1?o===-1?void 0:o:i);if(n&&(d=Qe(d)),r=o,d==="")continue;let c;i===-1?c="":(c=e.slice(i+1,o===-1?void 0:o),n&&(c=Qe(c))),s?(a[d]&&Array.isArray(a[d])||(a[d]=[]),a[d].push(c)):a[d]??(a[d]=c)}return t?a[t]:a},Zt=xt,es=(e,t)=>xt(e,t,!0),tt=decodeURIComponent,it=e=>Ve(e,tt),be,P,K,vt,It,et,Y,pt,Et=(pt=class{constructor(e,t="/",s=[[]]){I(this,K);E(this,"raw");I(this,be);I(this,P);E(this,"routeIndex",0);E(this,"path");E(this,"bodyCache",{});I(this,Y,e=>{const{bodyCache:t,raw:s}=this,n=t[e];if(n)return n;const a=Object.keys(t)[0];return a?t[a].then(r=>(a==="json"&&(r=JSON.stringify(r)),new Response(r)[e]())):t[e]=s[e]()});this.raw=e,this.path=t,y(this,P,s),y(this,be,{})}param(e){return e?k(this,K,vt).call(this,e):k(this,K,It).call(this)}query(e){return Zt(this.url,e)}queries(e){return es(this.url,e)}header(e){if(e)return this.raw.headers.get(e)??void 0;const t={};return this.raw.headers.forEach((s,n)=>{t[n]=s}),t}async parseBody(e){var t;return(t=this.bodyCache).parsedBody??(t.parsedBody=await Wt(this,e))}json(){return u(this,Y).call(this,"text").then(e=>JSON.parse(e))}text(){return u(this,Y).call(this,"text")}arrayBuffer(){return u(this,Y).call(this,"arrayBuffer")}blob(){return u(this,Y).call(this,"blob")}formData(){return u(this,Y).call(this,"formData")}addValidatedData(e,t){u(this,be)[e]=t}valid(e){return u(this,be)[e]}get url(){return this.raw.url}get method(){return this.raw.method}get[Ft](){return u(this,P)}get matchedRoutes(){return u(this,P)[0].map(([[,e]])=>e)}get routePath(){return u(this,P)[0].map(([[,e]])=>e)[this.routeIndex].path}},be=new WeakMap,P=new WeakMap,K=new WeakSet,vt=function(e){const t=u(this,P)[0][this.routeIndex][1][e],s=k(this,K,et).call(this,t);return s&&/\%/.test(s)?it(s):s},It=function(){const e={},t=Object.keys(u(this,P)[0][this.routeIndex][1]);for(const s of t){const n=k(this,K,et).call(this,u(this,P)[0][this.routeIndex][1][s]);n!==void 0&&(e[s]=/\%/.test(n)?it(n):n)}return e},et=function(e){return u(this,P)[1]?u(this,P)[1][e]:e},Y=new WeakMap,pt),ts={Stringify:1},St=async(e,t,s,n,a)=>{typeof e=="object"&&!(e instanceof String)&&(e instanceof Promise||(e=e.toString()),e instanceof Promise&&(e=await e));const r=e.callbacks;return r!=null&&r.length?(a?a[0]+=e:a=[e],Promise.all(r.map(i=>i({phase:t,buffer:a,context:n}))).then(i=>Promise.all(i.filter(Boolean).map(d=>St(d,t,!1,n,a))).then(()=>a[0]))):Promise.resolve(e)},ss="text/plain; charset=UTF-8",Xe=(e,t)=>({"Content-Type":e,...t}),Ce=(e,t)=>new Response(e,t),Oe,Le,J,fe,$,B,je,we,_e,ne,Be,Ae,G,he,mt,ns=(mt=class{constructor(e,t){I(this,G);I(this,Oe);I(this,Le);E(this,"env",{});I(this,J);E(this,"finalized",!1);E(this,"error");I(this,fe);I(this,$);I(this,B);I(this,je);I(this,we);I(this,_e);I(this,ne);I(this,Be);I(this,Ae);E(this,"render",(...e)=>(u(this,we)??y(this,we,t=>this.html(t)),u(this,we).call(this,...e)));E(this,"setLayout",e=>y(this,je,e));E(this,"getLayout",()=>u(this,je));E(this,"setRenderer",e=>{y(this,we,e)});E(this,"header",(e,t,s)=>{this.finalized&&y(this,B,Ce(u(this,B).body,u(this,B)));const n=u(this,B)?u(this,B).headers:u(this,ne)??y(this,ne,new Headers);t===void 0?n.delete(e):s!=null&&s.append?n.append(e,t):n.set(e,t)});E(this,"status",e=>{y(this,fe,e)});E(this,"set",(e,t)=>{u(this,J)??y(this,J,new Map),u(this,J).set(e,t)});E(this,"get",e=>u(this,J)?u(this,J).get(e):void 0);E(this,"newResponse",(...e)=>k(this,G,he).call(this,...e));E(this,"body",(e,t,s)=>k(this,G,he).call(this,e,t,s));E(this,"text",(e,t,s)=>!u(this,ne)&&!u(this,fe)&&!t&&!s&&!this.finalized?new Response(e):k(this,G,he).call(this,e,t,Xe(ss,s)));E(this,"json",(e,t,s)=>k(this,G,he).call(this,JSON.stringify(e),t,Xe("application/json",s)));E(this,"html",(e,t,s)=>{const n=a=>k(this,G,he).call(this,a,t,Xe("text/html; charset=UTF-8",s));return typeof e=="object"?St(e,ts.Stringify,!1,{}).then(n):n(e)});E(this,"redirect",(e,t)=>{const s=String(e);return this.header("Location",/[^\x00-\xFF]/.test(s)?encodeURI(s):s),this.newResponse(null,t??302)});E(this,"notFound",()=>(u(this,_e)??y(this,_e,()=>Ce()),u(this,_e).call(this,this)));y(this,Oe,e),t&&(y(this,$,t.executionCtx),this.env=t.env,y(this,_e,t.notFoundHandler),y(this,Ae,t.path),y(this,Be,t.matchResult))}get req(){return u(this,Le)??y(this,Le,new Et(u(this,Oe),u(this,Ae),u(this,Be))),u(this,Le)}get event(){if(u(this,$)&&"respondWith"in u(this,$))return u(this,$);throw Error("This context has no FetchEvent")}get executionCtx(){if(u(this,$))return u(this,$);throw Error("This context has no ExecutionContext")}get res(){return u(this,B)||y(this,B,Ce(null,{headers:u(this,ne)??y(this,ne,new Headers)}))}set res(e){if(u(this,B)&&e){e=Ce(e.body,e);for(const[t,s]of u(this,B).headers.entries())if(t!=="content-type")if(t==="set-cookie"){const n=u(this,B).headers.getSetCookie();e.headers.delete("set-cookie");for(const a of n)e.headers.append("set-cookie",a)}else e.headers.set(t,s)}y(this,B,e),this.finalized=!0}get var(){return u(this,J)?Object.fromEntries(u(this,J)):{}}},Oe=new WeakMap,Le=new WeakMap,J=new WeakMap,fe=new WeakMap,$=new WeakMap,B=new WeakMap,je=new WeakMap,we=new WeakMap,_e=new WeakMap,ne=new WeakMap,Be=new WeakMap,Ae=new WeakMap,G=new WeakSet,he=function(e,t,s){const n=u(this,B)?new Headers(u(this,B).headers):u(this,ne)??new Headers;if(typeof t=="object"&&"headers"in t){const r=t.headers instanceof Headers?t.headers:new Headers(t.headers);for(const[o,i]of r)o.toLowerCase()==="set-cookie"?n.append(o,i):n.set(o,i)}if(s)for(const[r,o]of Object.entries(s))if(typeof o=="string")n.set(r,o);else{n.delete(r);for(const i of o)n.append(r,i)}const a=typeof t=="number"?t:(t==null?void 0:t.status)??u(this,fe);return Ce(e,{status:a,headers:n})},mt),R="ALL",as="all",rs=["get","post","put","delete","options","patch"],kt="Can not add a route since the matcher is already built.",Ct=class extends Error{},os="__COMPOSED_HANDLER",is=e=>e.text("404 Not Found",404),dt=(e,t)=>{if("getResponse"in e){const s=e.getResponse();return t.newResponse(s.body,s)}return console.error(e),t.text("Internal Server Error",500)},q,N,Dt,F,te,qe,Fe,ye,ds=(ye=class{constructor(t={}){I(this,N);E(this,"get");E(this,"post");E(this,"put");E(this,"delete");E(this,"options");E(this,"patch");E(this,"all");E(this,"on");E(this,"use");E(this,"router");E(this,"getPath");E(this,"_basePath","/");I(this,q,"/");E(this,"routes",[]);I(this,F,is);E(this,"errorHandler",dt);E(this,"onError",t=>(this.errorHandler=t,this));E(this,"notFound",t=>(y(this,F,t),this));E(this,"fetch",(t,...s)=>k(this,N,Fe).call(this,t,s[1],s[0],t.method));E(this,"request",(t,s,n,a)=>t instanceof Request?this.fetch(s?new Request(t,s):t,n,a):(t=t.toString(),this.fetch(new Request(/^https?:\/\//.test(t)?t:`http://localhost${me("/",t)}`,s),n,a)));E(this,"fire",()=>{addEventListener("fetch",t=>{t.respondWith(k(this,N,Fe).call(this,t.request,t,void 0,t.request.method))})});[...rs,as].forEach(r=>{this[r]=(o,...i)=>(typeof o=="string"?y(this,q,o):k(this,N,te).call(this,r,u(this,q),o),i.forEach(d=>{k(this,N,te).call(this,r,u(this,q),d)}),this)}),this.on=(r,o,...i)=>{for(const d of[o].flat()){y(this,q,d);for(const c of[r].flat())i.map(p=>{k(this,N,te).call(this,c.toUpperCase(),u(this,q),p)})}return this},this.use=(r,...o)=>(typeof r=="string"?y(this,q,r):(y(this,q,"*"),o.unshift(r)),o.forEach(i=>{k(this,N,te).call(this,R,u(this,q),i)}),this);const{strict:n,...a}=t;Object.assign(this,a),this.getPath=n??!0?t.getPath??_t:Xt}route(t,s){const n=this.basePath(t);return s.routes.map(a=>{var o;let r;s.errorHandler===dt?r=a.handler:(r=async(i,d)=>(await ot([],s.errorHandler)(i,()=>a.handler(i,d))).res,r[os]=a.handler),k(o=n,N,te).call(o,a.method,a.path,r)}),this}basePath(t){const s=k(this,N,Dt).call(this);return s._basePath=me(this._basePath,t),s}mount(t,s,n){let a,r;n&&(typeof n=="function"?r=n:(r=n.optionHandler,n.replaceRequest===!1?a=d=>d:a=n.replaceRequest));const o=r?d=>{const c=r(d);return Array.isArray(c)?c:[c]}:d=>{let c;try{c=d.executionCtx}catch{}return[d.env,c]};a||(a=(()=>{const d=me(this._basePath,t),c=d==="/"?0:d.length;return p=>{const m=new URL(p.url);return m.pathname=m.pathname.slice(c)||"/",new Request(m,p)}})());const i=async(d,c)=>{const p=await s(a(d.req.raw),...o(d));if(p)return p;await c()};return k(this,N,te).call(this,R,me(t,"*"),i),this}},q=new WeakMap,N=new WeakSet,Dt=function(){const t=new ye({router:this.router,getPath:this.getPath});return t.errorHandler=this.errorHandler,y(t,F,u(this,F)),t.routes=this.routes,t},F=new WeakMap,te=function(t,s,n){t=t.toUpperCase(),s=me(this._basePath,s);const a={basePath:this._basePath,path:s,method:t,handler:n};this.router.add(t,s,[n,a]),this.routes.push(a)},qe=function(t,s){if(t instanceof Error)return this.errorHandler(t,s);throw t},Fe=function(t,s,n,a){if(a==="HEAD")return(async()=>new Response(null,await k(this,N,Fe).call(this,t,s,n,"GET")))();const r=this.getPath(t,{env:n}),o=this.router.match(a,r),i=new ns(t,{path:r,matchResult:o,env:n,executionCtx:s,notFoundHandler:u(this,F)});if(o[0].length===1){let c;try{c=o[0][0][0][0](i,async()=>{i.res=await u(this,F).call(this,i)})}catch(p){return k(this,N,qe).call(this,p,i)}return c instanceof Promise?c.then(p=>p||(i.finalized?i.res:u(this,F).call(this,i))).catch(p=>k(this,N,qe).call(this,p,i)):c??u(this,F).call(this,i)}const d=ot(o[0],this.errorHandler,u(this,F));return(async()=>{try{const c=await d(i);if(!c.finalized)throw new Error("Context is not finalized. Did you forget to return a Response object or `await next()`?");return c.res}catch(c){return k(this,N,qe).call(this,c,i)}})()},ye),Tt=[];function ls(e,t){const s=this.buildAllMatchers(),n=((a,r)=>{const o=s[a]||s[R],i=o[2][r];if(i)return i;const d=r.match(o[0]);if(!d)return[[],Tt];const c=d.indexOf("",1);return[o[1][c],d]});return this.match=n,n(e,t)}var Ue="[^/]+",Te=".*",Re="(?:|/.*)",ge=Symbol(),cs=new Set(".\\+*[^]$()");function us(e,t){return e.length===1?t.length===1?e<t?-1:1:-1:t.length===1||e===Te||e===Re?1:t===Te||t===Re?-1:e===Ue?1:t===Ue?-1:e.length===t.length?e<t?-1:1:t.length-e.length}var ae,re,W,de,ps=(de=class{constructor(){I(this,ae);I(this,re);I(this,W,Object.create(null))}insert(t,s,n,a,r){if(t.length===0){if(u(this,ae)!==void 0)throw ge;if(r)return;y(this,ae,s);return}const[o,...i]=t,d=o==="*"?i.length===0?["","",Te]:["","",Ue]:o==="/*"?["","",Re]:o.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);let c;if(d){const p=d[1];let m=d[2]||Ue;if(p&&d[2]&&(m===".*"||(m=m.replace(/^\((?!\?:)(?=[^)]+\)$)/,"(?:"),/\((?!\?:)/.test(m))))throw ge;if(c=u(this,W)[m],!c){if(Object.keys(u(this,W)).some(f=>f!==Te&&f!==Re))throw ge;if(r)return;c=u(this,W)[m]=new de,p!==""&&y(c,re,a.varIndex++)}!r&&p!==""&&n.push([p,u(c,re)])}else if(c=u(this,W)[o],!c){if(Object.keys(u(this,W)).some(p=>p.length>1&&p!==Te&&p!==Re))throw ge;if(r)return;c=u(this,W)[o]=new de}c.insert(i,s,n,a,r)}buildRegExpStr(){const s=Object.keys(u(this,W)).sort(us).map(n=>{const a=u(this,W)[n];return(typeof u(a,re)=="number"?`(${n})@${u(a,re)}`:cs.has(n)?`\\${n}`:n)+a.buildRegExpStr()});return typeof u(this,ae)=="number"&&s.unshift(`#${u(this,ae)}`),s.length===0?"":s.length===1?s[0]:"(?:"+s.join("|")+")"}},ae=new WeakMap,re=new WeakMap,W=new WeakMap,de),$e,He,ht,ms=(ht=class{constructor(){I(this,$e,{varIndex:0});I(this,He,new ps)}insert(e,t,s){const n=[],a=[];for(let o=0;;){let i=!1;if(e=e.replace(/\{[^}]+\}/g,d=>{const c=`@\\${o}`;return a[o]=[c,d],o++,i=!0,c}),!i)break}const r=e.match(/(?::[^\/]+)|(?:\/\*$)|./g)||[];for(let o=a.length-1;o>=0;o--){const[i]=a[o];for(let d=r.length-1;d>=0;d--)if(r[d].indexOf(i)!==-1){r[d]=r[d].replace(i,a[o][1]);break}}return u(this,He).insert(r,t,n,u(this,$e),s),n}buildRegExp(){let e=u(this,He).buildRegExpStr();if(e==="")return[/^$/,[],[]];let t=0;const s=[],n=[];return e=e.replace(/#(\d+)|@(\d+)|\.\*\$/g,(a,r,o)=>r!==void 0?(s[++t]=Number(r),"$()"):(o!==void 0&&(n[Number(o)]=++t),"")),[new RegExp(`^${e}`),s,n]}},$e=new WeakMap,He=new WeakMap,ht),hs=[/^$/,[],Object.create(null)],We=Object.create(null);function Rt(e){return We[e]??(We[e]=new RegExp(e==="*"?"":`^${e.replace(/\/\*$|([.\\+*[^\]$()])/g,(t,s)=>s?`\\${s}`:"(?:|/.*)")}$`))}function gs(){We=Object.create(null)}function bs(e){var c;const t=new ms,s=[];if(e.length===0)return hs;const n=e.map(p=>[!/\*|\/:/.test(p[0]),...p]).sort(([p,m],[f,w])=>p?1:f?-1:m.length-w.length),a=Object.create(null);for(let p=0,m=-1,f=n.length;p<f;p++){const[w,b,x]=n[p];w?a[b]=[x.map(([v])=>[v,Object.create(null)]),Tt]:m++;let _;try{_=t.insert(b,m,w)}catch(v){throw v===ge?new Ct(b):v}w||(s[m]=x.map(([v,g])=>{const S=Object.create(null);for(g-=1;g>=0;g--){const[C,T]=_[g];S[C]=T}return[v,S]}))}const[r,o,i]=t.buildRegExp();for(let p=0,m=s.length;p<m;p++)for(let f=0,w=s[p].length;f<w;f++){const b=(c=s[p][f])==null?void 0:c[1];if(!b)continue;const x=Object.keys(b);for(let _=0,v=x.length;_<v;_++)b[x[_]]=i[b[x[_]]]}const d=[];for(const p in o)d[p]=s[o[p]];return[r,d,a]}function pe(e,t){if(e){for(const s of Object.keys(e).sort((n,a)=>a.length-n.length))if(Rt(s).test(t))return[...e[s]]}}var Q,X,ze,Nt,gt,fs=(gt=class{constructor(){I(this,ze);E(this,"name","RegExpRouter");I(this,Q);I(this,X);E(this,"match",ls);y(this,Q,{[R]:Object.create(null)}),y(this,X,{[R]:Object.create(null)})}add(e,t,s){var i;const n=u(this,Q),a=u(this,X);if(!n||!a)throw new Error(kt);n[e]||[n,a].forEach(d=>{d[e]=Object.create(null),Object.keys(d[R]).forEach(c=>{d[e][c]=[...d[R][c]]})}),t==="/*"&&(t="*");const r=(t.match(/\/:/g)||[]).length;if(/\*$/.test(t)){const d=Rt(t);e===R?Object.keys(n).forEach(c=>{var p;(p=n[c])[t]||(p[t]=pe(n[c],t)||pe(n[R],t)||[])}):(i=n[e])[t]||(i[t]=pe(n[e],t)||pe(n[R],t)||[]),Object.keys(n).forEach(c=>{(e===R||e===c)&&Object.keys(n[c]).forEach(p=>{d.test(p)&&n[c][p].push([s,r])})}),Object.keys(a).forEach(c=>{(e===R||e===c)&&Object.keys(a[c]).forEach(p=>d.test(p)&&a[c][p].push([s,r]))});return}const o=yt(t)||[t];for(let d=0,c=o.length;d<c;d++){const p=o[d];Object.keys(a).forEach(m=>{var f;(e===R||e===m)&&((f=a[m])[p]||(f[p]=[...pe(n[m],p)||pe(n[R],p)||[]]),a[m][p].push([s,r-c+d+1]))})}}buildAllMatchers(){const e=Object.create(null);return Object.keys(u(this,X)).concat(Object.keys(u(this,Q))).forEach(t=>{e[t]||(e[t]=k(this,ze,Nt).call(this,t))}),y(this,Q,y(this,X,void 0)),gs(),e}},Q=new WeakMap,X=new WeakMap,ze=new WeakSet,Nt=function(e){const t=[];let s=e===R;return[u(this,Q),u(this,X)].forEach(n=>{const a=n[e]?Object.keys(n[e]).map(r=>[r,n[e][r]]):[];a.length!==0?(s||(s=!0),t.push(...a)):e!==R&&t.push(...Object.keys(n[R]).map(r=>[r,n[R][r]]))}),s?bs(t):null},gt),Z,z,bt,ws=(bt=class{constructor(e){E(this,"name","SmartRouter");I(this,Z,[]);I(this,z,[]);y(this,Z,e.routers)}add(e,t,s){if(!u(this,z))throw new Error(kt);u(this,z).push([e,t,s])}match(e,t){if(!u(this,z))throw new Error("Fatal error");const s=u(this,Z),n=u(this,z),a=s.length;let r=0,o;for(;r<a;r++){const i=s[r];try{for(let d=0,c=n.length;d<c;d++)i.add(...n[d]);o=i.match(e,t)}catch(d){if(d instanceof Ct)continue;throw d}this.match=i.match.bind(i),y(this,Z,[i]),y(this,z,void 0);break}if(r===a)throw new Error("Fatal error");return this.name=`SmartRouter + ${this.activeRouter.name}`,o}get activeRouter(){if(u(this,z)||u(this,Z).length!==1)throw new Error("No active router has been determined yet.");return u(this,Z)[0]}},Z=new WeakMap,z=new WeakMap,bt),De=Object.create(null),_s=e=>{for(const t in e)return!0;return!1},ee,j,oe,xe,L,V,se,Ee,ys=(Ee=class{constructor(t,s,n){I(this,V);I(this,ee);I(this,j);I(this,oe);I(this,xe,0);I(this,L,De);if(y(this,j,n||Object.create(null)),y(this,ee,[]),t&&s){const a=Object.create(null);a[t]={handler:s,possibleKeys:[],score:0},y(this,ee,[a])}y(this,oe,[])}insert(t,s,n){y(this,xe,++rt(this,xe)._);let a=this;const r=Vt(s),o=[];for(let i=0,d=r.length;i<d;i++){const c=r[i],p=r[i+1],m=Gt(c,p),f=Array.isArray(m)?m[0]:c;if(f in u(a,j)){a=u(a,j)[f],m&&o.push(m[1]);continue}u(a,j)[f]=new Ee,m&&(u(a,oe).push(m),o.push(m[1])),a=u(a,j)[f]}return u(a,ee).push({[t]:{handler:n,possibleKeys:o.filter((i,d,c)=>c.indexOf(i)===d),score:u(this,xe)}}),a}search(t,s){var p;const n=[];y(this,L,De);let r=[this];const o=wt(s),i=[],d=o.length;let c=null;for(let m=0;m<d;m++){const f=o[m],w=m===d-1,b=[];for(let _=0,v=r.length;_<v;_++){const g=r[_],S=u(g,j)[f];S&&(y(S,L,u(g,L)),w?(u(S,j)["*"]&&k(this,V,se).call(this,n,u(S,j)["*"],t,u(g,L)),k(this,V,se).call(this,n,S,t,u(g,L))):b.push(S));for(let C=0,T=u(g,oe).length;C<T;C++){const H=u(g,oe)[C],O=u(g,L)===De?{}:{...u(g,L)};if(H==="*"){const ce=u(g,j)["*"];ce&&(k(this,V,se).call(this,n,ce,t,u(g,L)),y(ce,L,O),b.push(ce));continue}const[Ke,nt,Se]=H;if(!f&&!(Se instanceof RegExp))continue;const U=u(g,j)[Ke];if(Se instanceof RegExp){if(c===null){c=new Array(d);let ue=s[0]==="/"?1:0;for(let ke=0;ke<d;ke++)c[ke]=ue,ue+=o[ke].length+1}const ce=s.substring(c[m]),Ye=Se.exec(ce);if(Ye){if(O[nt]=Ye[0],k(this,V,se).call(this,n,U,t,u(g,L),O),_s(u(U,j))){y(U,L,O);const ue=((p=Ye[0].match(/\//))==null?void 0:p.length)??0;(i[ue]||(i[ue]=[])).push(U)}continue}}(Se===!0||Se.test(f))&&(O[nt]=f,w?(k(this,V,se).call(this,n,U,t,O,u(g,L)),u(U,j)["*"]&&k(this,V,se).call(this,n,u(U,j)["*"],t,O,u(g,L))):(y(U,L,O),b.push(U)))}}const x=i.shift();r=x?b.concat(x):b}return n.length>1&&n.sort((m,f)=>m.score-f.score),[n.map(({handler:m,params:f})=>[m,f])]}},ee=new WeakMap,j=new WeakMap,oe=new WeakMap,xe=new WeakMap,L=new WeakMap,V=new WeakSet,se=function(t,s,n,a,r){for(let o=0,i=u(s,ee).length;o<i;o++){const d=u(s,ee)[o],c=d[n]||d[R],p={};if(c!==void 0&&(c.params=Object.create(null),t.push(c),a!==De||r&&r!==De))for(let m=0,f=c.possibleKeys.length;m<f;m++){const w=c.possibleKeys[m],b=p[c.score];c.params[w]=r!=null&&r[w]&&!b?r[w]:a[w]??(r==null?void 0:r[w]),p[c.score]=!0}}},Ee),ie,ft,xs=(ft=class{constructor(){E(this,"name","TrieRouter");I(this,ie);y(this,ie,new ys)}add(e,t,s){const n=yt(t);if(n){for(let a=0,r=n.length;a<r;a++)u(this,ie).insert(e,n[a],s);return}u(this,ie).insert(e,t,s)}match(e,t){return u(this,ie).search(e,t)}},ie=new WeakMap,ft),Ot=class extends ds{constructor(e={}){super(e),this.router=e.router??new ws({routers:[new fs,new xs]})}},Es=e=>{const s={...{origin:"*",allowMethods:["GET","HEAD","PUT","POST","DELETE","PATCH"],allowHeaders:[],exposeHeaders:[]},...e},n=(r=>typeof r=="string"?r==="*"?()=>r:o=>r===o?o:null:typeof r=="function"?r:o=>r.includes(o)?o:null)(s.origin),a=(r=>typeof r=="function"?r:Array.isArray(r)?()=>r:()=>[])(s.allowMethods);return async function(o,i){var p;function d(m,f){o.res.headers.set(m,f)}const c=await n(o.req.header("origin")||"",o);if(c&&d("Access-Control-Allow-Origin",c),s.credentials&&d("Access-Control-Allow-Credentials","true"),(p=s.exposeHeaders)!=null&&p.length&&d("Access-Control-Expose-Headers",s.exposeHeaders.join(",")),o.req.method==="OPTIONS"){s.origin!=="*"&&d("Vary","Origin"),s.maxAge!=null&&d("Access-Control-Max-Age",s.maxAge.toString());const m=await a(o.req.header("origin")||"",o);m.length&&d("Access-Control-Allow-Methods",m.join(","));let f=s.allowHeaders;if(!(f!=null&&f.length)){const w=o.req.header("Access-Control-Request-Headers");w&&(f=w.split(/\s*,\s*/))}return f!=null&&f.length&&(d("Access-Control-Allow-Headers",f.join(",")),o.res.headers.append("Vary","Access-Control-Request-Headers")),o.res.headers.delete("Content-Length"),o.res.headers.delete("Content-Type"),new Response(null,{headers:o.res.headers,status:204,statusText:"No Content"})}await i(),s.origin!=="*"&&o.header("Vary","Origin",{append:!0})}},vs=/^[\w!#$%&'*.^`|~+-]+$/,Is=/^[ !#-:<-[\]-~]*$/,Ss=(e,t)=>{if(t&&e.indexOf(t)===-1)return{};const s=e.trim().split(";"),n={};for(let a of s){a=a.trim();const r=a.indexOf("=");if(r===-1)continue;const o=a.substring(0,r).trim();if(t&&t!==o||!vs.test(o))continue;let i=a.substring(r+1).trim();if(i.startsWith('"')&&i.endsWith('"')&&(i=i.slice(1,-1)),Is.test(i)&&(n[o]=i.indexOf("%")!==-1?Ve(i,tt):i,t))break}return n},ks=(e,t,s={})=>{let n=`${e}=${t}`;if(e.startsWith("__Secure-")&&!s.secure)throw new Error("__Secure- Cookie must have Secure attributes");if(e.startsWith("__Host-")){if(!s.secure)throw new Error("__Host- Cookie must have Secure attributes");if(s.path!=="/")throw new Error('__Host- Cookie must have Path attributes with "/"');if(s.domain)throw new Error("__Host- Cookie must not have Domain attributes")}if(s&&typeof s.maxAge=="number"&&s.maxAge>=0){if(s.maxAge>3456e4)throw new Error("Cookies Max-Age SHOULD NOT be greater than 400 days (34560000 seconds) in duration.");n+=`; Max-Age=${s.maxAge|0}`}if(s.domain&&s.prefix!=="host"&&(n+=`; Domain=${s.domain}`),s.path&&(n+=`; Path=${s.path}`),s.expires){if(s.expires.getTime()-Date.now()>3456e7)throw new Error("Cookies Expires SHOULD NOT be greater than 400 days (34560000 seconds) in the future.");n+=`; Expires=${s.expires.toUTCString()}`}if(s.httpOnly&&(n+="; HttpOnly"),s.secure&&(n+="; Secure"),s.sameSite&&(n+=`; SameSite=${s.sameSite.charAt(0).toUpperCase()+s.sameSite.slice(1)}`),s.priority&&(n+=`; Priority=${s.priority.charAt(0).toUpperCase()+s.priority.slice(1)}`),s.partitioned){if(!s.secure)throw new Error("Partitioned Cookie must have Secure attributes");n+="; Partitioned"}return n},Ze=(e,t,s)=>(t=encodeURIComponent(t),ks(e,t,s)),Lt=(e,t,s)=>{const n=e.req.raw.headers.get("Cookie");{if(!n)return;let a=t;return s==="secure"?a="__Secure-"+t:s==="host"&&(a="__Host-"+t),Ss(n,a)[a]}},Cs=(e,t,s)=>{let n;return(s==null?void 0:s.prefix)==="secure"?n=Ze("__Secure-"+e,t,{path:"/",...s,secure:!0}):(s==null?void 0:s.prefix)==="host"?n=Ze("__Host-"+e,t,{...s,path:"/",secure:!0,domain:void 0}):n=Ze(e,t,{path:"/",...s}),n},jt=(e,t,s,n)=>{const a=Cs(t,s,n);e.header("Set-Cookie",a,{append:!0})},Ne=(e,t,s)=>{const n=Lt(e,t,s==null?void 0:s.prefix);return jt(e,t,"",{...s,maxAge:0}),n};const h=new Ot;h.onError((e,t)=>{console.error("Unhandled error:",e);const s=e instanceof Error?`${e.name}: ${e.message}`:String(e);return t.text(`Internal Error
${s}`,500)});h.use("/api/*",Es({origin:e=>e?e.endsWith(".pages.dev")||e==="http://localhost:8788"||e==="http://127.0.0.1:8788"?e:null:"*",credentials:!0}));const Pe=new Map;let lt=0;function Bt(e,t,s){const n=Date.now();if(n-lt>6e4){lt=n;for(const[r,o]of Pe)n>o.resetAt&&Pe.delete(r)}let a=Pe.get(e);return(!a||n>a.resetAt)&&(a={count:0,resetAt:n+s*1e3},Pe.set(e,a)),a.count++,!(a.count>t)}function l(e,t,s){return e.json({ok:!1,error:s},t)}function st(e){const t=new Uint8Array(e);let s="";for(let n=0;n<t.length;n++)s+=String.fromCharCode(t[n]);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}function At(e){for(e=e.replace(/-/g,"+").replace(/_/g,"/");e.length%4;)e+="=";const t=atob(e),s=new Uint8Array(t.length);for(let n=0;n<t.length;n++)s[n]=t.charCodeAt(n);return s}async function Ds(e,t){const s=new TextEncoder,n=await crypto.subtle.importKey("raw",s.encode(e),{name:"HMAC",hash:"SHA-256"},!1,["sign"]),a=await crypto.subtle.sign("HMAC",n,s.encode(t));return st(a)}async function Ts(e,t,s){const n=new TextEncoder,a=await crypto.subtle.importKey("raw",n.encode(e),{name:"HMAC",hash:"SHA-256"},!1,["verify"]);return crypto.subtle.verify("HMAC",a,At(s),n.encode(t))}function ve(e=16){const t=new Uint8Array(e);return crypto.getRandomValues(t),[...t].map(s=>s.toString(16).padStart(2,"0")).join("")}async function le(e,t,s=1e5){const n=new TextEncoder,a=new Uint8Array(t.match(/.{1,2}/g).map(i=>parseInt(i,16))),r=await crypto.subtle.importKey("raw",n.encode(e),"PBKDF2",!1,["deriveBits"]),o=await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:a,iterations:s},r,256);return st(o)}async function Rs(e,t){const s=st(new TextEncoder().encode(JSON.stringify(t))),n=await Ds(e,s);return`v1.${s}.${n}`}async function Ns(e,t){const s=t.split(".");if(s.length!==3||s[0]!=="v1")return null;const n=s[1],a=s[2];if(!await Ts(e,n,a))return null;const o=new TextDecoder().decode(At(n));return JSON.parse(o)}h.use("*",async(e,t)=>{const s=e.env.ADMIN_LOGIN_ID||"",n=e.env.ADMIN_PASSWORD||"",a=e.env.SESSION_SECRET;if(!s||!n||!a)return t();if(!await e.env.DB.prepare("SELECT id FROM users WHERE role='admin' AND login_id=? LIMIT 1").bind(s).first()){const o=crypto.randomUUID(),i=ve(16),d=await le(n,i);await e.env.DB.prepare(`INSERT INTO users (id, role, login_id, password_hash, password_salt, name, grade, class_name, is_active)
       VALUES (?, 'admin', ?, ?, ?, 'admin', 0, '-', 1)`).bind(o,s,d,i).run()}return t()});h.use("/api/*",async(e,t)=>{const s=Lt(e,"session");if(!s)return t();const n=e.env.SESSION_SECRET;if(!n)return t();const a=await Ns(n,s);if(!(a!=null&&a.id))return t();const r=720*60*60;return a.iat&&Math.floor(Date.now()/1e3)-a.iat>r?(Ne(e,"session",{path:"/"}),t()):(e.set("user",{id:a.id,role:a.role,loginId:a.loginId,isActive:!!a.isActive}),t())});h.post("/api/auth/signup",async e=>{const t=await e.req.json().catch(()=>null);if(!t)return l(e,400,"invalid_json");const s=String(t.loginId||"").trim(),n=String(t.password||""),a=String(t.name||"").trim(),r=Number(t.grade),o=String(t.className||"").trim();if(!s||s.length<3)return l(e,400,"loginId_too_short");if(!n||n.length<6)return l(e,400,"password_too_short");if(!a)return l(e,400,"name_required");if(!Number.isFinite(r)||r<1||r>12)return l(e,400,"grade_invalid");if(!o)return l(e,400,"class_required");const i=crypto.randomUUID(),d=ve(16),c=await le(n,d);try{await e.env.DB.prepare(`INSERT INTO users (id, role, login_id, password_hash, password_salt, name, grade, class_name, is_active)
       VALUES (?, 'student', ?, ?, ?, ?, ?, ?, 0)`).bind(i,s,c,d,a,r,o).run()}catch{return l(e,409,"loginId_taken")}return e.json({ok:!0,status:"ok"})});h.post("/api/auth/login",async e=>{const t=await e.req.json().catch(()=>null);if(!t)return l(e,400,"invalid_json");const s=String(t.loginId||"").trim(),n=String(t.password||"");if(!s||!n)return l(e,400,"missing_credentials");let a=await e.env.DB.prepare(`SELECT id, role, login_id as loginId, password_hash as hash, password_salt as salt, is_active as isActive,
            must_change_password as mustChangePassword
     FROM users WHERE login_id = ? LIMIT 1`).bind(s).first();if(!a){const i=await e.env.DB.prepare(`SELECT id, 'teacher' as role, login_id as loginId, password_hash as hash, password_salt as salt,
              is_active as isActive, 0 as mustChangePassword
       FROM teacher_accounts WHERE login_id = ? LIMIT 1`).bind(s).first();i&&(a=i)}if(!a||await le(n,a.salt)!==a.hash)return l(e,401,"invalid_credentials");if((a.role==="student"||a.role==="teacher")&&!a.isActive)return l(e,403,"pending_approval");a.role==="student"&&a.mustChangePassword;const o=await Rs(e.env.SESSION_SECRET,{id:a.id,role:a.role,loginId:a.loginId,isActive:!!a.isActive,iat:Math.floor(Date.now()/1e3)});return jt(e,"session",o,{httpOnly:!0,secure:!0,sameSite:"Lax",path:"/",maxAge:3600*24*30}),e.json({ok:!0,role:a.role,mustChangePassword:!!a.mustChangePassword})});h.post("/api/auth/logout",async e=>{const t={secure:!0,sameSite:"Lax",httpOnly:!0};return Ne(e,"session",{...t,path:"/"}),Ne(e,"session",{...t,path:"/api"}),e.json({ok:!0})});h.get("/api/auth/me",async e=>{const t=e.get("user");if(!t)return e.json({ok:!0,user:null});if(t.role==="teacher"){const n=await e.env.DB.prepare("SELECT name, school FROM teacher_accounts WHERE id = ? LIMIT 1").bind(t.id).first();return e.json({ok:!0,user:{...t,name:n==null?void 0:n.name,school:n==null?void 0:n.school,grade:null}})}let s=null;try{const n=await e.env.DB.prepare("SELECT grade, created_at FROM users WHERE id = ? LIMIT 1").bind(t.id).first();if(n&&(s=n.grade??null,s!==null&&s<6&&t.role==="student")){const a=new Date,r=a.getUTCFullYear(),o=a.getUTCMonth()+1,i=new Date(n.created_at),d=i.getUTCFullYear(),p=i.getUTCMonth()+1>=4?d:d-1,f=(o>=4?r:r-1)-p;if(f>0){const w=Math.min(6,n.grade+f);w!==n.grade&&(await e.env.DB.prepare("UPDATE users SET grade=? WHERE id=?").bind(w,t.id).run(),s=w)}}}catch{}return e.json({ok:!0,user:{...t,grade:s}})});function Ie(e){const t=e.get("user");return!t||t.role!=="student"&&t.role!=="admin"&&t.role!=="teacher"?null:t}h.get("/api/student/progress",async e=>{const t=Ie(e);if(!t)return l(e,401,"unauthorized");const s=await e.env.DB.prepare("SELECT state_json as stateJson, updated_at as updatedAt FROM progress WHERE user_id = ?").bind(t.id).first();return e.json({ok:!0,progress:s?{stateJson:s.stateJson,updatedAt:s.updatedAt}:null})});h.put("/api/student/progress",async e=>{const t=Ie(e);if(!t)return l(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return l(e,400,"invalid_json");const n=JSON.stringify(s.state??s);if(t.role==="teacher")return e.json({ok:!0});if(n.length>1e6)return e.json({ok:!0});try{await e.env.DB.prepare(`INSERT INTO progress (user_id, state_json, updated_at)
       VALUES (?, ?, datetime('now'))
       ON CONFLICT(user_id) DO UPDATE SET state_json=excluded.state_json, updated_at=datetime('now')`).bind(t.id,n).run()}catch(a){return console.error("[progress] DB error:",(a==null?void 0:a.message)||a),l(e,500,"db_error")}try{const a=await e.env.DB.prepare("SELECT name, grade FROM users WHERE id=? LIMIT 1").bind(t.id).first(),r=Os(n,(a==null?void 0:a.name)||""),o=Number((a==null?void 0:a.grade)||0),i=Ht(),d=await e.env.DB.prepare("SELECT week_start, correct_count, total_level, battle_power, pokedex_count, wild_win_streak, ranking_points FROM ranking_stats WHERE user_id=? LIMIT 1").bind(t.id).first();let c=0,p=0,m=0,f=0,w=0,b=0;d&&d.week_start===i||d&&(c=Number(d.correct_count||0),p=Number(d.total_level||0),m=Number(d.battle_power||0),f=Number(d.pokedex_count||0),w=Number(d.wild_win_streak||0),b=Number(d.ranking_points||0)),d?d.week_start!==i?await e.env.DB.prepare(`UPDATE ranking_stats SET
           display_name=?, total_level=?, monster_count=?, correct_count=?, ranking_points=?,
           grade=?, battle_power=?, pokedex_count=?, wild_win_streak=?,
           week_start=?, week_base_correct_count=?, week_base_total_level=?, week_base_battle_power=?, week_base_pokedex_count=?, week_base_wild_win_streak=?, week_base_ranking_points=?,
           updated_at=datetime('now')
         WHERE user_id=?`).bind(r.displayName,r.totalLevel,r.monsterCount,r.correctCount,r.rankingPoints,o,r.battlePower,r.pokedexCount,r.wildWinStreak,i,c,p,m,f,w,b,t.id).run():await e.env.DB.prepare(`UPDATE ranking_stats SET
           display_name=?, total_level=?, monster_count=?, correct_count=?, ranking_points=?,
           grade=?, battle_power=?, pokedex_count=?, wild_win_streak=?,
           updated_at=datetime('now')
         WHERE user_id=?`).bind(r.displayName,r.totalLevel,r.monsterCount,r.correctCount,r.rankingPoints,o,r.battlePower,r.pokedexCount,r.wildWinStreak,t.id).run():await e.env.DB.prepare(`INSERT INTO ranking_stats (user_id, display_name, total_level, monster_count, correct_count, ranking_points,
           grade, battle_power, pokedex_count, wild_win_streak,
           week_start, week_base_correct_count, week_base_total_level, week_base_battle_power, week_base_pokedex_count, week_base_wild_win_streak, week_base_ranking_points,
           updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`).bind(t.id,r.displayName,r.totalLevel,r.monsterCount,r.correctCount,r.rankingPoints,o,r.battlePower,r.pokedexCount,r.wildWinStreak,i,r.correctCount,r.totalLevel,r.battlePower,r.pokedexCount,r.wildWinStreak,r.rankingPoints).run()}catch{}return e.json({ok:!0})});h.post("/api/student/results",async e=>{const t=Ie(e);if(!t)return l(e,401,"unauthorized");if(!Bt(`results:${t.id}`,30,60))return l(e,429,"too_many_requests");const s=await e.req.json().catch(()=>null);if(!s)return l(e,400,"invalid_json");const n=String(s.unit||"").trim(),a=s.questionId!=null?String(s.questionId):null,r=s.isCorrect?1:0,o=s.timeMs!=null?Number(s.timeMs):null,i=s.answeredAt?String(s.answeredAt):null,d=s.meta?JSON.stringify(s.meta):null;return n?(await e.env.DB.prepare(`INSERT INTO learning_results (user_id, unit, question_id, is_correct, time_ms, answered_at, meta_json)
     VALUES (?, ?, ?, ?, ?, COALESCE(?, datetime('now')), ?)`).bind(t.id,n,a,r,o,i,d).run(),e.json({ok:!0})):l(e,400,"unit_required")});function Os(e,t){try{const s=JSON.parse(e),n=s.state||s,a=Number(n.level||1),r=n.monsters||{},o=Object.keys(r).length,i=Object.values(r).reduce((v,g)=>v+Number((g==null?void 0:g.level)||1),0),d=a+i,c=n.trainingProgress||{},p=Object.values(c).reduce((v,g)=>v+Number((g==null?void 0:g.correctCount)??(g==null?void 0:g.count)??0),0),m=Object.values(c).reduce((v,g)=>(g==null?void 0:g.rankingPoints)!=null?v+Number(g.rankingPoints):v+Number((g==null?void 0:g.correctCount)??(g==null?void 0:g.count)??0),0),f=Array.isArray(n.party)?n.party:[];let w=0;for(const v of f){const g=r[String(v)];if(g){const S=Number(g.level||1),C=Number(g.atk||0),T=Number(g.def||0),H=Number(g.hp||0),O=Number(g.spd||0);w+=C+T+H+O}}const b=Array.isArray(n.pokedex)?n.pokedex.length:0,x=n.max||n.M&&n.M.max||{},_=Number(x.winStreak||0);return{displayName:String(n.name||t).slice(0,30),totalLevel:d,monsterCount:o,correctCount:p,rankingPoints:m,battlePower:w,pokedexCount:b,wildWinStreak:_}}catch{return{displayName:t,totalLevel:0,monsterCount:0,correctCount:0,rankingPoints:0,battlePower:0,pokedexCount:0,wildWinStreak:0}}}function Ht(){const e=new Date,t=e.getUTCDay(),s=t===0?6:t-1,n=new Date(e);return n.setUTCDate(e.getUTCDate()-s),n.toISOString().slice(0,10)}function D(e){const t=e.get("user");return!t||t.role!=="admin"?null:t}h.get("/api/admin/pending",async e=>{if(!D(e))return l(e,401,"unauthorized");const s=await e.env.DB.prepare(`SELECT id, login_id as loginId, name, grade, class_name as className, created_at as createdAt, disabled_reason as disabledReason
     FROM users WHERE role='student' AND is_active=0
     ORDER BY created_at DESC`).all();return e.json({ok:!0,users:s.results})});h.get("/api/admin/users",async e=>{if(!D(e))return l(e,401,"unauthorized");const s=e.req.query("grade"),n=e.req.query("class"),a=["role='student'"],r=[];s&&(a.push("grade = ?"),r.push(Number(s))),n&&(a.push("class_name = ?"),r.push(String(n)));const o=`SELECT id, login_id as loginId, name, grade, class_name as className, is_active as isActive, disabled_reason as disabledReason, created_at as createdAt
               FROM users WHERE ${a.join(" AND ")} ORDER BY grade ASC, class_name ASC, name ASC`,i=await e.env.DB.prepare(o).bind(...r).all();return e.json({ok:!0,users:i.results})});h.post("/api/admin/approve/:id",async e=>{if(!D(e))return l(e,401,"unauthorized");const s=e.req.param("id");return await e.env.DB.prepare("UPDATE users SET is_active=1, disabled_reason=NULL WHERE id=? AND role='student'").bind(s).run(),e.json({ok:!0})});h.post("/api/admin/disable/:id",async e=>{if(!D(e))return l(e,401,"unauthorized");const s=e.req.param("id"),n=await e.req.json().catch(()=>({})),a=n!=null&&n.reason?String(n.reason).slice(0,200):null;return await e.env.DB.prepare("UPDATE users SET is_active=0, disabled_reason=? WHERE id=? AND role='student'").bind(a,s).run(),e.json({ok:!0})});h.post("/api/admin/reset-password/:id",async e=>{if(!D(e))return l(e,401,"unauthorized");const s=e.req.param("id"),n=ve(4),a=ve(16),r=await le(n,a);return await e.env.DB.prepare(`UPDATE users
       SET password_hash=?, password_salt=?, password_updated_at=datetime('now'), must_change_password=1
       WHERE id=? AND role='student'`).bind(r,a,s).run(),e.json({ok:!0,tempPassword:n})});h.delete("/api/admin/delete/:id",async e=>{const t=D(e);if(!t)return l(e,401,"unauthorized");const s=e.req.param("id");if(s===t.id)return l(e,400,"cannot_delete_self");const n=await e.env.DB.prepare("SELECT role FROM users WHERE id=? LIMIT 1").bind(s).first();return n?n.role!=="student"?l(e,400,"cannot_delete_admin"):(await e.env.DB.prepare("DELETE FROM progress WHERE user_id=?").bind(s).run(),await e.env.DB.prepare("DELETE FROM learning_results WHERE user_id=?").bind(s).run(),await e.env.DB.prepare("DELETE FROM battle_answers WHERE user_id=?").bind(s).run(),await e.env.DB.prepare("DELETE FROM users WHERE id=? AND role='student'").bind(s).run(),e.json({ok:!0})):l(e,404,"user_not_found")});h.post("/api/admin/change-password",async e=>{const t=D(e);if(!t)return l(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return l(e,400,"invalid_json");const n=String(s.oldPassword||""),a=String(s.newPassword||"");if(!n||!a)return l(e,400,"missing_fields");if(a.length<8)return l(e,400,"new_password_too_short");const r=await e.env.DB.prepare("SELECT id, password_hash as hash, password_salt as salt FROM users WHERE id=? AND role='admin' LIMIT 1").bind(t.id).first();if(!r)return l(e,404,"admin_not_found");if(await le(n,r.salt)!==r.hash)return l(e,401,"invalid_old_password");const i=ve(16),d=await le(a,i);return await e.env.DB.prepare("UPDATE users SET password_hash=?, password_salt=?, password_updated_at=datetime('now'), must_change_password=0 WHERE id=?").bind(d,i,t.id).run(),e.json({ok:!0})});h.get("/api/admin/results",async e=>{if(!D(e))return l(e,401,"unauthorized");const s=Math.min(500,Math.max(1,Number(e.req.query("limit")||100))),n=e.req.query("from"),a=e.req.query("to"),r=e.req.query("grade"),o=e.req.query("class"),i=[],d=[];n&&(i.push("r.answered_at >= ?"),d.push(n)),a&&(i.push("r.answered_at <= ?"),d.push(a)),r&&(i.push("u.grade = ?"),d.push(Number(r))),o&&(i.push("u.class_name = ?"),d.push(String(o)));const c=i.length?`WHERE ${i.join(" AND ")}`:"",p=await e.env.DB.prepare(`SELECT r.id, r.answered_at as answeredAt, r.unit, r.question_id as questionId, r.is_correct as isCorrect, r.time_ms as timeMs,
            u.login_id as loginId, u.name, u.grade, u.class_name as className
     FROM learning_results r
     JOIN users u ON u.id = r.user_id
     ${c}
     ORDER BY r.answered_at DESC
     LIMIT ?`).bind(...d,s).all();return e.json({ok:!0,results:p.results})});h.get("/api/admin/results.csv",async e=>{if(!D(e))return l(e,401,"unauthorized");const s=e.req.query("from"),n=e.req.query("to"),a=e.req.query("grade"),r=e.req.query("class"),o=[],i=[];s&&(o.push("r.answered_at >= ?"),i.push(s)),n&&(o.push("r.answered_at <= ?"),i.push(n)),a&&(o.push("u.grade = ?"),i.push(Number(a))),r&&(o.push("u.class_name = ?"),i.push(String(r)));const d=o.length?`WHERE ${o.join(" AND ")}`:"",c=await e.env.DB.prepare(`SELECT r.answered_at as answeredAt, u.grade, u.class_name as className, u.name, u.login_id as loginId,
            r.unit, r.question_id as questionId, r.is_correct as isCorrect, r.time_ms as timeMs
     FROM learning_results r
     JOIN users u ON u.id = r.user_id
     ${d}
     ORDER BY r.answered_at DESC
     LIMIT 5000`).bind(...i).all(),p=["answeredAt","grade","class","name","loginId","unit","questionId","isCorrect","timeMs"],m=w=>{const b=w==null?"":String(w);return/[\n\r",]/.test(b)?'"'+b.replace(/"/g,'""')+'"':b},f=[p.join(",")];for(const w of c.results)f.push([w.answeredAt,w.grade,w.className,w.name,w.loginId,w.unit,w.questionId,w.isCorrect,w.timeMs].map(m).join(","));return new Response(f.join(`
`),{headers:{"Content-Type":"text/csv; charset=utf-8","Content-Disposition":'attachment; filename="learning_results.csv"'}})});h.get("/api/admin/pending-teachers",async e=>{if(!D(e))return l(e,401,"unauthorized");const s=await e.env.DB.prepare("SELECT id, login_id as loginId, name, school, created_at as createdAt FROM teacher_accounts WHERE is_active=0 ORDER BY created_at DESC").all();return e.json({ok:!0,teachers:s.results})});h.post("/api/admin/approve-teacher/:id",async e=>D(e)?(await e.env.DB.prepare("UPDATE teacher_accounts SET is_active=1 WHERE id=?").bind(e.req.param("id")).run(),e.json({ok:!0})):l(e,401,"unauthorized"));h.delete("/api/admin/reject-teacher/:id",async e=>D(e)?(await e.env.DB.prepare("DELETE FROM teacher_accounts WHERE id=? AND is_active=0").bind(e.req.param("id")).run(),e.json({ok:!0})):l(e,401,"unauthorized"));h.get("/api/admin/settings",async e=>{if(!D(e))return l(e,401,"unauthorized");const s=await e.env.DB.prepare("SELECT key, value FROM admin_settings").all(),n={};for(const a of s.results)n[a.key]=a.value;return e.json({ok:!0,settings:n})});h.put("/api/admin/settings",async e=>{if(!D(e))return l(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return l(e,400,"invalid_json");for(const[n,a]of Object.entries(s))typeof a=="string"&&await e.env.DB.prepare(`INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
       ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now')`).bind(n,a).run();return e.json({ok:!0})});h.put("/api/admin/user-grade",async e=>{const t=e.get("user");if(!t||t.role!=="admin"&&t.role!=="teacher")return l(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return l(e,400,"invalid_json");const n=String(s.userId||""),a=Number(s.grade);return!n||!Number.isFinite(a)||a<1||a>6?l(e,400,"invalid_grade"):(await e.env.DB.prepare("UPDATE users SET grade=? WHERE id=? AND role='student'").bind(a,n).run(),e.json({ok:!0}))});function A(e){const t=e.get("user");return!t||t.role!=="teacher"&&t.role!=="admin"?null:t}function ct(){const e="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";let t="";const s=new Uint8Array(6);crypto.getRandomValues(s);for(let n=0;n<6;n++)t+=e[s[n]%e.length];return t}h.post("/api/auth/teacher-signup",async e=>{const t=await e.req.json().catch(()=>null);if(!t)return l(e,400,"invalid_json");const s=String(t.loginId||"").trim(),n=String(t.password||""),a=String(t.name||"").trim(),r=String(t.school||"").trim();if(!s||s.length<3)return l(e,400,"loginId_too_short");if(!n||n.length<6)return l(e,400,"password_too_short");if(!a)return l(e,400,"name_required");const o=crypto.randomUUID(),i=ve(16),d=await le(n,i);try{await e.env.DB.prepare("INSERT INTO teacher_accounts (id, login_id, password_hash, password_salt, name, school) VALUES (?, ?, ?, ?, ?, ?)").bind(o,s,d,i,a,r).run()}catch{return l(e,409,"loginId_taken")}return e.json({ok:!0})});h.post("/api/teacher/class",async e=>{const t=A(e);if(!t)return l(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return l(e,400,"invalid_json");const n=String(s.name||"").trim();if(!n)return l(e,400,"name_required");let a=ct();for(let o=0;o<5&&await e.env.DB.prepare("SELECT id FROM classes WHERE class_code=? LIMIT 1").bind(a).first();o++)a=ct();const r=crypto.randomUUID();return await e.env.DB.prepare("INSERT INTO classes (id, class_code, name, teacher_id) VALUES (?, ?, ?, ?)").bind(r,a,n,t.id).run(),e.json({ok:!0,classId:r,classCode:a})});h.get("/api/teacher/classes",async e=>{const t=A(e);if(!t)return l(e,401,"unauthorized");const n=t.role==="admin"?await e.env.DB.prepare(`SELECT c.id, c.class_code as classCode, c.name, c.ranking_enabled as rankingEnabled, c.homework_enabled as homeworkEnabled, c.contact_enabled as contactEnabled, c.created_at as createdAt, t.name as teacherName
         FROM classes c LEFT JOIN teacher_accounts t ON t.id = c.teacher_id ORDER BY c.created_at DESC`).all():await e.env.DB.prepare("SELECT id, class_code as classCode, name, ranking_enabled as rankingEnabled, homework_enabled as homeworkEnabled, contact_enabled as contactEnabled, created_at as createdAt FROM classes WHERE teacher_id=? ORDER BY created_at DESC").bind(t.id).all();return e.json({ok:!0,classes:n.results})});h.delete("/api/teacher/class/:classId",async e=>{const t=A(e);if(!t)return l(e,401,"unauthorized");const s=e.req.param("classId");return await e.env.DB.prepare("DELETE FROM class_members WHERE class_id=?").bind(s).run(),t.role==="admin"?await e.env.DB.prepare("DELETE FROM classes WHERE id=?").bind(s).run():await e.env.DB.prepare("DELETE FROM classes WHERE id=? AND teacher_id=?").bind(s,t.id).run(),e.json({ok:!0})});h.put("/api/teacher/class/:classId/homework-toggle",async e=>{var o;const t=A(e);if(!t)return l(e,401,"unauthorized");const s=e.req.param("classId"),n=await e.req.json().catch(()=>null),a=n!=null&&n.enabled?1:0;return(o=(t.role==="admin"?await e.env.DB.prepare("UPDATE classes SET homework_enabled=? WHERE id=?").bind(a,s).run():await e.env.DB.prepare("UPDATE classes SET homework_enabled=? WHERE id=? AND teacher_id=?").bind(a,s,t.id).run()).meta)!=null&&o.changes?e.json({ok:!0,homeworkEnabled:a}):l(e,404,"class_not_found")});h.put("/api/teacher/class/:classId/contact-toggle",async e=>{var o;const t=A(e);if(!t)return l(e,401,"unauthorized");const s=e.req.param("classId"),n=await e.req.json().catch(()=>null),a=n!=null&&n.enabled?1:0;return(o=(t.role==="admin"?await e.env.DB.prepare("UPDATE classes SET contact_enabled=? WHERE id=?").bind(a,s).run():await e.env.DB.prepare("UPDATE classes SET contact_enabled=? WHERE id=? AND teacher_id=?").bind(a,s,t.id).run()).meta)!=null&&o.changes?e.json({ok:!0,contactEnabled:a}):l(e,404,"class_not_found")});h.put("/api/teacher/class/:classId/ranking-toggle",async e=>{var o;const t=A(e);if(!t)return l(e,401,"unauthorized");const s=e.req.param("classId"),n=await e.req.json().catch(()=>null),a=n!=null&&n.enabled?1:0;return(o=(t.role==="admin"?await e.env.DB.prepare("UPDATE classes SET ranking_enabled=? WHERE id=?").bind(a,s).run():await e.env.DB.prepare("UPDATE classes SET ranking_enabled=? WHERE id=? AND teacher_id=?").bind(a,s,t.id).run()).meta)!=null&&o.changes?e.json({ok:!0,rankingEnabled:a}):l(e,404,"class_not_found")});h.get("/api/teacher/class/:classId/ranking",async e=>{const t=A(e);if(!t)return l(e,401,"unauthorized");const s=e.req.param("classId"),n=t.role==="admin"?await e.env.DB.prepare("SELECT id, name, class_code as classCode FROM classes WHERE id=? LIMIT 1").bind(s).first():await e.env.DB.prepare("SELECT id, name, class_code as classCode FROM classes WHERE id=? AND teacher_id=? LIMIT 1").bind(s,t.id).first();if(!n)return l(e,404,"class_not_found");const a=await e.env.DB.prepare(`
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
  `).bind(s).all();return e.json({ok:!0,class:n,members:a.results})});h.get("/api/teacher/class/:classId/unit-analytics",async e=>{var c,p,m,f,w;const t=A(e);if(!t)return l(e,401,"unauthorized");const s=e.req.param("classId"),n=t.role==="admin"?await e.env.DB.prepare("SELECT id, name FROM classes WHERE id=? LIMIT 1").bind(s).first():await e.env.DB.prepare("SELECT id, name FROM classes WHERE id=? AND teacher_id=? LIMIT 1").bind(s,t.id).first();if(!n)return l(e,404,"class_not_found");const a=await e.env.DB.prepare(`
    SELECT u.id, u.name, u.grade, p.state_json as stateJson
    FROM class_members cm
    JOIN users u ON u.id = cm.user_id
    LEFT JOIN progress p ON p.user_id = cm.user_id
    WHERE cm.class_id = ?
    ORDER BY u.name
  `).bind(s).all(),r=[],o=new Map;for(const b of a.results){let x={},_={},v=0;try{if(b.stateJson){const g=JSON.parse(b.stateJson);x=((p=(c=g==null?void 0:g.metrics)==null?void 0:c.learn)==null?void 0:p.byUnit)||{},_=((f=(m=g==null?void 0:g.metrics)==null?void 0:m.learn)==null?void 0:f.bySubject)||{};const S=((w=g==null?void 0:g.metrics)==null?void 0:w.daily)||{},C=Object.keys(S).filter(H=>{var O;return(((O=S[H])==null?void 0:O.training)||0)>=1}).sort();let T=0;for(let H=C.length-1;H>=0;H--){const O=new Date(C[H]+"T00:00:00+09:00");if(Math.round((Date.now()-O.getTime())/864e5)===C.length-1-H)T++;else break}v=T}}catch{}Object.keys(x).forEach(g=>{const S=x[g];!o.has(g)&&S.unitName&&o.set(g,{name:S.unitName,subject:S.subjectName||""})}),r.push({id:b.id,name:b.name||"",grade:b.grade||"",byUnit:x,bySubject:_,learnStreak:v})}const i=[];o.forEach((b,x)=>{r.some(_=>{var v;return(((v=_.byUnit[x])==null?void 0:v.total)||0)>=5})&&i.push(x)});const d=i.map(b=>{const x=o.get(b),_=r.filter(S=>{var C;return(((C=S.byUnit[b])==null?void 0:C.total)||0)>=5}),v=_.reduce((S,C)=>{const T=C.byUnit[b];return S+(T.total?T.correct/T.total:0)},0),g=_.length>0?Math.round(v/_.length*100):null;return{mode:b,name:x.name,subject:x.subject,classAvg:g,studentCount:_.length}}).sort((b,x)=>(b.classAvg??101)-(x.classAvg??101));return e.json({ok:!0,class:n,unitSummary:d,unitInfo:Object.fromEntries(o),students:r.map(b=>({id:b.id,name:b.name,grade:b.grade,learnStreak:b.learnStreak,bySubject:Object.fromEntries(Object.entries(b.bySubject).map(([x,_])=>[x,{total:_.total||0,correct:_.correct||0,acc:_.total?Math.round(_.correct/_.total*100):0}])),units:Object.fromEntries(i.map(x=>{const _=b.byUnit[x];return!_||(_.total||0)<5?[x,null]:[x,{total:_.total,correct:_.correct,acc:Math.round(_.correct/_.total*100)}]}))}))})});h.post("/api/student/join-class",async e=>{const t=Ie(e);if(!t)return l(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return l(e,400,"invalid_json");const n=String(s.classCode||"").trim().toUpperCase();if(!n)return l(e,400,"code_required");const a=await e.env.DB.prepare("SELECT id, name FROM classes WHERE class_code=? LIMIT 1").bind(n).first();return a?(await e.env.DB.prepare("SELECT 1 FROM class_members WHERE user_id=? AND class_id=? LIMIT 1").bind(t.id,a.id).first()||(await e.env.DB.prepare("DELETE FROM class_members WHERE user_id=?").bind(t.id).run(),await e.env.DB.prepare("INSERT INTO class_members (user_id, class_id) VALUES (?, ?)").bind(t.id,a.id).run()),e.json({ok:!0,className:a.name})):l(e,404,"class_not_found")});h.get("/api/student/class-info",async e=>{const t=Ie(e);if(!t)return l(e,401,"unauthorized");const s=await e.env.DB.prepare(`
    SELECT c.id, c.name, c.class_code as classCode, cm.joined_at as joinedAt,
           c.homework_enabled as homeworkEnabled, c.contact_enabled as contactEnabled
    FROM class_members cm JOIN classes c ON c.id = cm.class_id
    WHERE cm.user_id = ? LIMIT 1
  `).bind(t.id).first();return e.json({ok:!0,class:s||null})});h.post("/api/student/leave-class",async e=>{const t=Ie(e);return t?(await e.env.DB.prepare("DELETE FROM class_members WHERE user_id=?").bind(t.id).run(),e.json({ok:!0})):l(e,401,"unauthorized")});h.get("/api/ranking",async e=>{const t=e.get("user");if(!t)return l(e,401,"unauthorized");const s=await e.env.DB.prepare("SELECT value FROM admin_settings WHERE key='ranking_scope' LIMIT 1").first(),n=await e.env.DB.prepare("SELECT value FROM admin_settings WHERE key='ranking_enabled' LIMIT 1").first(),a=(s==null?void 0:s.value)||"class",r=(n==null?void 0:n.value)!=="0";if(!r||a==="hidden")return e.json({ok:!0,ranking:[],scope:a,enabled:!1,hidden:!0});const o=e.req.query("type")||"overall",i=e.req.query("period")||"cumulative",d=Number(e.req.query("grade")||0),c=Ht();let p="rs.total_level",m="";switch(o){case"overall":p="rs.total_level";break;case"power":p="rs.battle_power";break;case"correct":p="rs.ranking_points";break;case"pokedex":p="rs.pokedex_count";break;case"wild":p="rs.wild_win_streak";break;case"grade":p="rs.ranking_points";break}if(i==="weekly")switch(o){case"overall":m=", (rs.total_level - rs.week_base_total_level) as weeklyScore",p="weeklyScore";break;case"power":m=", (rs.battle_power - rs.week_base_battle_power) as weeklyScore",p="weeklyScore";break;case"correct":case"grade":m=", (rs.ranking_points - rs.week_base_ranking_points) as weeklyScore",p="weeklyScore";break;case"pokedex":m=", (rs.pokedex_count - rs.week_base_pokedex_count) as weeklyScore",p="weeklyScore";break;case"wild":m=", (rs.wild_win_streak - rs.week_base_wild_win_streak) as weeklyScore",p="weeklyScore";break}const f=o==="grade"&&d>=1&&d<=6?` AND rs.grade = ${d}`:"",w=i==="weekly"?` AND rs.week_start = '${c}'`:"";let b="";const x=[],_=`rs.user_id as userId, rs.display_name as displayName,
    rs.total_level as totalLevel, rs.monster_count as monsterCount, rs.correct_count as correctCount,
    rs.ranking_points as rankingPoints,
    rs.grade, rs.battle_power as battlePower, rs.pokedex_count as pokedexCount, rs.wild_win_streak as wildWinStreak
    ${m}`;if(a==="global"||t.role==="admin")b=`SELECT ${_}
           FROM ranking_stats rs
           JOIN users u ON u.id = rs.user_id AND u.is_active=1
           JOIN class_members cm ON cm.user_id = rs.user_id
           JOIN classes cl ON cl.id = cm.class_id AND cl.ranking_enabled = 1
           WHERE 1=1 ${f} ${w}
           ORDER BY ${p} DESC, rs.correct_count DESC LIMIT 100`;else if(a==="class"){const S=await e.env.DB.prepare("SELECT cm.class_id, cl.ranking_enabled FROM class_members cm JOIN classes cl ON cl.id=cm.class_id WHERE cm.user_id=? LIMIT 1").bind(t.id).first();if(!S)return e.json({ok:!0,ranking:[],scope:a,enabled:r,message:"no_class"});if(!S.ranking_enabled)return e.json({ok:!0,ranking:[],scope:a,enabled:r,message:"ranking_not_allowed"});b=`SELECT ${_}
           FROM ranking_stats rs
           JOIN class_members cm ON cm.user_id = rs.user_id AND cm.class_id = ?
           JOIN users u ON u.id = rs.user_id AND u.is_active=1
           WHERE 1=1 ${f} ${w}
           ORDER BY ${p} DESC, rs.correct_count DESC LIMIT 100`,x.push(S.class_id)}else return e.json({ok:!0,ranking:[],scope:a,enabled:!1,hidden:!0});const g=(await e.env.DB.prepare(b).bind(...x).all()).results.map((S,C)=>({...S,rank:C+1,isMe:S.userId===t.id}));return e.json({ok:!0,ranking:g,scope:a,enabled:r,type:o,period:i})});function Ls(){const e=new Uint8Array(16);return crypto.getRandomValues(e),[...e].map(t=>t.toString(16).padStart(2,"0")).join("")}h.post("/api/homework/submit",async e=>{const t=e.get("user");if(!t||t.role!=="student")return l(e,403,"forbidden");const s=await e.req.json().catch(()=>null);if(!s)return l(e,400,"invalid_json");const n=String(s.dayKey||"").slice(0,10);if(!n)return l(e,400,"day_key_required");const a=await e.env.DB.prepare("SELECT id FROM homework_submissions WHERE user_id=? AND day_key=? LIMIT 1").bind(t.id,n).first();if(a)return e.json({ok:!0,alreadySubmitted:!0,id:a.id});const r=await e.env.DB.prepare("SELECT c.teacher_id FROM class_members cm JOIN classes c ON c.id=cm.class_id WHERE cm.user_id=? LIMIT 1").bind(t.id).first(),o=(r==null?void 0:r.teacher_id)||null,i=Ls();return await e.env.DB.prepare(`
    INSERT INTO homework_submissions
      (id, user_id, day_key, submitted_at, todo, why, aim, minutes, end_weather,
       weather_reason, next_improve, rest_day, streak_after,
       reward_kind, reward_coins, reward_shards, bonus_coins, bonus_shards, teacher_id)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).bind(i,t.id,n,Date.now(),String(s.todo||"").slice(0,500),String(s.why||"").slice(0,500),String(s.aim||"").slice(0,500),Number(s.minutes||0),String(s.endWeather||"sun"),String(s.weatherReason||"").slice(0,500),String(s.nextImprove||"").slice(0,500),s.restDay?1:0,Number(s.streakAfter||0),String(s.rewardKind||"coin"),Number(s.rewardCoins||0),Number(s.rewardShards||0),Number(s.bonusCoins||0),Number(s.bonusShards||0),o).run(),e.json({ok:!0,id:i})});h.get("/api/homework/my",async e=>{const t=e.get("user");if(!t||t.role!=="student")return l(e,403,"forbidden");const s=await e.env.DB.prepare(`
    SELECT id, day_key as dayKey, submitted_at as submittedAt, rest_day as restDay,
           teacher_comment as teacherComment, has_physical as hasPhysical,
           returned_at as returnedAt, reward_claimed as rewardClaimed,
           reward_kind as rewardKind, reward_coins as rewardCoins, reward_shards as rewardShards,
           bonus_coins as bonusCoins, bonus_shards as bonusShards
    FROM homework_submissions WHERE user_id=? ORDER BY submitted_at DESC LIMIT 30
  `).bind(t.id).all();return e.json({ok:!0,submissions:s.results})});h.post("/api/homework/:id/claim",async e=>{const t=e.get("user");if(!t||t.role!=="student")return l(e,403,"forbidden");const s=e.req.param("id"),n=await e.env.DB.prepare(`
    SELECT * FROM homework_submissions WHERE id=? AND user_id=? LIMIT 1
  `).bind(s,t.id).first();if(!n)return l(e,404,"not_found");if(!n.returned_at)return l(e,400,"not_returned_yet");if(n.reward_claimed)return l(e,400,"already_claimed");const a=n.has_physical?1:.5,r=Math.floor((Number(n.reward_coins||0)+Number(n.bonus_coins||0))*a),o=Math.floor((Number(n.reward_shards||0)+Number(n.bonus_shards||0))*a),i=String(n.reward_kind||"coin");return await e.env.DB.prepare(`
    UPDATE homework_submissions SET reward_claimed=1, reward_claimed_at=? WHERE id=?
  `).bind(Date.now(),s).run(),e.json({ok:!0,coins:r,shards:o,rewardKind:i,hasPhysical:!!n.has_physical})});h.get("/api/teacher/homework",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return l(e,403,"forbidden");const s=e.req.query("classId");let n=`
    SELECT hs.id, hs.day_key as dayKey, hs.submitted_at as submittedAt,
           hs.todo, hs.why, hs.aim, hs.minutes,
           hs.end_weather as endWeather, hs.weather_reason as weatherReason, hs.next_improve as nextImprove,
           hs.rest_day as restDay, hs.reward_kind as rewardKind,
           hs.reward_coins as rewardCoins, hs.reward_shards as rewardShards,
           hs.bonus_coins as bonusCoins, hs.bonus_shards as bonusShards,
           hs.teacher_comment as teacherComment, hs.has_physical as hasPhysical,
           hs.returned_at as returnedAt, hs.reward_claimed as rewardClaimed,
           u.id as userId, u.name as studentName, u.grade, u.class_name as className
    FROM homework_submissions hs
    JOIN users u ON u.id = hs.user_id
    JOIN class_members cm ON cm.user_id = hs.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
  `;const a=[t.id];s&&(n+=" AND cl.id = ?",a.push(s)),n+=" ORDER BY hs.submitted_at DESC LIMIT 100";const r=await e.env.DB.prepare(n).bind(...a).all();return e.json({ok:!0,submissions:r.results})});h.post("/api/teacher/homework/:id/return",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return l(e,403,"forbidden");const s=e.req.param("id"),n=await e.req.json().catch(()=>({}));return await e.env.DB.prepare(`
    SELECT hs.id FROM homework_submissions hs
    JOIN class_members cm ON cm.user_id = hs.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
    WHERE hs.id = ? LIMIT 1
  `).bind(t.id,s).first()?(await e.env.DB.prepare(`
    UPDATE homework_submissions
    SET teacher_id=?, teacher_comment=?, has_physical=?, returned_at=?
    WHERE id=?
  `).bind(t.id,String(n.comment||"").slice(0,500),n.hasPhysical?1:0,Date.now(),s).run(),e.json({ok:!0})):l(e,404,"not_found")});function M(e){const t=e.get("user");return t||null}function Je(){const e="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";let t="";const s=new Uint8Array(6);crypto.getRandomValues(s);for(let n=0;n<6;n++)t+=e[s[n]%e.length];return t}h.post("/api/battle/create",async e=>{const t=M(e);if(!t)return l(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return l(e,400,"invalid_json");const n=JSON.stringify(s.party||[]),a=String(s.name||"プレイヤー").slice(0,20),r=String(s.area||"rounding").slice(0,40),o=String(s.battleMode||"normal").slice(0,10);await e.env.DB.prepare("DELETE FROM battle_rooms WHERE host_user_id=? AND status='waiting'").bind(t.id).run();let i=Je();for(let d=0;d<5&&await e.env.DB.prepare("SELECT id FROM battle_rooms WHERE id=?").bind(i).first();d++)i=Je();return await e.env.DB.prepare(`
    INSERT INTO battle_rooms (id, host_user_id, host_name, host_party_json, area, battle_mode, status, host_hp, guest_hp, host_score, guest_score, question_index)
    VALUES (?, ?, ?, ?, ?, ?, 'waiting', 100, 100, 0, 0, 0)
  `).bind(i,t.id,a,n,r,o).run(),e.json({ok:!0,roomId:i})});h.post("/api/battle/join/:roomId",async e=>{const t=M(e);if(!t)return l(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.req.json().catch(()=>null);if(!n)return l(e,400,"invalid_json");const a=String(n.name||"プレイヤー").slice(0,20),r=JSON.stringify(n.party||[]),o=await e.env.DB.prepare("SELECT * FROM battle_rooms WHERE id=? LIMIT 1").bind(s).first();return o?o.status!=="waiting"?l(e,409,"room_not_available"):o.host_user_id===t.id?l(e,400,"cannot_join_own_room"):(await e.env.DB.prepare(`
    UPDATE battle_rooms SET guest_user_id=?, guest_name=?, guest_party_json=?, status='ready', updated_at=datetime('now')
    WHERE id=? AND status='waiting'
  `).bind(t.id,a,r,s).run(),e.json({ok:!0,roomId:s,hostName:o.host_name,area:o.area,battleMode:o.battle_mode,hostParty:JSON.parse(o.host_party_json||"[]")})):l(e,404,"room_not_found")});h.get("/api/battle/room/:roomId",async e=>{const t=M(e);if(!t)return l(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.env.DB.prepare("SELECT * FROM battle_rooms WHERE id=? LIMIT 1").bind(s).first();if(!n)return l(e,404,"room_not_found");const a=n.host_user_id===t.id,r=n.guest_user_id===t.id;if(!a&&!r)return l(e,403,"not_a_participant");const o=await e.env.DB.prepare(`
    SELECT user_id, question_index, is_correct, answered_at FROM battle_answers
    WHERE room_id=? AND question_index=?
  `).bind(s,n.question_index).all(),i=a?"host":"guest",d=a?n.guest_user_id:n.host_user_id,c=o.results.find(m=>m.user_id===t.id),p=o.results.find(m=>m.user_id===d);return e.json({ok:!0,room:{id:n.id,status:n.status,area:n.area,hostName:n.host_name,guestName:n.guest_name,questionIndex:n.question_index,questionJson:n.current_question_json,hostScore:n.host_score,guestScore:n.guest_score,hostHp:n.host_hp,guestHp:n.guest_hp,winner:n.winner,myRole:i,myAnswer:c?{isCorrect:!!c.is_correct}:null,oppAnswered:!!p,oppCorrect:p?!!p.is_correct:null,battleMode:n.battle_mode,opponentParty:a?n.guest_party_json?JSON.parse(n.guest_party_json):null:n.host_party_json?JSON.parse(n.host_party_json):null,opponentName:a?n.guest_name:n.host_name}})});h.post("/api/battle/set-question/:roomId",async e=>{const t=M(e);if(!t)return l(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.req.json().catch(()=>null);if(!n)return l(e,400,"invalid_json");const a=await e.env.DB.prepare("SELECT * FROM battle_rooms WHERE id=? LIMIT 1").bind(s).first();if(!a)return l(e,404,"room_not_found");if(a.host_user_id!==t.id)return l(e,403,"host_only");if(a.status!=="ready"&&a.status!=="playing")return l(e,409,"invalid_status");const r=JSON.stringify(n.question),o=Number(n.questionIndex??a.question_index);return await e.env.DB.prepare(`
    UPDATE battle_rooms
    SET current_question_json=?, question_index=?, status='playing', updated_at=datetime('now')
    WHERE id=?
  `).bind(r,o,s).run(),e.json({ok:!0})});h.post("/api/battle/answer/:roomId",async e=>{const t=M(e);if(!t)return l(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.req.json().catch(()=>null);if(!n)return l(e,400,"invalid_json");const a=await e.env.DB.prepare("SELECT * FROM battle_rooms WHERE id=? LIMIT 1").bind(s).first();if(!a)return l(e,404,"room_not_found");if(a.status!=="playing")return l(e,409,"not_playing");const r=a.host_user_id===t.id,o=a.guest_user_id===t.id;if(!r&&!o)return l(e,403,"not_a_participant");const i=n.isCorrect?1:0,d=String(n.answer||"").slice(0,100),c=a.question_index;if(await e.env.DB.prepare(`
    SELECT id FROM battle_answers WHERE room_id=? AND user_id=? AND question_index=?
  `).bind(s,t.id,c).first())return e.json({ok:!0,alreadyAnswered:!0});await e.env.DB.prepare(`
    INSERT INTO battle_answers (room_id, user_id, question_index, answer, is_correct)
    VALUES (?, ?, ?, ?, ?)
  `).bind(s,t.id,c,d,i).run();const m=await e.env.DB.prepare(`
    SELECT user_id, is_correct FROM battle_answers WHERE room_id=? AND question_index=?
  `).bind(s,c).all(),f=m.results.find(T=>T.user_id===a.host_user_id),w=m.results.find(T=>T.user_id===a.guest_user_id);let b=a.host_score,x=a.guest_score,_=a.host_hp,v=a.guest_hp,g=!1,S=a.status,C=a.winner;if(f&&w){g=!0;const T=!!f.is_correct,H=!!w.is_correct;T&&!H?(b++,v=Math.max(0,v-20)):!T&&H&&(x++,_=Math.max(0,_-20));const O=c+1;(_<=0||v<=0||O>=5)&&(S="finished",b>x?C="host":x>b?C="guest":C="draw"),await e.env.DB.prepare(`
      UPDATE battle_rooms
      SET host_score=?, guest_score=?, host_hp=?, guest_hp=?, status=?, winner=?, updated_at=datetime('now')
      WHERE id=?
    `).bind(b,x,_,v,S,C,s).run()}return e.json({ok:!0,bothAnswered:g,hostScore:b,guestScore:x,hostHp:_,guestHp:v,status:S,winner:C})});h.post("/api/battle/leave/:roomId",async e=>{const t=M(e);if(!t)return l(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.env.DB.prepare("SELECT * FROM battle_rooms WHERE id=? LIMIT 1").bind(s).first();return n?(n.host_user_id===t.id?await e.env.DB.prepare("DELETE FROM battle_rooms WHERE id=?").bind(s).run():await e.env.DB.prepare(`
      UPDATE battle_rooms SET guest_user_id=NULL, guest_name=NULL, guest_party_json=NULL,
      status='waiting', current_question_json=NULL, question_index=0,
      host_score=0, guest_score=0, host_hp=100, guest_hp=100, winner=NULL, updated_at=datetime('now')
      WHERE id=?
    `).bind(s).run(),e.json({ok:!0})):e.json({ok:!0})});h.delete("/api/battle/cleanup",async e=>M(e)?(await e.env.DB.prepare(`
    DELETE FROM battle_rooms WHERE created_at < datetime('now', '-2 hours')
  `).run(),e.json({ok:!0})):l(e,401,"unauthorized"));h.post("/api/rt/create",async e=>{const t=M(e);if(!t)return l(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return l(e,400,"invalid_json");const n=String(s.name||"プレイヤー").slice(0,20),a=JSON.stringify(s.party||[]),r=String(s.area||"rounding").slice(0,40),o=s.battleType==="egg"?"egg":s.battleType==="gym"?"gym":"normal";await e.env.DB.prepare("DELETE FROM rt_rooms WHERE host_user_id=? AND status='waiting'").bind(t.id).run();const i=s.code?String(s.code).toUpperCase().replace(/[^A-Z0-9]/g,""):"";let d=i.length>=4?i:Je();if(!i.length)for(let c=0;c<5&&await e.env.DB.prepare("SELECT id FROM rt_rooms WHERE id=?").bind(d).first();c++)d=Je();return await e.env.DB.prepare(`
    INSERT INTO rt_rooms (id, host_user_id, host_name, host_party_json, host_area, host_hp, host_ready, guest_hp, guest_ready, battle_type, status)
    VALUES (?, ?, ?, ?, ?, 100, 0, 100, 0, ?, 'waiting')
  `).bind(d,t.id,n,a,r,o).run(),e.json({ok:!0,roomId:d})});h.post("/api/rt/join/:roomId",async e=>{const t=M(e);if(!t)return l(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.req.json().catch(()=>null);if(!n)return l(e,400,"invalid_json");const a=String(n.name||"プレイヤー").slice(0,20),r=JSON.stringify(n.party||[]),o=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();if(!o)return l(e,404,"room_not_found");if(o.status!=="waiting")return l(e,409,"room_not_available");if(o.host_user_id===t.id)return l(e,400,"cannot_join_own_room");await e.env.DB.prepare(`
    UPDATE rt_rooms SET guest_user_id=?, guest_name=?, guest_party_json=?, guest_ready=1, status='ready', updated_at=datetime('now')
    WHERE id=? AND status='waiting'
  `).bind(t.id,a,r,s).run();const i=JSON.parse(o.host_party_json||"[]");return e.json({ok:!0,roomId:s,hostName:o.host_name,area:o.host_area,battleType:o.battle_type,hostParty:i})});h.get("/api/rt/room/:roomId",async e=>{const t=M(e);if(!t)return l(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();if(!n)return l(e,404,"room_not_found");const a=n.host_user_id===t.id,r=n.guest_user_id===t.id;if(!a&&!r)return l(e,403,"not_a_participant");const o=Number(e.req.query("after")||0),i=await e.env.DB.prepare(`
    SELECT id, user_id, event_type, value, monster_id, meta_json, created_at FROM rt_events
    WHERE room_id=? AND id > ?
    ORDER BY id ASC LIMIT 50
  `).bind(s,o).all(),d=a?"host":"guest",c=a?n.guest_party_json?JSON.parse(n.guest_party_json):null:JSON.parse(n.host_party_json||"[]");return e.json({ok:!0,room:{id:n.id,status:n.status,battleType:n.battle_type,area:n.host_area,hostName:n.host_name,guestName:n.guest_name,hostHp:n.host_hp,guestHp:n.guest_hp,hostReady:!!n.host_ready,guestReady:!!n.guest_ready,winner:n.winner,myRole:d,opponentParty:c},events:i.results})});h.post("/api/rt/ready/:roomId",async e=>{const t=M(e);if(!t)return l(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();if(!n)return l(e,404,"room_not_found");const a=n.host_user_id===t.id,r=n.guest_user_id===t.id;if(!a&&!r)return l(e,403,"not_a_participant");a?await e.env.DB.prepare("UPDATE rt_rooms SET host_ready=1, updated_at=datetime('now') WHERE id=?").bind(s).run():await e.env.DB.prepare("UPDATE rt_rooms SET guest_ready=1, updated_at=datetime('now') WHERE id=?").bind(s).run();const o=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();return o&&o.host_ready&&o.guest_ready&&(o.status==="ready"||o.status==="waiting")&&await e.env.DB.prepare("UPDATE rt_rooms SET status='playing', updated_at=datetime('now') WHERE id=?").bind(s).run(),e.json({ok:!0})});h.post("/api/rt/damage/:roomId",async e=>{const t=M(e);if(!t)return l(e,401,"unauthorized");if(!Bt(`rtdmg:${t.id}`,20,10))return l(e,429,"too_many_requests");const s=e.req.param("roomId").toUpperCase(),n=await e.req.json().catch(()=>null);if(!n)return l(e,400,"invalid_json");const a=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();if(!a)return l(e,404,"room_not_found");if(a.status!=="playing")return l(e,409,"not_playing");const r=a.host_user_id===t.id,o=a.guest_user_id===t.id;if(!r&&!o)return l(e,403,"not_a_participant");const i=Math.max(0,Math.min(500,Number(n.damage||0)));if(!Number.isFinite(i))return l(e,400,"invalid_damage");const d=Math.max(0,Math.min(9999,Math.floor(Number(n.monsterId||0)))),c=n.meta?JSON.stringify(n.meta).slice(0,500):null,m=["damage","faint","win","lose"].includes(String(n.eventType))?String(n.eventType):"damage",w=(await e.env.DB.prepare(`
    INSERT INTO rt_events (room_id, user_id, event_type, value, monster_id, meta_json)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(s,t.id,m,i,d,c).run()).meta.last_row_id;let b=a.host_hp,x=a.guest_hp;m==="self_damage"?r?b=Math.max(0,b-i):x=Math.max(0,x-i):r?x=Math.max(0,x-i):b=Math.max(0,b-i);let _=a.status,v=a.winner;return m==="win"?(_="finished",v=r?"host":"guest"):m==="draw"&&(_="finished",v="draw"),await e.env.DB.prepare(`
    UPDATE rt_rooms SET host_hp=?, guest_hp=?, status=?, winner=?, updated_at=datetime('now') WHERE id=?
  `).bind(b,x,_,v,s).run(),e.json({ok:!0,eventId:w,hostHp:b,guestHp:x})});h.post("/api/rt/leave/:roomId",async e=>{const t=M(e);if(!t)return l(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),n=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();return n?(n.host_user_id===t.id?await e.env.DB.prepare("DELETE FROM rt_rooms WHERE id=?").bind(s).run():await e.env.DB.prepare(`
      UPDATE rt_rooms SET guest_user_id=NULL, guest_name=NULL, guest_party_json=NULL,
      status='waiting', host_hp=100, guest_hp=100, host_ready=0, guest_ready=0, winner=NULL,
      updated_at=datetime('now') WHERE id=?
    `).bind(s).run(),e.json({ok:!0})):e.json({ok:!0})});h.delete("/api/rt/cleanup",async e=>(await e.env.DB.prepare("DELETE FROM rt_rooms WHERE created_at < datetime('now', '-2 hours')").run(),await e.env.DB.prepare("DELETE FROM rt_events WHERE created_at < datetime('now', '-2 hours')").run(),e.json({ok:!0})));h.post("/api/report",async e=>{const t=e.get("user");if(!t)return l(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!(s!=null&&s.body)||typeof s.body!="string"||s.body.trim().length===0)return l(e,400,"body_required");const n=["bug","request","other"].includes(s.category)?s.category:"bug",a=s.body.trim().slice(0,1e3),r=await e.env.DB.prepare("SELECT name FROM users WHERE id=?").bind(t.id).first(),o=(r==null?void 0:r.name)||t.loginId||"unknown",i=crypto.randomUUID();return await e.env.DB.prepare("INSERT INTO reports (id, account_id, display_name, category, body) VALUES (?, ?, ?, ?, ?)").bind(i,t.id,o,n,a).run(),e.json({ok:!0,id:i})});h.get("/api/report/my",async e=>{const t=e.get("user");if(!t)return l(e,401,"unauthorized");const s=await e.env.DB.prepare(`SELECT id, category, body, status, admin_note as adminNote, created_at as createdAt
     FROM reports WHERE account_id=? ORDER BY created_at DESC LIMIT 20`).bind(t.id).all();return e.json({ok:!0,reports:s.results})});h.get("/api/admin/reports",async e=>{if(!(D(e)||A(e)))return l(e,401,"unauthorized");const s=e.req.query("status")||"all";let n="SELECT id, account_id as accountId, display_name as displayName, category, body, status, admin_note as adminNote, created_at as createdAt, updated_at as updatedAt FROM reports";const a=[];s!=="all"&&(n+=" WHERE status=?",a.push(s)),n+=" ORDER BY created_at DESC LIMIT 100";const o=await(a.length>0?e.env.DB.prepare(n).bind(...a):e.env.DB.prepare(n)).all();return e.json({ok:!0,reports:o.results})});h.put("/api/admin/report/:id",async e=>{if(!(D(e)||A(e)))return l(e,401,"unauthorized");const s=e.req.param("id"),n=await e.req.json().catch(()=>null);if(!n)return l(e,400,"invalid_body");const a=["open","in_progress","resolved","closed"],r=[],o=[];return n.status&&a.includes(n.status)&&(r.push("status=?"),o.push(n.status)),typeof n.adminNote=="string"&&(r.push("admin_note=?"),o.push(n.adminNote.slice(0,500))),r.length===0?l(e,400,"nothing_to_update"):(r.push("updated_at=datetime('now')"),o.push(s),await e.env.DB.prepare(`UPDATE reports SET ${r.join(", ")} WHERE id=?`).bind(...o).run(),e.json({ok:!0}))});h.delete("/api/admin/report/:id",async e=>D(e)||A(e)?(await e.env.DB.prepare("DELETE FROM reports WHERE id=?").bind(e.req.param("id")).run(),e.json({ok:!0})):l(e,401,"unauthorized"));h.post("/api/teacher/announcement",async e=>{const t=D(e);if(!t)return l(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return l(e,400,"invalid_json");const n=String(s.title||"").trim(),a=String(s.body||"").trim(),r=s.classId||null;if(!n||!a)return l(e,400,"title_and_body_required");const o=crypto.randomUUID();return await e.env.DB.prepare("INSERT INTO announcements (id, class_id, teacher_id, title, body) VALUES (?,?,?,?,?)").bind(o,r,t.id,n,a).run(),e.json({ok:!0,id:o})});h.get("/api/teacher/announcements",async e=>{if(!D(e))return l(e,401,"unauthorized");const s=await e.env.DB.prepare(`SELECT a.id, a.class_id as classId, a.title, a.body, a.created_at as createdAt, c.name as className
     FROM announcements a LEFT JOIN classes c ON c.id = a.class_id
     ORDER BY a.created_at DESC LIMIT 50`).all();return e.json({ok:!0,announcements:s.results})});h.delete("/api/teacher/announcement/:id",async e=>{if(!D(e))return l(e,401,"unauthorized");const s=e.req.param("id");return await e.env.DB.prepare("DELETE FROM announcement_reads WHERE announcement_id=?").bind(s).run(),await e.env.DB.prepare("DELETE FROM announcements WHERE id=?").bind(s).run(),e.json({ok:!0})});h.get("/api/student/announcements",async e=>{const t=e.get("user");if(!t)return l(e,401,"unauthorized");const s=await e.env.DB.prepare("SELECT class_id FROM class_members WHERE user_id=? LIMIT 1").bind(t.id).first(),n=(s==null?void 0:s.class_id)||null;let a;return n?a=await e.env.DB.prepare(`SELECT a.id, a.title, a.body, a.created_at as createdAt, a.class_id as classId,
              ar.read_at as readAt
       FROM announcements a
       LEFT JOIN announcement_reads ar ON ar.announcement_id = a.id AND ar.user_id = ?
       WHERE a.class_id IS NULL OR a.class_id = ?
       ORDER BY a.created_at DESC LIMIT 30`).bind(t.id,n).all():a=await e.env.DB.prepare(`SELECT a.id, a.title, a.body, a.created_at as createdAt, a.class_id as classId,
              ar.read_at as readAt
       FROM announcements a
       LEFT JOIN announcement_reads ar ON ar.announcement_id = a.id AND ar.user_id = ?
       WHERE a.class_id IS NULL
       ORDER BY a.created_at DESC LIMIT 30`).bind(t.id).all(),e.json({ok:!0,announcements:a.results})});h.post("/api/student/announcement/:id/read",async e=>{const t=e.get("user");if(!t)return l(e,401,"unauthorized");const s=e.req.param("id");return await e.env.DB.prepare("INSERT OR IGNORE INTO announcement_reads (user_id, announcement_id) VALUES (?,?)").bind(t.id,s).run(),e.json({ok:!0})});h.post("/api/teacher/contact-note",async e=>{const t=A(e);if(!t)return l(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return l(e,400,"invalid_json");const n=String(s.classId||"").trim(),a=String(s.body||"").trim(),r=String(s.dayKey||"").trim(),o=s.rewardDeadline||null,i=Number(s.rewardCoins)||5;if(!n||!a||!r)return l(e,400,"classId_body_dayKey_required");if(!await e.env.DB.prepare("SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1").bind(n,t.id).first())return l(e,403,"not_your_class");const c=crypto.randomUUID();return await e.env.DB.prepare("INSERT INTO contact_notes (id, class_id, teacher_id, day_key, body, reward_deadline, reward_coins) VALUES (?,?,?,?,?,?,?)").bind(c,n,t.id,r,a,o,i).run(),e.json({ok:!0,id:c})});h.get("/api/teacher/contact-notes",async e=>{const t=A(e);if(!t)return l(e,401,"unauthorized");const s=e.req.query("classId")||"",n=t.role==="admin";let a;return s?a=await e.env.DB.prepare(`SELECT cn.id, cn.class_id as classId, cn.day_key as dayKey, cn.body, cn.reward_deadline as rewardDeadline, cn.reward_coins as rewardCoins, cn.created_at as createdAt, c.name as className
       FROM contact_notes cn LEFT JOIN classes c ON c.id = cn.class_id
       WHERE cn.class_id = ? ${n?"":"AND cn.teacher_id = ?"}
       ORDER BY cn.created_at DESC LIMIT 30`).bind(...n?[s]:[s,t.id]).all():a=n?await e.env.DB.prepare(`SELECT cn.id, cn.class_id as classId, cn.day_key as dayKey, cn.body, cn.reward_deadline as rewardDeadline, cn.reward_coins as rewardCoins, cn.created_at as createdAt, c.name as className
           FROM contact_notes cn LEFT JOIN classes c ON c.id = cn.class_id
           ORDER BY cn.created_at DESC LIMIT 30`).all():await e.env.DB.prepare(`SELECT cn.id, cn.class_id as classId, cn.day_key as dayKey, cn.body, cn.reward_deadline as rewardDeadline, cn.reward_coins as rewardCoins, cn.created_at as createdAt, c.name as className
           FROM contact_notes cn LEFT JOIN classes c ON c.id = cn.class_id
           WHERE cn.teacher_id = ?
           ORDER BY cn.created_at DESC LIMIT 30`).bind(t.id).all(),e.json({ok:!0,notes:a.results})});h.delete("/api/teacher/contact-note/:id",async e=>{const t=A(e);if(!t)return l(e,401,"unauthorized");const s=e.req.param("id");return await e.env.DB.prepare("DELETE FROM contact_note_reads WHERE note_id=?").bind(s).run(),t.role==="admin"?await e.env.DB.prepare("DELETE FROM contact_notes WHERE id=?").bind(s).run():await e.env.DB.prepare("DELETE FROM contact_notes WHERE id=? AND teacher_id=?").bind(s,t.id).run(),e.json({ok:!0})});h.get("/api/teacher/contact-note/:id/reads",async e=>{if(!A(e))return l(e,401,"unauthorized");const s=e.req.param("id"),n=await e.env.DB.prepare(`SELECT cnr.user_id as userId, cnr.read_at as readAt, cnr.reward_claimed as rewardClaimed, u.name as studentName
     FROM contact_note_reads cnr JOIN users u ON u.id = cnr.user_id
     WHERE cnr.note_id = ? ORDER BY cnr.read_at ASC`).bind(s).all();return e.json({ok:!0,reads:n.results})});h.get("/api/student/contact-notes",async e=>{const t=e.get("user");if(!t)return l(e,401,"unauthorized");let s=null;if(t.role==="teacher"||t.role==="admin"){const a=t.role==="admin"?await e.env.DB.prepare("SELECT id FROM classes ORDER BY created_at DESC LIMIT 1").first():await e.env.DB.prepare("SELECT id FROM classes WHERE teacher_id=? ORDER BY created_at DESC LIMIT 1").bind(t.id).first();s=(a==null?void 0:a.id)||null}else{const a=await e.env.DB.prepare("SELECT class_id FROM class_members WHERE user_id=? LIMIT 1").bind(t.id).first();s=(a==null?void 0:a.class_id)||null}if(!s)return e.json({ok:!0,notes:[]});const n=await e.env.DB.prepare(`SELECT cn.id, cn.day_key as dayKey, cn.body, cn.reward_deadline as rewardDeadline, cn.reward_coins as rewardCoins, cn.created_at as createdAt,
            cnr.read_at as readAt, cnr.reward_claimed as rewardClaimed
     FROM contact_notes cn
     LEFT JOIN contact_note_reads cnr ON cnr.note_id = cn.id AND cnr.user_id = ?
     WHERE cn.class_id = ?
     ORDER BY cn.created_at DESC LIMIT 50`).bind(t.id,s).all();return e.json({ok:!0,notes:n.results})});h.post("/api/student/contact-note/:id/read",async e=>{const t=e.get("user");if(!t)return l(e,401,"unauthorized");const s=e.req.param("id");if(await e.env.DB.prepare("SELECT reward_claimed FROM contact_note_reads WHERE user_id=? AND note_id=? LIMIT 1").bind(t.id,s).first())return e.json({ok:!0,alreadyRead:!0,reward:0});const a=await e.env.DB.prepare("SELECT reward_deadline, reward_coins FROM contact_notes WHERE id=? LIMIT 1").bind(s).first();if(!a)return l(e,404,"not_found");const r=new Date().toISOString();let o=0,i=0;return a.reward_deadline?r<=a.reward_deadline&&(o=a.reward_coins||5,i=1):(o=a.reward_coins||5,i=1),await e.env.DB.prepare("INSERT OR IGNORE INTO contact_note_reads (user_id, note_id, reward_claimed) VALUES (?,?,?)").bind(t.id,s,i).run(),e.json({ok:!0,reward:o,rewardClaimed:!!i})});h.get("/",async e=>{var s;const t=await((s=e.env.ASSETS)==null?void 0:s.fetch(new Request(new URL("https://assets/index.html"))));return t||e.text("index.html not found",404)});h.get("/logout",async e=>{const t={secure:!0,sameSite:"Lax",httpOnly:!0};return Ne(e,"session",{...t,path:"/"}),Ne(e,"session",{...t,path:"/api"}),e.redirect("/login")});h.get("/login",e=>e.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
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
  </body></html>`));h.get("/signup",e=>e.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
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
          <div class="flex-1">
            <label class="text-sm font-bold text-gray-700 mb-1 block">クラス</label>
            <input id="className" class="w-full border p-2 rounded" placeholder="例：1組 / A"/>
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
        grade_invalid: '学年を選択してください',
        class_required: 'クラスを入力してください',
        invalid_json: '入力内容に問題があります',
      };
      document.getElementById('btn').onclick = async () => {
        msg.textContent='';
        const gradeVal = document.getElementById('grade').value;
        const payload = {
          name: document.getElementById('name').value.trim(),
          grade: gradeVal ? Number(gradeVal) : NaN,
          className: document.getElementById('className').value.trim(),
          loginId: document.getElementById('loginId').value.trim(),
          password: document.getElementById('password').value,
        };
        // クライアント側バリデーション
        if(!payload.name){ msg.textContent='名前を入力してください'; msg.className='text-sm text-red-600'; return; }
        if(!gradeVal){ msg.textContent='学年を選択してください'; msg.className='text-sm text-red-600'; return; }
        if(!payload.className){ msg.textContent='クラスを入力してください'; msg.className='text-sm text-red-600'; return; }
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
  </body></html>`));h.get("/admin",e=>e.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
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
          <input id="filterClass" class="border p-2 rounded" placeholder="クラス" />
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
        const cls = document.getElementById('filterClass').value.trim();
        const qs = new URLSearchParams();
        if(grade) qs.set('grade', grade);
        if(cls) qs.set('class', cls);
        const u = await api('/api/admin/users?' + qs.toString());
        const wrap = document.getElementById('users');
        wrap.innerHTML='';
        if(!u.users.length){ wrap.textContent='該当なし'; return; }
        for(const x of u.users){
          const div = document.createElement('div');
          div.className='flex flex-col md:flex-row md:items-center md:justify-between border rounded p-2 gap-2';
          const left = document.createElement('div');
          left.textContent = x.grade + '年 ' + x.className + ' / ' + x.name + '（' + x.loginId + '）' + (x.isActive? '' : ' [停止/未承認]');
          div.appendChild(left);
          const right = document.createElement('div');
          right.className='flex gap-2';

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
  </body></html>`));h.get("/teacher-signup",e=>e.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
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
  </body></html>`));h.get("/teacher",e=>e.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
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
        <button id="tabContact" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('contact')">📓 れんらくちょう</button>
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
        <div class="bg-white rounded-xl shadow p-4">
          <div class="flex gap-2 mb-3 flex-wrap">
            <select id="hwClassFilter" class="border p-2 rounded text-sm bg-white"></select>
            <select id="hwStatusFilter" class="border p-2 rounded text-sm bg-white">
              <option value="">すべて</option>
              <option value="unreturned">未返却</option>
              <option value="returned">返却済み</option>
            </select>
            <button onclick="loadHomework()" class="bg-emerald-600 text-white rounded px-3 py-1 text-sm font-bold">絞り込み</button>
            <button onclick="loadHomework()" class="bg-slate-200 rounded px-3 py-1 text-sm">更新</button>
          </div>
          <div id="hwList" class="space-y-3 text-sm"></div>
        </div>
      </div>

      <!-- れんらくちょうタブ -->
      <div id="tabPaneContact" class="hidden space-y-3">
        <div class="bg-white rounded-xl shadow p-4">
          <h3 class="font-bold mb-3">れんらくちょうを書く</h3>
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
          <h3 class="font-bold mb-3">送信済みれんらくちょう</h3>
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
        if(tab === 'homework') loadHomework();
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

      // ===== れんらくちょう機能 =====
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
  </body></html>`));const ut=new Ot,js=Object.assign({"/src/index.tsx":h});let Mt=!1;for(const[,e]of Object.entries(js))e&&(ut.all("*",t=>{let s;try{s=t.executionCtx}catch{}return e.fetch(t.req.raw,t.env,s)}),ut.notFound(t=>{let s;try{s=t.executionCtx}catch{}return e.fetch(t.req.raw,t.env,s)}),Mt=!0);if(!Mt)throw new Error("Can't import modules from ['/src/index.ts','/src/index.tsx','/app/server.ts']");export{ut as default};
