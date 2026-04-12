var qt=Object.defineProperty;var it=e=>{throw TypeError(e)};var Jt=(e,t,s)=>t in e?qt(e,t,{enumerable:!0,configurable:!0,writable:!0,value:s}):e[t]=s;var k=(e,t,s)=>Jt(e,typeof t!="symbol"?t+"":t,s),Qe=(e,t,s)=>t.has(e)||it("Cannot "+s);var p=(e,t,s)=>(Qe(e,t,"read from private field"),s?s.call(e):t.get(e)),I=(e,t,s)=>t.has(e)?it("Cannot add the same private member more than once"):t instanceof WeakSet?t.add(e):t.set(e,s),E=(e,t,s,a)=>(Qe(e,t,"write to private field"),a?a.call(e,s):t.set(e,s),s),S=(e,t,s)=>(Qe(e,t,"access private method"),s);var ot=(e,t,s,a)=>({set _(n){E(e,t,n,s)},get _(){return p(e,t,a)}});var dt=(e,t,s)=>(a,n)=>{let r=-1;return i(0);async function i(d){if(d<=r)throw new Error("next() called multiple times");r=d;let l,c=!1,u;if(e[d]?(u=e[d][0][0],a.req.routeIndex=d):u=d===e.length&&n||void 0,u)try{l=await u(a,()=>i(d+1))}catch(m){if(m instanceof Error&&t)a.error=m,l=await t(m,a),c=!0;else throw m}else a.finalized===!1&&s&&(l=await s(a));return l&&(a.finalized===!1||c)&&(a.res=l),a}},Kt=Symbol(),$t=async(e,t=Object.create(null))=>{const{all:s=!1,dot:a=!1}=t,r=(e instanceof It?e.raw.headers:e.headers).get("Content-Type");return r!=null&&r.startsWith("multipart/form-data")||r!=null&&r.startsWith("application/x-www-form-urlencoded")?zt(e,{all:s,dot:a}):{}};async function zt(e,t){const s=await e.formData();return s?Gt(s,t):{}}function Gt(e,t){const s=Object.create(null);return e.forEach((a,n)=>{t.all||n.endsWith("[]")?Vt(s,n,a):s[n]=a}),t.dot&&Object.entries(s).forEach(([a,n])=>{a.includes(".")&&(Yt(s,a,n),delete s[a])}),s}var Vt=(e,t,s)=>{e[t]!==void 0?Array.isArray(e[t])?e[t].push(s):e[t]=[e[t],s]:t.endsWith("[]")?e[t]=[s]:e[t]=s},Yt=(e,t,s)=>{let a=e;const n=t.split(".");n.forEach((r,i)=>{i===n.length-1?a[r]=s:((!a[r]||typeof a[r]!="object"||Array.isArray(a[r])||a[r]instanceof File)&&(a[r]=Object.create(null)),a=a[r])})},vt=e=>{const t=e.split("/");return t[0]===""&&t.shift(),t},Zt=e=>{const{groups:t,path:s}=Qt(e),a=vt(s);return Xt(a,t)},Qt=e=>{const t=[];return e=e.replace(/\{[^}]+\}/g,(s,a)=>{const n=`@${a}`;return t.push([n,s]),n}),{groups:t,path:e}},Xt=(e,t)=>{for(let s=t.length-1;s>=0;s--){const[a]=t[s];for(let n=e.length-1;n>=0;n--)if(e[n].includes(a)){e[n]=e[n].replace(a,t[s][1]);break}}return e},Pe={},es=(e,t)=>{if(e==="*")return"*";const s=e.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);if(s){const a=`${e}#${t}`;return Pe[a]||(s[2]?Pe[a]=t&&t[0]!==":"&&t[0]!=="*"?[a,s[1],new RegExp(`^${s[2]}(?=/${t})`)]:[e,s[1],new RegExp(`^${s[2]}$`)]:Pe[a]=[e,s[1],!0]),Pe[a]}return null},Ge=(e,t)=>{try{return t(e)}catch{return e.replace(/(?:%[0-9A-Fa-f]{2})+/g,s=>{try{return t(s)}catch{return s}})}},ts=e=>Ge(e,decodeURI),_t=e=>{const t=e.url,s=t.indexOf("/",t.indexOf(":")+4);let a=s;for(;a<t.length;a++){const n=t.charCodeAt(a);if(n===37){const r=t.indexOf("?",a),i=t.indexOf("#",a),d=r===-1?i===-1?void 0:i:i===-1?r:Math.min(r,i),l=t.slice(s,d);return ts(l.includes("%25")?l.replace(/%25/g,"%2525"):l)}else if(n===63||n===35)break}return t.slice(s,a)},ss=e=>{const t=_t(e);return t.length>1&&t.at(-1)==="/"?t.slice(0,-1):t},be=(e,t,...s)=>(s.length&&(t=be(t,...s)),`${(e==null?void 0:e[0])==="/"?"":"/"}${e}${t==="/"?"":`${(e==null?void 0:e.at(-1))==="/"?"":"/"}${(t==null?void 0:t[0])==="/"?t.slice(1):t}`}`),Et=e=>{if(e.charCodeAt(e.length-1)!==63||!e.includes(":"))return null;const t=e.split("/"),s=[];let a="";return t.forEach(n=>{if(n!==""&&!/\:/.test(n))a+="/"+n;else if(/\:/.test(n))if(/\?/.test(n)){s.length===0&&a===""?s.push("/"):s.push(a);const r=n.replace("?","");a+="/"+r,s.push(a)}else a+="/"+n}),s.filter((n,r,i)=>i.indexOf(n)===r)},Xe=e=>/[%+]/.test(e)?(e.indexOf("+")!==-1&&(e=e.replace(/\+/g," ")),e.indexOf("%")!==-1?Ge(e,at):e):e,kt=(e,t,s)=>{let a;if(!s&&t&&!/[%+]/.test(t)){let i=e.indexOf("?",8);if(i===-1)return;for(e.startsWith(t,i+1)||(i=e.indexOf(`&${t}`,i+1));i!==-1;){const d=e.charCodeAt(i+t.length+1);if(d===61){const l=i+t.length+2,c=e.indexOf("&",l);return Xe(e.slice(l,c===-1?void 0:c))}else if(d==38||isNaN(d))return"";i=e.indexOf(`&${t}`,i+1)}if(a=/[%+]/.test(e),!a)return}const n={};a??(a=/[%+]/.test(e));let r=e.indexOf("?",8);for(;r!==-1;){const i=e.indexOf("&",r+1);let d=e.indexOf("=",r);d>i&&i!==-1&&(d=-1);let l=e.slice(r+1,d===-1?i===-1?void 0:i:d);if(a&&(l=Xe(l)),r=i,l==="")continue;let c;d===-1?c="":(c=e.slice(d+1,i===-1?void 0:i),a&&(c=Xe(c))),s?(n[l]&&Array.isArray(n[l])||(n[l]=[]),n[l].push(c)):n[l]??(n[l]=c)}return t?n[t]:n},as=kt,ns=(e,t)=>kt(e,t,!0),at=decodeURIComponent,lt=e=>Ge(e,at),ye,P,Y,St,Ct,st,Z,gt,It=(gt=class{constructor(e,t="/",s=[[]]){I(this,Y);k(this,"raw");I(this,ye);I(this,P);k(this,"routeIndex",0);k(this,"path");k(this,"bodyCache",{});I(this,Z,e=>{const{bodyCache:t,raw:s}=this,a=t[e];if(a)return a;const n=Object.keys(t)[0];return n?t[n].then(r=>(n==="json"&&(r=JSON.stringify(r)),new Response(r)[e]())):t[e]=s[e]()});this.raw=e,this.path=t,E(this,P,s),E(this,ye,{})}param(e){return e?S(this,Y,St).call(this,e):S(this,Y,Ct).call(this)}query(e){return as(this.url,e)}queries(e){return ns(this.url,e)}header(e){if(e)return this.raw.headers.get(e)??void 0;const t={};return this.raw.headers.forEach((s,a)=>{t[a]=s}),t}async parseBody(e){var t;return(t=this.bodyCache).parsedBody??(t.parsedBody=await $t(this,e))}json(){return p(this,Z).call(this,"text").then(e=>JSON.parse(e))}text(){return p(this,Z).call(this,"text")}arrayBuffer(){return p(this,Z).call(this,"arrayBuffer")}blob(){return p(this,Z).call(this,"blob")}formData(){return p(this,Z).call(this,"formData")}addValidatedData(e,t){p(this,ye)[e]=t}valid(e){return p(this,ye)[e]}get url(){return this.raw.url}get method(){return this.raw.method}get[Kt](){return p(this,P)}get matchedRoutes(){return p(this,P)[0].map(([[,e]])=>e)}get routePath(){return p(this,P)[0].map(([[,e]])=>e)[this.routeIndex].path}},ye=new WeakMap,P=new WeakMap,Y=new WeakSet,St=function(e){const t=p(this,P)[0][this.routeIndex][1][e],s=S(this,Y,st).call(this,t);return s&&/\%/.test(s)?lt(s):s},Ct=function(){const e={},t=Object.keys(p(this,P)[0][this.routeIndex][1]);for(const s of t){const a=S(this,Y,st).call(this,p(this,P)[0][this.routeIndex][1][s]);a!==void 0&&(e[s]=/\%/.test(a)?lt(a):a)}return e},st=function(e){return p(this,P)[1]?p(this,P)[1][e]:e},Z=new WeakMap,gt),rs={Stringify:1},Tt=async(e,t,s,a,n)=>{typeof e=="object"&&!(e instanceof String)&&(e instanceof Promise||(e=e.toString()),e instanceof Promise&&(e=await e));const r=e.callbacks;return r!=null&&r.length?(n?n[0]+=e:n=[e],Promise.all(r.map(d=>d({phase:t,buffer:n,context:a}))).then(d=>Promise.all(d.filter(Boolean).map(l=>Tt(l,t,!1,a,n))).then(()=>n[0]))):Promise.resolve(e)},is="text/plain; charset=UTF-8",et=(e,t)=>({"Content-Type":e,...t}),Te=(e,t)=>new Response(e,t),Le,Oe,$,xe,z,B,Ae,ve,_e,oe,Be,je,Q,fe,bt,os=(bt=class{constructor(e,t){I(this,Q);I(this,Le);I(this,Oe);k(this,"env",{});I(this,$);k(this,"finalized",!1);k(this,"error");I(this,xe);I(this,z);I(this,B);I(this,Ae);I(this,ve);I(this,_e);I(this,oe);I(this,Be);I(this,je);k(this,"render",(...e)=>(p(this,ve)??E(this,ve,t=>this.html(t)),p(this,ve).call(this,...e)));k(this,"setLayout",e=>E(this,Ae,e));k(this,"getLayout",()=>p(this,Ae));k(this,"setRenderer",e=>{E(this,ve,e)});k(this,"header",(e,t,s)=>{this.finalized&&E(this,B,Te(p(this,B).body,p(this,B)));const a=p(this,B)?p(this,B).headers:p(this,oe)??E(this,oe,new Headers);t===void 0?a.delete(e):s!=null&&s.append?a.append(e,t):a.set(e,t)});k(this,"status",e=>{E(this,xe,e)});k(this,"set",(e,t)=>{p(this,$)??E(this,$,new Map),p(this,$).set(e,t)});k(this,"get",e=>p(this,$)?p(this,$).get(e):void 0);k(this,"newResponse",(...e)=>S(this,Q,fe).call(this,...e));k(this,"body",(e,t,s)=>S(this,Q,fe).call(this,e,t,s));k(this,"text",(e,t,s)=>!p(this,oe)&&!p(this,xe)&&!t&&!s&&!this.finalized?new Response(e):S(this,Q,fe).call(this,e,t,et(is,s)));k(this,"json",(e,t,s)=>S(this,Q,fe).call(this,JSON.stringify(e),t,et("application/json",s)));k(this,"html",(e,t,s)=>{const a=n=>S(this,Q,fe).call(this,n,t,et("text/html; charset=UTF-8",s));return typeof e=="object"?Tt(e,rs.Stringify,!1,{}).then(a):a(e)});k(this,"redirect",(e,t)=>{const s=String(e);return this.header("Location",/[^\x00-\xFF]/.test(s)?encodeURI(s):s),this.newResponse(null,t??302)});k(this,"notFound",()=>(p(this,_e)??E(this,_e,()=>Te()),p(this,_e).call(this,this)));E(this,Le,e),t&&(E(this,z,t.executionCtx),this.env=t.env,E(this,_e,t.notFoundHandler),E(this,je,t.path),E(this,Be,t.matchResult))}get req(){return p(this,Oe)??E(this,Oe,new It(p(this,Le),p(this,je),p(this,Be))),p(this,Oe)}get event(){if(p(this,z)&&"respondWith"in p(this,z))return p(this,z);throw Error("This context has no FetchEvent")}get executionCtx(){if(p(this,z))return p(this,z);throw Error("This context has no ExecutionContext")}get res(){return p(this,B)||E(this,B,Te(null,{headers:p(this,oe)??E(this,oe,new Headers)}))}set res(e){if(p(this,B)&&e){e=Te(e.body,e);for(const[t,s]of p(this,B).headers.entries())if(t!=="content-type")if(t==="set-cookie"){const a=p(this,B).headers.getSetCookie();e.headers.delete("set-cookie");for(const n of a)e.headers.append("set-cookie",n)}else e.headers.set(t,s)}E(this,B,e),this.finalized=!0}get var(){return p(this,$)?Object.fromEntries(p(this,$)):{}}},Le=new WeakMap,Oe=new WeakMap,$=new WeakMap,xe=new WeakMap,z=new WeakMap,B=new WeakMap,Ae=new WeakMap,ve=new WeakMap,_e=new WeakMap,oe=new WeakMap,Be=new WeakMap,je=new WeakMap,Q=new WeakSet,fe=function(e,t,s){const a=p(this,B)?new Headers(p(this,B).headers):p(this,oe)??new Headers;if(typeof t=="object"&&"headers"in t){const r=t.headers instanceof Headers?t.headers:new Headers(t.headers);for(const[i,d]of r)i.toLowerCase()==="set-cookie"?a.append(i,d):a.set(i,d)}if(s)for(const[r,i]of Object.entries(s))if(typeof i=="string")a.set(r,i);else{a.delete(r);for(const d of i)a.append(r,d)}const n=typeof t=="number"?t:(t==null?void 0:t.status)??p(this,xe);return Te(e,{status:n,headers:a})},bt),R="ALL",ds="all",ls=["get","post","put","delete","options","patch"],Dt="Can not add a route since the matcher is already built.",Nt=class extends Error{},cs="__COMPOSED_HANDLER",us=e=>e.text("404 Not Found",404),ct=(e,t)=>{if("getResponse"in e){const s=e.getResponse();return t.newResponse(s.body,s)}return console.error(e),t.text("Internal Server Error",500)},F,M,Rt,W,re,We,Ue,Ee,ms=(Ee=class{constructor(t={}){I(this,M);k(this,"get");k(this,"post");k(this,"put");k(this,"delete");k(this,"options");k(this,"patch");k(this,"all");k(this,"on");k(this,"use");k(this,"router");k(this,"getPath");k(this,"_basePath","/");I(this,F,"/");k(this,"routes",[]);I(this,W,us);k(this,"errorHandler",ct);k(this,"onError",t=>(this.errorHandler=t,this));k(this,"notFound",t=>(E(this,W,t),this));k(this,"fetch",(t,...s)=>S(this,M,Ue).call(this,t,s[1],s[0],t.method));k(this,"request",(t,s,a,n)=>t instanceof Request?this.fetch(s?new Request(t,s):t,a,n):(t=t.toString(),this.fetch(new Request(/^https?:\/\//.test(t)?t:`http://localhost${be("/",t)}`,s),a,n)));k(this,"fire",()=>{addEventListener("fetch",t=>{t.respondWith(S(this,M,Ue).call(this,t.request,t,void 0,t.request.method))})});[...ls,ds].forEach(r=>{this[r]=(i,...d)=>(typeof i=="string"?E(this,F,i):S(this,M,re).call(this,r,p(this,F),i),d.forEach(l=>{S(this,M,re).call(this,r,p(this,F),l)}),this)}),this.on=(r,i,...d)=>{for(const l of[i].flat()){E(this,F,l);for(const c of[r].flat())d.map(u=>{S(this,M,re).call(this,c.toUpperCase(),p(this,F),u)})}return this},this.use=(r,...i)=>(typeof r=="string"?E(this,F,r):(E(this,F,"*"),i.unshift(r)),i.forEach(d=>{S(this,M,re).call(this,R,p(this,F),d)}),this);const{strict:a,...n}=t;Object.assign(this,n),this.getPath=a??!0?t.getPath??_t:ss}route(t,s){const a=this.basePath(t);return s.routes.map(n=>{var i;let r;s.errorHandler===ct?r=n.handler:(r=async(d,l)=>(await dt([],s.errorHandler)(d,()=>n.handler(d,l))).res,r[cs]=n.handler),S(i=a,M,re).call(i,n.method,n.path,r)}),this}basePath(t){const s=S(this,M,Rt).call(this);return s._basePath=be(this._basePath,t),s}mount(t,s,a){let n,r;a&&(typeof a=="function"?r=a:(r=a.optionHandler,a.replaceRequest===!1?n=l=>l:n=a.replaceRequest));const i=r?l=>{const c=r(l);return Array.isArray(c)?c:[c]}:l=>{let c;try{c=l.executionCtx}catch{}return[l.env,c]};n||(n=(()=>{const l=be(this._basePath,t),c=l==="/"?0:l.length;return u=>{const m=new URL(u.url);return m.pathname=m.pathname.slice(c)||"/",new Request(m,u)}})());const d=async(l,c)=>{const u=await s(n(l.req.raw),...i(l));if(u)return u;await c()};return S(this,M,re).call(this,R,be(t,"*"),d),this}},F=new WeakMap,M=new WeakSet,Rt=function(){const t=new Ee({router:this.router,getPath:this.getPath});return t.errorHandler=this.errorHandler,E(t,W,p(this,W)),t.routes=this.routes,t},W=new WeakMap,re=function(t,s,a){t=t.toUpperCase(),s=be(this._basePath,s);const n={basePath:this._basePath,path:s,method:t,handler:a};this.router.add(t,s,[a,n]),this.routes.push(n)},We=function(t,s){if(t instanceof Error)return this.errorHandler(t,s);throw t},Ue=function(t,s,a,n){if(n==="HEAD")return(async()=>new Response(null,await S(this,M,Ue).call(this,t,s,a,"GET")))();const r=this.getPath(t,{env:a}),i=this.router.match(n,r),d=new os(t,{path:r,matchResult:i,env:a,executionCtx:s,notFoundHandler:p(this,W)});if(i[0].length===1){let c;try{c=i[0][0][0][0](d,async()=>{d.res=await p(this,W).call(this,d)})}catch(u){return S(this,M,We).call(this,u,d)}return c instanceof Promise?c.then(u=>u||(d.finalized?d.res:p(this,W).call(this,d))).catch(u=>S(this,M,We).call(this,u,d)):c??p(this,W).call(this,d)}const l=dt(i[0],this.errorHandler,p(this,W));return(async()=>{try{const c=await l(d);if(!c.finalized)throw new Error("Context is not finalized. Did you forget to return a Response object or `await next()`?");return c.res}catch(c){return S(this,M,We).call(this,c,d)}})()},Ee),Mt=[];function ps(e,t){const s=this.buildAllMatchers(),a=((n,r)=>{const i=s[n]||s[R],d=i[2][r];if(d)return d;const l=r.match(i[0]);if(!l)return[[],Mt];const c=l.indexOf("",1);return[i[1][c],l]});return this.match=a,a(e,t)}var Je="[^/]+",Ne=".*",Re="(?:|/.*)",we=Symbol(),hs=new Set(".\\+*[^]$()");function gs(e,t){return e.length===1?t.length===1?e<t?-1:1:-1:t.length===1||e===Ne||e===Re?1:t===Ne||t===Re?-1:e===Je?1:t===Je?-1:e.length===t.length?e<t?-1:1:t.length-e.length}var de,le,U,me,bs=(me=class{constructor(){I(this,de);I(this,le);I(this,U,Object.create(null))}insert(t,s,a,n,r){if(t.length===0){if(p(this,de)!==void 0)throw we;if(r)return;E(this,de,s);return}const[i,...d]=t,l=i==="*"?d.length===0?["","",Ne]:["","",Je]:i==="/*"?["","",Re]:i.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);let c;if(l){const u=l[1];let m=l[2]||Je;if(u&&l[2]&&(m===".*"||(m=m.replace(/^\((?!\?:)(?=[^)]+\)$)/,"(?:"),/\((?!\?:)/.test(m))))throw we;if(c=p(this,U)[m],!c){if(Object.keys(p(this,U)).some(g=>g!==Ne&&g!==Re))throw we;if(r)return;c=p(this,U)[m]=new me,u!==""&&E(c,le,n.varIndex++)}!r&&u!==""&&a.push([u,p(c,le)])}else if(c=p(this,U)[i],!c){if(Object.keys(p(this,U)).some(u=>u.length>1&&u!==Ne&&u!==Re))throw we;if(r)return;c=p(this,U)[i]=new me}c.insert(d,s,a,n,r)}buildRegExpStr(){const s=Object.keys(p(this,U)).sort(gs).map(a=>{const n=p(this,U)[a];return(typeof p(n,le)=="number"?`(${a})@${p(n,le)}`:hs.has(a)?`\\${a}`:a)+n.buildRegExpStr()});return typeof p(this,de)=="number"&&s.unshift(`#${p(this,de)}`),s.length===0?"":s.length===1?s[0]:"(?:"+s.join("|")+")"}},de=new WeakMap,le=new WeakMap,U=new WeakMap,me),$e,He,ft,fs=(ft=class{constructor(){I(this,$e,{varIndex:0});I(this,He,new bs)}insert(e,t,s){const a=[],n=[];for(let i=0;;){let d=!1;if(e=e.replace(/\{[^}]+\}/g,l=>{const c=`@\\${i}`;return n[i]=[c,l],i++,d=!0,c}),!d)break}const r=e.match(/(?::[^\/]+)|(?:\/\*$)|./g)||[];for(let i=n.length-1;i>=0;i--){const[d]=n[i];for(let l=r.length-1;l>=0;l--)if(r[l].indexOf(d)!==-1){r[l]=r[l].replace(d,n[i][1]);break}}return p(this,He).insert(r,t,a,p(this,$e),s),a}buildRegExp(){let e=p(this,He).buildRegExpStr();if(e==="")return[/^$/,[],[]];let t=0;const s=[],a=[];return e=e.replace(/#(\d+)|@(\d+)|\.\*\$/g,(n,r,i)=>r!==void 0?(s[++t]=Number(r),"$()"):(i!==void 0&&(a[Number(i)]=++t),"")),[new RegExp(`^${e}`),s,a]}},$e=new WeakMap,He=new WeakMap,ft),ws=[/^$/,[],Object.create(null)],qe=Object.create(null);function Lt(e){return qe[e]??(qe[e]=new RegExp(e==="*"?"":`^${e.replace(/\/\*$|([.\\+*[^\]$()])/g,(t,s)=>s?`\\${s}`:"(?:|/.*)")}$`))}function ys(){qe=Object.create(null)}function xs(e){var c;const t=new fs,s=[];if(e.length===0)return ws;const a=e.map(u=>[!/\*|\/:/.test(u[0]),...u]).sort(([u,m],[g,w])=>u?1:g?-1:m.length-w.length),n=Object.create(null);for(let u=0,m=-1,g=a.length;u<g;u++){const[w,b,y]=a[u];w?n[b]=[y.map(([v])=>[v,Object.create(null)]),Mt]:m++;let f;try{f=t.insert(b,m,w)}catch(v){throw v===we?new Nt(b):v}w||(s[m]=y.map(([v,x])=>{const _=Object.create(null);for(x-=1;x>=0;x--){const[T,D]=f[x];_[T]=D}return[v,_]}))}const[r,i,d]=t.buildRegExp();for(let u=0,m=s.length;u<m;u++)for(let g=0,w=s[u].length;g<w;g++){const b=(c=s[u][g])==null?void 0:c[1];if(!b)continue;const y=Object.keys(b);for(let f=0,v=y.length;f<v;f++)b[y[f]]=d[b[y[f]]]}const l=[];for(const u in i)l[u]=s[i[u]];return[r,l,n]}function ge(e,t){if(e){for(const s of Object.keys(e).sort((a,n)=>n.length-a.length))if(Lt(s).test(t))return[...e[s]]}}var X,ee,ze,Ot,wt,vs=(wt=class{constructor(){I(this,ze);k(this,"name","RegExpRouter");I(this,X);I(this,ee);k(this,"match",ps);E(this,X,{[R]:Object.create(null)}),E(this,ee,{[R]:Object.create(null)})}add(e,t,s){var d;const a=p(this,X),n=p(this,ee);if(!a||!n)throw new Error(Dt);a[e]||[a,n].forEach(l=>{l[e]=Object.create(null),Object.keys(l[R]).forEach(c=>{l[e][c]=[...l[R][c]]})}),t==="/*"&&(t="*");const r=(t.match(/\/:/g)||[]).length;if(/\*$/.test(t)){const l=Lt(t);e===R?Object.keys(a).forEach(c=>{var u;(u=a[c])[t]||(u[t]=ge(a[c],t)||ge(a[R],t)||[])}):(d=a[e])[t]||(d[t]=ge(a[e],t)||ge(a[R],t)||[]),Object.keys(a).forEach(c=>{(e===R||e===c)&&Object.keys(a[c]).forEach(u=>{l.test(u)&&a[c][u].push([s,r])})}),Object.keys(n).forEach(c=>{(e===R||e===c)&&Object.keys(n[c]).forEach(u=>l.test(u)&&n[c][u].push([s,r]))});return}const i=Et(t)||[t];for(let l=0,c=i.length;l<c;l++){const u=i[l];Object.keys(n).forEach(m=>{var g;(e===R||e===m)&&((g=n[m])[u]||(g[u]=[...ge(a[m],u)||ge(a[R],u)||[]]),n[m][u].push([s,r-c+l+1]))})}}buildAllMatchers(){const e=Object.create(null);return Object.keys(p(this,ee)).concat(Object.keys(p(this,X))).forEach(t=>{e[t]||(e[t]=S(this,ze,Ot).call(this,t))}),E(this,X,E(this,ee,void 0)),ys(),e}},X=new WeakMap,ee=new WeakMap,ze=new WeakSet,Ot=function(e){const t=[];let s=e===R;return[p(this,X),p(this,ee)].forEach(a=>{const n=a[e]?Object.keys(a[e]).map(r=>[r,a[e][r]]):[];n.length!==0?(s||(s=!0),t.push(...n)):e!==R&&t.push(...Object.keys(a[R]).map(r=>[r,a[R][r]]))}),s?xs(t):null},wt),te,G,yt,_s=(yt=class{constructor(e){k(this,"name","SmartRouter");I(this,te,[]);I(this,G,[]);E(this,te,e.routers)}add(e,t,s){if(!p(this,G))throw new Error(Dt);p(this,G).push([e,t,s])}match(e,t){if(!p(this,G))throw new Error("Fatal error");const s=p(this,te),a=p(this,G),n=s.length;let r=0,i;for(;r<n;r++){const d=s[r];try{for(let l=0,c=a.length;l<c;l++)d.add(...a[l]);i=d.match(e,t)}catch(l){if(l instanceof Nt)continue;throw l}this.match=d.match.bind(d),E(this,te,[d]),E(this,G,void 0);break}if(r===n)throw new Error("Fatal error");return this.name=`SmartRouter + ${this.activeRouter.name}`,i}get activeRouter(){if(p(this,G)||p(this,te).length!==1)throw new Error("No active router has been determined yet.");return p(this,te)[0]}},te=new WeakMap,G=new WeakMap,yt),De=Object.create(null),Es=e=>{for(const t in e)return!0;return!1},se,O,ce,ke,L,V,ie,Ie,ks=(Ie=class{constructor(t,s,a){I(this,V);I(this,se);I(this,O);I(this,ce);I(this,ke,0);I(this,L,De);if(E(this,O,a||Object.create(null)),E(this,se,[]),t&&s){const n=Object.create(null);n[t]={handler:s,possibleKeys:[],score:0},E(this,se,[n])}E(this,ce,[])}insert(t,s,a){E(this,ke,++ot(this,ke)._);let n=this;const r=Zt(s),i=[];for(let d=0,l=r.length;d<l;d++){const c=r[d],u=r[d+1],m=es(c,u),g=Array.isArray(m)?m[0]:c;if(g in p(n,O)){n=p(n,O)[g],m&&i.push(m[1]);continue}p(n,O)[g]=new Ie,m&&(p(n,ce).push(m),i.push(m[1])),n=p(n,O)[g]}return p(n,se).push({[t]:{handler:a,possibleKeys:i.filter((d,l,c)=>c.indexOf(d)===l),score:p(this,ke)}}),n}search(t,s){var u;const a=[];E(this,L,De);let r=[this];const i=vt(s),d=[],l=i.length;let c=null;for(let m=0;m<l;m++){const g=i[m],w=m===l-1,b=[];for(let f=0,v=r.length;f<v;f++){const x=r[f],_=p(x,O)[g];_&&(E(_,L,p(x,L)),w?(p(_,O)["*"]&&S(this,V,ie).call(this,a,p(_,O)["*"],t,p(x,L)),S(this,V,ie).call(this,a,_,t,p(x,L))):b.push(_));for(let T=0,D=p(x,ce).length;T<D;T++){const H=p(x,ce)[T],A=p(x,L)===De?{}:{...p(x,L)};if(H==="*"){const pe=p(x,O)["*"];pe&&(S(this,V,ie).call(this,a,pe,t,p(x,L)),E(pe,L,A),b.push(pe));continue}const[Ye,rt,Se]=H;if(!g&&!(Se instanceof RegExp))continue;const K=p(x,O)[Ye];if(Se instanceof RegExp){if(c===null){c=new Array(l);let he=s[0]==="/"?1:0;for(let Ce=0;Ce<l;Ce++)c[Ce]=he,he+=i[Ce].length+1}const pe=s.substring(c[m]),Ze=Se.exec(pe);if(Ze){if(A[rt]=Ze[0],S(this,V,ie).call(this,a,K,t,p(x,L),A),Es(p(K,O))){E(K,L,A);const he=((u=Ze[0].match(/\//))==null?void 0:u.length)??0;(d[he]||(d[he]=[])).push(K)}continue}}(Se===!0||Se.test(g))&&(A[rt]=g,w?(S(this,V,ie).call(this,a,K,t,A,p(x,L)),p(K,O)["*"]&&S(this,V,ie).call(this,a,p(K,O)["*"],t,A,p(x,L))):(E(K,L,A),b.push(K)))}}const y=d.shift();r=y?b.concat(y):b}return a.length>1&&a.sort((m,g)=>m.score-g.score),[a.map(({handler:m,params:g})=>[m,g])]}},se=new WeakMap,O=new WeakMap,ce=new WeakMap,ke=new WeakMap,L=new WeakMap,V=new WeakSet,ie=function(t,s,a,n,r){for(let i=0,d=p(s,se).length;i<d;i++){const l=p(s,se)[i],c=l[a]||l[R],u={};if(c!==void 0&&(c.params=Object.create(null),t.push(c),n!==De||r&&r!==De))for(let m=0,g=c.possibleKeys.length;m<g;m++){const w=c.possibleKeys[m],b=u[c.score];c.params[w]=r!=null&&r[w]&&!b?r[w]:n[w]??(r==null?void 0:r[w]),u[c.score]=!0}}},Ie),ue,xt,Is=(xt=class{constructor(){k(this,"name","TrieRouter");I(this,ue);E(this,ue,new ks)}add(e,t,s){const a=Et(t);if(a){for(let n=0,r=a.length;n<r;n++)p(this,ue).insert(e,a[n],s);return}p(this,ue).insert(e,t,s)}match(e,t){return p(this,ue).search(e,t)}},ue=new WeakMap,xt),At=class extends ms{constructor(e={}){super(e),this.router=e.router??new _s({routers:[new vs,new Is]})}},Ss=e=>{const s={...{origin:"*",allowMethods:["GET","HEAD","PUT","POST","DELETE","PATCH"],allowHeaders:[],exposeHeaders:[]},...e},a=(r=>typeof r=="string"?r==="*"?()=>r:i=>r===i?i:null:typeof r=="function"?r:i=>r.includes(i)?i:null)(s.origin),n=(r=>typeof r=="function"?r:Array.isArray(r)?()=>r:()=>[])(s.allowMethods);return async function(i,d){var u;function l(m,g){i.res.headers.set(m,g)}const c=await a(i.req.header("origin")||"",i);if(c&&l("Access-Control-Allow-Origin",c),s.credentials&&l("Access-Control-Allow-Credentials","true"),(u=s.exposeHeaders)!=null&&u.length&&l("Access-Control-Expose-Headers",s.exposeHeaders.join(",")),i.req.method==="OPTIONS"){s.origin!=="*"&&l("Vary","Origin"),s.maxAge!=null&&l("Access-Control-Max-Age",s.maxAge.toString());const m=await n(i.req.header("origin")||"",i);m.length&&l("Access-Control-Allow-Methods",m.join(","));let g=s.allowHeaders;if(!(g!=null&&g.length)){const w=i.req.header("Access-Control-Request-Headers");w&&(g=w.split(/\s*,\s*/))}return g!=null&&g.length&&(l("Access-Control-Allow-Headers",g.join(",")),i.res.headers.append("Vary","Access-Control-Request-Headers")),i.res.headers.delete("Content-Length"),i.res.headers.delete("Content-Type"),new Response(null,{headers:i.res.headers,status:204,statusText:"No Content"})}await d(),s.origin!=="*"&&i.header("Vary","Origin",{append:!0})}},Cs=/^[\w!#$%&'*.^`|~+-]+$/,Ts=/^[ !#-:<-[\]-~]*$/,Ds=(e,t)=>{if(t&&e.indexOf(t)===-1)return{};const s=e.trim().split(";"),a={};for(let n of s){n=n.trim();const r=n.indexOf("=");if(r===-1)continue;const i=n.substring(0,r).trim();if(t&&t!==i||!Cs.test(i))continue;let d=n.substring(r+1).trim();if(d.startsWith('"')&&d.endsWith('"')&&(d=d.slice(1,-1)),Ts.test(d)&&(a[i]=d.indexOf("%")!==-1?Ge(d,at):d,t))break}return a},Ns=(e,t,s={})=>{let a=`${e}=${t}`;if(e.startsWith("__Secure-")&&!s.secure)throw new Error("__Secure- Cookie must have Secure attributes");if(e.startsWith("__Host-")){if(!s.secure)throw new Error("__Host- Cookie must have Secure attributes");if(s.path!=="/")throw new Error('__Host- Cookie must have Path attributes with "/"');if(s.domain)throw new Error("__Host- Cookie must not have Domain attributes")}if(s&&typeof s.maxAge=="number"&&s.maxAge>=0){if(s.maxAge>3456e4)throw new Error("Cookies Max-Age SHOULD NOT be greater than 400 days (34560000 seconds) in duration.");a+=`; Max-Age=${s.maxAge|0}`}if(s.domain&&s.prefix!=="host"&&(a+=`; Domain=${s.domain}`),s.path&&(a+=`; Path=${s.path}`),s.expires){if(s.expires.getTime()-Date.now()>3456e7)throw new Error("Cookies Expires SHOULD NOT be greater than 400 days (34560000 seconds) in the future.");a+=`; Expires=${s.expires.toUTCString()}`}if(s.httpOnly&&(a+="; HttpOnly"),s.secure&&(a+="; Secure"),s.sameSite&&(a+=`; SameSite=${s.sameSite.charAt(0).toUpperCase()+s.sameSite.slice(1)}`),s.priority&&(a+=`; Priority=${s.priority.charAt(0).toUpperCase()+s.priority.slice(1)}`),s.partitioned){if(!s.secure)throw new Error("Partitioned Cookie must have Secure attributes");a+="; Partitioned"}return a},tt=(e,t,s)=>(t=encodeURIComponent(t),Ns(e,t,s)),Bt=(e,t,s)=>{const a=e.req.raw.headers.get("Cookie");{if(!a)return;let n=t;return s==="secure"?n="__Secure-"+t:s==="host"&&(n="__Host-"+t),Ds(a,n)[n]}},Rs=(e,t,s)=>{let a;return(s==null?void 0:s.prefix)==="secure"?a=tt("__Secure-"+e,t,{path:"/",...s,secure:!0}):(s==null?void 0:s.prefix)==="host"?a=tt("__Host-"+e,t,{...s,path:"/",secure:!0,domain:void 0}):a=tt(e,t,{path:"/",...s}),a},jt=(e,t,s,a)=>{const n=Rs(t,s,a);e.header("Set-Cookie",n,{append:!0})},Me=(e,t,s)=>{const a=Bt(e,t,s==null?void 0:s.prefix);return jt(e,t,"",{...s,maxAge:0}),a};const h=new At;h.onError((e,t)=>{console.error("Unhandled error:",e);const s=e instanceof Error?`${e.name}: ${e.message}`:String(e);return t.text(`Internal Error
${s}`,500)});h.use("/api/*",Ss({origin:e=>e?e.endsWith(".pages.dev")||e==="http://localhost:8788"||e==="http://127.0.0.1:8788"?e:null:"*",credentials:!0}));const Fe=new Map;let ut=0;function Ht(e,t,s){const a=Date.now();if(a-ut>6e4){ut=a;for(const[r,i]of Fe)a>i.resetAt&&Fe.delete(r)}let n=Fe.get(e);return(!n||a>n.resetAt)&&(n={count:0,resetAt:a+s*1e3},Fe.set(e,n)),n.count++,!(n.count>t)}function o(e,t,s){return e.json({ok:!1,error:s},t)}function nt(e){const t=new Uint8Array(e);let s="";for(let a=0;a<t.length;a++)s+=String.fromCharCode(t[a]);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}function Pt(e){for(e=e.replace(/-/g,"+").replace(/_/g,"/");e.length%4;)e+="=";const t=atob(e),s=new Uint8Array(t.length);for(let a=0;a<t.length;a++)s[a]=t.charCodeAt(a);return s}async function Ms(e,t){const s=new TextEncoder,a=await crypto.subtle.importKey("raw",s.encode(e),{name:"HMAC",hash:"SHA-256"},!1,["sign"]),n=await crypto.subtle.sign("HMAC",a,s.encode(t));return nt(n)}async function Ls(e,t,s){const a=new TextEncoder,n=await crypto.subtle.importKey("raw",a.encode(e),{name:"HMAC",hash:"SHA-256"},!1,["verify"]);return crypto.subtle.verify("HMAC",n,Pt(s),a.encode(t))}function ae(e=16){const t=new Uint8Array(e);return crypto.getRandomValues(t),[...t].map(s=>s.toString(16).padStart(2,"0")).join("")}async function ne(e,t,s=1e5){const a=new TextEncoder,n=new Uint8Array(t.match(/.{1,2}/g).map(d=>parseInt(d,16))),r=await crypto.subtle.importKey("raw",a.encode(e),"PBKDF2",!1,["deriveBits"]),i=await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:n,iterations:s},r,256);return nt(i)}async function Os(e,t){const s=nt(new TextEncoder().encode(JSON.stringify(t))),a=await Ms(e,s);return`v1.${s}.${a}`}async function As(e,t){const s=t.split(".");if(s.length!==3||s[0]!=="v1")return null;const a=s[1],n=s[2];if(!await Ls(e,a,n))return null;const i=new TextDecoder().decode(Pt(a));return JSON.parse(i)}h.use("*",async(e,t)=>{const s=e.env.ADMIN_LOGIN_ID||"",a=e.env.ADMIN_PASSWORD||"",n=e.env.SESSION_SECRET;if(!s||!a||!n)return t();if(!await e.env.DB.prepare("SELECT id FROM users WHERE role='admin' AND login_id=? LIMIT 1").bind(s).first()){const i=crypto.randomUUID(),d=ae(16),l=await ne(a,d);await e.env.DB.prepare(`INSERT INTO users (id, role, login_id, password_hash, password_salt, name, grade, class_name, is_active)
       VALUES (?, 'admin', ?, ?, ?, 'admin', 0, '-', 1)`).bind(i,s,l,d).run()}return t()});h.use("/api/*",async(e,t)=>{const s=Bt(e,"session");if(!s)return t();const a=e.env.SESSION_SECRET;if(!a)return t();const n=await As(a,s);if(!(n!=null&&n.id))return t();const r=720*60*60;return n.iat&&Math.floor(Date.now()/1e3)-n.iat>r?(Me(e,"session",{path:"/"}),t()):(e.set("user",{id:n.id,role:n.role,loginId:n.loginId,isActive:!!n.isActive}),t())});const Bs=[/[ちチﾁ][んンﾝ][こコﾞぽポ]/i,/[まマ][んンﾝ][こコ]/i,/[おオ][っッ][ぱパ][いイ]/i,/[ちチ][んンﾝ][ちチ][んンﾝ]/i,/[うウ][んンﾝ][こコ][ちチ]/i,/[うウ][んンﾝ][ちチ]/i,/[きキ][んンﾝ][たタ][まマ]/i,/[おオ][なナ][にニ]/i,/[しシ][ねネ]/,/[こコ][ろロ][すス]/,/死ね/,/殺す/,/殺/,/糞/,/クソ/,/ころす/,/しね[よ！]?$/,/ばか[やァ]?ろう/,/あほ/,/セックス/,/sex/i,/fuck/i,/shit/i,/dick/i,/pussy/i,/bitch/i,/エロ/,/えろ/,/ペニス/,/ヴァギナ/,/レイプ/,/うんこ/,/ウンコ/,/おしり/,/ケツ/];function js(e){const t=(e||"").trim();return Bs.some(s=>s.test(t))}h.post("/api/auth/signup",async e=>{const t=await e.req.json().catch(()=>null);if(!t)return o(e,400,"invalid_json");const s=String(t.loginId||"").trim(),a=String(t.password||""),n=String(t.name||"").trim(),r=Number(t.grade),i=String(t.className||"").trim();if(!s||s.length<3)return o(e,400,"loginId_too_short");if(!a||a.length<6)return o(e,400,"password_too_short");if(!n)return o(e,400,"name_required");if(js(n))return o(e,400,"name_inappropriate");if(!Number.isFinite(r)||r<1||r>12)return o(e,400,"grade_invalid");const d=crypto.randomUUID(),l=ae(16),c=await ne(a,l);try{await e.env.DB.prepare(`INSERT INTO users (id, role, login_id, password_hash, password_salt, name, grade, class_name, is_active)
       VALUES (?, 'student', ?, ?, ?, ?, ?, ?, 0)`).bind(d,s,c,l,n,r,i).run()}catch{return o(e,409,"loginId_taken")}return e.json({ok:!0,status:"ok"})});h.post("/api/auth/login",async e=>{const t=await e.req.json().catch(()=>null);if(!t)return o(e,400,"invalid_json");const s=String(t.loginId||"").trim(),a=String(t.password||"");if(!s||!a)return o(e,400,"missing_credentials");let n=await e.env.DB.prepare(`SELECT id, role, login_id as loginId, password_hash as hash, password_salt as salt, is_active as isActive,
            must_change_password as mustChangePassword
     FROM users WHERE login_id = ? LIMIT 1`).bind(s).first();if(!n){const d=await e.env.DB.prepare(`SELECT id, 'teacher' as role, login_id as loginId, password_hash as hash, password_salt as salt,
              is_active as isActive, 0 as mustChangePassword
       FROM teacher_accounts WHERE login_id = ? LIMIT 1`).bind(s).first();d&&(n=d)}if(!n||await ne(a,n.salt)!==n.hash)return o(e,401,"invalid_credentials");if((n.role==="student"||n.role==="teacher")&&!n.isActive)return o(e,403,"pending_approval");n.role==="student"&&n.mustChangePassword,n.role==="teacher"?await e.env.DB.prepare("UPDATE teacher_accounts SET last_login_at=datetime('now') WHERE id=?").bind(n.id).run():await e.env.DB.prepare("UPDATE users SET last_login_at=datetime('now') WHERE id=?").bind(n.id).run();const i=await Os(e.env.SESSION_SECRET,{id:n.id,role:n.role,loginId:n.loginId,isActive:!!n.isActive,iat:Math.floor(Date.now()/1e3)});return jt(e,"session",i,{httpOnly:!0,secure:!0,sameSite:"Lax",path:"/",maxAge:3600*24*30}),e.json({ok:!0,role:n.role,mustChangePassword:!!n.mustChangePassword})});h.post("/api/auth/logout",async e=>{const t={secure:!0,sameSite:"Lax",httpOnly:!0};return Me(e,"session",{...t,path:"/"}),Me(e,"session",{...t,path:"/api"}),e.json({ok:!0})});h.get("/api/auth/me",async e=>{const t=e.get("user");if(!t)return e.json({ok:!0,user:null});if(t.role==="teacher"){const a=await e.env.DB.prepare("SELECT name, school FROM teacher_accounts WHERE id = ? LIMIT 1").bind(t.id).first();return e.json({ok:!0,user:{...t,name:a==null?void 0:a.name,school:a==null?void 0:a.school,grade:null}})}let s=null;try{const a=await e.env.DB.prepare("SELECT grade, created_at FROM users WHERE id = ? LIMIT 1").bind(t.id).first();if(a&&(s=a.grade??null,s!==null&&s<6&&t.role==="student")){const n=new Date,r=n.getUTCFullYear(),i=n.getUTCMonth()+1,d=new Date(a.created_at),l=d.getUTCFullYear(),u=d.getUTCMonth()+1>=4?l:l-1,g=(i>=4?r:r-1)-u;if(g>0){const w=Math.min(6,a.grade+g);w!==a.grade&&(await e.env.DB.prepare("UPDATE users SET grade=? WHERE id=?").bind(w,t.id).run(),s=w)}}}catch{}return e.json({ok:!0,user:{...t,grade:s}})});function q(e){const t=e.get("user");return!t||t.role!=="student"&&t.role!=="admin"&&t.role!=="teacher"?null:t}h.get("/api/student/progress",async e=>{const t=q(e);if(!t)return o(e,401,"unauthorized");const s=await e.env.DB.prepare("SELECT state_json as stateJson, updated_at as updatedAt FROM progress WHERE user_id = ?").bind(t.id).first();return e.json({ok:!0,progress:s?{stateJson:s.stateJson,updatedAt:s.updatedAt}:null})});h.put("/api/student/progress",async e=>{const t=q(e);if(!t)return o(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return o(e,400,"invalid_json");const a=JSON.stringify(s.state??s);if(t.role==="teacher")return e.json({ok:!0});if(a.length>1e6)return e.json({ok:!0});try{await e.env.DB.prepare(`INSERT INTO progress (user_id, state_json, updated_at)
       VALUES (?, ?, datetime('now'))
       ON CONFLICT(user_id) DO UPDATE SET state_json=excluded.state_json, updated_at=datetime('now')`).bind(t.id,a).run()}catch(n){return console.error("[progress] DB error:",(n==null?void 0:n.message)||n),o(e,500,"db_error")}try{const n=await e.env.DB.prepare("SELECT name, grade FROM users WHERE id=? LIMIT 1").bind(t.id).first(),r=Hs(a,(n==null?void 0:n.name)||""),i=Number((n==null?void 0:n.grade)||0),d=Ft(),l=await e.env.DB.prepare("SELECT week_start, correct_count, total_level, battle_power, pokedex_count, wild_win_streak, ranking_points FROM ranking_stats WHERE user_id=? LIMIT 1").bind(t.id).first();let c=0,u=0,m=0,g=0,w=0,b=0;l&&l.week_start===d||l&&(c=Number(l.correct_count||0),u=Number(l.total_level||0),m=Number(l.battle_power||0),g=Number(l.pokedex_count||0),w=Number(l.wild_win_streak||0),b=Number(l.ranking_points||0)),l?l.week_start!==d?await e.env.DB.prepare(`UPDATE ranking_stats SET
           display_name=?, total_level=?, monster_count=?, correct_count=?, ranking_points=?,
           grade=?, battle_power=?, pokedex_count=?, wild_win_streak=?,
           week_start=?, week_base_correct_count=?, week_base_total_level=?, week_base_battle_power=?, week_base_pokedex_count=?, week_base_wild_win_streak=?, week_base_ranking_points=?,
           updated_at=datetime('now')
         WHERE user_id=?`).bind(r.displayName,r.totalLevel,r.monsterCount,r.correctCount,r.rankingPoints,i,r.battlePower,r.pokedexCount,r.wildWinStreak,d,c,u,m,g,w,b,t.id).run():await e.env.DB.prepare(`UPDATE ranking_stats SET
           display_name=?, total_level=?, monster_count=?, correct_count=?, ranking_points=?,
           grade=?, battle_power=?, pokedex_count=?, wild_win_streak=?,
           updated_at=datetime('now')
         WHERE user_id=?`).bind(r.displayName,r.totalLevel,r.monsterCount,r.correctCount,r.rankingPoints,i,r.battlePower,r.pokedexCount,r.wildWinStreak,t.id).run():await e.env.DB.prepare(`INSERT INTO ranking_stats (user_id, display_name, total_level, monster_count, correct_count, ranking_points,
           grade, battle_power, pokedex_count, wild_win_streak,
           week_start, week_base_correct_count, week_base_total_level, week_base_battle_power, week_base_pokedex_count, week_base_wild_win_streak, week_base_ranking_points,
           updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`).bind(t.id,r.displayName,r.totalLevel,r.monsterCount,r.correctCount,r.rankingPoints,i,r.battlePower,r.pokedexCount,r.wildWinStreak,d,r.correctCount,r.totalLevel,r.battlePower,r.pokedexCount,r.wildWinStreak,r.rankingPoints).run()}catch{}return e.json({ok:!0})});h.post("/api/student/results",async e=>{const t=q(e);if(!t)return o(e,401,"unauthorized");if(!Ht(`results:${t.id}`,30,60))return o(e,429,"too_many_requests");const s=await e.req.json().catch(()=>null);if(!s)return o(e,400,"invalid_json");const a=String(s.unit||"").trim(),n=s.questionId!=null?String(s.questionId):null,r=s.isCorrect?1:0,i=s.timeMs!=null?Number(s.timeMs):null,d=s.answeredAt?String(s.answeredAt):null,l=s.meta?JSON.stringify(s.meta):null;return a?(await e.env.DB.prepare(`INSERT INTO learning_results (user_id, unit, question_id, is_correct, time_ms, answered_at, meta_json)
     VALUES (?, ?, ?, ?, ?, COALESCE(?, datetime('now')), ?)`).bind(t.id,a,n,r,i,d,l).run(),e.json({ok:!0})):o(e,400,"unit_required")});function Hs(e,t){try{const s=JSON.parse(e),a=s.state||s,n=Number(a.level||1),r=a.monsters||{},i=Object.keys(r).length,d=Object.values(r).reduce((f,v)=>f+Number((v==null?void 0:v.level)||1),0),l=n+d,c=a.trainingProgress||{},u=Object.values(c).reduce((f,v)=>f+Number((v==null?void 0:v.correctCount)??(v==null?void 0:v.count)??0),0),m=Object.values(c).reduce((f,v)=>(v==null?void 0:v.rankingPoints)!=null?f+Number(v.rankingPoints):f+Number((v==null?void 0:v.correctCount)??(v==null?void 0:v.count)??0),0),g=Number(a._cachedBattlePower||0),w=Array.isArray(a.pokedex)?a.pokedex.length:0,b=a.max||a.M&&a.M.max||{},y=Number(b.winStreak||a._cachedWildWinStreak||0);return{displayName:String(a.name||t).slice(0,30),totalLevel:l,monsterCount:i,correctCount:u,rankingPoints:m,battlePower:g,pokedexCount:w,wildWinStreak:y}}catch{return{displayName:t,totalLevel:0,monsterCount:0,correctCount:0,rankingPoints:0,battlePower:0,pokedexCount:0,wildWinStreak:0}}}function Ft(){const e=new Date,t=e.getUTCDay(),s=t===0?6:t-1,a=new Date(e);return a.setUTCDate(e.getUTCDate()-s),a.toISOString().slice(0,10)}function C(e){const t=e.get("user");return!t||t.role!=="admin"?null:t}h.get("/api/admin/pending",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=await e.env.DB.prepare(`SELECT id, login_id as loginId, name, grade, class_name as className, created_at as createdAt, disabled_reason as disabledReason
     FROM users WHERE role='student' AND is_active=0
     ORDER BY created_at DESC`).all();return e.json({ok:!0,users:s.results})});h.get("/api/admin/users",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=e.req.query("grade"),a=e.req.query("class"),n=["role='student'"],r=[];s&&(n.push("grade = ?"),r.push(Number(s))),a&&(n.push("class_name = ?"),r.push(String(a)));const i=`SELECT id, login_id as loginId, name, grade, class_name as className, is_active as isActive, disabled_reason as disabledReason, created_at as createdAt, last_login_at as lastLoginAt
               FROM users WHERE ${n.join(" AND ")} ORDER BY grade ASC, class_name ASC, name ASC`,d=await e.env.DB.prepare(i).bind(...r).all();return e.json({ok:!0,users:d.results})});h.post("/api/admin/approve/:id",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=e.req.param("id");return await e.env.DB.prepare("UPDATE users SET is_active=1, disabled_reason=NULL WHERE id=? AND role='student'").bind(s).run(),e.json({ok:!0})});h.post("/api/admin/disable/:id",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=e.req.param("id"),a=await e.req.json().catch(()=>({})),n=a!=null&&a.reason?String(a.reason).slice(0,200):null;return await e.env.DB.prepare("UPDATE users SET is_active=0, disabled_reason=? WHERE id=? AND role='student'").bind(n,s).run(),e.json({ok:!0})});h.post("/api/admin/reset-password/:id",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=e.req.param("id"),a=ae(4),n=ae(16),r=await ne(a,n);return await e.env.DB.prepare(`UPDATE users
       SET password_hash=?, password_salt=?, password_updated_at=datetime('now'), must_change_password=1
       WHERE id=? AND role='student'`).bind(r,n,s).run(),e.json({ok:!0,tempPassword:a})});h.delete("/api/admin/delete/:id",async e=>{const t=C(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("id");if(s===t.id)return o(e,400,"cannot_delete_self");const a=await e.env.DB.prepare("SELECT role FROM users WHERE id=? LIMIT 1").bind(s).first();return a?a.role!=="student"?o(e,400,"cannot_delete_admin"):(await e.env.DB.prepare("DELETE FROM progress WHERE user_id=?").bind(s).run(),await e.env.DB.prepare("DELETE FROM learning_results WHERE user_id=?").bind(s).run(),await e.env.DB.prepare("DELETE FROM battle_answers WHERE user_id=?").bind(s).run(),await e.env.DB.prepare("DELETE FROM users WHERE id=? AND role='student'").bind(s).run(),e.json({ok:!0})):o(e,404,"user_not_found")});h.post("/api/admin/change-password",async e=>{const t=C(e);if(!t)return o(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return o(e,400,"invalid_json");const a=String(s.oldPassword||""),n=String(s.newPassword||"");if(!a||!n)return o(e,400,"missing_fields");if(n.length<8)return o(e,400,"new_password_too_short");const r=await e.env.DB.prepare("SELECT id, password_hash as hash, password_salt as salt FROM users WHERE id=? AND role='admin' LIMIT 1").bind(t.id).first();if(!r)return o(e,404,"admin_not_found");if(await ne(a,r.salt)!==r.hash)return o(e,401,"invalid_old_password");const d=ae(16),l=await ne(n,d);return await e.env.DB.prepare("UPDATE users SET password_hash=?, password_salt=?, password_updated_at=datetime('now'), must_change_password=0 WHERE id=?").bind(l,d,t.id).run(),e.json({ok:!0})});h.get("/api/admin/results",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=Math.min(500,Math.max(1,Number(e.req.query("limit")||100))),a=e.req.query("from"),n=e.req.query("to"),r=e.req.query("grade"),i=e.req.query("class"),d=[],l=[];a&&(d.push("r.answered_at >= ?"),l.push(a)),n&&(d.push("r.answered_at <= ?"),l.push(n)),r&&(d.push("u.grade = ?"),l.push(Number(r))),i&&(d.push("u.class_name = ?"),l.push(String(i)));const c=d.length?`WHERE ${d.join(" AND ")}`:"",u=await e.env.DB.prepare(`SELECT r.id, r.answered_at as answeredAt, r.unit, r.question_id as questionId, r.is_correct as isCorrect, r.time_ms as timeMs,
            u.login_id as loginId, u.name, u.grade, u.class_name as className
     FROM learning_results r
     JOIN users u ON u.id = r.user_id
     ${c}
     ORDER BY r.answered_at DESC
     LIMIT ?`).bind(...l,s).all();return e.json({ok:!0,results:u.results})});h.get("/api/admin/results.csv",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=e.req.query("from"),a=e.req.query("to"),n=e.req.query("grade"),r=e.req.query("class"),i=[],d=[];s&&(i.push("r.answered_at >= ?"),d.push(s)),a&&(i.push("r.answered_at <= ?"),d.push(a)),n&&(i.push("u.grade = ?"),d.push(Number(n))),r&&(i.push("u.class_name = ?"),d.push(String(r)));const l=i.length?`WHERE ${i.join(" AND ")}`:"",c=await e.env.DB.prepare(`SELECT r.answered_at as answeredAt, u.grade, u.class_name as className, u.name, u.login_id as loginId,
            r.unit, r.question_id as questionId, r.is_correct as isCorrect, r.time_ms as timeMs
     FROM learning_results r
     JOIN users u ON u.id = r.user_id
     ${l}
     ORDER BY r.answered_at DESC
     LIMIT 5000`).bind(...d).all(),u=["answeredAt","grade","class","name","loginId","unit","questionId","isCorrect","timeMs"],m=w=>{const b=w==null?"":String(w);return/[\n\r",]/.test(b)?'"'+b.replace(/"/g,'""')+'"':b},g=[u.join(",")];for(const w of c.results)g.push([w.answeredAt,w.grade,w.className,w.name,w.loginId,w.unit,w.questionId,w.isCorrect,w.timeMs].map(m).join(","));return new Response(g.join(`
`),{headers:{"Content-Type":"text/csv; charset=utf-8","Content-Disposition":'attachment; filename="learning_results.csv"'}})});h.get("/api/admin/pending-teachers",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=await e.env.DB.prepare("SELECT id, login_id as loginId, name, school, created_at as createdAt FROM teacher_accounts WHERE is_active=0 ORDER BY created_at DESC").all();return e.json({ok:!0,teachers:s.results})});h.post("/api/admin/approve-teacher/:id",async e=>C(e)?(await e.env.DB.prepare("UPDATE teacher_accounts SET is_active=1 WHERE id=?").bind(e.req.param("id")).run(),e.json({ok:!0})):o(e,401,"unauthorized"));h.delete("/api/admin/reject-teacher/:id",async e=>C(e)?(await e.env.DB.prepare("DELETE FROM teacher_accounts WHERE id=? AND is_active=0").bind(e.req.param("id")).run(),e.json({ok:!0})):o(e,401,"unauthorized"));h.get("/api/admin/teachers",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=await e.env.DB.prepare(`SELECT id, login_id as loginId, name, school, is_active as isActive, last_login_at as lastLoginAt, created_at as createdAt
     FROM teacher_accounts ORDER BY created_at DESC`).all();return e.json({ok:!0,teachers:s.results})});h.post("/api/admin/teacher-reset-password/:id",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=e.req.param("id"),a=ae(4),n=ae(16),r=await ne(a,n);return await e.env.DB.prepare("UPDATE teacher_accounts SET password_hash=?, password_salt=? WHERE id=?").bind(r,n,s).run(),e.json({ok:!0,tempPassword:a})});h.get("/api/admin/settings",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=await e.env.DB.prepare("SELECT key, value FROM admin_settings").all(),a={};for(const n of s.results)a[n.key]=n.value;return e.json({ok:!0,settings:a})});h.put("/api/admin/settings",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return o(e,400,"invalid_json");for(const[a,n]of Object.entries(s))typeof n=="string"&&await e.env.DB.prepare(`INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
       ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now')`).bind(a,n).run();return e.json({ok:!0})});h.put("/api/admin/user-grade",async e=>{const t=e.get("user");if(!t||t.role!=="admin"&&t.role!=="teacher")return o(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return o(e,400,"invalid_json");const a=String(s.userId||""),n=Number(s.grade);return!a||!Number.isFinite(n)||n<1||n>6?o(e,400,"invalid_grade"):(await e.env.DB.prepare("UPDATE users SET grade=? WHERE id=? AND role='student'").bind(n,a).run(),e.json({ok:!0}))});h.get("/api/admin/classes",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=await e.env.DB.prepare(`SELECT c.id, c.class_code as classCode, c.name, c.created_at as createdAt, COALESCE(t.name, u.name) as teacherName,
     (SELECT COUNT(*) FROM class_members cm WHERE cm.class_id = c.id) as memberCount
     FROM classes c LEFT JOIN teacher_accounts t ON t.id = c.teacher_id LEFT JOIN users u ON u.id = c.teacher_id ORDER BY c.created_at DESC`).all();return e.json({ok:!0,classes:s.results})});h.get("/api/admin/class/:classId/members",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=e.req.param("classId");if(!await e.env.DB.prepare("SELECT id FROM classes WHERE id=? LIMIT 1").bind(s).first())return o(e,404,"class_not_found");const n=await e.env.DB.prepare(`SELECT u.id as userId, u.login_id as loginId, u.name, u.grade, u.class_name as className, cm.joined_at as joinedAt
     FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id=? ORDER BY u.grade ASC, u.name ASC`).bind(s).all();return e.json({ok:!0,members:n.results})});h.post("/api/admin/class/:classId/add-member",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=e.req.param("classId"),a=await e.req.json().catch(()=>null);if(!a)return o(e,400,"invalid_json");const n=String(a.userId||"").trim();if(!n)return o(e,400,"userId_required");const r=await e.env.DB.prepare("SELECT id, name FROM classes WHERE id=? LIMIT 1").bind(s).first();if(!r)return o(e,404,"class_not_found");const i=await e.env.DB.prepare("SELECT id, name FROM users WHERE id=? AND role='student' LIMIT 1").bind(n).first();return i?await e.env.DB.prepare("SELECT 1 FROM class_members WHERE user_id=? AND class_id=? LIMIT 1").bind(n,s).first()?e.json({ok:!0,already:!0,className:r.name}):(await e.env.DB.prepare("DELETE FROM class_members WHERE user_id=?").bind(n).run(),await e.env.DB.prepare("INSERT INTO class_members (user_id, class_id) VALUES (?, ?)").bind(n,s).run(),e.json({ok:!0,className:r.name,studentName:i.name})):o(e,404,"student_not_found")});h.post("/api/admin/class/:classId/add-members-bulk",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=e.req.param("classId"),a=await e.req.json().catch(()=>null);if(!a||!Array.isArray(a.userIds)||a.userIds.length===0)return o(e,400,"userIds_required");if(!await e.env.DB.prepare("SELECT id, name FROM classes WHERE id=? LIMIT 1").bind(s).first())return o(e,404,"class_not_found");let r=0,i=0;for(const d of a.userIds){const l=String(d).trim();if(!l)continue;if(!await e.env.DB.prepare("SELECT id FROM users WHERE id=? AND role='student' LIMIT 1").bind(l).first()){i++;continue}if(await e.env.DB.prepare("SELECT 1 FROM class_members WHERE user_id=? AND class_id=? LIMIT 1").bind(l,s).first()){i++;continue}await e.env.DB.prepare("DELETE FROM class_members WHERE user_id=?").bind(l).run(),await e.env.DB.prepare("INSERT INTO class_members (user_id, class_id) VALUES (?, ?)").bind(l,s).run(),r++}return e.json({ok:!0,added:r,skipped:i})});h.delete("/api/admin/class/:classId/remove-member/:userId",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=e.req.param("classId"),a=e.req.param("userId");return await e.env.DB.prepare("DELETE FROM class_members WHERE user_id=? AND class_id=?").bind(a,s).run(),e.json({ok:!0})});h.get("/api/admin/unassigned-students",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=await e.env.DB.prepare(`SELECT u.id, u.login_id as loginId, u.name, u.grade, u.class_name as className
     FROM users u
     WHERE u.role='student' AND u.is_active=1
       AND u.id NOT IN (SELECT cm.user_id FROM class_members cm)
     ORDER BY u.grade ASC, u.class_name ASC, u.name ASC`).all();return e.json({ok:!0,students:s.results})});function N(e){const t=e.get("user");return!t||t.role!=="teacher"&&t.role!=="admin"?null:t}function mt(){const e="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";let t="";const s=new Uint8Array(6);crypto.getRandomValues(s);for(let a=0;a<6;a++)t+=e[s[a]%e.length];return t}h.post("/api/auth/teacher-signup",async e=>{const t=await e.req.json().catch(()=>null);if(!t)return o(e,400,"invalid_json");const s=String(t.loginId||"").trim(),a=String(t.password||""),n=String(t.name||"").trim(),r=String(t.school||"").trim();if(!s||s.length<3)return o(e,400,"loginId_too_short");if(!a||a.length<6)return o(e,400,"password_too_short");if(!n)return o(e,400,"name_required");const i=crypto.randomUUID(),d=ae(16),l=await ne(a,d);try{await e.env.DB.prepare("INSERT INTO teacher_accounts (id, login_id, password_hash, password_salt, name, school) VALUES (?, ?, ?, ?, ?, ?)").bind(i,s,l,d,n,r).run()}catch{return o(e,409,"loginId_taken")}return e.json({ok:!0})});h.post("/api/teacher/class",async e=>{const t=N(e);if(!t)return o(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return o(e,400,"invalid_json");const a=String(s.name||"").trim();if(!a)return o(e,400,"name_required");let n=mt();for(let i=0;i<5&&await e.env.DB.prepare("SELECT id FROM classes WHERE class_code=? LIMIT 1").bind(n).first();i++)n=mt();const r=crypto.randomUUID();return await e.env.DB.prepare("INSERT INTO classes (id, class_code, name, teacher_id) VALUES (?, ?, ?, ?)").bind(r,n,a,t.id).run(),e.json({ok:!0,classId:r,classCode:n})});h.get("/api/teacher/classes",async e=>{const t=N(e);if(!t)return o(e,401,"unauthorized");const s=await e.env.DB.prepare(`SELECT id, class_code as classCode, name, ranking_enabled as rankingEnabled, homework_enabled as homeworkEnabled, contact_enabled as contactEnabled, menus_enabled as menusEnabled, created_at as createdAt,
         (SELECT COUNT(*) FROM class_members cm WHERE cm.class_id = classes.id) as memberCount
         FROM classes WHERE teacher_id=? ORDER BY created_at DESC`).bind(t.id).all();return e.json({ok:!0,classes:s.results})});h.get("/api/teacher/class/:classId/members",async e=>{const t=N(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("classId");if(!await e.env.DB.prepare("SELECT id FROM classes WHERE id=? AND teacher_id=?").bind(s,t.id).first())return o(e,404,"class not found");const n=await e.env.DB.prepare("SELECT u.id as userId, u.name FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id=? ORDER BY u.name").bind(s).all();return e.json({ok:!0,members:n.results})});h.delete("/api/teacher/class/:classId",async e=>{const t=N(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("classId");return await e.env.DB.prepare("DELETE FROM class_members WHERE class_id=?").bind(s).run(),t.role==="admin"?await e.env.DB.prepare("DELETE FROM classes WHERE id=?").bind(s).run():await e.env.DB.prepare("DELETE FROM classes WHERE id=? AND teacher_id=?").bind(s,t.id).run(),e.json({ok:!0})});h.put("/api/teacher/class/:classId/homework-toggle",async e=>{var i;const t=N(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("classId"),a=await e.req.json().catch(()=>null),n=a!=null&&a.enabled?1:0;return(i=(t.role==="admin"?await e.env.DB.prepare("UPDATE classes SET homework_enabled=? WHERE id=?").bind(n,s).run():await e.env.DB.prepare("UPDATE classes SET homework_enabled=? WHERE id=? AND teacher_id=?").bind(n,s,t.id).run()).meta)!=null&&i.changes?e.json({ok:!0,homeworkEnabled:n}):o(e,404,"class_not_found")});h.put("/api/teacher/class/:classId/contact-toggle",async e=>{var i;const t=N(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("classId"),a=await e.req.json().catch(()=>null),n=a!=null&&a.enabled?1:0;return(i=(t.role==="admin"?await e.env.DB.prepare("UPDATE classes SET contact_enabled=? WHERE id=?").bind(n,s).run():await e.env.DB.prepare("UPDATE classes SET contact_enabled=? WHERE id=? AND teacher_id=?").bind(n,s,t.id).run()).meta)!=null&&i.changes?e.json({ok:!0,contactEnabled:n}):o(e,404,"class_not_found")});h.put("/api/teacher/class/:classId/ranking-toggle",async e=>{var i;const t=N(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("classId"),a=await e.req.json().catch(()=>null),n=a!=null&&a.enabled?1:0;return(i=(t.role==="admin"?await e.env.DB.prepare("UPDATE classes SET ranking_enabled=? WHERE id=?").bind(n,s).run():await e.env.DB.prepare("UPDATE classes SET ranking_enabled=? WHERE id=? AND teacher_id=?").bind(n,s,t.id).run()).meta)!=null&&i.changes?e.json({ok:!0,rankingEnabled:n}):o(e,404,"class_not_found")});h.put("/api/teacher/class/:classId/menus-toggle",async e=>{var i;const t=N(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("classId"),a=await e.req.json().catch(()=>null),n=a!=null&&a.menusEnabled?JSON.stringify(a.menusEnabled):"{}";return(i=(t.role==="admin"?await e.env.DB.prepare("UPDATE classes SET menus_enabled=? WHERE id=?").bind(n,s).run():await e.env.DB.prepare("UPDATE classes SET menus_enabled=? WHERE id=? AND teacher_id=?").bind(n,s,t.id).run()).meta)!=null&&i.changes?e.json({ok:!0,menusEnabled:JSON.parse(n)}):o(e,404,"class_not_found")});h.get("/api/teacher/class/:classId/ranking",async e=>{const t=N(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("classId"),a=t.role==="admin"?await e.env.DB.prepare("SELECT id, name, class_code as classCode FROM classes WHERE id=? LIMIT 1").bind(s).first():await e.env.DB.prepare("SELECT id, name, class_code as classCode FROM classes WHERE id=? AND teacher_id=? LIMIT 1").bind(s,t.id).first();if(!a)return o(e,404,"class_not_found");const n=await e.env.DB.prepare(`
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
  `).bind(s).all();return e.json({ok:!0,class:a,members:n.results})});h.get("/api/teacher/class/:classId/unit-analytics",async e=>{var c,u,m,g,w;const t=N(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("classId"),a=t.role==="admin"?await e.env.DB.prepare("SELECT id, name FROM classes WHERE id=? LIMIT 1").bind(s).first():await e.env.DB.prepare("SELECT id, name FROM classes WHERE id=? AND teacher_id=? LIMIT 1").bind(s,t.id).first();if(!a)return o(e,404,"class_not_found");const n=await e.env.DB.prepare(`
    SELECT u.id, u.name, u.grade, p.state_json as stateJson
    FROM class_members cm
    JOIN users u ON u.id = cm.user_id
    LEFT JOIN progress p ON p.user_id = cm.user_id
    WHERE cm.class_id = ?
    ORDER BY u.name
  `).bind(s).all(),r=[],i=new Map;for(const b of n.results){let y={},f={},v=0;try{if(b.stateJson){const x=JSON.parse(b.stateJson);y=((u=(c=x==null?void 0:x.metrics)==null?void 0:c.learn)==null?void 0:u.byUnit)||{},f=((g=(m=x==null?void 0:x.metrics)==null?void 0:m.learn)==null?void 0:g.bySubject)||{};const _=((w=x==null?void 0:x.metrics)==null?void 0:w.daily)||{},T=Object.keys(_).filter(H=>{var A;return(((A=_[H])==null?void 0:A.training)||0)>=1}).sort();let D=0;for(let H=T.length-1;H>=0;H--){const A=new Date(T[H]+"T00:00:00+09:00");if(Math.round((Date.now()-A.getTime())/864e5)===T.length-1-H)D++;else break}v=D}}catch{}Object.keys(y).forEach(x=>{const _=y[x];!i.has(x)&&_.unitName&&i.set(x,{name:_.unitName,subject:_.subjectName||""})}),r.push({id:b.id,name:b.name||"",grade:b.grade||"",byUnit:y,bySubject:f,learnStreak:v})}const d=[];i.forEach((b,y)=>{r.some(f=>{var v;return(((v=f.byUnit[y])==null?void 0:v.total)||0)>=5})&&d.push(y)});const l=d.map(b=>{const y=i.get(b),f=r.filter(_=>{var T;return(((T=_.byUnit[b])==null?void 0:T.total)||0)>=5}),v=f.reduce((_,T)=>{const D=T.byUnit[b];return _+(D.total?D.correct/D.total:0)},0),x=f.length>0?Math.round(v/f.length*100):null;return{mode:b,name:y.name,subject:y.subject,classAvg:x,studentCount:f.length}}).sort((b,y)=>(b.classAvg??101)-(y.classAvg??101));return e.json({ok:!0,class:a,unitSummary:l,unitInfo:Object.fromEntries(i),students:r.map(b=>({id:b.id,name:b.name,grade:b.grade,learnStreak:b.learnStreak,bySubject:Object.fromEntries(Object.entries(b.bySubject).map(([y,f])=>[y,{total:f.total||0,correct:f.correct||0,acc:f.total?Math.round(f.correct/f.total*100):0}])),units:Object.fromEntries(d.map(y=>{const f=b.byUnit[y];return!f||(f.total||0)<5?[y,null]:[y,{total:f.total,correct:f.correct,acc:Math.round(f.correct/f.total*100)}]}))}))})});h.get("/api/teacher/class/:classId/activity",async e=>{const t=N(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("classId"),a=t.role==="admin"?await e.env.DB.prepare("SELECT id, name FROM classes WHERE id=? LIMIT 1").bind(s).first():await e.env.DB.prepare("SELECT id, name FROM classes WHERE id=? AND teacher_id=? LIMIT 1").bind(s,t.id).first();if(!a)return o(e,404,"class_not_found");const n=await e.env.DB.prepare(`SELECT u.id, u.name, u.last_login_at as lastLoginAt
     FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id = ?`).bind(s).all(),r=await e.env.DB.prepare(`SELECT r.user_id as userId, r.is_correct as isCorrect
     FROM learning_results r
     JOIN class_members cm ON cm.user_id = r.user_id AND cm.class_id = ?
     WHERE r.answered_at >= datetime('now', '-24 hours')`).bind(s).all(),i=new Set(r.results.map(g=>g.userId)),d=r.results.length,l=r.results.filter(g=>g.isCorrect).length,c=d>0?Math.round(l/d*100):null,u=await e.env.DB.prepare(`SELECT r.answered_at as answeredAt, r.unit, r.is_correct as isCorrect, r.time_ms as timeMs,
            u.name, u.login_id as loginId
     FROM learning_results r
     JOIN class_members cm ON cm.user_id = r.user_id AND cm.class_id = ?
     JOIN users u ON u.id = r.user_id
     ORDER BY r.answered_at DESC LIMIT 50`).bind(s).all(),m=n.results.filter(g=>{if(!g.lastLoginAt)return!0;const w=new Date(g.lastLoginAt+"Z");return Date.now()-w.getTime()>7*864e5}).map(g=>({id:g.id,name:g.name,lastLoginAt:g.lastLoginAt}));return e.json({ok:!0,class:a,summary:{memberCount:n.results.length,activeToday:i.size,totalProblems:d,accuracy:c},recentLog:u.results,inactive:m})});h.get("/api/teacher/class-ai-analysis",async e=>{const t=N(e);if(!t)return o(e,401,"unauthorized");const s=e.req.query("classId");if(!s)return o(e,400,"classId required");const a=t.role==="admin"?await e.env.DB.prepare("SELECT id, name FROM classes WHERE id=? LIMIT 1").bind(s).first():await e.env.DB.prepare("SELECT id, name FROM classes WHERE id=? AND teacher_id=? LIMIT 1").bind(s,t.id).first();if(!a)return o(e,404,"class_not_found");const n=await e.env.DB.prepare(`
    SELECT u.id, u.name, p.state_json
    FROM class_members cm JOIN users u ON u.id = cm.user_id
    LEFT JOIN progress p ON p.user_id = cm.user_id
    WHERE cm.class_id = ?
  `).bind(s).all(),r=e.req.query("weekKey")||"";let i={results:[]},d={results:[]},l={results:[]};try{i=await e.env.DB.prepare("SELECT user_id, subject, minutes, created_at FROM homework_logs WHERE class_id = ? AND week_key = ?").bind(s,r).all()}catch{}try{d=await e.env.DB.prepare("SELECT user_id, goal_text, plan_text, revision_count FROM weekly_plans WHERE class_id = ? AND week_key = ?").bind(s,r).all()}catch{}try{l=await e.env.DB.prepare("SELECT user_id, reflection_text, concentration, achievement FROM weekly_reflections WHERE class_id = ? AND week_key = ?").bind(s,r).all()}catch{}const c=n.results.map(m=>{var f,v;const g=i.results.filter(x=>x.user_id===m.id),w=d.results.find(x=>x.user_id===m.id),b=l.results.find(x=>x.user_id===m.id);let y={};try{if(m.state_json){const x=JSON.parse(m.state_json),_=((v=(f=x==null?void 0:x.metrics)==null?void 0:f.learn)==null?void 0:v.bySubject)||{};y=Object.fromEntries(Object.entries(_).map(([T,D])=>[T,{total:D.total||0,correct:D.correct||0,acc:D.total?Math.round(D.correct/D.total*100):0}]))}}catch{}return{name:m.name,homework:{count:g.length,totalMinutes:g.reduce((x,_)=>x+(_.minutes||0),0),subjects:g.map(x=>x.subject)},plan:w?{goal:w.goal_text,plan:w.plan_text,revisions:w.revision_count}:null,reflection:b?{text:b.reflection_text,concentration:b.concentration,achievement:b.achievement}:null,learning:y}}),u=["あなたは小学校の教師を支援するAIアシスタントです。以下は"+a.name+"の今週（"+r+"）の学習データです。","クラス人数: "+n.results.length+"人","","【児童別データ】",...c.map(m=>{let g="■ "+m.name+": 家庭学習"+m.homework.count+"回("+m.homework.totalMinutes+"分)";return m.plan&&(g+=", 計画あり(修正"+m.plan.revisions+"回)"),m.reflection&&(g+=", ふりかえりあり(集中度"+m.reflection.concentration+")"),Object.keys(m.learning).length>0&&(g+=", 教科別正答率: "+Object.entries(m.learning).map(([w,b])=>w+b.acc+"%").join("/")),g}),"","以下の観点で分析してください：","1. 家庭学習の傾向: クラス全体の提出状況、学習時間の傾向","2. 困りごとの検出: 学習量が少ない・正答率が低い・未提出の児童を特定","3. 自己調整の力: 計画→実行→ふりかえりのサイクルができている児童、支援が必要な児童","4. 具体的なアドバイス: 教師として来週どんな声かけや支援をすべきか","","日本語で、箇条書きではなく教師に語りかけるような文章で回答してください。"].join(`
`);try{const m=await e.env.AI.run("@cf/meta/llama-3.1-8b-instruct",{messages:[{role:"user",content:u}],max_tokens:1024});return e.json({ok:!0,analysis:m.response||m.result||""})}catch(m){return e.json({ok:!1,error:m.message||"AI error"},500)}});h.post("/api/student/join-class",async e=>{const t=q(e);if(!t)return o(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return o(e,400,"invalid_json");const a=String(s.classCode||"").trim().toUpperCase();if(!a)return o(e,400,"code_required");const n=await e.env.DB.prepare("SELECT id, name FROM classes WHERE class_code=? LIMIT 1").bind(a).first();return n?(await e.env.DB.prepare("SELECT 1 FROM class_members WHERE user_id=? AND class_id=? LIMIT 1").bind(t.id,n.id).first()||(await e.env.DB.prepare("DELETE FROM class_members WHERE user_id=?").bind(t.id).run(),await e.env.DB.prepare("INSERT INTO class_members (user_id, class_id) VALUES (?, ?)").bind(t.id,n.id).run()),e.json({ok:!0,className:n.name})):o(e,404,"class_not_found")});h.get("/api/student/class-info",async e=>{const t=q(e);if(!t)return o(e,401,"unauthorized");const s=await e.env.DB.prepare(`
    SELECT c.id, c.name, c.class_code as classCode, cm.joined_at as joinedAt,
           c.homework_enabled as homeworkEnabled, c.contact_enabled as contactEnabled, c.menus_enabled as menusEnabled
    FROM class_members cm JOIN classes c ON c.id = cm.class_id
    WHERE cm.user_id = ? LIMIT 1
  `).bind(t.id).first();return e.json({ok:!0,class:s||null})});h.post("/api/student/leave-class",async e=>{const t=q(e);return t?(await e.env.DB.prepare("DELETE FROM class_members WHERE user_id=?").bind(t.id).run(),e.json({ok:!0})):o(e,401,"unauthorized")});h.get("/api/ranking",async e=>{const t=e.get("user");if(!t)return o(e,401,"unauthorized");const s=await e.env.DB.prepare("SELECT value FROM admin_settings WHERE key='ranking_scope' LIMIT 1").first(),a=await e.env.DB.prepare("SELECT value FROM admin_settings WHERE key='ranking_enabled' LIMIT 1").first(),n=(s==null?void 0:s.value)||"class",r=(a==null?void 0:a.value)!=="0";if(!r||n==="hidden")return e.json({ok:!0,ranking:[],scope:n,enabled:!1,hidden:!0});const i=e.req.query("type")||"overall",d=e.req.query("period")||"cumulative",l=Number(e.req.query("grade")||0),c=Ft();let u="rs.total_level",m="";switch(i){case"overall":u="rs.total_level";break;case"power":u="rs.battle_power";break;case"correct":u="rs.ranking_points";break;case"pokedex":u="rs.pokedex_count";break;case"wild":u="rs.wild_win_streak";break;case"grade":u="rs.ranking_points";break}if(d==="weekly")switch(i){case"overall":m=", (rs.total_level - rs.week_base_total_level) as weeklyScore",u="weeklyScore";break;case"power":m=", (rs.battle_power - rs.week_base_battle_power) as weeklyScore",u="weeklyScore";break;case"correct":case"grade":m=", ROUND(rs.ranking_points - rs.week_base_ranking_points, 1) as weeklyScore",u="weeklyScore";break;case"pokedex":m=", (rs.pokedex_count - rs.week_base_pokedex_count) as weeklyScore",u="weeklyScore";break;case"wild":m=", (rs.wild_win_streak - rs.week_base_wild_win_streak) as weeklyScore",u="weeklyScore";break}const g=i==="grade"&&l>=1&&l<=6?` AND rs.grade = ${l}`:"",w=d==="weekly"?` AND rs.week_start = '${c}'`:"";let b="";const y=[],f=`rs.user_id as userId, rs.display_name as displayName,
    rs.total_level as totalLevel, rs.monster_count as monsterCount, rs.correct_count as correctCount,
    rs.ranking_points as rankingPoints,
    rs.grade, rs.battle_power as battlePower, rs.pokedex_count as pokedexCount, rs.wild_win_streak as wildWinStreak
    ${m}`;if(n==="global"||t.role==="admin")b=`SELECT ${f}
           FROM ranking_stats rs
           JOIN users u ON u.id = rs.user_id AND u.is_active=1
           JOIN class_members cm ON cm.user_id = rs.user_id
           JOIN classes cl ON cl.id = cm.class_id AND cl.ranking_enabled = 1
           WHERE 1=1 ${g} ${w}
           ORDER BY ${u} DESC, rs.correct_count DESC LIMIT 100`;else if(n==="class"){const _=await e.env.DB.prepare("SELECT cm.class_id, cl.ranking_enabled FROM class_members cm JOIN classes cl ON cl.id=cm.class_id WHERE cm.user_id=? LIMIT 1").bind(t.id).first();if(!_)return e.json({ok:!0,ranking:[],scope:n,enabled:r,message:"no_class"});if(!_.ranking_enabled)return e.json({ok:!0,ranking:[],scope:n,enabled:r,message:"ranking_not_allowed"});b=`SELECT ${f}
           FROM ranking_stats rs
           JOIN class_members cm ON cm.user_id = rs.user_id AND cm.class_id = ?
           JOIN users u ON u.id = rs.user_id AND u.is_active=1
           WHERE 1=1 ${g} ${w}
           ORDER BY ${u} DESC, rs.correct_count DESC LIMIT 100`,y.push(_.class_id)}else return e.json({ok:!0,ranking:[],scope:n,enabled:!1,hidden:!0});const x=(await e.env.DB.prepare(b).bind(...y).all()).results.map((_,T)=>({..._,rank:T+1,isMe:_.userId===t.id}));return e.json({ok:!0,ranking:x,scope:n,enabled:r,type:i,period:d})});function Ps(){const e=new Uint8Array(16);return crypto.getRandomValues(e),[...e].map(t=>t.toString(16).padStart(2,"0")).join("")}h.post("/api/homework/submit",async e=>{const t=e.get("user");if(!t||t.role!=="student")return o(e,403,"forbidden");const s=await e.req.json().catch(()=>null);if(!s)return o(e,400,"invalid_json");const a=String(s.dayKey||"").slice(0,10);if(!a)return o(e,400,"day_key_required");const n=await e.env.DB.prepare("SELECT id FROM homework_submissions WHERE user_id=? AND day_key=? LIMIT 1").bind(t.id,a).first();if(n)return e.json({ok:!0,alreadySubmitted:!0,id:n.id});const r=await e.env.DB.prepare("SELECT c.teacher_id FROM class_members cm JOIN classes c ON c.id=cm.class_id WHERE cm.user_id=? LIMIT 1").bind(t.id).first(),i=(r==null?void 0:r.teacher_id)||null,d=Ps();return await e.env.DB.prepare(`
    INSERT INTO homework_submissions
      (id, user_id, day_key, submitted_at, todo, why, aim, minutes, end_weather,
       weather_reason, next_improve, rest_day, streak_after,
       reward_kind, reward_coins, reward_shards, bonus_coins, bonus_shards, teacher_id,
       self_study_plan, weekly_plan, weekly_reflection, work_photo_analysis)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).bind(d,t.id,a,Date.now(),String(s.todo||"").slice(0,500),String(s.why||"").slice(0,500),String(s.aim||"").slice(0,500),Number(s.minutes||0),String(s.endWeather||"sun"),String(s.weatherReason||"").slice(0,500),String(s.nextImprove||"").slice(0,500),s.restDay?1:0,Number(s.streakAfter||0),String(s.rewardKind||"coin"),Number(s.rewardCoins||0),Number(s.rewardShards||0),Number(s.bonusCoins||0),Number(s.bonusShards||0),i,String(s.selfStudyPlan||"").slice(0,500),String(s.weeklyPlan||"").slice(0,1e3),String(s.weeklyReflection||"").slice(0,1e3),String(s.workPhotoAnalysis||"").slice(0,500)).run(),e.json({ok:!0,id:d})});h.post("/api/homework/analyze-photo",async e=>{try{const t=e.get("user");if(!t)return o(e,403,"forbidden");const s=await e.req.formData().catch(()=>null);if(!s)return o(e,400,"invalid_form_data");const a=String(s.get("dayKey")||"").slice(0,10);if(!a)return o(e,400,"day_key_required");const n=s.get("photo");if(!n||!n.size)return o(e,400,"photo_required");if(n.size>5*1024*1024)return o(e,400,"photo_too_large_max_5mb");let r="";try{const i=new Uint8Array(await n.arrayBuffer());let d="";for(let g=0;g<i.length;g+=8192)d+=String.fromCharCode(...i.subarray(g,Math.min(g+8192,i.length)));const l=btoa(d),u=`data:${n.type||"image/jpeg"};base64,${l}`,m=await e.env.AI.run("@cf/google/gemma-4-26b-a4b-it",{messages:[{role:"user",content:[{type:"image_url",image_url:{url:u}},{type:"text",text:`You are an experienced Japanese elementary school teacher reviewing a student's home study notebook photo.

Analyze the image and respond in Japanese (日本語で回答). Describe:
1. 教科・学習内容（何の勉強か）
2. 学習の量（文字数やページ数の印象）
3. 丁寧さ（字の綺麗さ、レイアウト）
4. 良い点や特徴

80〜120文字程度で簡潔にまとめてください。温かい言葉で書いてください。`}]}],max_tokens:300});r=String(m.response||"").trim().slice(0,500)}catch(i){console.error("AI photo analysis error:",i),r=""}if(r)try{const i=await e.env.DB.prepare("SELECT id FROM homework_submissions WHERE user_id=? AND day_key=? LIMIT 1").bind(t.id,a).first();i&&await e.env.DB.prepare("UPDATE homework_submissions SET work_photo_analysis=? WHERE id=?").bind(r,i.id).run()}catch{}return e.json({ok:!0,analysis:r||"",saved:!!r})}catch(t){return console.error("analyze-photo error:",t),e.json({ok:!0,analysis:"",saved:!1})}});h.put("/api/homework/submit",async e=>{var r;const t=e.get("user");if(!t||t.role!=="student")return o(e,403,"forbidden");const s=await e.req.json().catch(()=>null);if(!s)return o(e,400,"invalid_json");const a=String(s.dayKey||"").slice(0,10);return a?(r=(await e.env.DB.prepare(`
    UPDATE homework_submissions
    SET todo=?, why=?, aim=?, minutes=?, end_weather=?, weather_reason=?, next_improve=?,
        self_study_plan=?, weekly_plan=?, weekly_reflection=?,
        updated_at=?
    WHERE user_id=? AND day_key=?
  `).bind(String(s.todo||"").slice(0,500),String(s.why||"").slice(0,500),String(s.aim||"").slice(0,500),Number(s.minutes||0),String(s.endWeather||"sun"),String(s.weatherReason||"").slice(0,500),String(s.nextImprove||"").slice(0,500),String(s.selfStudyPlan||"").slice(0,500),String(s.weeklyPlan||"").slice(0,1e3),String(s.weeklyReflection||"").slice(0,1e3),Date.now(),t.id,a).run()).meta)!=null&&r.changes?e.json({ok:!0}):o(e,404,"not_found"):o(e,400,"day_key_required")});h.get("/api/homework/my",async e=>{const t=e.get("user");if(!t||t.role!=="student")return o(e,403,"forbidden");const s=await e.env.DB.prepare(`
    SELECT id, day_key as dayKey, submitted_at as submittedAt, rest_day as restDay,
           teacher_comment as teacherComment, has_physical as hasPhysical,
           returned_at as returnedAt, reward_claimed as rewardClaimed,
           reward_kind as rewardKind, reward_coins as rewardCoins, reward_shards as rewardShards,
           bonus_coins as bonusCoins, bonus_shards as bonusShards
    FROM homework_submissions WHERE user_id=? ORDER BY submitted_at DESC LIMIT 30
  `).bind(t.id).all();return e.json({ok:!0,submissions:s.results})});h.post("/api/homework/:id/claim",async e=>{const t=e.get("user");if(!t||t.role!=="student")return o(e,403,"forbidden");const s=e.req.param("id"),a=await e.env.DB.prepare(`
    SELECT * FROM homework_submissions WHERE id=? AND user_id=? LIMIT 1
  `).bind(s,t.id).first();if(!a)return o(e,404,"not_found");if(!a.returned_at)return o(e,400,"not_returned_yet");if(a.reward_claimed)return o(e,400,"already_claimed");const n=a.has_physical?1:.5,r=Math.floor((Number(a.reward_coins||0)+Number(a.bonus_coins||0))*n),i=Math.floor((Number(a.reward_shards||0)+Number(a.bonus_shards||0))*n),d=String(a.reward_kind||"coin");return await e.env.DB.prepare(`
    UPDATE homework_submissions SET reward_claimed=1, reward_claimed_at=? WHERE id=?
  `).bind(Date.now(),s).run(),e.json({ok:!0,coins:r,shards:i,rewardKind:d,hasPhysical:!!a.has_physical})});h.get("/api/teacher/homework",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return o(e,403,"forbidden");const s=e.req.query("classId");let a=`
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
           hs.work_photo_analysis as workPhotoAnalysis,
           u.id as userId, u.name as studentName, u.grade, u.class_name as className
    FROM homework_submissions hs
    JOIN users u ON u.id = hs.user_id
    JOIN class_members cm ON cm.user_id = hs.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
  `;const n=[t.id];s&&(a+=" AND cl.id = ?",n.push(s)),a+=" ORDER BY hs.submitted_at DESC LIMIT 100";const r=await e.env.DB.prepare(a).bind(...n).all();return e.json({ok:!0,submissions:r.results})});h.post("/api/teacher/homework/:id/return",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return o(e,403,"forbidden");const s=e.req.param("id"),a=await e.req.json().catch(()=>({}));return await e.env.DB.prepare(`
    SELECT hs.id FROM homework_submissions hs
    JOIN class_members cm ON cm.user_id = hs.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
    WHERE hs.id = ? LIMIT 1
  `).bind(t.id,s).first()?(await e.env.DB.prepare(`
    UPDATE homework_submissions
    SET teacher_id=?, teacher_comment=?, has_physical=?, returned_at=?
    WHERE id=?
  `).bind(t.id,String(a.comment||"").slice(0,500),a.hasPhysical?1:0,Date.now(),s).run(),e.json({ok:!0})):o(e,404,"not_found")});h.post("/api/teacher/homework-ai-comments",async e=>{var c;const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return o(e,403,"forbidden");const s=await e.req.json().catch(()=>null);if(!(s!=null&&s.classId))return o(e,400,"classId required");if(!(t.role==="admin"?await e.env.DB.prepare("SELECT id FROM classes WHERE id=? LIMIT 1").bind(s.classId).first():await e.env.DB.prepare("SELECT id FROM classes WHERE id=? AND teacher_id=?").bind(s.classId,t.id).first()))return o(e,404,"class_not_found");const n=await e.env.DB.prepare(`
    SELECT hs.id, hs.user_id, hs.todo, hs.why, hs.aim, hs.minutes, hs.end_weather,
           hs.weather_reason, hs.next_improve, hs.weekly_reflection, hs.day_key, u.name,
           hs.work_photo_analysis
    FROM homework_submissions hs
    JOIN class_members cm ON cm.user_id = hs.user_id AND cm.class_id = ?
    JOIN users u ON u.id = hs.user_id
    WHERE hs.returned_at IS NULL
    ORDER BY u.name, hs.day_key DESC
  `).bind(s.classId).all();if(!((c=n.results)!=null&&c.length))return e.json({ok:!0,comments:[]});const r=[...new Set(n.results.map(u=>u.user_id))],i={};for(const u of r)try{const m=await e.env.DB.prepare(`
        SELECT day_key, todo, minutes, end_weather, weather_reason, teacher_comment
        FROM homework_submissions WHERE user_id=? AND returned_at IS NOT NULL
        ORDER BY day_key DESC LIMIT 20
      `).bind(u).all();i[u]=m.results||[]}catch{i[u]=[]}const l=`You are an assistant for a Japanese elementary school teacher. Read each student's home study reflection below and write a short, warm comment (20-30 characters in Japanese) for each student.

Rules:
- Write comments in Japanese (日本語)
- Each comment should praise specific effort or progress
- Reference what the student studied and their reflection
- If "成果物の様子" (work photo analysis) is provided, mention the neatness or effort visible in their work
- Use encouraging, warm tone appropriate for elementary students
- Return ONLY valid JSON, no other text: {"comments":["コメント1","コメント2",...]}
- The number of comments must exactly match the number of students listed

=== Student Reflections ===
${n.results.map((u,m)=>{const g=i[u.user_id]||[],w=g.length?g.map(y=>`  [${y.day_key}] ${y.todo||""}(${y.minutes||0}分) 先生:${y.teacher_comment||"なし"}`).join(`
`):"  なし",b=u.work_photo_analysis?`
  成果物の様子: ${u.work_photo_analysis}`:"";return`${m+1}. 【${u.name}】(${u.day_key})
  やったこと: ${u.todo||"未記入"}
  なんで: ${u.why||"未記入"}
  めあて: ${u.aim||"未記入"}
  学習時間: ${u.minutes||0}分
  振り返り: ${u.weather_reason||"未記入"}
  次どうする: ${u.next_improve||"未記入"}${b}
  過去の記録:
${w}`}).join(`

`)}`;try{const m=((await e.env.AI.run("@cf/google/gemma-4-26b-a4b-it",{messages:[{role:"user",content:l}],max_tokens:2e3})).response||"").trim();let g=[];try{const b=m.match(/\{[\s\S]*\}/);b&&(g=JSON.parse(b[0]).comments||[])}catch{g=m.split(`
`).filter(b=>b.match(/^\d+[\.\)]/)).map(b=>b.replace(/^\d+[\.\)]\s*/,"").trim())}const w=n.results.map((b,y)=>({id:b.id,name:b.name,dayKey:b.day_key,comment:(g[y]||"").slice(0,50)}));return e.json({ok:!0,comments:w})}catch(u){return o(e,500,"AI error: "+(u.message||String(u)))}});function J(e){const t=new Date,s=new Date(Date.UTC(t.getFullYear(),t.getMonth(),t.getDate()));s.setUTCDate(s.getUTCDate()+4-(s.getUTCDay()||7));const a=new Date(Date.UTC(s.getUTCFullYear(),0,1)),n=Math.ceil(((s.getTime()-a.getTime())/864e5+1)/7);return`${s.getUTCFullYear()}-W${String(n).padStart(2,"0")}`}function Ve(e){const t=e.match(/^(\d{4})-W(\d{2})$/);if(!t)return e;let s=parseInt(t[1]),a=parseInt(t[2]);return a--,a<1&&(s--,a=52),s+"-W"+String(a).padStart(2,"0")}h.post("/api/teacher/class/:classId/weekly-menu",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return o(e,403,"forbidden");const s=e.req.param("classId");if(!(t.role==="admin"?await e.env.DB.prepare("SELECT id FROM classes WHERE id=? LIMIT 1").bind(s).first():await e.env.DB.prepare("SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1").bind(s,t.id).first()))return o(e,404,"class_not_found");const r=await e.req.json().catch(()=>null);if(!r)return o(e,400,"invalid_json");const i=String(r.weekKey||J()).slice(0,8),d=String(r.kanjiPage||"").slice(0,100),l=String(r.keisanPage||"").slice(0,100),c=String(r.otherTasks||"").slice(0,500),u=String(r.tests||"").slice(0,500),m=["mon","tue","wed","thu","fri"],g=Array.isArray(r.activeDays)?r.activeDays.filter(b=>m.includes(b)):m,w=JSON.stringify(g);return await e.env.DB.prepare(`
    INSERT INTO class_weekly_menu (class_id, week_key, kanji_page, keisan_page, other_tasks, tests, active_days, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(class_id, week_key) DO UPDATE SET
      kanji_page=excluded.kanji_page, keisan_page=excluded.keisan_page,
      other_tasks=excluded.other_tasks, tests=excluded.tests, active_days=excluded.active_days, updated_at=excluded.updated_at
  `).bind(s,i,d,l,c,u,w,Date.now()).run(),e.json({ok:!0,weekKey:i})});h.get("/api/teacher/class/:classId/weekly-menu",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return o(e,403,"forbidden");const s=e.req.param("classId");if(!(t.role==="admin"?await e.env.DB.prepare("SELECT id FROM classes WHERE id=? LIMIT 1").bind(s).first():await e.env.DB.prepare("SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1").bind(s,t.id).first()))return o(e,404,"class_not_found");const r=e.req.query("weekKey")||J(),i=await e.env.DB.prepare("SELECT * FROM class_weekly_menu WHERE class_id=? AND week_key=? LIMIT 1").bind(s,r).first();return e.json({ok:!0,menu:i||null,weekKey:r})});h.get("/api/student/weekly-menu",async e=>{const t=e.get("user");if(!t)return o(e,403,"forbidden");const s=e.req.query("weekKey")||J(),a=e.req.query("classId")||"";let n=null;if(t.role==="teacher"||t.role==="admin"?a?n=await e.env.DB.prepare(`
        SELECT kanji_page as kanjiPage, keisan_page as keisanPage,
               other_tasks as otherTasks, tests, week_key as weekKey, active_days as activeDays
        FROM class_weekly_menu WHERE class_id = ? AND week_key = ? LIMIT 1
      `).bind(a,s).first():n=await e.env.DB.prepare(`
        SELECT cwm.kanji_page as kanjiPage, cwm.keisan_page as keisanPage,
               cwm.other_tasks as otherTasks, cwm.tests as tests, cwm.week_key as weekKey,
               cwm.active_days as activeDays
        FROM class_weekly_menu cwm
        JOIN classes cls ON cls.id = cwm.class_id
        WHERE cls.teacher_id = ? AND cwm.week_key = ?
        LIMIT 1
      `).bind(t.id,s).first():n=await e.env.DB.prepare(`
      SELECT cwm.kanji_page as kanjiPage, cwm.keisan_page as keisanPage,
             cwm.other_tasks as otherTasks, cwm.tests as tests, cwm.week_key as weekKey,
             cwm.active_days as activeDays
      FROM class_weekly_menu cwm
      JOIN class_members cm ON cm.class_id = cwm.class_id
      WHERE cm.user_id = ? AND cwm.week_key = ?
      LIMIT 1
    `).bind(t.id,s).first(),!n){const r=Ve(s);let i=null;return t.role==="teacher"||t.role==="admin"?a?i=await e.env.DB.prepare(`
          SELECT kanji_page as kanjiPage, keisan_page as keisanPage,
                 other_tasks as otherTasks, tests, week_key as weekKey, active_days as activeDays
          FROM class_weekly_menu WHERE class_id = ? AND week_key = ? LIMIT 1
        `).bind(a,r).first():i=await e.env.DB.prepare(`
          SELECT cwm.kanji_page as kanjiPage, cwm.keisan_page as keisanPage,
                 cwm.other_tasks as otherTasks, cwm.tests as tests, cwm.week_key as weekKey,
                 cwm.active_days as activeDays
          FROM class_weekly_menu cwm
          JOIN classes cls ON cls.id = cwm.class_id
          WHERE cls.teacher_id = ? AND cwm.week_key = ?
          LIMIT 1
        `).bind(t.id,r).first():i=await e.env.DB.prepare(`
        SELECT cwm.kanji_page as kanjiPage, cwm.keisan_page as keisanPage,
               cwm.other_tasks as otherTasks, cwm.tests as tests, cwm.week_key as weekKey,
               cwm.active_days as activeDays
        FROM class_weekly_menu cwm
        JOIN class_members cm ON cm.class_id = cwm.class_id
        WHERE cm.user_id = ? AND cwm.week_key = ?
        LIMIT 1
      `).bind(t.id,r).first(),e.json({ok:!0,menu:i||null,weekKey:s,published:!1,fallbackWeek:i?r:null})}return e.json({ok:!0,menu:n,weekKey:s,published:!0})});h.get("/api/student/weekly-plan-status",async e=>{const t=e.get("user");if(!t)return o(e,403,"forbidden");const s=e.req.query("weekKey")||J(),a=await e.env.DB.prepare(`
    SELECT plan_approved as planApproved, plan_reward_coins as planRewardCoins,
           reflection_comment as reflectionComment, reflection_returned_at as reflectionReturnedAt,
           reflection_reward_coins as reflectionRewardCoins
    FROM student_weekly_plans WHERE user_id=? AND week_key=?
  `).bind(t.id,s).first();return e.json({ok:!0,status:a||null})});h.post("/api/student/weekly-plan",async e=>{const t=e.get("user");if(!t)return o(e,403,"forbidden");const s=await e.req.json().catch(()=>null);if(!s||!s.weekKey||!s.plans)return o(e,400,"invalid");const a=String(s.weekKey).slice(0,10),n=JSON.stringify(s.plans).slice(0,5e3),r=String(s.reason||"").slice(0,200),i=Date.now(),d=await e.env.DB.prepare("SELECT id, plans_json, revision_count FROM student_weekly_plans WHERE user_id=? AND week_key=?").bind(t.id,a).first();if(d&&d.plans_json&&d.plans_json!==n){const l=(d.revision_count||0)+1;await e.env.DB.prepare(`
      INSERT INTO plan_revisions (plan_id, user_id, week_key, revision_number, before_json, after_json, reason, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(d.id,t.id,a,l,d.plans_json,n,r,i).run(),await e.env.DB.prepare("UPDATE student_weekly_plans SET plans_json=?, updated_at=?, revision_count=? WHERE id=?").bind(n,i,l,d.id).run()}else await e.env.DB.prepare(`
      INSERT INTO student_weekly_plans (user_id, week_key, plans_json, updated_at, revision_count)
      VALUES (?, ?, ?, ?, 0)
      ON CONFLICT(user_id, week_key) DO UPDATE SET plans_json=excluded.plans_json, updated_at=excluded.updated_at
    `).bind(t.id,a,n,i).run();return e.json({ok:!0})});h.post("/api/student/weekly-reflection",async e=>{const t=e.get("user");if(!t)return o(e,403,"forbidden");const s=await e.req.json().catch(()=>null);if(!s||!s.weekKey)return o(e,400,"invalid");const a=String(s.weekKey).slice(0,10),n=Math.min(3,Math.max(1,Number(s.concentration)||2)),r=String(s.goodPoint||"").slice(0,300),i=String(s.improvePoint||"").slice(0,300),d=String(s.nextAction||"").slice(0,50),l=String(s.freeText||"").slice(0,500),c=Date.now();return await e.env.DB.prepare(`
    INSERT INTO structured_reflections (user_id, week_key, concentration, good_point, improve_point, next_action, free_text, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id, week_key) DO UPDATE SET
      concentration=excluded.concentration, good_point=excluded.good_point,
      improve_point=excluded.improve_point, next_action=excluded.next_action,
      free_text=excluded.free_text, created_at=excluded.created_at
  `).bind(t.id,a,n,r,i,d,l,c).run(),e.json({ok:!0})});h.get("/api/student/weekly-reflection",async e=>{const t=e.get("user");if(!t)return o(e,403,"forbidden");const s=e.req.query("weekKey")||J(),a=await e.env.DB.prepare(`
    SELECT concentration, good_point as goodPoint, improve_point as improvePoint,
           next_action as nextAction, free_text as freeText, created_at as createdAt
    FROM structured_reflections WHERE user_id=? AND week_key=?
  `).bind(t.id,s).first();return e.json({ok:!0,reflection:a||null})});h.get("/api/student/dashboard",async e=>{const t=e.get("user");if(!t)return o(e,403,"forbidden");const s=J(),a=Ve(s),n=await e.env.DB.prepare(`
    SELECT COUNT(*) as cnt, COALESCE(SUM(minutes),0) as totalMin, COALESCE(AVG(minutes),0) as avgMin
    FROM homework_submissions WHERE user_id=? AND week_key=?
  `).bind(t.id,s).first(),r=await e.env.DB.prepare(`
    SELECT COUNT(*) as cnt, COALESCE(SUM(minutes),0) as totalMin, COALESCE(AVG(minutes),0) as avgMin
    FROM homework_submissions WHERE user_id=? AND week_key=?
  `).bind(t.id,a).first(),i=await e.env.DB.prepare(`
    SELECT unit, COUNT(*) as total,
           SUM(CASE WHEN correct=1 THEN 1 ELSE 0 END) as correct_count
    FROM learning_results WHERE user_id=? AND week_key=?
    GROUP BY unit
  `).bind(t.id,s).all(),d=await e.env.DB.prepare(`
    SELECT unit, COUNT(*) as total,
           SUM(CASE WHEN correct=1 THEN 1 ELSE 0 END) as correct_count
    FROM learning_results WHERE user_id=? AND week_key=?
    GROUP BY unit
  `).bind(t.id,a).all(),l=await e.env.DB.prepare(`
    SELECT streak_after as streak FROM homework_submissions
    WHERE user_id=? ORDER BY submitted_at DESC LIMIT 1
  `).bind(t.id).first(),c=await e.env.DB.prepare(`
    SELECT revision_count, plan_approved FROM student_weekly_plans WHERE user_id=? AND week_key=?
  `).bind(t.id,s).first(),u=await e.env.DB.prepare(`
    SELECT concentration, good_point, improve_point, next_action FROM structured_reflections WHERE user_id=? AND week_key=?
  `).bind(t.id,s).first(),m=await e.env.DB.prepare(`
    SELECT reason FROM plan_revisions WHERE user_id=? AND week_key=?
  `).bind(t.id,s).all();let g=0;c&&(g+=2);const w=Math.min(1,((n==null?void 0:n.cnt)||0)/5);g+=Math.round(w*3);const b=(m.results||[]).filter(f=>f.reason&&f.reason.length>0).length;if(g+=Math.min(6,b*2),u){let f=0;u.good_point&&u.good_point.length>=5&&(f+=1),u.improve_point&&u.improve_point.length>=5&&(f+=1),u.next_action&&(f+=1),g+=f}const y=Wt({streak:(l==null?void 0:l.streak)||0,thisWeekMin:(n==null?void 0:n.totalMin)||0,prevWeekMin:(r==null?void 0:r.totalMin)||0,thisWeekCount:(n==null?void 0:n.cnt)||0,thisWeekResults:i.results||[],prevWeekResults:d.results||[],selfRegScore:g,revisionCount:(c==null?void 0:c.revision_count)||0});return e.json({ok:!0,weekKey:s,homework:{thisWeek:{count:(n==null?void 0:n.cnt)||0,totalMin:(n==null?void 0:n.totalMin)||0,avgMin:Math.round((n==null?void 0:n.avgMin)||0)},prevWeek:{count:(r==null?void 0:r.cnt)||0,totalMin:(r==null?void 0:r.totalMin)||0,avgMin:Math.round((r==null?void 0:r.avgMin)||0)}},results:{thisWeek:(i.results||[]).map(f=>({unit:f.unit,rate:f.total>0?Math.round(f.correct_count/f.total*100):0,total:f.total})),prevWeek:(d.results||[]).map(f=>({unit:f.unit,rate:f.total>0?Math.round(f.correct_count/f.total*100):0,total:f.total}))},streak:(l==null?void 0:l.streak)||0,selfRegulation:{score:g,maxScore:14,planMade:!!c,revisionCount:(c==null?void 0:c.revision_count)||0,reflectionDone:!!u},feedback:y})});function Wt(e){const t=[];if(e.streak>=14?t.push("🔥 "+e.streak+"日連続提出！すごい継続力だね！この調子！"):e.streak>=7?t.push("⭐ 1週間連続で提出できたね！がんばってるね！"):e.streak>=3&&t.push("👍 "+e.streak+"日連続！いいリズムだよ！"),e.prevWeekMin>0&&e.thisWeekMin>0){const a=e.thisWeekMin-e.prevWeekMin,n=Math.round(a/e.prevWeekMin*100);n>=20?t.push("📈 先週より学習時間が"+n+"%アップ！がんばりが見えるよ！"):n<=-20&&e.thisWeekCount>=3&&t.push("💪 今週は少し時間が短めだけど、ちゃんと取り組めてるね！")}const s={};for(const a of e.prevWeekResults)s[a.unit]=a.total>0?Math.round(a.correct_count/a.total*100):0;for(const a of e.thisWeekResults){const n=a.total>0?Math.round(a.correct_count/a.total*100):0,r=s[a.unit]||0;n>=r+15&&a.total>=3&&t.push("🎯 "+a.unit+"の正答率が先週より"+(n-r)+"%アップ！力がついてきたね！"),n<50&&a.total>=5&&t.push("📝 "+a.unit+"はもう少し練習してみよう。コツコツやれば必ず伸びるよ！")}return e.revisionCount>=2?t.push("🔄 計画を"+e.revisionCount+"回見直せたね！自分で考えて調整できるのはすごいことだよ！"):e.revisionCount===1&&t.push("🔄 計画を見直して修正できたね！これが「自分で学ぶ力」だよ！"),e.selfRegScore>=10&&t.push("🏆 自己調整スコアが"+e.selfRegScore+"点！自分の学びをしっかりコントロールできてるね！"),t.length===0&&t.push("🌟 今週も家庭学羒をがんばろう！少しずつで大丈夫だよ！"),t.slice(0,4)}h.get("/api/teacher/class-analytics",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return o(e,403,"forbidden");const s=e.req.query("classId");if(!s)return o(e,400,"classId required");const a=e.req.query("weekKey")||J(),n=Ve(a);if(!(t.role==="admin"?await e.env.DB.prepare("SELECT id FROM classes WHERE id=? LIMIT 1").bind(s).first():await e.env.DB.prepare("SELECT id FROM classes WHERE id=? AND teacher_id=?").bind(s,t.id).first()))return o(e,404,"class_not_found");const i=await e.env.DB.prepare(`
    SELECT u.id, u.name, u.grade, u.class_name as className
    FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id=?
    ORDER BY u.grade, u.class_name, u.name
  `).bind(s).all();let d={results:[]},l={results:[]};try{d=await e.env.DB.prepare(`
    SELECT hs.user_id, hs.submitted_at, hs.minutes
    FROM homework_submissions hs
    JOIN class_members cm ON cm.user_id = hs.user_id AND cm.class_id=?
    WHERE hs.week_key=?
  `).bind(s,a).all()}catch{}try{l=await e.env.DB.prepare(`
    SELECT hs.user_id, COUNT(*) as cnt, SUM(hs.minutes) as totalMin
    FROM homework_submissions hs
    JOIN class_members cm ON cm.user_id = hs.user_id AND cm.class_id=?
    WHERE hs.week_key=?
    GROUP BY hs.user_id
  `).bind(s,n).all()}catch{}const c=await e.env.DB.prepare(`
    SELECT swp.user_id, swp.revision_count, swp.plan_approved
    FROM student_weekly_plans swp
    JOIN class_members cm ON cm.user_id = swp.user_id AND cm.class_id=?
    WHERE swp.week_key=?
  `).bind(s,a).all(),u=await e.env.DB.prepare(`
    SELECT sr.user_id, sr.concentration, sr.good_point, sr.improve_point, sr.next_action
    FROM structured_reflections sr
    JOIN class_members cm ON cm.user_id = sr.user_id AND cm.class_id=?
    WHERE sr.week_key=?
  `).bind(s,a).all(),m={};for(const b of l.results||[])m[b.user_id]=b;const g={};for(const b of d.results||[])g[b.user_id]||(g[b.user_id]={cnt:0,totalMin:0}),g[b.user_id].cnt++,g[b.user_id].totalMin+=b.minutes||0;const w=[];for(const b of i.results||[]){const y=g[b.id],f=m[b.id];f&&f.cnt>=3&&(!y||y.cnt<=1)&&w.push({userId:b.id,name:b.name,type:"submission_drop",detail:"先週"+f.cnt+"回→今週"+((y==null?void 0:y.cnt)||0)+"回に減少"}),f&&f.totalMin>=60&&y&&y.totalMin<f.totalMin*.5&&w.push({userId:b.id,name:b.name,type:"time_drop",detail:"学習時間が先週の半分以下"}),!y&&(i.results||[]).length>0&&w.push({userId:b.id,name:b.name,type:"no_submission",detail:"今週まだ提出なし"})}return e.json({ok:!0,weekKey:a,members:i.results,homework:d.results,plans:c.results,reflections:u.results,alerts:w})});h.get("/api/teacher/auto-feedback",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return o(e,403,"forbidden");const s=e.req.query("classId");if(!s)return o(e,400,"classId required");const a=e.req.query("weekKey")||J(),n=Ve(a);if(!(t.role==="admin"?await e.env.DB.prepare("SELECT id FROM classes WHERE id=? LIMIT 1").bind(s).first():await e.env.DB.prepare("SELECT id FROM classes WHERE id=? AND teacher_id=?").bind(s,t.id).first()))return o(e,404,"class_not_found");const i=await e.env.DB.prepare(`
    SELECT u.id, u.name FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id=?
  `).bind(s).all(),d=[];for(const l of i.results||[]){let c={cnt:0,totalMin:0},u={cnt:0,totalMin:0};try{c=await e.env.DB.prepare(`
      SELECT COUNT(*) as cnt, COALESCE(SUM(minutes),0) as totalMin FROM homework_submissions WHERE user_id=? AND week_key=?
    `).bind(l.id,a).first()||c}catch{}try{u=await e.env.DB.prepare(`
      SELECT COUNT(*) as cnt, COALESCE(SUM(minutes),0) as totalMin FROM homework_submissions WHERE user_id=? AND week_key=?
    `).bind(l.id,n).first()||u}catch{}let m=null;try{m=await e.env.DB.prepare(`
      SELECT streak_after as streak FROM homework_submissions WHERE user_id=? ORDER BY submitted_at DESC LIMIT 1
    `).bind(l.id).first()}catch{}let g={results:[]};try{g=await e.env.DB.prepare(`
      SELECT unit, COUNT(*) as total, SUM(CASE WHEN correct=1 THEN 1 ELSE 0 END) as correct_count
      FROM learning_results WHERE user_id=? AND week_key=? GROUP BY unit
    `).bind(l.id,a).all()}catch{}let w={results:[]};try{w=await e.env.DB.prepare(`
      SELECT unit, COUNT(*) as total, SUM(CASE WHEN correct=1 THEN 1 ELSE 0 END) as correct_count
      FROM learning_results WHERE user_id=? AND week_key=? GROUP BY unit
    `).bind(l.id,n).all()}catch{}let b=null;try{b=await e.env.DB.prepare(`
      SELECT revision_count FROM student_weekly_plans WHERE user_id=? AND week_key=?
    `).bind(l.id,a).first()}catch{}const y=Wt({streak:(m==null?void 0:m.streak)||0,thisWeekMin:(c==null?void 0:c.totalMin)||0,prevWeekMin:(u==null?void 0:u.totalMin)||0,thisWeekCount:(c==null?void 0:c.cnt)||0,thisWeekResults:g.results||[],prevWeekResults:w.results||[],selfRegScore:0,revisionCount:(b==null?void 0:b.revision_count)||0});d.push({userId:l.id,name:l.name,messages:y})}return e.json({ok:!0,feedbackList:d,weekKey:a})});h.get("/api/teacher/weekly-plan/:id/revisions",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return o(e,403,"forbidden");const s=e.req.param("id");if(!await e.env.DB.prepare(`
    SELECT swp.user_id, swp.week_key FROM student_weekly_plans swp
    JOIN class_members cm ON cm.user_id = swp.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
    WHERE swp.id = ?
  `).bind(t.id,s).first())return o(e,404,"not_found");const n=await e.env.DB.prepare(`
    SELECT id, revision_number as revisionNumber, before_json as beforeJson, after_json as afterJson,
           reason, created_at as createdAt
    FROM plan_revisions WHERE plan_id=? ORDER BY revision_number DESC
  `).bind(s).all();return e.json({ok:!0,revisions:n.results})});h.get("/api/teacher/weekly-plans",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return o(e,403,"forbidden");const s=e.req.query("classId"),a=e.req.query("weekKey")||J();let n=`
    SELECT swp.id, swp.plans_json as plansJson, swp.updated_at as updatedAt, swp.week_key as weekKey,
           swp.plan_approved as planApproved, swp.plan_approved_at as planApprovedAt,
           swp.reflection_comment as reflectionComment, swp.reflection_returned_at as reflectionReturnedAt,
           swp.revision_count as revisionCount,
           u.id as userId, u.name as studentName, u.grade, u.class_name as className
    FROM student_weekly_plans swp
    JOIN users u ON u.id = swp.user_id
    JOIN class_members cm ON cm.user_id = swp.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
    WHERE swp.week_key = ?
  `;const r=[t.id,a];s&&(n+=" AND cl.id = ?",r.push(s)),n+=" ORDER BY u.grade, u.class_name, u.name";const i=await e.env.DB.prepare(n).bind(...r).all();return e.json({ok:!0,plans:i.results,weekKey:a})});h.post("/api/teacher/weekly-plan/:id/approve",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return o(e,403,"forbidden");const s=e.req.param("id"),a=await e.env.DB.prepare(`
    SELECT swp.*, cm.class_id FROM student_weekly_plans swp
    JOIN class_members cm ON cm.user_id = swp.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
    WHERE swp.id = ?
  `).bind(t.id,s).first();if(!a)return o(e,404,"not_found");if(a.plan_approved)return o(e,400,"already_approved");const n=300,r=5;return await e.env.DB.prepare("UPDATE student_weekly_plans SET plan_approved=1, plan_approved_at=?, plan_reward_coins=? WHERE id=?").bind(Date.now(),n,s).run(),e.json({ok:!0,coins:n,shards:r})});h.post("/api/teacher/weekly-plan/:id/return-reflection",async e=>{const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return o(e,403,"forbidden");const s=e.req.param("id"),a=await e.req.json().catch(()=>null);if(!a)return o(e,400,"invalid");const n=String(a.comment||"").slice(0,500),r=await e.env.DB.prepare(`
    SELECT swp.*, cm.class_id FROM student_weekly_plans swp
    JOIN class_members cm ON cm.user_id = swp.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
    WHERE swp.id = ?
  `).bind(t.id,s).first();if(!r)return o(e,404,"not_found");if(r.reflection_returned_at)return o(e,400,"already_returned");const i=300,d=5;return await e.env.DB.prepare("UPDATE student_weekly_plans SET reflection_comment=?, reflection_returned_at=?, reflection_reward_coins=? WHERE id=?").bind(n,Date.now(),i,s).run(),e.json({ok:!0,coins:i,shards:d})});h.post("/api/teacher/weekly-ai-comments",async e=>{var l;const t=e.get("user");if(!t||t.role!=="teacher"&&t.role!=="admin")return o(e,403,"forbidden");const s=await e.req.json().catch(()=>null);if(!(s!=null&&s.classId))return o(e,400,"classId required");if(!(t.role==="admin"?await e.env.DB.prepare("SELECT id FROM classes WHERE id=? LIMIT 1").bind(s.classId).first():await e.env.DB.prepare("SELECT id FROM classes WHERE id=? AND teacher_id=?").bind(s.classId,t.id).first()))return o(e,404,"class_not_found");const n=s.weekKey||J(),r=await e.env.DB.prepare(`
    SELECT swp.id, swp.user_id, swp.weekly_reflection, u.name
    FROM student_weekly_plans swp
    JOIN class_members cm ON cm.user_id = swp.user_id AND cm.class_id = ?
    JOIN users u ON u.id = swp.user_id
    WHERE swp.week_key = ? AND swp.reflection_returned_at IS NULL AND swp.weekly_reflection IS NOT NULL
  `).bind(s.classId,n).all();if(!((l=r.results)!=null&&l.length))return e.json({ok:!0,comments:[]});const d=`You are an assistant for a Japanese elementary school teacher. Read each student's weekly home study reflection below and write a short, warm comment (20-30 characters in Japanese) for each student.

Rules:
- Write comments in Japanese (日本語)
- Praise their weekly effort and growth
- Be specific about what they reflected on
- Use encouraging, warm tone appropriate for elementary students
- Return ONLY valid JSON, no other text: {"comments":["コメント1","コメント2",...]}
- The number of comments must exactly match the number of students listed

=== Student Weekly Reflections ===
${r.results.map((c,u)=>`${u+1}. 【${c.name}】
  振り返り: ${c.weekly_reflection||"未記入"}`).join(`

`)}`;try{const u=((await e.env.AI.run("@cf/google/gemma-4-26b-a4b-it",{messages:[{role:"user",content:d}],max_tokens:2e3})).response||"").trim();let m=[];try{const w=u.match(/\{[\s\S]*\}/);w&&(m=JSON.parse(w[0]).comments||[])}catch{m=u.split(`
`).filter(w=>w.match(/^\d+[\.\)]/)).map(w=>w.replace(/^\d+[\.\)]\s*/,"").trim())}const g=r.results.map((w,b)=>({id:w.id,name:w.name,comment:(m[b]||"").slice(0,50)}));return e.json({ok:!0,comments:g})}catch(c){return o(e,500,"AI error: "+(c.message||String(c)))}});function j(e){const t=e.get("user");return t||null}function Ke(){const e="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";let t="";const s=new Uint8Array(6);crypto.getRandomValues(s);for(let a=0;a<6;a++)t+=e[s[a]%e.length];return t}h.post("/api/battle/create",async e=>{const t=j(e);if(!t)return o(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return o(e,400,"invalid_json");const a=JSON.stringify(s.party||[]),n=String(s.name||"プレイヤー").slice(0,20),r=String(s.area||"rounding").slice(0,40),i=String(s.battleMode||"normal").slice(0,10);await e.env.DB.prepare("DELETE FROM battle_rooms WHERE host_user_id=? AND status='waiting'").bind(t.id).run();let d=Ke();for(let l=0;l<5&&await e.env.DB.prepare("SELECT id FROM battle_rooms WHERE id=?").bind(d).first();l++)d=Ke();return await e.env.DB.prepare(`
    INSERT INTO battle_rooms (id, host_user_id, host_name, host_party_json, area, battle_mode, status, host_hp, guest_hp, host_score, guest_score, question_index)
    VALUES (?, ?, ?, ?, ?, ?, 'waiting', 100, 100, 0, 0, 0)
  `).bind(d,t.id,n,a,r,i).run(),e.json({ok:!0,roomId:d})});h.post("/api/battle/join/:roomId",async e=>{const t=j(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),a=await e.req.json().catch(()=>null);if(!a)return o(e,400,"invalid_json");const n=String(a.name||"プレイヤー").slice(0,20),r=JSON.stringify(a.party||[]),i=await e.env.DB.prepare("SELECT * FROM battle_rooms WHERE id=? LIMIT 1").bind(s).first();return i?i.status!=="waiting"?o(e,409,"room_not_available"):i.host_user_id===t.id?o(e,400,"cannot_join_own_room"):(await e.env.DB.prepare(`
    UPDATE battle_rooms SET guest_user_id=?, guest_name=?, guest_party_json=?, status='ready', updated_at=datetime('now')
    WHERE id=? AND status='waiting'
  `).bind(t.id,n,r,s).run(),e.json({ok:!0,roomId:s,hostName:i.host_name,area:i.area,battleMode:i.battle_mode,hostParty:JSON.parse(i.host_party_json||"[]")})):o(e,404,"room_not_found")});h.get("/api/battle/room/:roomId",async e=>{const t=j(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),a=await e.env.DB.prepare("SELECT * FROM battle_rooms WHERE id=? LIMIT 1").bind(s).first();if(!a)return o(e,404,"room_not_found");const n=a.host_user_id===t.id,r=a.guest_user_id===t.id;if(!n&&!r)return o(e,403,"not_a_participant");const i=await e.env.DB.prepare(`
    SELECT user_id, question_index, is_correct, answered_at FROM battle_answers
    WHERE room_id=? AND question_index=?
  `).bind(s,a.question_index).all(),d=n?"host":"guest",l=n?a.guest_user_id:a.host_user_id,c=i.results.find(m=>m.user_id===t.id),u=i.results.find(m=>m.user_id===l);return e.json({ok:!0,room:{id:a.id,status:a.status,area:a.area,hostName:a.host_name,guestName:a.guest_name,questionIndex:a.question_index,questionJson:a.current_question_json,hostScore:a.host_score,guestScore:a.guest_score,hostHp:a.host_hp,guestHp:a.guest_hp,winner:a.winner,myRole:d,myAnswer:c?{isCorrect:!!c.is_correct}:null,oppAnswered:!!u,oppCorrect:u?!!u.is_correct:null,battleMode:a.battle_mode,opponentParty:n?a.guest_party_json?JSON.parse(a.guest_party_json):null:a.host_party_json?JSON.parse(a.host_party_json):null,opponentName:n?a.guest_name:a.host_name}})});h.post("/api/battle/set-question/:roomId",async e=>{const t=j(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),a=await e.req.json().catch(()=>null);if(!a)return o(e,400,"invalid_json");const n=await e.env.DB.prepare("SELECT * FROM battle_rooms WHERE id=? LIMIT 1").bind(s).first();if(!n)return o(e,404,"room_not_found");if(n.host_user_id!==t.id)return o(e,403,"host_only");if(n.status!=="ready"&&n.status!=="playing")return o(e,409,"invalid_status");const r=JSON.stringify(a.question),i=Number(a.questionIndex??n.question_index);return await e.env.DB.prepare(`
    UPDATE battle_rooms
    SET current_question_json=?, question_index=?, status='playing', updated_at=datetime('now')
    WHERE id=?
  `).bind(r,i,s).run(),e.json({ok:!0})});h.post("/api/battle/answer/:roomId",async e=>{const t=j(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),a=await e.req.json().catch(()=>null);if(!a)return o(e,400,"invalid_json");const n=await e.env.DB.prepare("SELECT * FROM battle_rooms WHERE id=? LIMIT 1").bind(s).first();if(!n)return o(e,404,"room_not_found");if(n.status!=="playing")return o(e,409,"not_playing");const r=n.host_user_id===t.id,i=n.guest_user_id===t.id;if(!r&&!i)return o(e,403,"not_a_participant");const d=a.isCorrect?1:0,l=String(a.answer||"").slice(0,100),c=n.question_index;if(await e.env.DB.prepare(`
    SELECT id FROM battle_answers WHERE room_id=? AND user_id=? AND question_index=?
  `).bind(s,t.id,c).first())return e.json({ok:!0,alreadyAnswered:!0});await e.env.DB.prepare(`
    INSERT INTO battle_answers (room_id, user_id, question_index, answer, is_correct)
    VALUES (?, ?, ?, ?, ?)
  `).bind(s,t.id,c,l,d).run();const m=await e.env.DB.prepare(`
    SELECT user_id, is_correct FROM battle_answers WHERE room_id=? AND question_index=?
  `).bind(s,c).all(),g=m.results.find(D=>D.user_id===n.host_user_id),w=m.results.find(D=>D.user_id===n.guest_user_id);let b=n.host_score,y=n.guest_score,f=n.host_hp,v=n.guest_hp,x=!1,_=n.status,T=n.winner;if(g&&w){x=!0;const D=!!g.is_correct,H=!!w.is_correct;D&&!H?(b++,v=Math.max(0,v-20)):!D&&H&&(y++,f=Math.max(0,f-20));const A=c+1;(f<=0||v<=0||A>=5)&&(_="finished",b>y?T="host":y>b?T="guest":T="draw"),await e.env.DB.prepare(`
      UPDATE battle_rooms
      SET host_score=?, guest_score=?, host_hp=?, guest_hp=?, status=?, winner=?, updated_at=datetime('now')
      WHERE id=?
    `).bind(b,y,f,v,_,T,s).run()}return e.json({ok:!0,bothAnswered:x,hostScore:b,guestScore:y,hostHp:f,guestHp:v,status:_,winner:T})});h.post("/api/battle/leave/:roomId",async e=>{const t=j(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),a=await e.env.DB.prepare("SELECT * FROM battle_rooms WHERE id=? LIMIT 1").bind(s).first();return a?(a.host_user_id===t.id?await e.env.DB.prepare("DELETE FROM battle_rooms WHERE id=?").bind(s).run():await e.env.DB.prepare(`
      UPDATE battle_rooms SET guest_user_id=NULL, guest_name=NULL, guest_party_json=NULL,
      status='waiting', current_question_json=NULL, question_index=0,
      host_score=0, guest_score=0, host_hp=100, guest_hp=100, winner=NULL, updated_at=datetime('now')
      WHERE id=?
    `).bind(s).run(),e.json({ok:!0})):e.json({ok:!0})});h.delete("/api/battle/cleanup",async e=>j(e)?(await e.env.DB.prepare(`
    DELETE FROM battle_rooms WHERE created_at < datetime('now', '-2 hours')
  `).run(),e.json({ok:!0})):o(e,401,"unauthorized"));function pt(){const e="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";let t="";for(let s=0;s<6;s++)t+=e[Math.floor(Math.random()*e.length)];return t}h.post("/api/trade/offer",async e=>{const t=e.get("user");if(!t)return o(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!(s!=null&&s.monster))return o(e,400,"monster_required");await e.env.DB.prepare("UPDATE trade_offers SET status='cancelled' WHERE from_user_id=? AND status='pending'").bind(t.id).run();const a=crypto.randomUUID();let n=pt();for(let d=0;d<3&&await e.env.DB.prepare("SELECT id FROM trade_offers WHERE code=? AND status='pending' AND expires_at > ?").bind(n,Date.now()).first();d++)n=pt();const r=Date.now(),i=r+1440*60*1e3;return await e.env.DB.prepare(`
    INSERT INTO trade_offers (id, code, from_user_id, from_user_name, from_monster_json, status, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
  `).bind(a,n,t.id,t.name||t.username||"プレイヤー",JSON.stringify(s.monster),r,i).run(),e.json({ok:!0,code:n,expiresAt:i})});h.get("/api/trade/offer/:code",async e=>{const t=e.get("user");if(!t)return o(e,401,"unauthorized");const s=e.req.param("code").toUpperCase(),a=await e.env.DB.prepare("SELECT * FROM trade_offers WHERE code=? AND status='pending' AND expires_at > ?").bind(s,Date.now()).first();return a?a.from_user_id===t.id?o(e,400,"cannot_trade_with_yourself"):e.json({ok:!0,offer:{id:a.id,code:a.code,fromUserName:a.from_user_name,fromMonster:JSON.parse(a.from_monster_json),expiresAt:a.expires_at}}):o(e,404,"offer_not_found")});h.post("/api/trade/complete",async e=>{const t=e.get("user");if(!t)return o(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!(s!=null&&s.code)||!(s!=null&&s.monster))return o(e,400,"code_and_monster_required");const a=String(s.code).toUpperCase(),n=await e.env.DB.prepare("SELECT * FROM trade_offers WHERE code=? AND status='pending' AND expires_at > ?").bind(a,Date.now()).first();if(!n)return o(e,404,"offer_not_found");if(n.from_user_id===t.id)return o(e,400,"cannot_trade_with_yourself");const r=JSON.parse(n.from_monster_json),i=s.monster,d=await e.env.DB.prepare("SELECT state_json FROM progress WHERE user_id=?").bind(n.from_user_id).first();if(!d)return o(e,404,"from_user_progress_not_found");let l;try{l=JSON.parse(d.state_json)}catch{return o(e,500,"state_parse_error")}const c=await e.env.DB.prepare("SELECT state_json FROM progress WHERE user_id=?").bind(t.id).first();if(!c)return o(e,404,"to_user_progress_not_found");let u;try{u=JSON.parse(c.state_json)}catch{return o(e,500,"state_parse_error")}if(!Array.isArray(l.boxes))return o(e,400,"from_box_invalid");let m=-1,g=-1;e:for(let f=0;f<l.boxes.length;f++){const v=l.boxes[f];if(Array.isArray(v))for(let x=0;x<v.length;x++){const _=v[x];if(_&&(_.uid===r.uid||_.monsterId===r.monsterId&&_.level===r.level)){m=f,g=x;break e}}}if(m===-1)return o(e,400,"from_monster_not_in_box");if(l.boxes[m][g]=null,!Array.isArray(u.boxes))return o(e,400,"to_box_invalid");let w=-1,b=-1;e:for(let f=0;f<u.boxes.length;f++){const v=u.boxes[f];if(Array.isArray(v))for(let x=0;x<v.length;x++){const _=v[x];if(_&&(_.uid===i.uid||_.monsterId===i.monsterId&&_.level===i.level)){w=f,b=x;break e}}}if(w===-1)return o(e,400,"to_monster_not_in_box");u.boxes[w][b]=null;const y=(f,v)=>{for(let x=0;x<f.length;x++){Array.isArray(f[x])||(f[x]=[]);for(let _=0;_<100;_++)if(!f[x][_]){f[x][_]={...v,tradedAt:Date.now()};return}}f[0].push({...v,tradedAt:Date.now()})};return y(l.boxes,i),y(u.boxes,r),await e.env.DB.prepare("UPDATE progress SET state_json=?, updated_at=datetime('now') WHERE user_id=?").bind(JSON.stringify(l),n.from_user_id).run(),await e.env.DB.prepare("UPDATE progress SET state_json=?, updated_at=datetime('now') WHERE user_id=?").bind(JSON.stringify(u),t.id).run(),await e.env.DB.prepare("UPDATE trade_offers SET status='completed', to_user_id=?, to_monster_json=?, completed_at=? WHERE id=?").bind(t.id,JSON.stringify(i),Date.now(),n.id).run(),e.json({ok:!0,received:r,sent:i,fromUserName:n.from_user_name})});h.delete("/api/trade/offer",async e=>{const t=e.get("user");return t?(await e.env.DB.prepare("UPDATE trade_offers SET status='cancelled' WHERE from_user_id=? AND status='pending'").bind(t.id).run(),e.json({ok:!0})):o(e,401,"unauthorized")});h.post("/api/rt/create",async e=>{const t=j(e);if(!t)return o(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return o(e,400,"invalid_json");const a=String(s.name||"プレイヤー").slice(0,20),n=JSON.stringify(s.party||[]),r=String(s.area||"rounding").slice(0,40),i=s.battleType==="egg"?"egg":s.battleType==="gym"?"gym":"normal";await e.env.DB.prepare("DELETE FROM rt_rooms WHERE host_user_id=? AND status='waiting'").bind(t.id).run();const d=s.code?String(s.code).toUpperCase().replace(/[^A-Z0-9]/g,""):"";let l=d.length>=4?d:Ke();if(!d.length)for(let c=0;c<5&&await e.env.DB.prepare("SELECT id FROM rt_rooms WHERE id=?").bind(l).first();c++)l=Ke();return await e.env.DB.prepare(`
    INSERT INTO rt_rooms (id, host_user_id, host_name, host_party_json, host_area, host_hp, host_ready, guest_hp, guest_ready, battle_type, status)
    VALUES (?, ?, ?, ?, ?, 100, 0, 100, 0, ?, 'waiting')
  `).bind(l,t.id,a,n,r,i).run(),e.json({ok:!0,roomId:l})});h.post("/api/rt/join/:roomId",async e=>{const t=j(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),a=await e.req.json().catch(()=>null);if(!a)return o(e,400,"invalid_json");const n=String(a.name||"プレイヤー").slice(0,20),r=JSON.stringify(a.party||[]),i=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();if(!i)return o(e,404,"room_not_found");if(i.status!=="waiting")return o(e,409,"room_not_available");if(i.host_user_id===t.id)return o(e,400,"cannot_join_own_room");await e.env.DB.prepare(`
    UPDATE rt_rooms SET guest_user_id=?, guest_name=?, guest_party_json=?, guest_ready=1, status='ready', updated_at=datetime('now')
    WHERE id=? AND status='waiting'
  `).bind(t.id,n,r,s).run();const d=JSON.parse(i.host_party_json||"[]");return e.json({ok:!0,roomId:s,hostName:i.host_name,area:i.host_area,battleType:i.battle_type,hostParty:d})});h.get("/api/rt/room/:roomId",async e=>{const t=j(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),a=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();if(!a)return o(e,404,"room_not_found");const n=a.host_user_id===t.id,r=a.guest_user_id===t.id;if(!n&&!r)return o(e,403,"not_a_participant");const i=Number(e.req.query("after")||0),d=await e.env.DB.prepare(`
    SELECT id, user_id, event_type, value, monster_id, meta_json, created_at FROM rt_events
    WHERE room_id=? AND id > ?
    ORDER BY id ASC LIMIT 50
  `).bind(s,i).all(),l=n?"host":"guest",c=n?a.guest_party_json?JSON.parse(a.guest_party_json):null:JSON.parse(a.host_party_json||"[]");return e.json({ok:!0,room:{id:a.id,status:a.status,battleType:a.battle_type,area:a.host_area,hostName:a.host_name,guestName:a.guest_name,hostHp:a.host_hp,guestHp:a.guest_hp,hostReady:!!a.host_ready,guestReady:!!a.guest_ready,winner:a.winner,myRole:l,opponentParty:c},events:d.results})});h.post("/api/rt/ready/:roomId",async e=>{const t=j(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),a=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();if(!a)return o(e,404,"room_not_found");const n=a.host_user_id===t.id,r=a.guest_user_id===t.id;if(!n&&!r)return o(e,403,"not_a_participant");n?await e.env.DB.prepare("UPDATE rt_rooms SET host_ready=1, updated_at=datetime('now') WHERE id=?").bind(s).run():await e.env.DB.prepare("UPDATE rt_rooms SET guest_ready=1, updated_at=datetime('now') WHERE id=?").bind(s).run();const i=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();return i&&i.host_ready&&i.guest_ready&&(i.status==="ready"||i.status==="waiting")&&await e.env.DB.prepare("UPDATE rt_rooms SET status='playing', updated_at=datetime('now') WHERE id=?").bind(s).run(),e.json({ok:!0})});h.post("/api/rt/damage/:roomId",async e=>{const t=j(e);if(!t)return o(e,401,"unauthorized");if(!Ht(`rtdmg:${t.id}`,20,10))return o(e,429,"too_many_requests");const s=e.req.param("roomId").toUpperCase(),a=await e.req.json().catch(()=>null);if(!a)return o(e,400,"invalid_json");const n=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();if(!n)return o(e,404,"room_not_found");if(n.status!=="playing")return o(e,409,"not_playing");const r=n.host_user_id===t.id,i=n.guest_user_id===t.id;if(!r&&!i)return o(e,403,"not_a_participant");const d=Math.max(0,Math.min(500,Number(a.damage||0)));if(!Number.isFinite(d))return o(e,400,"invalid_damage");const l=Math.max(0,Math.min(9999,Math.floor(Number(a.monsterId||0)))),c=a.meta?JSON.stringify(a.meta).slice(0,500):null,m=["damage","faint","win","lose","self_damage","gym_ready","egg_battle"].includes(String(a.eventType))?String(a.eventType):"damage",w=(await e.env.DB.prepare(`
    INSERT INTO rt_events (room_id, user_id, event_type, value, monster_id, meta_json)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(s,t.id,m,d,l,c).run()).meta.last_row_id;let b=n.host_hp,y=n.guest_hp;m==="self_damage"?r?b=Math.max(0,b-d):y=Math.max(0,y-d):r?y=Math.max(0,y-d):b=Math.max(0,b-d);let f=n.status,v=n.winner;return m==="win"?(f="finished",v=r?"host":"guest"):m==="draw"&&(f="finished",v="draw"),await e.env.DB.prepare(`
    UPDATE rt_rooms SET host_hp=?, guest_hp=?, status=?, winner=?, updated_at=datetime('now') WHERE id=?
  `).bind(b,y,f,v,s).run(),e.json({ok:!0,eventId:w,hostHp:b,guestHp:y})});h.post("/api/rt/leave/:roomId",async e=>{const t=j(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("roomId").toUpperCase(),a=await e.env.DB.prepare("SELECT * FROM rt_rooms WHERE id=? LIMIT 1").bind(s).first();return a?(a.host_user_id===t.id?await e.env.DB.prepare("DELETE FROM rt_rooms WHERE id=?").bind(s).run():await e.env.DB.prepare(`
      UPDATE rt_rooms SET guest_user_id=NULL, guest_name=NULL, guest_party_json=NULL,
      status='waiting', host_hp=100, guest_hp=100, host_ready=0, guest_ready=0, winner=NULL,
      updated_at=datetime('now') WHERE id=?
    `).bind(s).run(),e.json({ok:!0})):e.json({ok:!0})});h.delete("/api/rt/cleanup",async e=>(await e.env.DB.prepare("DELETE FROM rt_rooms WHERE created_at < datetime('now', '-2 hours')").run(),await e.env.DB.prepare("DELETE FROM rt_events WHERE created_at < datetime('now', '-2 hours')").run(),e.json({ok:!0})));h.post("/api/teacher/message",async e=>{const t=N(e);if(!t)return o(e,401,"unauthorized");const{classId:s,studentId:a,body:n,image:r}=await e.req.json();if(!s||!a||!(n!=null&&n.trim()))return o(e,400,"classId, studentId, body required");if(!await e.env.DB.prepare("SELECT id FROM classes WHERE id=? AND teacher_id=?").bind(s,t.id).first())return o(e,403,"not your class");if(!await e.env.DB.prepare("SELECT user_id FROM class_members WHERE class_id=? AND user_id=?").bind(s,a).first())return o(e,400,"student not in class");const l=crypto.randomUUID();return await e.env.DB.prepare("INSERT INTO messages (id, class_id, sender_id, sender_role, recipient_id, body, image) VALUES (?,?,?,?,?,?,?)").bind(l,s,t.id,"teacher",a,n.trim(),r||null).run(),e.json({ok:!0,id:l})});h.get("/api/teacher/messages",async e=>{const t=N(e);if(!t)return o(e,401,"unauthorized");const s=e.req.query("classId")||"",a=e.req.query("studentId")||"";if(!s)return o(e,400,"classId required");if(!await e.env.DB.prepare("SELECT id FROM classes WHERE id=? AND teacher_id=?").bind(s,t.id).first())return o(e,403,"not your class");await e.env.DB.prepare("UPDATE messages SET image=NULL WHERE image IS NOT NULL AND created_at < datetime('now','-14 days')").run();let r=`SELECT m.id, m.sender_id as senderId, m.sender_role as senderRole, m.recipient_id as recipientId, m.body, m.image, m.read_at as readAt, m.created_at as createdAt,
     CASE WHEN m.sender_role='student' THEN u.name ELSE '(先生)' END as senderName,
     CASE WHEN m.sender_role='teacher' THEN u2.name ELSE NULL END as recipientName
     FROM messages m
     LEFT JOIN users u ON m.sender_id = u.id
     LEFT JOIN users u2 ON m.recipient_id = u2.id
     WHERE m.class_id=?`;const i=[s];a&&(r+=" AND (m.sender_id=? OR m.recipient_id=?)",i.push(a,a)),r+=" ORDER BY m.created_at DESC LIMIT 100";const d=e.env.DB.prepare(r),l=await(i.length===1?d.bind(i[0]):d.bind(i[0],i[1],i[2])).all();return e.json({ok:!0,messages:l.results})});h.post("/api/teacher/message/:id/read",async e=>{const t=N(e);return t?(await e.env.DB.prepare("UPDATE messages SET read_at=datetime('now') WHERE id=? AND recipient_id=? AND read_at IS NULL").bind(e.req.param("id"),t.id).run(),e.json({ok:!0})):o(e,401,"unauthorized")});h.get("/api/teacher/messages/unread-count",async e=>{const t=N(e);if(!t)return o(e,401,"unauthorized");const s=await e.env.DB.prepare("SELECT COUNT(*) as cnt FROM messages WHERE recipient_id=? AND read_at IS NULL").bind(t.id).first();return e.json({ok:!0,count:(s==null?void 0:s.cnt)||0})});h.post("/api/student/message",async e=>{const t=q(e);if(!t)return o(e,401,"unauthorized");const{body:s,image:a}=await e.req.json();if(!(s!=null&&s.trim())&&!a)return o(e,400,"body or image required");const n=await e.env.DB.prepare("SELECT cm.class_id, c.teacher_id FROM class_members cm JOIN classes c ON cm.class_id=c.id WHERE cm.user_id=?").bind(t.id).first();if(!n)return o(e,400,"no class joined");const r=crypto.randomUUID();return await e.env.DB.prepare("INSERT INTO messages (id, class_id, sender_id, sender_role, recipient_id, body, image) VALUES (?,?,?,?,?,?,?)").bind(r,n.class_id,t.id,"student",n.teacher_id,(s||"").trim()||"(画像)",a||null).run(),e.json({ok:!0,id:r})});h.get("/api/student/messages",async e=>{const t=q(e);if(!t)return o(e,401,"unauthorized");const s=await e.env.DB.prepare(`SELECT id, sender_id as senderId, sender_role as senderRole, recipient_id as recipientId, body, image, read_at as readAt, created_at as createdAt
     FROM messages WHERE sender_id=? OR recipient_id=?
     ORDER BY created_at DESC LIMIT 50`).bind(t.id,t.id).all();return e.json({ok:!0,messages:s.results})});h.post("/api/student/message/:id/read",async e=>{const t=q(e);return t?(await e.env.DB.prepare("UPDATE messages SET read_at=datetime('now') WHERE id=? AND recipient_id=? AND read_at IS NULL").bind(e.req.param("id"),t.id).run(),e.json({ok:!0})):o(e,401,"unauthorized")});h.get("/api/student/messages/unread-count",async e=>{const t=q(e);if(!t)return o(e,401,"unauthorized");const s=await e.env.DB.prepare("SELECT COUNT(*) as cnt FROM messages WHERE recipient_id=? AND read_at IS NULL").bind(t.id).first();return e.json({ok:!0,count:(s==null?void 0:s.cnt)||0})});h.post("/api/report",async e=>{const t=e.get("user");if(!t)return o(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!(s!=null&&s.body)||typeof s.body!="string"||s.body.trim().length===0)return o(e,400,"body_required");const a=["bug","request","other"].includes(s.category)?s.category:"bug",n=s.body.trim().slice(0,1e3),r=await e.env.DB.prepare("SELECT name FROM users WHERE id=?").bind(t.id).first(),i=(r==null?void 0:r.name)||t.loginId||"unknown",d=crypto.randomUUID();return await e.env.DB.prepare("INSERT INTO reports (id, account_id, display_name, category, body) VALUES (?, ?, ?, ?, ?)").bind(d,t.id,i,a,n).run(),e.json({ok:!0,id:d})});h.get("/api/report/my",async e=>{const t=e.get("user");if(!t)return o(e,401,"unauthorized");const s=await e.env.DB.prepare(`SELECT id, category, body, status, admin_note as adminNote, created_at as createdAt
     FROM reports WHERE account_id=? ORDER BY created_at DESC LIMIT 20`).bind(t.id).all();return e.json({ok:!0,reports:s.results})});h.get("/api/admin/reports",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=e.req.query("status")||"all";let a="SELECT id, account_id as accountId, display_name as displayName, category, body, status, admin_note as adminNote, created_at as createdAt, updated_at as updatedAt FROM reports";const n=[];s!=="all"&&(a+=" WHERE status=?",n.push(s)),a+=" ORDER BY created_at DESC LIMIT 100";const i=await(n.length>0?e.env.DB.prepare(a).bind(...n):e.env.DB.prepare(a)).all();return e.json({ok:!0,reports:i.results})});h.put("/api/admin/report/:id",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=e.req.param("id"),a=await e.req.json().catch(()=>null);if(!a)return o(e,400,"invalid_body");const n=["open","in_progress","resolved","closed"],r=[],i=[];return a.status&&n.includes(a.status)&&(r.push("status=?"),i.push(a.status)),typeof a.adminNote=="string"&&(r.push("admin_note=?"),i.push(a.adminNote.slice(0,500))),r.length===0?o(e,400,"nothing_to_update"):(r.push("updated_at=datetime('now')"),i.push(s),await e.env.DB.prepare(`UPDATE reports SET ${r.join(", ")} WHERE id=?`).bind(...i).run(),e.json({ok:!0}))});h.delete("/api/admin/report/:id",async e=>C(e)?(await e.env.DB.prepare("DELETE FROM reports WHERE id=?").bind(e.req.param("id")).run(),e.json({ok:!0})):o(e,401,"unauthorized"));h.post("/api/teacher/announcement",async e=>{const t=C(e);if(!t)return o(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return o(e,400,"invalid_json");const a=String(s.title||"").trim(),n=String(s.body||"").trim(),r=s.classId||null;if(!a||!n)return o(e,400,"title_and_body_required");const i=crypto.randomUUID();return await e.env.DB.prepare("INSERT INTO announcements (id, class_id, teacher_id, title, body) VALUES (?,?,?,?,?)").bind(i,r,t.id,a,n).run(),e.json({ok:!0,id:i})});h.get("/api/teacher/announcements",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=await e.env.DB.prepare(`SELECT a.id, a.class_id as classId, a.title, a.body, a.created_at as createdAt, c.name as className
     FROM announcements a LEFT JOIN classes c ON c.id = a.class_id
     ORDER BY a.created_at DESC LIMIT 50`).all();return e.json({ok:!0,announcements:s.results})});h.delete("/api/teacher/announcement/:id",async e=>{if(!C(e))return o(e,401,"unauthorized");const s=e.req.param("id");return await e.env.DB.prepare("DELETE FROM announcement_reads WHERE announcement_id=?").bind(s).run(),await e.env.DB.prepare("DELETE FROM announcements WHERE id=?").bind(s).run(),e.json({ok:!0})});h.get("/api/student/announcements",async e=>{const t=e.get("user");if(!t)return o(e,401,"unauthorized");const s=await e.env.DB.prepare("SELECT class_id FROM class_members WHERE user_id=? LIMIT 1").bind(t.id).first(),a=(s==null?void 0:s.class_id)||null;let n;return a?n=await e.env.DB.prepare(`SELECT a.id, a.title, a.body, a.created_at as createdAt, a.class_id as classId,
              ar.read_at as readAt
       FROM announcements a
       LEFT JOIN announcement_reads ar ON ar.announcement_id = a.id AND ar.user_id = ?
       WHERE a.class_id IS NULL OR a.class_id = ?
       ORDER BY a.created_at DESC LIMIT 30`).bind(t.id,a).all():n=await e.env.DB.prepare(`SELECT a.id, a.title, a.body, a.created_at as createdAt, a.class_id as classId,
              ar.read_at as readAt
       FROM announcements a
       LEFT JOIN announcement_reads ar ON ar.announcement_id = a.id AND ar.user_id = ?
       WHERE a.class_id IS NULL
       ORDER BY a.created_at DESC LIMIT 30`).bind(t.id).all(),e.json({ok:!0,announcements:n.results})});h.post("/api/student/announcement/:id/read",async e=>{const t=e.get("user");if(!t)return o(e,401,"unauthorized");const s=e.req.param("id");return await e.env.DB.prepare("INSERT OR IGNORE INTO announcement_reads (user_id, announcement_id) VALUES (?,?)").bind(t.id,s).run(),e.json({ok:!0})});h.post("/api/teacher/contact-note",async e=>{const t=N(e);if(!t)return o(e,401,"unauthorized");const s=await e.req.json().catch(()=>null);if(!s)return o(e,400,"invalid_json");const a=String(s.classId||"").trim(),n=String(s.body||"").trim(),r=String(s.dayKey||"").trim(),i=s.rewardDeadline||null,d=Number(s.rewardCoins)||5;if(!a||!n||!r)return o(e,400,"classId_body_dayKey_required");if(!(t.role==="admin"?await e.env.DB.prepare("SELECT id FROM classes WHERE id=? LIMIT 1").bind(a).first():await e.env.DB.prepare("SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1").bind(a,t.id).first()))return o(e,403,"not_your_class");const c=crypto.randomUUID();return await e.env.DB.prepare("INSERT INTO contact_notes (id, class_id, teacher_id, day_key, body, reward_deadline, reward_coins) VALUES (?,?,?,?,?,?,?)").bind(c,a,t.id,r,n,i,d).run(),e.json({ok:!0,id:c})});h.get("/api/teacher/contact-notes",async e=>{const t=N(e);if(!t)return o(e,401,"unauthorized");const s=e.req.query("classId")||"",a=t.role==="admin";let n;return s?n=await e.env.DB.prepare(`SELECT cn.id, cn.class_id as classId, cn.day_key as dayKey, cn.body, cn.reward_deadline as rewardDeadline, cn.reward_coins as rewardCoins, cn.created_at as createdAt, c.name as className
       FROM contact_notes cn LEFT JOIN classes c ON c.id = cn.class_id
       WHERE cn.class_id = ? ${a?"":"AND cn.teacher_id = ?"}
       ORDER BY cn.created_at DESC LIMIT 30`).bind(...a?[s]:[s,t.id]).all():n=a?await e.env.DB.prepare(`SELECT cn.id, cn.class_id as classId, cn.day_key as dayKey, cn.body, cn.reward_deadline as rewardDeadline, cn.reward_coins as rewardCoins, cn.created_at as createdAt, c.name as className
           FROM contact_notes cn LEFT JOIN classes c ON c.id = cn.class_id
           ORDER BY cn.created_at DESC LIMIT 30`).all():await e.env.DB.prepare(`SELECT cn.id, cn.class_id as classId, cn.day_key as dayKey, cn.body, cn.reward_deadline as rewardDeadline, cn.reward_coins as rewardCoins, cn.created_at as createdAt, c.name as className
           FROM contact_notes cn LEFT JOIN classes c ON c.id = cn.class_id
           WHERE cn.teacher_id = ?
           ORDER BY cn.created_at DESC LIMIT 30`).bind(t.id).all(),e.json({ok:!0,notes:n.results})});h.delete("/api/teacher/contact-note/:id",async e=>{const t=N(e);if(!t)return o(e,401,"unauthorized");const s=e.req.param("id");return await e.env.DB.prepare("DELETE FROM contact_note_reads WHERE note_id=?").bind(s).run(),t.role==="admin"?await e.env.DB.prepare("DELETE FROM contact_notes WHERE id=?").bind(s).run():await e.env.DB.prepare("DELETE FROM contact_notes WHERE id=? AND teacher_id=?").bind(s,t.id).run(),e.json({ok:!0})});h.get("/api/teacher/contact-note/:id/reads",async e=>{if(!N(e))return o(e,401,"unauthorized");const s=e.req.param("id"),a=await e.env.DB.prepare(`SELECT cnr.user_id as userId, cnr.read_at as readAt, cnr.reward_claimed as rewardClaimed, u.name as studentName
     FROM contact_note_reads cnr JOIN users u ON u.id = cnr.user_id
     WHERE cnr.note_id = ? ORDER BY cnr.read_at ASC`).bind(s).all();return e.json({ok:!0,reads:a.results})});h.get("/api/student/contact-notes",async e=>{const t=e.get("user");if(!t)return o(e,401,"unauthorized");let s=null;if(t.role==="teacher"||t.role==="admin"){const n=await e.env.DB.prepare("SELECT id FROM classes WHERE teacher_id=? ORDER BY created_at DESC LIMIT 1").bind(t.id).first();s=(n==null?void 0:n.id)||null}else{const n=await e.env.DB.prepare("SELECT class_id FROM class_members WHERE user_id=? LIMIT 1").bind(t.id).first();s=(n==null?void 0:n.class_id)||null}if(!s)return e.json({ok:!0,notes:[]});const a=await e.env.DB.prepare(`SELECT cn.id, cn.day_key as dayKey, cn.body, cn.reward_deadline as rewardDeadline, cn.reward_coins as rewardCoins, cn.created_at as createdAt,
            cnr.read_at as readAt, cnr.reward_claimed as rewardClaimed
     FROM contact_notes cn
     LEFT JOIN contact_note_reads cnr ON cnr.note_id = cn.id AND cnr.user_id = ?
     WHERE cn.class_id = ?
     ORDER BY cn.created_at DESC LIMIT 50`).bind(t.id,s).all();return e.json({ok:!0,notes:a.results})});h.post("/api/student/contact-note/:id/read",async e=>{const t=e.get("user");if(!t)return o(e,401,"unauthorized");const s=e.req.param("id");if(await e.env.DB.prepare("SELECT reward_claimed FROM contact_note_reads WHERE user_id=? AND note_id=? LIMIT 1").bind(t.id,s).first())return e.json({ok:!0,alreadyRead:!0,reward:0});const n=await e.env.DB.prepare("SELECT reward_deadline, reward_coins FROM contact_notes WHERE id=? LIMIT 1").bind(s).first();if(!n)return o(e,404,"not_found");const r=new Date().toISOString();let i=0,d=0;return n.reward_deadline?r<=n.reward_deadline&&(i=n.reward_coins||5,d=1):(i=n.reward_coins||5,d=1),await e.env.DB.prepare("INSERT OR IGNORE INTO contact_note_reads (user_id, note_id, reward_claimed) VALUES (?,?,?)").bind(t.id,s,d).run(),e.json({ok:!0,reward:i,rewardClaimed:!!d})});h.get("/",async e=>{var s;const t=await((s=e.env.ASSETS)==null?void 0:s.fetch(new Request(new URL("https://assets/index.html"))));return t||e.text("index.html not found",404)});h.get("/logout",async e=>{const t={secure:!0,sameSite:"Lax",httpOnly:!0};return Me(e,"session",{...t,path:"/"}),Me(e,"session",{...t,path:"/api"}),e.redirect("/login")});h.get("/login",e=>e.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
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

      <!-- 教師一覧 -->
      <div class="bg-white rounded-xl shadow p-6">
        <h2 class="font-bold mb-2">👩‍🏫 教師一覧</h2>
        <div id="teacherList" class="space-y-2 text-sm"></div>
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

      <!-- クラス管理 -->
      <div class="bg-white rounded-xl shadow p-6">
        <h2 class="font-bold mb-3">📚 クラス管理（児童追加・削除）</h2>
        <div id="classManagement">
          <div class="flex gap-2 mb-3">
            <button id="loadClassesBtn" class="bg-indigo-600 text-white rounded px-3 py-2 text-sm">クラス一覧を読み込む</button>
          </div>
          <div id="classList" class="space-y-3 text-sm"></div>
          <div id="classDetail" class="mt-4 hidden">
            <div class="border-2 border-indigo-200 rounded-lg p-4">
              <div class="flex items-center justify-between mb-3">
                <h3 id="classDetailName" class="font-bold text-lg"></h3>
                <button id="closeClassDetail" class="text-gray-400 hover:text-gray-700 text-xl">&times;</button>
              </div>
              <p id="classDetailInfo" class="text-gray-600 mb-3"></p>
              <div class="grid md:grid-cols-2 gap-4">
                <div>
                  <h4 class="font-bold mb-2">現在のメンバー</h4>
                  <div id="classMemberList" class="space-y-1 max-h-60 overflow-y-auto"></div>
                </div>
                <div>
                  <h4 class="font-bold mb-2">児童を追加</h4>
                  <div class="space-y-2">
                    <div class="flex gap-2">
                      <select id="addStudentGradeFilter" class="border p-1 rounded text-sm">
                        <option value="">全学年</option>
                        <option value="1">1年</option><option value="2">2年</option><option value="3">3年</option>
                        <option value="4">4年</option><option value="5">5年</option><option value="6">6年</option>
                      </select>
                      <button id="loadUnassignedBtn" class="bg-slate-600 text-white rounded px-2 py-1 text-xs">未所属を表示</button>
                      <button id="loadAllStudentsBtn" class="bg-slate-400 text-white rounded px-2 py-1 text-xs">全児童を表示</button>
                    </div>
                    <div id="addStudentList" class="space-y-1 max-h-60 overflow-y-auto"></div>
                    <button id="bulkAddBtn" class="bg-emerald-600 text-white rounded px-3 py-1 text-sm hidden">チェック済みを一括追加</button>
                  </div>
                </div>
              </div>
              <p id="classActionMsg" class="text-sm mt-2"></p>
            </div>
          </div>
        </div>
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

      function fmtLogin(dt){
        if(!dt) return '未ログイン';
        const d = new Date(dt + 'Z');
        return d.getFullYear() + '/' + String(d.getMonth()+1).padStart(2,'0') + '/' + String(d.getDate()).padStart(2,'0')
          + ' ' + String(d.getHours()).padStart(2,'0') + ':' + String(d.getMinutes()).padStart(2,'0');
      }

      async function renderTeachers(){
        const wrap = document.getElementById('teacherList');
        let data;
        try{ data = await api('/api/admin/teachers'); }
        catch(e){ wrap.innerHTML='<p class="text-red-600">読み込みエラー</p>'; return; }
        wrap.innerHTML='';
        if(!data.teachers.length){ wrap.textContent='教師がいません'; return; }
        for(const t of data.teachers){
          const div = document.createElement('div');
          div.className='flex flex-col md:flex-row md:items-center md:justify-between border rounded p-2 gap-2';
          const left = document.createElement('div');
          left.innerHTML = '<span class="font-bold">' + t.name + '</span>'
            + ' <span class="text-gray-500 select-all">ID: ' + t.loginId + '</span>'
            + (t.school ? ' <span class="text-xs text-gray-400">' + t.school + '</span>' : '')
            + ' <span class="text-xs text-blue-600 ml-1">最終ログイン: ' + fmtLogin(t.lastLoginAt) + '</span>';
          div.appendChild(left);
          const right = document.createElement('div');
          right.className='flex gap-2';
          const reset = document.createElement('button');
          reset.className='bg-slate-800 text-white rounded px-3 py-1';
          reset.textContent='PWリセット';
          reset.onclick = async ()=>{
            if(!confirm(t.name + 'のパスワードをリセットしますか？')){ return; }
            const r = await api('/api/admin/teacher-reset-password/'+t.id,{method:'POST'});
            alert('仮パスワード: '+r.tempPassword+'\\n本人に伝えてください');
          };
          right.appendChild(reset);
          div.appendChild(right);
          wrap.appendChild(div);
        }
      }

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
          left.innerHTML = x.grade + '年 / ' + x.name + '（' + x.loginId + '）' + (x.isActive? '' : ' <span class="text-red-500">[停止/未承認]</span>')
            + ' <span class="text-xs text-blue-600">最終ログイン: ' + fmtLogin(x.lastLoginAt) + '</span>';
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

// ========== クラス管理 ==========
      let currentClassId = null;

      document.getElementById('loadClassesBtn').onclick = renderClassList;

      async function renderClassList(){
        const wrap = document.getElementById('classList');
        wrap.innerHTML='<p class="text-gray-400">読み込み中...</p>';
        try{
          const d = await api('/api/admin/classes');
          wrap.innerHTML='';
          if(!d.classes.length){ wrap.textContent='クラスがまだありません'; return; }
          for(const cls of d.classes){
            const div = document.createElement('div');
            div.className='flex items-center justify-between border rounded p-2 hover:bg-indigo-50 cursor-pointer';
            const left = document.createElement('div');
            left.innerHTML = '<span class="font-bold">' + cls.name + '</span> <span class="text-gray-500">(' + cls.classCode + ')</span>' +
              ' <span class="text-xs text-gray-400">' + (cls.teacherName || '教師不明') + '</span>' +
              ' <span class="bg-indigo-100 text-indigo-700 rounded px-2 py-0.5 text-xs ml-1">' + cls.memberCount + '人</span>';
            div.appendChild(left);
            const btn = document.createElement('button');
            btn.className='bg-indigo-600 text-white rounded px-3 py-1 text-xs';
            btn.textContent='管理';
            btn.onclick = (e)=>{ e.stopPropagation(); openClassDetail(cls.id, cls.name, cls.classCode, cls.teacherName); };
            div.appendChild(btn);
            div.onclick = ()=>{ openClassDetail(cls.id, cls.name, cls.classCode, cls.teacherName); };
            wrap.appendChild(div);
          }
        }catch(e){ wrap.innerHTML='<p class="text-red-600">読み込みエラー</p>'; }
      }

      async function openClassDetail(classId, name, code, teacher){
        currentClassId = classId;
        document.getElementById('classDetail').classList.remove('hidden');
        document.getElementById('classDetailName').textContent = name + '（' + code + '）';
        document.getElementById('classDetailInfo').textContent = '教師: ' + (teacher || '不明');
        document.getElementById('classActionMsg').textContent = '';
        document.getElementById('addStudentList').innerHTML = '';
        document.getElementById('bulkAddBtn').classList.add('hidden');
        await renderClassMembers(classId);
      }

      document.getElementById('closeClassDetail').onclick = ()=>{
        document.getElementById('classDetail').classList.add('hidden');
        currentClassId = null;
      };

      async function renderClassMembers(classId){
        const wrap = document.getElementById('classMemberList');
        wrap.innerHTML='<p class="text-gray-400">読み込み中...</p>';
        try{
          const d = await api('/api/admin/class/' + classId + '/members');
          wrap.innerHTML='';
          if(!d.members.length){ wrap.textContent='メンバーなし'; return; }
          for(const m of d.members){
            const div = document.createElement('div');
            div.className='flex items-center justify-between border rounded px-2 py-1';
            const left = document.createElement('span');
            left.textContent = m.grade + '年 ' + m.name + '（' + m.loginId + '）';
            div.appendChild(left);
            const rm = document.createElement('button');
            rm.className='bg-red-500 text-white rounded px-2 py-0.5 text-xs hover:bg-red-700';
            rm.textContent='外す';
            rm.onclick = async ()=>{
              if(!confirm(m.name + 'をこのクラスから外しますか？')) return;
              await api('/api/admin/class/' + classId + '/remove-member/' + m.userId, {method:'DELETE'});
              await renderClassMembers(classId);
              showClassMsg('text-green-700', m.name + 'をクラスから外しました');
            };
            div.appendChild(rm);
            wrap.appendChild(div);
          }
        }catch(e){ wrap.innerHTML='<p class="text-red-600">読み込みエラー</p>'; }
      }

      document.getElementById('loadUnassignedBtn').onclick = async ()=>{
        if(!currentClassId) return;
        const wrap = document.getElementById('addStudentList');
        wrap.innerHTML='<p class="text-gray-400">読み込み中...</p>';
        try{
          const d = await api('/api/admin/unassigned-students');
          renderAddStudentList(d.students);
        }catch(e){ wrap.innerHTML='<p class="text-red-600">エラー</p>'; }
      };

      document.getElementById('loadAllStudentsBtn').onclick = async ()=>{
        if(!currentClassId) return;
        const wrap = document.getElementById('addStudentList');
        wrap.innerHTML='<p class="text-gray-400">読み込み中...</p>';
        try{
          const d = await api('/api/admin/users');
          renderAddStudentList(d.users.filter(u => u.isActive));
        }catch(e){ wrap.innerHTML='<p class="text-red-600">エラー</p>'; }
      };

      function renderAddStudentList(students){
        const gradeFilter = document.getElementById('addStudentGradeFilter').value;
        const filtered = gradeFilter ? students.filter(s => String(s.grade) === gradeFilter) : students;
        const wrap = document.getElementById('addStudentList');
        wrap.innerHTML='';
        if(!filtered.length){ wrap.textContent='該当する児童がいません'; document.getElementById('bulkAddBtn').classList.add('hidden'); return; }
        const checkboxes = [];
        for(const s of filtered){
          const div = document.createElement('div');
          div.className='flex items-center gap-2 border rounded px-2 py-1';
          const cb = document.createElement('input');
          cb.type='checkbox'; cb.value=s.id; cb.className='accent-emerald-600';
          checkboxes.push(cb);
          div.appendChild(cb);
          const label = document.createElement('span');
          label.textContent = s.grade + '年 ' + (s.className || '') + ' ' + s.name + '（' + s.loginId + '）';
          label.className='flex-1 cursor-pointer';
          label.onclick = ()=>{ cb.checked = !cb.checked; };
          div.appendChild(label);
          const addOne = document.createElement('button');
          addOne.className='bg-emerald-500 text-white rounded px-2 py-0.5 text-xs';
          addOne.textContent='追加';
          addOne.onclick = async ()=>{
            await api('/api/admin/class/' + currentClassId + '/add-member', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({userId:s.id})});
            await renderClassMembers(currentClassId);
            showClassMsg('text-green-700', s.name + 'を追加しました');
            div.remove();
          };
          div.appendChild(addOne);
          wrap.appendChild(div);
        }
        const bulkBtn = document.getElementById('bulkAddBtn');
        bulkBtn.classList.remove('hidden');
        bulkBtn.onclick = async ()=>{
          const ids = checkboxes.filter(c=>c.checked).map(c=>c.value);
          if(!ids.length){ alert('追加する児童を選んでください'); return; }
          if(!confirm(ids.length + '人をこのクラスに追加しますか？')) return;
          const r = await api('/api/admin/class/' + currentClassId + '/add-members-bulk', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({userIds:ids})});
          await renderClassMembers(currentClassId);
          showClassMsg('text-green-700', r.added + '人を追加しました（スキップ: ' + r.skipped + '人）');
          document.getElementById('loadUnassignedBtn').click();
        };
      }

      document.getElementById('addStudentGradeFilter').onchange = ()=>{
        document.getElementById('addStudentList').innerHTML='';
        document.getElementById('bulkAddBtn').classList.add('hidden');
      };

      function showClassMsg(cls, text){
        const msg = document.getElementById('classActionMsg');
        msg.textContent = text;
        msg.className = 'text-sm mt-2 ' + cls;
        setTimeout(()=>{ msg.textContent=''; }, 3000);
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
        await renderTeachers();
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

      <!-- 今日の学習状況 -->
      <div class="bg-white rounded-xl shadow p-4">
        <div class="flex items-center justify-between mb-3">
          <h2 class="font-bold">📈 今日の学習状況</h2>
          <select id="activityClassFilter" class="border p-1 rounded text-sm bg-white">
            <option value="">クラスを選択...</option>
          </select>
        </div>
        <div id="activitySummary" class="text-sm text-slate-400">クラスを選択してください</div>
      </div>

      <!-- タブナビ -->
      <div class="bg-white rounded-xl shadow p-1 flex gap-1">
        <button id="tabClasses" class="flex-1 py-2 rounded-lg text-sm font-bold bg-emerald-600 text-white" onclick="switchTab('classes')">📚 クラス管理</button>
        <button id="tabContact" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('contact')">📓 連絡帳</button>
        <button id="tabAnnouncements" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('announcements')">📢 おしらせ</button>
        <button id="tabHomework" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('homework')">📬 家庭学習</button>
        <button id="tabAnalytics" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('analytics')">📊 分析</button>
        <button id="tabMail" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('mail')">💬 質問チャット</button>
      </div>

      <!-- クラス一覧タブ -->
      <div id="tabPaneClasses" class="space-y-4">
        <div id="classList" class="space-y-4"></div>
      </div>

      <!-- 分析タブ（統合） -->
      <div id="tabPaneAnalytics" class="hidden space-y-3">
        <!-- サブタブナビ -->
        <div class="bg-white rounded-xl shadow p-2 flex items-center gap-1 overflow-x-auto">
          <button id="anSubTab_subject" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold bg-purple-500 text-white" onclick="switchAnalyticsSubTab('subject')">
            <span class="bg-white text-purple-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">1</span> 教科の成績
          </button>
          <span class="text-slate-300 text-lg font-bold">→</span>
          <button id="anSubTab_homework" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchAnalyticsSubTab('homework')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">2</span> 家庭学習
          </button>
          <span class="text-slate-300 text-lg font-bold">→</span>
          <button id="anSubTab_ai" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchAnalyticsSubTab('ai')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">3</span> AI分析
          </button>
        </div>
        <!-- 共通クラス選択 -->
        <div class="bg-white rounded-xl shadow p-3 flex gap-2 items-center flex-wrap">
          <span class="text-sm font-bold text-slate-600">クラス:</span>
          <select id="analyticsClassFilter" class="border p-2 rounded text-sm bg-white"></select>
        </div>

        <!-- サブタブ①: 教科の成績 -->
        <div id="anPane_subject" class="space-y-3">
          <div class="bg-purple-50 border border-purple-200 rounded-xl p-4">
            <div class="flex items-center justify-between flex-wrap gap-2 mb-3">
              <div class="font-bold text-sm text-purple-800">📊 教科別・単元別の正解率</div>
              <button onclick="loadUnitAnalytics()" class="bg-purple-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">📊 分析を表示</button>
            </div>
            <div id="analyticsContent"><p class="text-xs text-slate-400">クラスを選んで「分析を表示」を押してください</p></div>
          </div>
          <!-- 非アクティブ生徒の警告 -->
          <div id="inactiveStudentsCard" class="bg-orange-50 border border-orange-200 rounded-xl p-4 hidden">
            <h3 class="font-bold text-orange-600 mb-2">⚠️ しばらく学習していない生徒</h3>
            <p class="text-xs text-slate-400 mb-2">7日以上ログインがありません</p>
            <div id="inactiveStudentsList" class="space-y-1 text-sm"></div>
          </div>
          <!-- 最近の活動ログ -->
          <div id="recentActivityCard" class="bg-white rounded-xl shadow p-4 hidden">
            <h3 class="font-bold text-slate-700 mb-2">📋 最近の活動ログ</h3>
            <div id="recentActivityLog" class="space-y-1 text-sm max-h-96 overflow-y-auto"></div>
          </div>
        </div>

        <!-- サブタブ②: 家庭学習 -->
        <div id="anPane_homework" class="hidden space-y-3">
          <div class="bg-indigo-50 border border-indigo-200 rounded-xl p-4 space-y-3">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div class="font-bold text-sm text-indigo-800">📝 今週の家庭学習ダッシュボード</div>
              <button onclick="loadClassAnalytics()" class="bg-indigo-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">📊 分析</button>
            </div>
            <div id="classAnalyticsContent" class="space-y-3">
              <p class="text-xs text-slate-400">「分析」を押してください</p>
            </div>
          </div>
        </div>

        <!-- サブタブ③: AI分析 -->
        <div id="anPane_ai" class="hidden space-y-3">
          <div class="bg-gradient-to-br from-purple-50 to-indigo-50 border border-purple-200 rounded-xl p-4 space-y-3">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div class="font-bold text-sm text-purple-800">🤖 AIクラス分析</div>
              <button onclick="loadAIAnalysis()" class="bg-purple-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:bg-purple-700" id="btnAIAnalysis">✨ AIで分析</button>
            </div>
            <p class="text-xs text-purple-600">教科の成績＋家庭学習＋自己調整のデータをAIが総合的に分析し、声かけアドバイスを生成します。</p>
            <div id="aiAnalysisContent" class="text-sm text-slate-600">
              <p class="text-xs text-slate-400">クラスを選んで「AIで分析」を押してください</p>
            </div>
          </div>
        </div>

        <!-- 個人カルテ（生徒名クリックで表示） -->
        <div id="studentKartePanel" class="hidden bg-white rounded-xl shadow-lg p-4 space-y-3 border-2 border-purple-300">
          <div class="flex items-center justify-between">
            <div class="font-bold text-lg text-purple-800" id="karteStudentName"></div>
            <button onclick="document.getElementById('studentKartePanel').classList.add('hidden')" class="text-slate-400 hover:text-slate-700 text-xl font-bold">✕</button>
          </div>
          <div id="karteContent"></div>
        </div>
      </div>

      <!-- 家庭学習提出一覧タブ -->
      <div id="tabPaneHomework" class="hidden space-y-3">
        <!-- ステップ風サブタブナビゲーション -->
        <div class="bg-white rounded-xl shadow p-2 flex items-center gap-1 overflow-x-auto">
          <button id="hwSubTab_menu" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold bg-green-500 text-white" onclick="switchHomeworkSubTab('menu')">
            <span class="bg-white text-green-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">1</span> 先生メニュー
          </button>
          <span class="text-slate-300 text-lg font-bold">→</span>
          <button id="hwSubTab_plan" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchHomeworkSubTab('plan')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">2</span> 今週の計画
          </button>
          <span class="text-slate-300 text-lg font-bold">→</span>
          <button id="hwSubTab_daily" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchHomeworkSubTab('daily')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">3</span> 毎日の振り返り
          </button>
          <span class="text-slate-300 text-lg font-bold">→</span>
          <button id="hwSubTab_weekly" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchHomeworkSubTab('weekly')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">4</span> 今週の振り返り
          </button>
        </div>

        <!-- サブタブ①: 先生メニュー -->
        <div id="hwPane_menu" class="space-y-3">
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
          <div>
            <label class="text-xs font-bold text-green-800">📝 今週のテスト</label>
            <input id="menuTests" class="w-full border border-green-300 rounded-lg p-2 text-sm" placeholder="例：金曜 漢字50問テスト"/>
          </div>
          <div>
            <label class="text-xs font-bold text-green-800 block mb-1">📅 今週の家庭学習がある曜日</label>
            <div class="flex gap-3 flex-wrap">
              <label class="inline-flex items-center gap-1 text-sm"><input type="checkbox" id="menuDayMon" value="mon" checked class="accent-green-600"> 月</label>
              <label class="inline-flex items-center gap-1 text-sm"><input type="checkbox" id="menuDayTue" value="tue" checked class="accent-green-600"> 火</label>
              <label class="inline-flex items-center gap-1 text-sm"><input type="checkbox" id="menuDayWed" value="wed" checked class="accent-green-600"> 水</label>
              <label class="inline-flex items-center gap-1 text-sm"><input type="checkbox" id="menuDayThu" value="thu" checked class="accent-green-600"> 木</label>
              <label class="inline-flex items-center gap-1 text-sm"><input type="checkbox" id="menuDayFri" value="fri" checked class="accent-green-600"> 金</label>
            </div>
            <p class="text-xs text-green-600 mt-1">祝日や行事がある日はチェックを外してください</p>
          </div>
          <div class="flex gap-2 items-center">
            <button onclick="saveWeeklyMenu()" class="bg-green-600 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:opacity-90">📤 送信</button>
            <span id="menuSaveMsg" class="text-xs text-green-700"></span>
          </div>
        </div>

        </div>
        <!-- サブタブ②: 今週の計画 -->
        <div id="hwPane_plan" class="hidden space-y-3">
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
          <div id="bulkRefPanel" class="hidden border-t border-blue-200 pt-3 space-y-3">
            <!-- アプリ内AI -->
            <div class="bg-emerald-50 border border-emerald-200 rounded-lg p-2 space-y-2">
              <div class="font-bold text-xs text-emerald-800">🤖 AIで一括コメント生成</div>
              <button onclick="generateWeeklyAIComments()" class="bg-emerald-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90" id="weeklyAiGenBtn">🤖 AIコメント一括生成</button>
              <div id="weeklyAiGenMsg" class="text-xs text-emerald-700"></div>
            </div>
            <!-- 手動Gemini（折りたたみ） -->
            <details class="bg-purple-50 border border-purple-200 rounded-lg">
              <summary class="cursor-pointer p-2 text-xs font-bold text-purple-800 select-none">📋 Geminiでも手動で返却できます</summary>
              <div class="px-2 pb-2 space-y-2">
                <div class="flex items-center gap-2 flex-wrap">
                  <span class="text-xs text-slate-500">①</span>
                  <button onclick="copyWeeklyReflections()" class="bg-purple-500 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">📋 振り返りをコピー</button>
                  <span class="text-xs text-slate-400">→ GeminiのGemに貼り付けてコメントを生成 →</span>
                </div>
                <div class="text-xs text-slate-500">② Geminiの返答をここに貼り付け</div>
                <textarea id="bulkRefComments" class="w-full border border-purple-300 rounded-lg p-2 text-xs" rows="3" placeholder='{"comments":["よく頑張りました！","毎日続けてえらいね",...]}&#10;または番号付きリスト形式でもOK'></textarea>
                <button onclick="bulkReturnReflections()" class="bg-purple-600 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:opacity-90">✅ 貼り付けて一括返却</button>
                <div id="bulkRefMsg" class="text-xs text-purple-700"></div>
              </div>
            </details>
          </div>
        </div>

        </div>
        <!-- サブタブ③: 毎日の振り返り -->
        <div id="hwPane_daily" class="hidden space-y-3">
        <!-- アプリ内AIコメント生成パネル -->
        <div class="bg-emerald-50 border border-emerald-200 rounded-xl p-3 space-y-2">
          <div class="font-bold text-sm text-emerald-800">🤖 AIで一括コメント生成</div>
          <div class="text-xs text-emerald-600">ボタンを押すと内蔵AIが未返却の家庭学習にコメントを自動生成し、各コメント欄に反映します。確認・修正してから返却できます。</div>
          <button onclick="generateHWAIComments()" class="bg-emerald-600 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:opacity-90" id="hwAiGenBtn">🤖 AIコメント一括生成</button>
          <div id="hwAiGenMsg" class="text-xs text-emerald-700 min-h-[16px]"></div>
        </div>

        <!-- Gemini連携パネル（折りたたみ） -->
        <details class="bg-amber-50 border border-amber-200 rounded-xl">
          <summary class="cursor-pointer p-3 text-sm font-bold text-amber-800 select-none">📋 Geminiでも手動で返却できます</summary>
          <div class="px-3 pb-3 space-y-3">
            <button onclick="toggleGemPrompt()" class="text-xs text-amber-700 underline hover:no-underline">📝 Gem設定用プロンプトを表示</button>
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
            <textarea id="aiPasteArea" rows="4" class="w-full border border-amber-300 rounded-lg p-2 text-xs bg-white focus:outline-none focus:border-amber-500" placeholder='{"comments":["よく頑張りました！","毎日続けてえらいね",...]}&#10;または番号付きリスト形式でもOK'></textarea>
          </div>
          <button onclick="pasteAndBulkReturn()" class="w-full bg-emerald-600 text-white rounded-lg px-4 py-2.5 text-sm font-bold shadow hover:opacity-90">✅ ③ 貼り付けて一括返却</button>
          <div id="aiGenMsg" class="text-xs text-amber-700 min-h-[16px]"></div>
          </div>
        </details>
        <!-- 毎日の宿題一覧（日次返却） -->
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

        <!-- サブタブ④: 今週の振り返り -->
        <div id="hwPane_weekly" class="hidden space-y-3">
        <!-- 自動フィードバック（週間） -->
        <div class="bg-yellow-50 border border-yellow-200 rounded-xl p-4 space-y-3">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div class="font-bold text-sm text-yellow-800">💡 今週の自動フィードバック</div>
            <div class="flex gap-2 items-center">
              <select id="fbClassFilter" class="border p-1.5 rounded text-sm bg-white">
                <option value="">クラスを選択...</option>
              </select>
              <button onclick="loadAutoFeedback()" class="bg-yellow-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">🔄 生成</button>
            </div>
          </div>
          <p class="text-xs text-yellow-700">1週間の提出回数・学習時間・計画修正などから、児童ごとの声かけ候補を自動生成します。コメントは編集してから送信できます。</p>
          <div id="autoFeedbackList" class="space-y-2 text-sm">
            <p class="text-xs text-slate-400">クラスを選んで「生成」を押してください</p>
          </div>
        </div>
        </div>
      </div>


      <!-- (クラス分析は分析タブに統合済み) -->

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

    </div>

      <!-- メールタブ -->      <div id="tabPaneMail" class="hidden">        <div id="mailStudentListView">          <div class="flex gap-2 mb-3 items-center">            <select id="mailClassFilter" class="border p-2 rounded text-sm bg-white font-bold"></select>          </div>          <div id="mailStudentCards" class="space-y-1"></div>        </div>        <div id="mailChatView" class="hidden" style="height:70vh;display:none;">          <div class="flex items-center gap-3 bg-gradient-to-r from-teal-500 to-teal-600 text-white px-4 py-3 rounded-t-xl">            <button onclick="closeMailChat()" class="text-white font-bold text-lg">←</button>            <span id="mailChatName" class="font-bold"></span>          </div>          <div id="mailChatMessages" class="overflow-y-auto p-3 space-y-2 bg-[#e2efe9]" style="height:calc(70vh - 110px);"></div>          <div id="mailImagePreview" class="hidden px-2 pt-2 bg-white border-t"><div class="relative inline-block"><img id="mailImageThumb" class="h-16 rounded"/><button onclick="clearMailImage()" class="absolute -top-1 -right-1 bg-red-500 text-white rounded-full w-5 h-5 text-xs flex items-center justify-center">✕</button></div></div>          <div class="flex gap-2 items-end bg-white border-t p-2 rounded-b-xl">            <input type="file" id="mailImageInput" accept="image/*" class="hidden" onchange="handleMailImage(this)"/>            <button onclick="document.getElementById('mailImageInput').click()" class="w-10 h-10 flex items-center justify-center rounded-full bg-slate-200 text-slate-600 font-bold shadow hover:bg-slate-300 flex-shrink-0" title="画像を添付">📷</button>            <textarea id="mailBody" class="flex-1 border border-slate-300 rounded-2xl px-3 py-2 text-sm resize-none focus:border-teal-500 focus:outline-none" rows="1" placeholder="メッセージを入力..." oninput="this.style.height='auto';this.style.height=Math.min(this.scrollHeight,80)+'px'"></textarea>            <button onclick="sendTeacherMail()" class="w-10 h-10 flex items-center justify-center rounded-full bg-teal-500 text-white font-bold shadow hover:opacity-90 flex-shrink-0">▶</button>          </div>          <p id="mailMsg" class="text-xs text-center py-1"></p>        </div>      </div>
    <script>
      async function api(path, opt){
        const r = await fetch(path, opt);
        const j = await r.json().catch(()=>({}));
        if(!r.ok) throw new Error(j.error || 'error');
        return j;
      }

      function escH(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

      function switchTab(tab){
        ['classes','contact','announcements','homework','analytics','mail'].forEach(function(t){
          var pane = document.getElementById('tabPane' + t.charAt(0).toUpperCase() + t.slice(1));
          if(pane) pane.classList.toggle('hidden', tab !== t);
          var btn = document.getElementById('tab' + t.charAt(0).toUpperCase() + t.slice(1));
          if(btn) btn.className = tab===t
            ? 'flex-1 py-2 rounded-lg text-sm font-bold bg-emerald-600 text-white'
            : 'flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100';
        });
        if(tab === 'homework') { loadWeeklyMenu(); switchHomeworkSubTab('menu'); }
        if(tab === 'analytics') { initAnalyticsFilters(); switchAnalyticsSubTab('subject'); }
        if(tab === 'announcements') loadAnnouncements();
        if(tab === 'contact') loadContactNotes();
        if(tab === 'mail'){ loadTeacherMail(); if(_mailListPollTimer) clearInterval(_mailListPollTimer); _mailListPollTimer = setInterval(function(){ loadMailStudentList(); }, 10000); } else { if(_mailPollTimer){ clearInterval(_mailPollTimer); _mailPollTimer=null; } if(_mailListPollTimer){ clearInterval(_mailListPollTimer); _mailListPollTimer=null; } }
      }

      // --- 家庭学習サブタブ切り替え ---
      function switchHomeworkSubTab(sub){
        const tabs = ['menu','plan','daily','weekly'];
        const colors = {menu:'green',plan:'blue',daily:'emerald',weekly:'yellow'};
        tabs.forEach(function(t){
          var pane = document.getElementById('hwPane_' + t);
          if(pane) pane.classList.toggle('hidden', sub !== t);
          var btn = document.getElementById('hwSubTab_' + t);
          if(!btn) return;
          var c = colors[t] || 'slate';
          if(sub === t){
            btn.className = 'flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold bg-'+c+'-500 text-white';
            var num = btn.querySelector('span');
            if(num) num.className = 'bg-white text-'+c+'-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black';
          } else {
            btn.className = 'flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100';
            var num = btn.querySelector('span');
            if(num) num.className = 'bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black';
          }
        });
        if(sub === 'daily') loadHomework();
        if(sub === 'plan') loadStudentPlans();
        if(sub === 'weekly'){ initNewTabFilters(); }
      }

      // --- アクティビティ（今日の学習状況）---
      async function loadActivitySummary(){
        const classId = document.getElementById('activityClassFilter').value;
        const wrap = document.getElementById('activitySummary');
        if(!classId){ wrap.innerHTML='<span class="text-slate-400">クラスを選択してください</span>'; return; }
        wrap.innerHTML='<span class="text-slate-400">読み込み中...</span>';
        let data;
        try{ data = await api('/api/teacher/class/'+encodeURIComponent(classId)+'/activity'); }
        catch(e){ wrap.innerHTML='<span class="text-red-600">読み込みエラー</span>'; return; }
        const s = data.summary;
        wrap.innerHTML =
          '<div class="grid grid-cols-2 sm:grid-cols-4 gap-3">'
          +'<div class="rounded-lg border p-3 text-center"><div class="text-xs text-slate-400">取り組んだ生徒</div><div class="text-2xl font-black text-emerald-600">'+s.activeToday+'<span class="text-sm font-normal text-slate-400"> / '+s.memberCount+'人</span></div></div>'
          +'<div class="rounded-lg border p-3 text-center"><div class="text-xs text-slate-400">解いた問題数</div><div class="text-2xl font-black text-blue-600">'+s.totalProblems+'<span class="text-sm font-normal text-slate-400">問</span></div></div>'
          +'<div class="rounded-lg border p-3 text-center"><div class="text-xs text-slate-400">正答率</div><div class="text-2xl font-black '+(s.accuracy===null?'text-slate-400':s.accuracy>=80?'text-green-600':s.accuracy>=60?'text-yellow-600':'text-red-600')+'">'+(s.accuracy!==null?s.accuracy+'%':'−')+'</div></div>'
          +'<div class="rounded-lg border p-3 text-center"><div class="text-xs text-slate-400">未学習（7日+）</div><div class="text-2xl font-black '+(data.inactive.length>0?'text-orange-600':'text-slate-400')+'">'+data.inactive.length+'<span class="text-sm font-normal text-slate-400">人</span></div></div>'
          +'</div>';

        // 非アクティブ生徒を学習分析タブにも反映
        const inactiveCard = document.getElementById('inactiveStudentsCard');
        const inactiveList = document.getElementById('inactiveStudentsList');
        if(data.inactive.length > 0){
          inactiveCard.classList.remove('hidden');
          inactiveList.innerHTML = data.inactive.map(function(st){
            var lastTxt = st.lastLoginAt ? fmtLoginT(st.lastLoginAt) : '一度もログインなし';
            return '<div class="flex items-center justify-between border rounded px-3 py-1.5">'
              +'<span class="font-bold">'+escH(st.name)+'</span>'
              +'<span class="text-xs text-slate-400">最終: '+lastTxt+'</span></div>';
          }).join('');
        } else {
          inactiveCard.classList.add('hidden');
        }

        // 最近の活動ログを学習分析タブに反映
        var logCard = document.getElementById('recentActivityCard');
        var logWrap = document.getElementById('recentActivityLog');
        if(data.recentLog.length > 0){
          logCard.classList.remove('hidden');
          var unitNames = {decimal:'小数', fraction:'分数', integer:'整数', kanji_read:'漢字読み', kanji_write:'漢字書き', social:'社会', science:'理科'};
          logWrap.innerHTML = data.recentLog.map(function(r){
            var dt = r.answeredAt ? fmtLoginT(r.answeredAt) : '';
            var unitLabel = r.unit ? (r.unit.split(':')[0]) : '';
            unitLabel = unitNames[unitLabel] || unitLabel;
            var mark = r.isCorrect ? '<span class="text-green-600 font-bold">○</span>' : '<span class="text-red-500 font-bold">×</span>';
            return '<div class="flex items-center gap-2 border-b py-1 text-xs">'
              +'<span class="text-slate-400 w-32 shrink-0">'+dt+'</span>'
              +'<span class="font-bold w-20 shrink-0">'+escH(r.name)+'</span>'
              +'<span class="text-slate-500 w-16 shrink-0">'+escH(unitLabel)+'</span>'
              +mark
              +(r.timeMs ? '<span class="text-slate-400 ml-1">'+Math.round(r.timeMs/1000)+'秒</span>' : '')
              +'</div>';
          }).join('');
        } else {
          logCard.classList.add('hidden');
        }
      }

      function fmtLoginT(dt){
        if(!dt) return '';
        var d = new Date(dt.indexOf('Z') >= 0 ? dt : dt + 'Z');
        return d.getFullYear() + '/' + String(d.getMonth()+1).padStart(2,'0') + '/' + String(d.getDate()).padStart(2,'0')
          + ' ' + String(d.getHours()).padStart(2,'0') + ':' + String(d.getMinutes()).padStart(2,'0');
      }

      document.getElementById('activityClassFilter').onchange = function(){ loadActivitySummary(); };

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
            +'<td class="border px-2 py-1 font-bold sticky left-0 '+(i%2===0?'bg-white':'bg-slate-50')+'"><a href="javascript:void(0)" onclick="showStudentKarte(&#39;'+escH(s.id)+'&#39;,&#39;'+escH(s.name)+'&#39;)" class="text-purple-600 hover:underline cursor-pointer">'+escH(s.name)+'</a></td>'
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

      // --- 分析サブタブ切り替え ---
      function switchAnalyticsSubTab(sub){
        var tabs = ['subject','homework','ai'];
        var colors = {subject:'purple',homework:'indigo',ai:'purple'};
        tabs.forEach(function(t){
          var pane = document.getElementById('anPane_' + t);
          if(pane) pane.classList.toggle('hidden', sub !== t);
          var btn = document.getElementById('anSubTab_' + t);
          if(!btn) return;
          var c = colors[t] || 'slate';
          if(sub === t){
            btn.className = 'flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold bg-'+c+'-500 text-white';
            var num = btn.querySelector('span');
            if(num) num.className = 'bg-white text-'+c+'-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black';
          } else {
            btn.className = 'flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100';
            var num = btn.querySelector('span');
            if(num) num.className = 'bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black';
          }
        });
      }

      async function initAnalyticsFilters(){
        try{
          var cdata = await api('/api/teacher/classes');
          var classes = (cdata && cdata.classes) || [];
          var el = document.getElementById('analyticsClassFilter');
          if(el && el.options.length <= 1){
            el.innerHTML = '';
            classes.forEach(function(cls){
              var opt = document.createElement('option');
              opt.value = cls.id;
              opt.textContent = cls.name;
              el.appendChild(opt);
            });
          }
        }catch(_){}
      }

      // --- 個人カルテ ---
      async function showStudentKarte(studentId, studentName){
        var panel = document.getElementById('studentKartePanel');
        var content = document.getElementById('karteContent');
        document.getElementById('karteStudentName').textContent = studentName + ' さんのカルテ';
        panel.classList.remove('hidden');
        content.innerHTML = '<p class="text-slate-400 text-sm animate-pulse">読み込み中...</p>';
        var classId = document.getElementById('analyticsClassFilter').value;
        try{
          var weekKey = typeof getWeekKeyLocal === 'function' ? getWeekKeyLocal() : '';
          var unitData = await api('/api/teacher/class/' + encodeURIComponent(classId) + '/unit-analytics');
          var caData = await api('/api/teacher/class-analytics?classId=' + encodeURIComponent(classId) + '&weekKey=' + encodeURIComponent(weekKey));
          var student = (unitData.students||[]).find(function(s){ return s.id === studentId; });
          var hwAll = (caData.homework||[]).filter(function(h){ return h.user_id === studentId; });
          var plan = (caData.plans||[]).find(function(p){ return p.user_id === studentId; });
          var ref = (caData.reflections||[]).find(function(r){ return r.user_id === studentId; });
          var subjName = {math:'算数', jp:'国語', soc:'社会', science:'理科'};
          var html = '';

          // 教科別成績
          html += '<div class="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3">';
          ['math','jp','soc','science'].forEach(function(subj){
            var d = student && student.bySubject[subj];
            if(!d || d.total < 5){
              html += '<div class="rounded-lg border p-2 text-center"><div class="text-xs text-slate-400">'+(subjName[subj]||subj)+'</div><div class="text-lg font-bold text-slate-300">−</div></div>';
            } else {
              var c = d.acc>=80?'text-green-600':d.acc>=60?'text-yellow-600':'text-red-600';
              html += '<div class="rounded-lg border p-2 text-center"><div class="text-xs font-bold text-slate-500">'+(subjName[subj]||subj)+'</div><div class="text-xl font-black '+c+'">'+d.acc+'%</div><div class="text-[10px] text-slate-400">'+d.total+'問</div></div>';
            }
          });
          html += '</div>';

          // 連続学習
          if(student && student.learnStreak > 0){
            html += '<div class="bg-orange-50 border border-orange-200 rounded-lg p-2 mb-3 text-sm">🔥 連続学習 <b>'+student.learnStreak+'日</b></div>';
          }

          // 家庭学習状況
          html += '<div class="bg-blue-50 border border-blue-200 rounded-lg p-3 mb-3 space-y-1">';
          html += '<div class="font-bold text-xs text-blue-800">📝 今週の家庭学習</div>';
          if(hwAll.length > 0){
            var totalMin = hwAll.reduce(function(s,h){ return s + (h.minutes||0); }, 0);
            html += '<div class="text-sm">提出 <b>'+hwAll.length+'回</b> / 合計 <b>'+totalMin+'分</b></div>';
            html += '<div class="flex gap-1 flex-wrap">';
            hwAll.forEach(function(h){
              html += '<span class="bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded text-[10px]">'+escH(h.subject||'')+(h.minutes?(' '+h.minutes+'分'):'')+'</span>';
            });
            html += '</div>';
          } else {
            html += '<div class="text-xs text-slate-400">今週の提出はまだありません</div>';
          }
          html += '</div>';

          // 計画・ふりかえり
          html += '<div class="bg-purple-50 border border-purple-200 rounded-lg p-3 space-y-1">';
          html += '<div class="font-bold text-xs text-purple-800">🔄 自己調整</div>';
          if(plan){
            html += '<div class="text-xs"><b>計画:</b> '+escH(plan.plan_text||plan.goal_text||'(内容なし)')+'</div>';
            if(plan.revision_count > 0) html += '<div class="text-xs text-orange-600">🔄 計画修正 '+plan.revision_count+'回</div>';
          } else {
            html += '<div class="text-xs text-slate-400">計画の提出なし</div>';
          }
          if(ref){
            html += '<div class="text-xs"><b>ふりかえり:</b> '+escH(ref.reflection_text||'(内容なし)')+'</div>';
            if(ref.concentration) html += '<div class="text-xs">集中度: '+('★'.repeat(ref.concentration))+'</div>';
          } else {
            html += '<div class="text-xs text-slate-400">ふりかえりなし</div>';
          }
          html += '</div>';

          content.innerHTML = html;
          panel.scrollIntoView({behavior:'smooth', block:'nearest'});
        }catch(e){
          content.innerHTML = '<p class="text-red-500 text-sm">読み込みエラー: '+escH(String(e.message||e))+'</p>';
        }
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
        // アクティビティ（今日の学習状況）のクラスフィルターも更新
        const actSel = document.getElementById('activityClassFilter');
        if(actSel){
          const prevVal = actSel.value;
          actSel.innerHTML = '<option value="">クラスを選択...</option>';
          data.classes.forEach(c => { actSel.innerHTML += '<option value="'+escH(c.id)+'">'+escH(c.name)+'</option>'; });
          if(data.classes.length === 1){ actSel.value = data.classes[0].id; loadActivitySummary(); }
          else if(prevVal){ actSel.value = prevVal; }
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

          // ====== 全メニュー表示トグル ======
          const menusDivider = document.createElement('div');
          menusDivider.className = 'mt-3 pt-3 border-t border-slate-200';
          menusDivider.innerHTML = '<div class="text-xs font-bold text-slate-600 mb-2"> メニュー表示設定</div>';
          const menusGrid = document.createElement('div');
          menusGrid.className = 'flex flex-wrap gap-1';

          const currentMenus = cls.menusEnabled ? (typeof cls.menusEnabled === 'string' ? JSON.parse(cls.menusEnabled) : cls.menusEnabled) : {};

          const allMenuItems = [
            {key:'status', label:'ステータス', color:'emerald'},
            {key:'training', label:'️修行', color:'blue'},
            {key:'mail', label:'質問', color:'purple'},
            {key:'battle', label:'⚔️バトル', color:'red'},
            {key:'friend', label:'欄友達通信', color:'violet'},
            {key:'shop', label:'ショップ', color:'orange'},
            {key:'lab', label:'ラボ', color:'teal'},
            {key:'pokedex', label:'図鑑', color:'slate'},
            {key:'box', label:'ボックス', color:'cyan'},
          ];

          allMenuItems.forEach(function(item){
            const isOn = currentMenus[item.key] !== false && currentMenus[item.key] !== 0;
            const mbtn = document.createElement('button');
            mbtn.className = isOn
              ? 'text-xs px-2 py-1 rounded font-bold bg-'+item.color+'-100 text-'+item.color+'-700 border border-'+item.color+'-300'
              : 'text-xs px-2 py-1 rounded font-bold bg-slate-100 text-slate-400 border border-slate-200 line-through';
            mbtn.textContent = item.label;
            mbtn.dataset.menuKey = item.key;
            mbtn.dataset.on = isOn ? '1' : '';
            mbtn.onclick = async function(){
              const wasOn = !!mbtn.dataset.on;
              mbtn.dataset.on = wasOn ? '' : '1';
              currentMenus[item.key] = !wasOn;
              mbtn.className = !wasOn
                ? 'text-xs px-2 py-1 rounded font-bold bg-'+item.color+'-100 text-'+item.color+'-700 border border-'+item.color+'-300'
                : 'text-xs px-2 py-1 rounded font-bold bg-slate-100 text-slate-400 border border-slate-200 line-through';
              try{
                await api('/api/teacher/class/'+cls.id+'/menus-toggle',{
                  method:'PUT', headers:{'content-type':'application/json'},
                  body: JSON.stringify({menusEnabled: currentMenus})
                });
              }catch(e){ alert(String(e.message||e)); }
            };
            menusGrid.appendChild(mbtn);
          });

          menusDivider.appendChild(menusGrid);
          header.appendChild(menusDivider);


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
                +'<td class="border px-2 py-1">'+escH(m.name||m.id)+'</td>'
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
          document.getElementById('menuTests').value = menu.tests || '';
          // 曜日チェックボックスの復元
          var activeDays = [];
          try{ activeDays = JSON.parse(menu.active_days || menu.activeDays || '["mon","tue","wed","thu","fri"]'); }catch(e){ activeDays = ['mon','tue','wed','thu','fri']; }
          ['mon','tue','wed','thu','fri'].forEach(function(d){
            var cb = document.getElementById('menuDay' + d.charAt(0).toUpperCase() + d.slice(1));
            if(cb) cb.checked = activeDays.indexOf(d) >= 0;
          });
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
            tests: document.getElementById('menuTests').value || '',
            activeDays: ['mon','tue','wed','thu','fri'].filter(function(d){
              var cb = document.getElementById('menuDay' + d.charAt(0).toUpperCase() + d.slice(1));
              return cb && cb.checked;
            }),
          };
          await api('/api/teacher/class/' + encodeURIComponent(classId) + '/weekly-menu', {
            method: 'POST',
            headers: {'content-type':'application/json'},
            body: JSON.stringify(body),
          });
          if(msg) msg.textContent = '✅ 送信しました（' + wk + '）';
          setTimeout(function(){ if(msg) msg.textContent = ''; }, 3000);
        }catch(e){
          if(msg) msg.textContent = '⚠️ 送信に失敗しました';
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

            // ヘッダー + 承認バッジ + 修正回数バッジ
            const approvedBadge = p.planApproved
              ? '<span class="bg-green-100 text-green-700 text-xs px-1.5 rounded font-bold">✅ 承認済(+300coin+5かけら)</span>'
              : '';
            const revBadge = (p.revisionCount && p.revisionCount > 0)
              ? '<span class="bg-orange-100 text-orange-700 text-xs px-1.5 rounded font-bold cursor-pointer" onclick="showRevisions('+p.id+',\\''+escH(p.studentName)+'\\')">🔄 '+p.revisionCount+'回修正（自己調整）</span>'
              : '';
            let html = '<div class="flex items-center justify-between flex-wrap gap-1">'
              + '<div class="font-bold text-sm">'+escH(p.studentName)+' <span class="text-xs text-slate-400 font-normal">'+escH(p.grade+'年'+p.className)+'</span> '+approvedBadge+' '+revBadge+'</div>'
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
        let text = '以下は小学生の今週の家庭学習の振り返りです。それぞれに温かく励ましつつ具体的に褒める短いコメント（1〜2文）を書いてください。\\nJSON形式 {"comments":["コメント1","コメント2",...]} で返してください。\\n\\n';
        data.forEach(function(d, i){
          text += (i+1) + '. ' + d.name + '「' + d.reflection + '」\\n';
        });
        navigator.clipboard.writeText(text).then(function(){
          alert('📋 '+data.length+'人分の振り返りをコピーしました！\\nGemini等に貼り付けてコメントを生成してください。');
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
          comments = raw.split(/\\n/).map(function(line){
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
wrap.innerHTML = '';
          for(const item of list){
            const card = document.createElement('div');
            card.className = 'border rounded-lg p-2 bg-white space-y-1';
            let html = '<div class="font-bold text-sm text-slate-700">'+escH(item.name)+'</div>';
            html += '<div class="space-y-0.5">';
            for(const msg of item.messages){
              html += '<div class="text-xs text-slate-600 bg-yellow-50 rounded p-1.5 border border-yellow-100">'+escH(msg)+'</div>';
            }
            html += '</div>';
            // 編集可能なテキストエリア + 送信ボタン
            html += '<div class="flex gap-1 items-end mt-1">';
            html += '<textarea class="flex-1 border rounded p-1.5 text-xs" rows="2" id="fbMsg_'+item.userId+'" placeholder="コメントを編集...">'+escH(item.messages.join(' '))+'</textarea>';
            html += '<button class="bg-emerald-600 text-white rounded px-2 py-1.5 text-[11px] font-bold hover:opacity-90 shrink-0" onclick="sendFeedback(\\''+item.userId+'\\',this)">💬 送信</button>';
            html += '</div>';
            card.innerHTML = html;
            wrap.appendChild(card);
          }
        }catch(e){
          wrap.innerHTML='<p class="text-red-600">エラー: '+escH(String(e.message||e))+'</p>';
        }
      }

          async function loadAutoFeedback(){
            const wrap = document.getElementById('autoFeedbackList');
            if(!wrap) return;
            const classId = document.getElementById('fbClassFilter')?.value;
            if(!classId){ alert('クラスを選択してください'); return; }
            wrap.innerHTML = '<p class="text-xs text-slate-400">生成中...</p>';
            try{
              const data = await api('/api/teacher/auto-feedback?classId='+encodeURIComponent(classId)+'&weekKey='+encodeURIComponent(getWeekKeyLocal()));
              const list = data.feedbackList || [];
              if(!list.length){ wrap.innerHTML = '<p class="text-xs text-slate-400">データがありません</p>'; return; }
              wrap.innerHTML = '';
              for(const item of list){
                const card = document.createElement('div');
                card.className = 'border rounded-lg p-2 bg-white space-y-1 mb-2';
                const hdr = document.createElement('div');
                hdr.className = 'font-bold text-sm text-slate-700 mb-1';
                hdr.textContent = item.name;
                card.appendChild(hdr);
                for(const msg of item.messages){
                  const d = document.createElement('div');
                  d.className = 'text-xs text-yellow-800 bg-yellow-50 px-1.5 py-0.5 rounded';
                  d.textContent = msg;
                  card.appendChild(d);
                }
                const ta = document.createElement('textarea');
                ta.id = 'fbMsg_' + item.userId;
                ta.className = 'w-full border rounded p-1.5 text-xs mt-1';
                ta.rows = 2;
                ta.value = item.messages.join(' ');
                const btn = document.createElement('button');
                btn.className = 'mt-1 bg-emerald-600 text-white rounded px-3 py-1.5 text-xs font-bold w-full';
                btn.textContent = '送信';
                const uid = item.userId;
                btn.onclick = function(){ sendFeedback(uid, btn); };
                card.appendChild(ta);
                card.appendChild(btn);
                wrap.appendChild(card);
              }
            }catch(e){
              wrap.innerHTML = '<p class="text-red-600">エラー: ' + escH(String(e.message||e)) + '</p>';
            }
          }

      async function sendFeedback(userId, btn){
        btn.disabled = true;
        const msg = (document.getElementById('fbMsg_'+userId)||{}).value || '';
        if(!msg.trim()){ alert('メッセージを入力してください'); btn.disabled=false; return; }
        try{
          await api('/api/teacher/message', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({studentId:userId, content:msg})});
          btn.textContent='✅ 送信済';
          btn.className='bg-slate-300 text-slate-500 rounded px-2 py-1.5 text-[11px] font-bold shrink-0';
        }catch(e){ btn.disabled=false; alert('送信エラー: '+String(e.message||e)); }
      }

      // ===== クラス分析ダッシュボード =====
      async function loadClassAnalytics(){
        const wrap = document.getElementById('classAnalyticsContent');
        if(!wrap) return;
        const classId = document.getElementById('analyticsClassFilter')?.value;
        if(!classId){ alert('クラスを選択してください'); return; }
        wrap.innerHTML='<p class="text-slate-400">分析中...</p>';
        try{
          const data = await api('/api/teacher/class-analytics?classId='+encodeURIComponent(classId)+'&weekKey='+encodeURIComponent(getWeekKeyLocal()));
          let html = '';

          // 1) 気になる児童アラート
          const alerts = data.alerts || [];
          if(alerts.length > 0){
            html += '<div class="bg-red-50 border border-red-200 rounded-lg p-3 space-y-1">';
            html += '<div class="font-bold text-sm text-red-800">⚠️ 気になる児童 ('+alerts.length+'人)</div>';
            for(const a of alerts){
              const icon = a.type==='no_submission' ? '🔴' : a.type==='submission_drop' ? '🟡' : '🟠';
              html += '<div class="text-xs text-red-700">'+icon+' <b>'+escH(a.name)+'</b>: '+escH(a.detail)+'</div>';
            }
            html += '</div>';
          } else {
            html += '<div class="bg-green-50 border border-green-200 rounded-lg p-3"><div class="text-sm text-green-700">✅ 特に気になる児童はいません</div></div>';
          }

          // 2) 提出状況サマリー
          const members = data.members || [];
          const hwData = data.homework || [];
          const hwByUser = {};
          for(const h of hwData){ if(!hwByUser[h.user_id]) hwByUser[h.user_id]={cnt:0,totalMin:0}; hwByUser[h.user_id].cnt++; hwByUser[h.user_id].totalMin+=(h.minutes||0); }
          const submitted = Object.keys(hwByUser).length;
          const total = members.length;
          const rate = total > 0 ? Math.round(submitted/total*100) : 0;

          html += '<div class="bg-white border rounded-lg p-3 space-y-2">';
          html += '<div class="font-bold text-sm text-slate-700">📊 今週の提出状況</div>';
          html += '<div class="flex gap-4 text-center">';
          html += '<div><div class="text-2xl font-bold text-emerald-600">'+rate+'%</div><div class="text-[10px] text-slate-500">提出率</div></div>';
          html += '<div><div class="text-2xl font-bold text-blue-600">'+submitted+'/'+total+'</div><div class="text-[10px] text-slate-500">提出人数</div></div>';
          html += '</div>';

          // ミニヒートマップ（提出回数をバーで表示）
          html += '<div class="space-y-0.5 mt-2">';
          for(const m of members){
            const hw = hwByUser[m.id] || {cnt:0, totalMin:0};
            const barW = Math.min(100, hw.cnt * 20); // 5回=100%
            const color = hw.cnt >= 4 ? 'bg-emerald-500' : hw.cnt >= 2 ? 'bg-yellow-500' : hw.cnt > 0 ? 'bg-orange-400' : 'bg-red-300';
            html += '<div class="flex items-center gap-1 text-[11px]">';
            html += '<div class="w-16 truncate text-slate-600">'+escH(m.name)+'</div>';
            html += '<div class="flex-1 bg-slate-100 rounded-full h-3 overflow-hidden"><div class="h-full rounded-full '+color+'" style="width:'+barW+'%"></div></div>';
            html += '<div class="w-10 text-right text-slate-500">'+hw.cnt+'回</div>';
            html += '<div class="w-14 text-right text-slate-400">'+(hw.totalMin||0)+'分</div>';
            html += '</div>';
          }
          html += '</div></div>';

          // 3) 自己調整スコア分布
          const plans = data.plans || [];
          const reflections = data.reflections || [];
          const planMap = {}; for(const p of plans) planMap[p.user_id] = p;
          const refMap = {}; for(const r of reflections) refMap[r.user_id] = r;

          html += '<div class="bg-white border rounded-lg p-3 space-y-2">';
          html += '<div class="font-bold text-sm text-slate-700">🔄 自己調整の状況</div>';
          const planCount = plans.length;
          const refCount = reflections.length;
          const revisionStudents = plans.filter(function(p){ return p.revision_count > 0; }).length;
          html += '<div class="flex gap-4 text-center text-xs">';
          html += '<div><div class="text-lg font-bold text-blue-600">'+planCount+'/'+total+'</div><div class="text-slate-500">計画提出</div></div>';
          html += '<div><div class="text-lg font-bold text-orange-600">'+revisionStudents+'</div><div class="text-slate-500">計画修正した人</div></div>';
          html += '<div><div class="text-lg font-bold text-purple-600">'+refCount+'/'+total+'</div><div class="text-slate-500">ふりかえり</div></div>';
          html += '</div>';

          // 児童別の自己調整状況
          html += '<div class="space-y-0.5 mt-2">';
          for(const m of members){
            const p = planMap[m.id];
            const r = refMap[m.id];
            const badges = [];
            if(p) badges.push('<span class="bg-blue-100 text-blue-700 px-1 rounded text-[9px]">📝計画</span>');
            if(p && p.revision_count > 0) badges.push('<span class="bg-orange-100 text-orange-700 px-1 rounded text-[9px]">🔄修正'+p.revision_count+'回</span>');
            if(r) badges.push('<span class="bg-purple-100 text-purple-700 px-1 rounded text-[9px]">💭ふりかえり</span>');
            if(r && r.concentration) badges.push('<span class="bg-yellow-100 text-yellow-700 px-1 rounded text-[9px]">集中'+('★'.repeat(r.concentration))+'</span>');
            html += '<div class="flex items-center gap-1 text-[11px]">';
            html += '<div class="w-16 truncate text-slate-600">'+escH(m.name)+'</div>';
            html += '<div class="flex gap-0.5 flex-wrap">'+(badges.length > 0 ? badges.join(' ') : '<span class="text-slate-300 text-[9px]">—</span>')+'</div>';
            html += '</div>';
          }
          html += '</div></div>';

          wrap.innerHTML = html;
        }catch(e){
          wrap.innerHTML='<p class="text-red-600">エラー: '+escH(String(e.message||e))+'</p>';
        }
      }

      async function loadAIAnalysis(){
        const classId = document.getElementById('analyticsClassFilter').value;
        if(!classId){ document.getElementById('aiAnalysisContent').innerHTML='<p class="text-xs text-red-500">クラスを選択してください</p>'; return; }
        const btn = document.getElementById('btnAIAnalysis');
        btn.disabled = true; btn.textContent = '分析中...';
        document.getElementById('aiAnalysisContent').innerHTML='<p class="text-xs text-purple-500 animate-pulse">🤖 AIがデータを分析しています。少々お待ちください（数秒～10秒）...</p>';
        try {
          const weekKey = typeof getWeekKeyLocal === 'function' ? getWeekKeyLocal() : '';
          const res = await fetch('/api/teacher/class-ai-analysis?classId=' + classId + '&weekKey=' + weekKey);
          const data = await res.json();
          if(data.ok && data.analysis){
            const formatted = data.analysis.replace(/\\n/g, '<br>');
            document.getElementById('aiAnalysisContent').innerHTML = '<div class="bg-white rounded-lg p-3 text-sm leading-relaxed text-slate-700 border">' + formatted + '</div>';
          } else {
            document.getElementById('aiAnalysisContent').innerHTML = '<p class="text-xs text-red-500">分析に失敗しました: ' + (data.error || 'unknown') + '</p>';
          }
        } catch(e) {
          document.getElementById('aiAnalysisContent').innerHTML = '<p class="text-xs text-red-500">エラー: ' + e.message + '</p>';
        } finally {
          btn.disabled = false; btn.textContent = '✨ AIで分析';
        }
      }
      // フィルター初期化
      async function initNewTabFilters(){
        try{
          const cdata = await api('/api/teacher/classes');
          const classes= (cdata && cdata.classes) || [];
          ['fbClassFilter'].forEach(function(filterId){
            const el = document.getElementById(filterId);
            if(el && el.options.length <= 1){
              el.innerHTML = '';
              classes.forEach(function(cls){
                var opt = document.createElement('option');
                opt.value = cls.id;
                opt.textContent = cls.name;
                el.appendChild(opt);
              });
            }
          });
        }catch(_){}
      }
      // 初期化時にフィルターを設定
      setTimeout(initNewTabFilters, 500);

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
            + (s.workPhotoAnalysis ? '<div class="mt-1 p-1.5 bg-cyan-50 rounded border border-cyan-200"><b>📷 成果物（AI分析）：</b>'+escH(s.workPhotoAnalysis)+'</div>' : '')
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

      async function generateHWAIComments(){
        var btn = document.getElementById('hwAiGenBtn');
        var msg = document.getElementById('hwAiGenMsg');
        var classId = document.getElementById('hwClassFilter').value;
        if(!classId){ alert('クラスを選択してください'); return; }
        btn.disabled=true; btn.textContent='⏳ AI生成中...';
        msg.textContent='AIがコメントを生成しています…少しお待ちください';
        try{
          var r = await api('/api/teacher/homework-ai-comments',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({classId:classId})});
          if(!r.comments || !r.comments.length){ msg.textContent='未返却の提出がありません'; return; }
          var filled = 0;
          for(var i=0;i<r.comments.length;i++){
            var c = r.comments[i];
            var ta = document.getElementById('hwComment_'+c.id);
            if(ta){ ta.value = c.comment; filled++; }
          }
          msg.textContent='✅ '+filled+'件のコメントを生成しました！内容を確認して「未返却をまとめて返却」で返却してください。';
        }catch(e){
          msg.textContent='❌ エラー: '+String(e.message||e);
        }finally{
          btn.disabled=false; btn.textContent='🤖 AIコメント一括生成';
        }
      }

      async function generateWeeklyAIComments(){
        var btn = document.getElementById('weeklyAiGenBtn');
        var msg = document.getElementById('weeklyAiGenMsg');
        var data = window._weeklyRefData || [];
        if(!data.length){ alert('未返却の振り返りがありません'); return; }
        var classId = (document.getElementById('wpClassSel')||{}).value || (document.getElementById('hwClassFilter')||{}).value;
        if(!classId){ alert('クラスを選択してください'); return; }
        btn.disabled=true; btn.textContent='⏳ AI生成中...';
        msg.textContent='AIがコメントを生成しています…';
        try{
          var r = await api('/api/teacher/weekly-ai-comments',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({classId:classId})});
          if(!r.comments || !r.comments.length){ msg.textContent='未返却の振り返りがありません'; return; }
          var ta = document.getElementById('bulkRefComments');
          if(ta){
            var json = JSON.stringify({comments: r.comments.map(function(c){ return c.comment; })});
            ta.value = json;
          }
          msg.textContent='✅ '+r.comments.length+'件のコメントを生成しました！「貼り付けて一括返却」で返却してください。';
        }catch(e){
          msg.textContent='❌ エラー: '+String(e.message||e);
        }finally{
          btn.disabled=false; btn.textContent='🤖 AIコメント一括生成';
        }
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

      // ===== メール機能 =====
      function _utcToJST(utcStr){
        if(!utcStr) return {date:'',time:''};
        var d = new Date(utcStr.replace(' ','T')+'Z');
        var jp = new Date(d.getTime() + 9*60*60*1000);
        var mm = String(jp.getUTCMonth()+1).padStart(2,'0');
        var dd = String(jp.getUTCDate()).padStart(2,'0');
        var hh = String(jp.getUTCHours()).padStart(2,'0');
        var mi = String(jp.getUTCMinutes()).padStart(2,'0');
        return {date: jp.getUTCFullYear()+'-'+mm+'-'+dd, time: hh+':'+mi};
      }
      var _mailCurrentStudent = null;
      var _mailCurrentClass = null;

      var _mailPollTimer = null;
      var _mailListPollTimer = null;

      async function loadTeacherMail(){
        try{
          var clsData = await api('/api/teacher/classes');
          var sel = document.getElementById('mailClassFilter');
          var cur = sel.value;
          sel.innerHTML = '';
          (clsData.classes||[]).forEach(function(c,i){ sel.innerHTML += '<option value="'+escH(c.id)+'"'+(c.id===cur||(!cur&&i===0)?' selected':'')+'>'+escH(c.name)+'</option>'; });
          sel.onchange = function(){ loadMailStudentList(); };
          _mailCurrentClass = sel.value;
          loadMailStudentList();
        }catch(e){}
      }

      async function loadMailStudentList(){
        var classId = document.getElementById('mailClassFilter').value;
        _mailCurrentClass = classId;
        var wrap = document.getElementById('mailStudentCards');
        wrap.innerHTML = '<p class="text-slate-400 text-sm">読み込み中...</p>';
        if(!classId) return;
        try{
          var data = await api('/api/teacher/class/'+encodeURIComponent(classId)+'/members');
          var members = data.members || [];
          if(!members.length){ wrap.innerHTML='<p class="text-slate-400 text-sm">生徒がいません</p>'; return; }
          var unreadData = await api('/api/teacher/messages?classId='+encodeURIComponent(classId));
          var msgs = unreadData.messages || [];
          var unreadMap = {};
          var lastMsgMap = {};
          msgs.forEach(function(m){
            var sid = m.senderRole==='student' ? m.senderId : m.recipientId;
            if(!lastMsgMap[sid]) lastMsgMap[sid] = m;
            if(m.senderRole==='student' && !m.readAt){ unreadMap[sid] = (unreadMap[sid]||0) + 1; }
          });
          wrap.innerHTML='';
          // 未読がある生徒を上に、次に最新メッセージがある生徒、最後にメッセージなし
          members.sort(function(a,b){
            var ua = unreadMap[a.userId] || 0;
            var ub = unreadMap[b.userId] || 0;
            if(ua !== ub) return ub - ua; // 未読多い順
            var la = lastMsgMap[a.userId];
            var lb = lastMsgMap[b.userId];
            if(la && !lb) return -1;
            if(!la && lb) return 1;
            if(la && lb) return la.createdAt > lb.createdAt ? -1 : 1; // 新しい順
            return 0;
          });
          members.forEach(function(m){
            var card = document.createElement('div');
            var unread = unreadMap[m.userId] || 0;
            var lastMsg = lastMsgMap[m.userId];
            var preview = lastMsg ? lastMsg.body.slice(0,30) : 'メッセージなし';
            var time = lastMsg ? _utcToJST(lastMsg.createdAt).time : '';
            card.className = 'flex items-center gap-3 bg-white rounded-xl p-3 shadow-sm cursor-pointer hover:bg-slate-50 border' + (unread ? ' border-orange-300' : ' border-slate-100');
            card.innerHTML = '<div class="w-10 h-10 rounded-full bg-teal-100 flex items-center justify-center text-teal-700 font-bold text-sm flex-shrink-0">'+escH(m.name.slice(0,1))+'</div>'
              + '<div class="flex-1 min-w-0"><div class="flex justify-between items-center"><span class="font-bold text-sm">'+escH(m.name)+'</span><span class="text-[10px] text-slate-400">'+escH(time)+'</span></div><div class="text-xs text-slate-500 truncate">'+escH(preview)+'</div></div>'
              + (unread ? '<span class="bg-red-500 text-white text-[10px] rounded-full min-w-[18px] h-[18px] flex items-center justify-center font-bold">'+unread+'</span>' : '');
            card.onclick = (function(s){ return function(){ openMailChat(s.userId, s.name); }; })({userId:m.userId,name:m.name});
            wrap.appendChild(card);
          });
        }catch(e){ wrap.innerHTML='<p class="text-red-500 text-sm">読み込みエラー</p>'; }
      }

      function openMailChat(studentId, studentName){
        _mailCurrentStudent = studentId;
        document.getElementById('mailChatName').textContent = studentName + 'さん';
        document.getElementById('mailStudentListView').style.display='none';
        var cv = document.getElementById('mailChatView');
        cv.classList.remove('hidden'); cv.style.display='';
        loadMailChat();
        if(_mailPollTimer) clearInterval(_mailPollTimer);
        _mailPollTimer = setInterval(function(){ loadMailChat(true); }, 5000);
      }

      function closeMailChat(){
        if(_mailPollTimer){ clearInterval(_mailPollTimer); _mailPollTimer = null; }
        _mailCurrentStudent = null;
        document.getElementById('mailStudentListView').style.display='';
        document.getElementById('mailChatView').style.display='none';
        loadMailStudentList();
      }

      async function loadMailChat(silent){
        var wrap = document.getElementById('mailChatMessages');
        if(!silent) wrap.innerHTML = '<p class="text-sm text-slate-400 text-center">読み込み中...</p>';
        if(!_mailCurrentClass || !_mailCurrentStudent) return;
        try{
          var data = await api('/api/teacher/messages?classId='+encodeURIComponent(_mailCurrentClass)+'&studentId='+encodeURIComponent(_mailCurrentStudent));
          var list = data.messages || [];
          if(!list.length){ wrap.innerHTML='<p class="text-sm text-slate-400 text-center py-4">まだメッセージはありません</p>'; return; }
          // 生徒からの未読メッセージを自動で既読にする
          var unreadIds = [];
          list.forEach(function(m){ if(m.senderRole==='student' && !m.readAt) unreadIds.push(m.id); });
          if(unreadIds.length > 0){
            Promise.all(unreadIds.map(function(mid){ return api('/api/teacher/message/'+mid+'/read',{method:'POST'}); }))
              .then(function(){ if(!silent) loadMailChat(true); });
          }
          wrap.innerHTML='';
          var prevDate='';
          list.slice().reverse().forEach(function(m){
            var isFromMe = m.senderRole === 'teacher';
            var jst = _utcToJST(m.createdAt);
            var dt = jst.date;
            if(dt !== prevDate){
              wrap.insertAdjacentHTML('beforeend','<div class="text-center my-2"><span class="bg-black/10 text-slate-600 text-[10px] rounded-full px-3 py-0.5">'+escH(dt)+'</span></div>');
              prevDate = dt;
            }
            var row = document.createElement('div');
            row.className = 'flex ' + (isFromMe ? 'justify-end' : 'justify-start') + ' mb-1';
            var bubble = document.createElement('div');
            bubble.className = 'max-w-[75%]';
            var nameTag = '';
            if(!isFromMe){ nameTag = '<div class="text-[10px] text-slate-500 mb-0.5 ml-1">'+escH(m.senderName||'生徒')+'</div>'; }
            var time = escH(jst.time);
            var readMark = '';
            if(isFromMe && m.readAt){ readMark = '<span class="text-[10px] text-teal-600">既読</span> '; }
            var msgDiv = document.createElement('div');
            if(isFromMe){
              msgDiv.className = 'rounded-2xl rounded-br-sm px-3 py-2 text-sm shadow-sm bg-teal-500 text-white';
            } else {
              msgDiv.className = 'rounded-2xl rounded-bl-sm px-3 py-2 text-sm shadow-sm bg-white';
            }
            if(m.image){ var img=document.createElement('img'); img.src=m.image; img.className='rounded-lg max-w-full max-h-[200px] mb-1 cursor-pointer'; img.onclick=function(){window.open(m.image,'_blank');}; msgDiv.appendChild(img); }
            if(m.body && m.body!=='(画像)'){ var txt=document.createElement('span'); txt.textContent=m.body; msgDiv.appendChild(txt); } else if(!m.image){ msgDiv.textContent=m.body; }
            bubble.insertAdjacentHTML('beforeend', nameTag);
            bubble.appendChild(msgDiv);
            bubble.insertAdjacentHTML('beforeend', '<div class="flex items-end gap-1 mt-0.5 '+(isFromMe?'justify-end mr-1':'ml-1')+'"><span class="text-[10px] text-slate-400">'+readMark+time+'</span></div>');
            if(!isFromMe && !m.readAt){
              msgDiv.onclick = (function(mid){ return async function(){
                await api('/api/teacher/message/'+mid+'/read',{method:'POST'});
                loadMailChat();
              }; })(m.id);
              msgDiv.style.cursor='pointer';
              msgDiv.title='クリックで既読';
            }
            row.appendChild(bubble);
            wrap.appendChild(row);
          });
          wrap.scrollTop = wrap.scrollHeight;
        }catch(e){ wrap.innerHTML='<p class="text-red-500 text-sm text-center">読み込みエラー</p>'; }
      }

      var _mailImageData = null;
      function handleMailImage(input){
        var file = input.files[0]; if(!file) return;
        var reader = new FileReader();
        reader.onload = function(e){
          var img = new Image();
          img.onload = function(){
            var canvas = document.createElement('canvas');
            var maxW = 800, w = img.width, h = img.height;
            if(w > maxW){ h = Math.round(h * maxW / w); w = maxW; }
            canvas.width = w; canvas.height = h;
            canvas.getContext('2d').drawImage(img, 0, 0, w, h);
            _mailImageData = canvas.toDataURL('image/jpeg', 0.6);
            document.getElementById('mailImageThumb').src = _mailImageData;
            document.getElementById('mailImagePreview').classList.remove('hidden');
          };
          img.src = e.target.result;
        };
        reader.readAsDataURL(file);
        input.value = '';
      }
      function clearMailImage(){ _mailImageData = null; document.getElementById('mailImagePreview').classList.add('hidden'); }
      async function sendTeacherMail(){
        if(!_mailCurrentStudent){ return; }
        var body = document.getElementById('mailBody').value.trim();
        var msg = document.getElementById('mailMsg');
        if(!body && !_mailImageData){ msg.textContent='メッセージを入力してください'; msg.className='text-xs text-center py-1 text-red-600'; return; }
        try{
          await api('/api/teacher/message',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({classId:_mailCurrentClass,studentId:_mailCurrentStudent,body:body||'(画像)',image:_mailImageData||undefined})});
          msg.textContent=''; document.getElementById('mailBody').value=''; clearMailImage();
          loadMailChat();
        }catch(e){ msg.textContent='送信エラー'; msg.className='text-xs text-center py-1 text-red-600'; }
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
        // 締切のデフォルトを今日の20:00に
        var dlEl = document.getElementById('cnDeadline');
        if(dlEl && !dlEl.value){
          var y = today.getFullYear(), m = String(today.getMonth()+1).padStart(2,'0'), d = String(today.getDate()).padStart(2,'0');
          dlEl.value = y+'-'+m+'-'+d+'T20:00';
        }
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
  </body></html>`));const ht=new At,Fs=Object.assign({"/src/index.tsx":h});let Ut=!1;for(const[,e]of Object.entries(Fs))e&&(ht.all("*",t=>{let s;try{s=t.executionCtx}catch{}return e.fetch(t.req.raw,t.env,s)}),ht.notFound(t=>{let s;try{s=t.executionCtx}catch{}return e.fetch(t.req.raw,t.env,s)}),Ut=!0);if(!Ut)throw new Error("Can't import modules from ['/src/index.ts','/src/index.tsx','/app/server.ts']");export{ht as default};
