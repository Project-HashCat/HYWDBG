(function(){const e=document.createElement("link").relList;if(e&&e.supports&&e.supports("modulepreload"))return;for(const n of document.querySelectorAll('link[rel="modulepreload"]'))o(n);new MutationObserver(n=>{for(const r of n)if(r.type==="childList")for(const c of r.addedNodes)c.tagName==="LINK"&&c.rel==="modulepreload"&&o(c)}).observe(document,{childList:!0,subtree:!0});function a(n){const r={};return n.integrity&&(r.integrity=n.integrity),n.referrerPolicy&&(r.referrerPolicy=n.referrerPolicy),n.crossOrigin==="use-credentials"?r.credentials="include":n.crossOrigin==="anonymous"?r.credentials="omit":r.credentials="same-origin",r}function o(n){if(n.ep)return;n.ep=!0;const r=a(n);fetch(n.href,r)}})();async function G(t,e={},a){return window.__TAURI_INTERNALS__.invoke(t,e,a)}const C="http://127.0.0.1:31338/rpc";let Y=1,R=!1;const K=document.querySelector("#app");K.innerHTML=`
<div class="dbg-shell">
  <header class="topbar">
    <div class="brand"><strong>HYWDbg</strong></div>
    <nav class="menubar"><span>File</span><span>View</span><span>Debug</span><span>Plugins</span><span>Window</span><span>Help</span></nav>
    <div class="win-controls"><span>—</span><span>□</span><span>×</span></div>
  </header>

  <section class="actionbar">
    <button class="tool primary" id="runBtn"><span class="ico green">▶</span> Run <em>F5</em></button>
    <button class="tool" id="pauseBtn"><span class="ico blue">Ⅱ</span> Pause <em>F6</em></button>
    <button class="tool" id="stepBtn"><span class="ico blue">↧</span> Step Into <em>F11</em></button>
    <button class="tool" id="stepOverBtn"><span class="ico blue">↪</span> Step Over <em>F10</em></button>
    <button class="tool" id="bpBtn"><span class="ico red">●</span> Breakpoint</button>
    <button class="tool" id="launchBtn"><span class="ico yellow">📂</span> Open Process</button>
    <button class="tool" id="attachBtn"><span class="ico muted">🔗</span> Attach</button>
    <div class="spacer"></div>
    <button class="tool backend" id="helloBtn">Core</button>
    <button class="tool backend" id="startWinapiBtn">WinAPI</button>
    <button class="tool backend danger" id="stopBackendBtn">Stop</button>
  </section>

  <main class="workspace">
    <aside class="left-dock">
      <section class="dock-panel processes">
        <div class="panel-title">Processes <span>⌁</span></div>
        <table>
          <thead><tr><th>PID</th><th>Process Name</th><th>Arch</th><th>Status</th></tr></thead>
          <tbody id="processRows"></tbody>
        </table>
      </section>

      <section class="dock-panel modules">
        <div class="panel-title">Modules <span>⌁</span></div>
        <table>
          <thead><tr><th>Base</th><th>Module</th><th>Size</th></tr></thead>
          <tbody id="moduleRows"></tbody>
        </table>
      </section>

      <section class="dock-panel threads">
        <div class="panel-title">Threads <span>⌁</span></div>
        <table>
          <thead><tr><th>TID</th><th>PC</th><th>State</th></tr></thead>
          <tbody id="threadRows"></tbody>
        </table>
      </section>

      <section class="dock-panel breakpoints">
        <div class="panel-title">Breakpoints <span>⌁</span></div>
        <table>
          <thead><tr><th>Address</th><th>Type</th><th>Hits</th></tr></thead>
          <tbody id="bpRows"></tbody>
        </table>
      </section>

      <section class="dock-panel memory-map">
        <div class="panel-title">Memory Map <span>⌁</span></div>
        <table>
          <thead><tr><th>Base</th><th>Size</th><th>Protect</th></tr></thead>
          <tbody id="mapRows"></tbody>
        </table>
        <input class="filter" placeholder="Filter..." />
      </section>
    </aside>

    <section class="center-dock">
      <section class="dock-panel disasm-panel">
        <div class="tabbar"><div class="tab active">Disassembly - Thread <span id="activeTid">----</span> <b>×</b></div><div class="tab plus">+</div></div>
        <div class="subline">RIP: <span id="ripLine">00000000</span> <span id="symbolLine">(no target)</span></div>
        <table class="disasm-table">
          <thead><tr><th></th><th>Address</th><th>Bytes</th><th>Instruction</th><th>Comment</th></tr></thead>
          <tbody id="disasmRows"></tbody>
        </table>
      </section>

      <section class="bottom-grid">
        <section class="dock-panel stack-panel">
          <div class="tabbar small"><div class="tab active">Stack <b>×</b></div><div class="tab">Watch 1</div></div>
          <div class="subline">RSP: <span id="rspLine">00000000</span></div>
          <table>
            <thead><tr><th>Address</th><th>Value</th><th>Comment</th></tr></thead>
            <tbody id="stackRows"></tbody>
          </table>
        </section>

        <section class="dock-panel hex-panel">
          <div class="tabbar small"><div class="tab active">Hex View 1 <b>×</b></div></div>
          <div class="subline">Address: <input id="addrBox" class="addr-input" placeholder="0x..." /> <button id="readMemBtn" class="micro">read</button></div>
          <table class="hex-table">
            <thead id="hexHead"></thead>
            <tbody id="hexRows"></tbody>
          </table>
        </section>
      </section>

      <section class="dock-panel log-panel">
        <div class="tabbar small"><div class="tab active">Log / Console <b>×</b></div></div>
        <pre id="logView"></pre>
        <div class="cmdline"><span>hyw&gt;</span><input id="commandBox" spellcheck="false" placeholder="launch C:\\Windows\\System32\\notepad.exe | attach 1234 | regs | u rip | db rsp 80 | bp rip | g | t | pause" /></div>
      </section>
    </section>

    <aside class="right-dock">
      <section class="dock-panel registers-panel">
        <div class="panel-title">Registers <span id="refreshRegs">⟳</span></div>
        <div class="reg-group">General (<span id="archName">x64</span>)</div>
        <div id="registerRows" class="register-list"></div>
        <div class="flags-title">Flags</div>
        <div id="flagRows" class="flags"></div>
      </section>
    </aside>
  </main>

  <footer class="statusbar">
    <span id="statusText">Status: Idle</span>
    <span>PID: <b id="statusPid">----</b></span>
    <span>TID: <b id="statusTid">----</b></span>
    <span>Arch: <b id="statusArch">x64</b></span>
    <span>Backend: <b id="statusBackend">none</b></span>
    <span>Transport: <b id="transportState">detecting</b></span>
    <span class="right">Core: <b id="coreState">unknown</b></span>
  </footer>
</div>
`;const i=t=>document.querySelector(t),s={coreOnline:!1,backend:"none",pid:"----",tid:"----",arch:"x64",status:"Idle",regs:{},modules:[],threads:[],disasm:[],memory:{addr:"",size:0,hex:""},breakpoints:[],log:[]};function Z(){return new Date().toTimeString().slice(0,8)}function d(t,e="info"){const a=`[${Z()}] ${t}`;s.log.push(a),s.log.length>300&&s.log.shift();const o=i("#logView");o.innerHTML=s.log.map(n=>`<span class="log-${e}">${u(n)}</span>`).join(`
`),o.scrollTop=o.scrollHeight}function u(t){return String(t).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;")}function B(t){return t?t.replace(/^0x/i,"").replace(/^0+/,"")||"0":""}function b(t){const e=B(t).padStart(16,"0").slice(-16).toUpperCase();return`${e.slice(0,8)}\`${e.slice(8)}`}function O(t){if(!t)return 0;const e=t.trim();return e.toLowerCase()==="rip"?Number.parseInt(s.regs.rip||"0",16):e.toLowerCase()==="rsp"?Number.parseInt(s.regs.rsp||"0",16):e.toLowerCase()in s.regs?Number.parseInt(s.regs[e.toLowerCase()].replace(/^0x/i,""),16):e.startsWith("0x")||e.startsWith("0X")?Number.parseInt(e.slice(2),16):Number.parseInt(e,10)}function A(t){if(!t)return null;const e=t.trim(),a=e.toLowerCase()in s.regs?s.regs[e.toLowerCase()]:e;if(!a)return null;try{return a.startsWith("0x")||a.startsWith("0X"),BigInt(a)}catch{return null}}function M(t){return`0x${t.toString(16).padStart(16,"0")}`}function y(t){const e=O(t);return!Number.isFinite(e)||Number.isNaN(e)?t||"0x0":`0x${Math.trunc(e).toString(16)}`}function L(){var e,a,o;const t=globalThis;return typeof((e=t.__TAURI_INTERNALS__)==null?void 0:e.invoke)=="function"||typeof((o=(a=t.__TAURI__)==null?void 0:a.core)==null?void 0:o.invoke)=="function"}function _(){return L()?"tauri":"http"}async function Q(t,e){var r,c;const a=globalThis;if(L()){const m=(c=(r=a.__TAURI__)==null?void 0:r.core)==null?void 0:c.invoke;return typeof m=="function"?m("core_request",{method:t,params:e}):G("core_request",{method:t,params:e})}const o=await fetch(C,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:Y++,method:t,params:e})}),n=await o.text();if(!o.ok)throw new Error(`HTTP ${o.status}: ${n.slice(0,240)}`);return n}function tt(t){const e=t instanceof Error?t.message:String(t);return!L()&&/fetch|network|load failed/i.test(e)?`core HTTP bridge offline at ${C}; start run-core.ps1 or use npm run tauri dev`:/__TAURI|invoke|undefined/i.test(e)?"Tauri invoke bridge is unavailable; run the shell with npm run tauri dev, or use browser mode with the core HTTP bridge":e}function et(t){return/core HTTP bridge offline|connect core failed|connection refused|failed to fetch|network|load failed/i.test(t)}function h(t,e){return`<tr class="empty-row"><td colspan="${t}">${u(e)}</td></tr>`}function f(){return s.coreOnline?"No target":"Core offline"}function w(t=s.status){s.pid="----",s.tid="----",s.regs={},s.modules=[],s.threads=[],s.disasm=[],s.memory={addr:"",size:0,hex:""},s.breakpoints=[],s.status=t}function T(t){s.coreOnline=t,i("#coreState").textContent=t?"online":"offline",t||(s.backend="none",w("Core offline"))}async function l(t,e=null){var a;try{const o=await Q(t,e),n=JSON.parse(o);if(T(!0),R=!1,!n.ok){const r=typeof n.error=="string"?n.error:((a=n.error)==null?void 0:a.message)||JSON.stringify(n.error);d(`${t} failed: ${r}`,"err"),t.startsWith("dbg.")&&/no active backend|no debuggee/i.test(r)&&w(s.coreOnline?"Idle":"Core offline")}return n}catch(o){const n=tt(o),r=et(n);return r&&(T(!1),p()),(!r||!R)&&d(`${t} exception: ${n}`,"err"),R||(R=r),{ok:!1,error:n}}}function P(t){s.status=t,F()}function p(){st(),nt(),at(),rt(),it(),ot(),lt(),pt(),ut(),F()}function st(){var e;if(!s.coreOnline||s.pid==="----"){i("#processRows").innerHTML=h(4,f());return}const t=((e=s.modules[0])==null?void 0:e.name)||"debuggee";i("#processRows").innerHTML=`<tr class="sel"><td>${u(s.pid)}</td><td>${u(t)}</td><td>${s.arch}</td><td>${u(s.status)}</td></tr>`}function nt(){if(!s.modules.length){i("#moduleRows").innerHTML=h(3,f());return}i("#moduleRows").innerHTML=s.modules.slice(0,8).map((t,e)=>`<tr class="${e===0?"soft":""}"><td>${b(t.base)}</td><td>${u(t.name||"?")}</td><td>0x${(t.size||0).toString(16).toUpperCase()}</td></tr>`).join("")}function at(){if(!s.threads.length){i("#threadRows").innerHTML=h(3,f());return}i("#threadRows").innerHTML=s.threads.slice(0,8).map(t=>`<tr class="${t.active?"sel":""}"><td>${u(t.id||"?")}</td><td>${t.pc?b(t.pc):""}</td><td>${t.active?"Active":"Ready"}</td></tr>`).join("")}function rt(){if(!s.breakpoints.length){i("#bpRows").innerHTML=h(3,f());return}i("#bpRows").innerHTML=s.breakpoints.map(t=>`<tr><td>${b(t.address)}</td><td>${u(t.type)}</td><td>${t.hits}</td></tr>`).join("")}function it(){const t=s.modules.slice(0,5).map(e=>{const a=e.size||0;return`<tr><td>${b(e.base)}</td><td>0x${a.toString(16).toUpperCase()}</td><td></td></tr>`});t.length||t.push(h(3,f())),i("#mapRows").innerHTML=t.join("")}function ot(){var e;if(i("#activeTid").textContent=s.tid,i("#ripLine").textContent=s.regs.rip?b(s.regs.rip):"----",i("#symbolLine").textContent=(e=s.modules[0])!=null&&e.name?`(${s.modules[0].name})`:"(no target)",!s.disasm.length){i("#disasmRows").innerHTML=h(5,f());return}const t=B(s.regs.rip).toLowerCase();i("#disasmRows").innerHTML=s.disasm.map((a,o)=>{const n=!!t&&B(a.addr).toLowerCase()===t,r=ct(a.text||"");return`<tr class="${n?"current":""}"><td class="arrow">${n?"➜":""}</td><td>${b(a.addr)}</td><td class="bytes">${dt(a.bytes||"")}</td><td class="instr"><span class="mnemonic">${u(r.mnemonic)}</span>${u(r.rest)}</td><td class="comment">${u(r.comment)}</td></tr>`}).join("")}function ct(t){const[e,...a]=t.split(";"),o=a.length?`;${a.join(";")}`:"",n=e.trim().match(/^(\S+)(.*)$/);return{mnemonic:(n==null?void 0:n[1])||"db",rest:(n==null?void 0:n[2])||` ${e}`,comment:o}}function dt(t){var e;return((e=t.replace(/[^0-9a-f]/gi,"").match(/.{1,2}/g))==null?void 0:e.join(" ").toUpperCase())||""}function lt(){const t=["rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","rip","r8","r9","r10","r11","r12","r13","r14","r15"];if(i("#archName").textContent=s.arch,!Object.keys(s.regs).length){i("#registerRows").innerHTML=`<div class="empty-panel">${u(f())}</div>`,E();return}i("#registerRows").innerHTML=t.map(e=>{const a=s.regs[e];return`<div class="reg-row ${e==="rip"?"hot":""}"><span>${e.toUpperCase()}</span><code>${a?b(a):""}</code></div>`}).join(""),E()}function E(){if(!Object.keys(s.regs).length){i("#flagRows").innerHTML=`<div class="empty-panel">${u(f())}</div>`;return}const t=s.regs.eflags;if(!t){i("#flagRows").innerHTML='<div class="empty-panel">No flags</div>';return}const e=Number.parseInt(t.replace(/^0x/i,""),16)||0,a=[["CF",0],["PF",2],["AF",4],["ZF",6],["SF",7],["TF",8],["IF",9],["DF",10],["OF",11],["NT",14]];i("#flagRows").innerHTML=`<div class="rflags">RFLAGS <code>${b(t)}</code></div>`+a.map(([o,n])=>{const r=(e&1<<Number(n))!==0;return`<span class="flag ${r?"on":""}">${o} ${r?1:0}</span>`}).join("")}function pt(){var r;const t=A(s.regs.rsp),e=A(s.memory.addr),a=((r=(s.memory.hex||"").replace(/[^0-9a-f]/gi,"").match(/.{1,2}/g))==null?void 0:r.map(c=>Number.parseInt(c,16)))||[];if(t===null){i("#rspLine").textContent="----",i("#stackRows").innerHTML=h(3,f());return}if(i("#rspLine").textContent=b(s.regs.rsp),e===null||!a.length||t<e){i("#stackRows").innerHTML=h(3,"No stack memory");return}const o=Number(t-e);if(!Number.isSafeInteger(o)||o<0||o>=a.length){i("#stackRows").innerHTML=h(3,"No stack memory");return}const n=[];for(let c=0;c<8;c+=1){const m=o+c*8,k=a.slice(m,m+8);if(k.length<8)break;let g=0n;for(let x=0;x<k.length;x+=1)g|=BigInt(k[x])<<BigInt(x*8);n.push(`<tr><td>${b(M(t+BigInt(c*8)))}</td><td>${b(M(g))}</td><td class="comment"></td></tr>`)}n.length||n.push(h(3,"No stack memory")),i("#stackRows").innerHTML=n.join("")}function ut(){var n;i("#addrBox").setAttribute("value",s.memory.addr||"");const t=["Address",...Array.from({length:16},(r,c)=>c.toString(16).padStart(2,"0").toUpperCase()),"ASCII"];i("#hexHead").innerHTML=`<tr>${t.map(r=>`<th>${r}</th>`).join("")}</tr>`;const e=((n=(s.memory.hex||"").replace(/[^0-9a-f]/gi,"").match(/.{1,2}/g))==null?void 0:n.map(r=>Number.parseInt(r,16)))||[],a=O(s.memory.addr)||0,o=[];if(!e.length){i("#hexRows").innerHTML=h(18,f());return}for(let r=0;r<Math.min(e.length,160);r+=16){const c=e.slice(r,r+16),m=c.map(g=>`<td>${g.toString(16).padStart(2,"0").toUpperCase()}</td>`).join("")+Array.from({length:16-c.length},()=>"<td></td>").join(""),k=c.map(g=>g>=32&&g<=126?String.fromCharCode(g):".").join("");o.push(`<tr><td class="addr">${b(`0x${(a+r).toString(16)}`)}</td>${m}<td class="ascii">${u(k)}</td></tr>`)}i("#hexRows").innerHTML=o.join("")}function F(){i("#statusText").textContent=`Status: ${s.status}`,i("#statusPid").textContent=s.pid,i("#statusTid").textContent=s.tid,i("#statusArch").textContent=s.arch,i("#statusBackend").textContent=s.backend,i("#transportState").textContent=_()}function v(t){const e=t.result||{};if(e.pid&&(s.pid=String(e.pid)),e.tid){const a=Number(e.tid);s.tid=Number.isFinite(a)?a.toString(16).toUpperCase():String(e.tid)}e.event&&(s.status=e.event==="breakpoint"?"Breakpoint Hit":String(e.event),d(`event: ${e.event} pid=${e.pid||s.pid} tid=${e.tid||s.tid}`))}async function $(){await I(),await D(),await U(),await W(),await N(s.regs.rsp||s.regs.rip||"0x0",128),p()}async function I(){const t=await l("dbg.regs");if(t.ok&&t.result){const e=t.result;s.arch=e.arch||s.arch,s.regs={...s.regs,...e.registers||{}},d("registers refreshed")}p()}async function D(){const t=await l("dbg.modules");t.ok&&Array.isArray(t.result)&&(s.modules=t.result,d(`modules: ${s.modules.length}`)),p()}async function U(){const t=await l("dbg.threads");if(t.ok&&Array.isArray(t.result)){s.threads=t.result;const e=s.threads.find(a=>a.active)||s.threads[0];e!=null&&e.id&&(s.tid=e.id),d(`threads: ${s.threads.length}`)}p()}async function W(t=s.regs.rip||"0x0"){const e=await l("dbg.disasm",{addr:y(t),count:24});e.ok&&Array.isArray(e.result)&&(s.disasm=e.result,d(`disasm ${y(t)}`)),p()}async function N(t=s.memory.addr||"0x0",e=128){const a=await l("dbg.readMem",{addr:y(t),size:e});a.ok&&a.result&&(s.memory=a.result,d(`read memory ${s.memory.addr} size=${s.memory.size}`)),p()}async function z(t){(await l("core.startBackend",{kind:t})).ok&&(w("Backend Ready"),s.backend=t,d(`backend started: ${t}`)),p()}async function q(){(await l("core.stopBackend")).ok&&(s.backend="none",w("Idle"),d("backend stopped")),p()}async function J(){const t=prompt("EXE path","C:\\Windows\\System32\\notepad.exe");if(!t)return;const e=await l("dbg.launch",{path:t});e.ok&&(w("Launching"),v(e),d(`process launched: ${t}`),await $())}async function V(){const t=prompt("PID","1234");if(!t)return;const e=await l("dbg.attach",{pid:Number(t)});e.ok&&(w("Attaching"),s.pid=t,v(e),d(`process attached: pid=${t}`),await $())}async function H(){const t=s.status;P("Running"),p();const e=await l("dbg.go");e.ok?(v(e),await $()):s.coreOnline&&(P(t),p())}async function S(){const t=await l("dbg.stepInto");t.ok&&(v(t),await $())}async function j(){const t=await l("dbg.pause");t.ok&&(v(t),await $())}async function bt(){const t=prompt("Breakpoint address",s.regs.rip||"0x0");if(!t)return;const e=await l("dbg.bpSet",{addr:y(t)});e.ok&&e.result&&(s.breakpoints.push({address:e.result.addr||y(t),type:"INT3",hits:0}),d(`breakpoint set at ${e.result.addr||t}`)),p()}async function X(){var e;const t=await l("core.hello");t.ok?(T(!0),d(`core online: ${((e=t.result)==null?void 0:e.name)||"hywdbg-core"}`)):(T(!1),p())}async function ht(t){const e=t.trim();if(!e)return;d(`hyw> ${e}`,"cmd");const[a,...o]=e.split(/\s+/);try{switch(a.toLowerCase()){case"help":d("commands: backend winapi|titan, launch <exe>, attach <pid>, regs, modules, threads, u [addr], db <addr> [size], bp <addr>, g, t, pause, stop, rpc <method> <json>");break;case"backend":await z(o[0]||"winapi");break;case"stop":await q();break;case"launch":if(!o.length)return await J();{const n=e.slice(a.length).trim(),r=await l("dbg.launch",{path:n});r.ok&&(w("Launching"),v(r),await $())}break;case"attach":if(!o[0])return await V();{const n=await l("dbg.attach",{pid:Number(o[0])});n.ok&&(w("Attaching"),s.pid=o[0],v(n),await $())}break;case"regs":case"r":await I();break;case"modules":case"lm":await D();break;case"threads":await U();break;case"u":await W(o[0]||s.regs.rip||"0x0");break;case"db":await N(o[0]||s.regs.rsp||"0x0",Number(o[1]||"128"));break;case"bp":{const n=o[0]||s.regs.rip,r=await l("dbg.bpSet",{addr:y(n)});r.ok&&r.result&&s.breakpoints.push({address:r.result.addr||y(n),type:"INT3",hits:0}),p()}break;case"g":case"run":await H();break;case"t":case"step":await S();break;case"pause":await j();break;case"rpc":{const n=o[0],r=e.indexOf(n)+n.length,c=e.slice(r).trim(),m=c?JSON.parse(c):null,k=await l(n,m);d(JSON.stringify(k,null,2))}break;default:d(`unknown command: ${a}`,"err")}}catch(n){d(`command failed: ${String(n)}`,"err")}}i("#helloBtn").addEventListener("click",X);i("#startWinapiBtn").addEventListener("click",()=>z("winapi"));i("#stopBackendBtn").addEventListener("click",q);i("#launchBtn").addEventListener("click",J);i("#attachBtn").addEventListener("click",V);i("#runBtn").addEventListener("click",H);i("#pauseBtn").addEventListener("click",j);i("#stepBtn").addEventListener("click",S);i("#stepOverBtn").addEventListener("click",S);i("#bpBtn").addEventListener("click",bt);i("#refreshRegs").addEventListener("click",I);i("#readMemBtn").addEventListener("click",()=>N(document.querySelector("#addrBox").value||s.memory.addr,128));i("#commandBox").addEventListener("keydown",async t=>{if(t.key!=="Enter")return;const e=t.currentTarget,a=e.value;e.value="",await ht(a)});document.addEventListener("keydown",t=>{t.target.tagName!=="INPUT"&&(t.key==="F5"&&(t.preventDefault(),H()),t.key==="F6"&&(t.preventDefault(),j()),t.key==="F11"&&(t.preventDefault(),S()))});d("HYWDbg 0.1.0 UI loaded");d(`RPC transport: ${_()}${L()?"":` (${C})`}`);d("Run core-daemon, then click Core + WinAPI. Use console: help");p();X();
