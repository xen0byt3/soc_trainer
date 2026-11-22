#!/usr/bin/env python3
"""Threat Simulation & SOC Training App - fully mocked, offline, stdlib only.
Run:  python3 soc_trainer.py            (serves http://127.0.0.1:5050, localhost only)
      python3 soc_trainer.py --export   (writes standalone index.html, open it in a browser)
All hosts use RFC 5737/1918 documentation ranges. No real network traffic is ever generated."""
import argparse, http.server, threading, webbrowser

HTML = r"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>SOC Threat Sim Trainer</title>
<meta name="viewport" content="width=device-width,initial-scale=1"><style>
:root{--dp:#0d1426;--pu:#8b5cf6;--lp:#c4b5fd;--wh:#e6edf7;--sl:#111a30;--sd:#060b18;--ok:#22ff9c;--bad:#ff5c7a;--warn:#ffc857;--cy:#22d3ee}
*{box-sizing:border-box}body{margin:0;background:var(--sd);color:var(--wh);font:14px system-ui,sans-serif;height:100vh;display:flex;flex-direction:column}
header{background:var(--dp);padding:10px 16px;display:flex;justify-content:space-between;border-bottom:2px solid var(--pu)}
header b{font-size:16px}.badge{background:var(--pu);padding:2px 8px;border-radius:10px;font-size:12px}
main{flex:1;display:grid;grid-template-columns:1fr 1.4fr 1.2fr;gap:8px;padding:8px;min-height:0}
@media(max-width:1000px){main{grid-template-columns:1fr;overflow:auto}body{height:auto}}
section{background:var(--sl);border-radius:6px;display:flex;flex-direction:column;min-height:0;overflow:hidden;border:1px solid var(--pu)}
.tabs{display:flex;flex-wrap:wrap;background:var(--dp)}.tabs button{flex:1;background:none;border:0;color:var(--lp);padding:8px 4px;cursor:pointer;font-size:12px}
.tabs button.on{background:var(--pu);color:var(--wh);font-weight:700}
.body{padding:10px;overflow:auto;flex:1;min-height:200px}h3{margin:.2em 0;color:var(--lp)}h4{margin:.8em 0 .2em;color:#d8b4fe}
li{margin:3px 0}code,pre,.mono{font-family:Consolas,monospace;font-size:12.5px}code{background:var(--dp);padding:1px 4px;border-radius:3px}
.box{background:var(--dp);border-left:3px solid var(--pu);padding:6px 10px;margin:6px 0;border-radius:3px}
#term{background:#12081f;color:#e9dcf7;font-family:Consolas,monospace;font-size:13px;white-space:pre-wrap;overflow:auto;flex:1;padding:8px;min-height:240px}
.i{display:flex;background:#12081f;border-top:1px solid var(--pu)}.i span{padding:6px 0 6px 8px;color:#c084fc;font-family:Consolas,monospace;white-space:nowrap}
.i input{flex:1;background:none;border:0;color:#fff;font:13px Consolas,monospace;padding:6px;outline:0}
.g{color:var(--ok)}.r{color:var(--bad)}.y{color:var(--warn)}.p{color:#c084fc}.d{color:#94a3b8}
table{border-collapse:collapse;width:100%}td,th{padding:3px 6px;text-align:left;border-bottom:1px solid #64748b;font-size:12px;vertical-align:top}th{background:var(--dp);position:sticky;top:0}
select,input.f,button.b{background:var(--dp);color:#fff;border:1px solid var(--pu);padding:5px;border-radius:4px;font:12px Consolas,monospace}button.b{cursor:pointer;background:var(--pu)}
.bar{display:flex;gap:6px;padding:6px;background:var(--dp)}.bar select,.bar input{flex:1}
.prog span{display:inline-block;margin:2px;padding:2px 7px;border-radius:9px;background:var(--dp);font-size:11px}.prog .ok{background:var(--ok);color:#000}
body{background:radial-gradient(circle at 15% 0,#1b1140 0,transparent 45%),linear-gradient(rgba(34,211,238,.045) 1px,transparent 1px) 0 0/100% 30px,linear-gradient(90deg,rgba(34,211,238,.045) 1px,transparent 1px) 0 0/30px 100%,var(--sd)}
header{background:linear-gradient(90deg,#0d1426,#1b1140);border-bottom:1px solid var(--cy);position:relative;overflow:hidden;letter-spacing:.5px}
header:after{content:"";position:absolute;left:-30%;bottom:0;height:2px;width:30%;background:linear-gradient(90deg,transparent,var(--cy),transparent);animation:sweep 3s linear infinite}
@keyframes sweep{to{left:100%}}@keyframes pulse{50%{opacity:.35;transform:scale(.85)}}
.live{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok);margin-right:6px;animation:pulse 1.6s infinite}
section{border:1px solid #2a3a63;box-shadow:0 4px 18px rgba(0,0,0,.45);transition:box-shadow .25s}section:hover{box-shadow:0 0 14px rgba(34,211,238,.25)}
.tabs button.on{background:linear-gradient(180deg,#6d28d9,#4c1d95);box-shadow:inset 0 -2px var(--cy)}.tabs button:hover{color:#fff;background:#1b2547}
#term{background:#050a14!important;color:#c9f7e4;text-shadow:0 0 4px rgba(34,255,156,.25);background-image:repeating-linear-gradient(0deg,rgba(255,255,255,.025) 0 1px,transparent 1px 3px)!important}
#term div{animation:in .25s ease-out}@keyframes in{from{opacity:0;transform:translateX(-6px)}}
.i{background:#050a14}.i span{color:var(--cy)}.i input{caret-color:var(--cy)}code{color:var(--cy)}
.prog span{border:1px solid #2a3a63;transition:.3s}.prog .ok{background:var(--ok);color:#001a0e;box-shadow:0 0 8px var(--ok)}
.badge{background:#6d28d9;transition:.4s}.lv.l{background:#065f46}.lv.e{background:#a16207}.lv.h{background:#c2410c}.lv.c{background:#b91c1c;animation:pulse 1s infinite}
.box{background:#0a1022;border-left:3px solid var(--cy)}th{color:var(--cy)}tr:last-child td{animation:fl 1.2s}@keyframes fl{from{background:rgba(34,211,238,.35)}}
.chips{display:flex;flex-wrap:wrap;gap:4px;padding:6px;background:#0a1022}.chip{background:#1b2547;color:var(--lp);border:1px solid #3b4a7a;border-radius:12px;padding:2px 9px;font:11px Consolas,monospace;cursor:pointer}.chip:hover{border-color:var(--cy);color:#fff}
.bad{border-color:var(--bad)!important;box-shadow:0 0 6px var(--bad)}button.b{background:#6d28d9}
@media(prefers-reduced-motion:reduce){*,*:after{animation:none!important;transition:none!important}}

:root{--dp:#101216;--pu:#2f6fed;--lp:#b8c0cc;--wh:#e8eaed;--sl:#17191e;--sd:#0d0f12;--ok:#6db3ff;--bad:#e5484d;--warn:#d9a441;--cy:#6db3ff;--rd:#e5484d;--bd:#2b2f37}
body{background:#0d0f12}
header{background:#101216;border-bottom:1px solid var(--bd);letter-spacing:.3px}header:after{background:linear-gradient(90deg,transparent,var(--pu),transparent);animation-duration:7s}
.live{background:var(--pu);box-shadow:none}.glitch{animation:none}
section{border:1px solid var(--bd);background:var(--sl);box-shadow:none}section:hover{box-shadow:none;border-color:#3a4150}
.tabs{background:var(--dp)}.tabs button{color:var(--lp)}.tabs button.on{background:#232733;color:#fff;box-shadow:inset 0 -2px var(--pu)}.tabs button:hover{background:#1c1f26;color:#fff}
#term{background:#0a0b0d!important;background-image:none!important;color:#d6dae0;text-shadow:none}
.i{background:#0a0b0d;border-top:1px solid var(--bd)}.i span{color:var(--pu)}.i input{caret-color:var(--pu);color:#fff}
h3{color:#fff}h4{color:var(--ok)}code{background:#0d0f12;color:#8ec5ff}
.box{background:#12141a;border-left:3px solid var(--pu)}.d{color:#8b94a3}
td,th{border-bottom:1px solid var(--bd)}th{background:#101216;color:var(--lp)}
tr:last-child td{animation:fl 1.2s}@keyframes fl{from{background:rgba(47,111,237,.28)}}
.prog span{background:#101216;border:1px solid var(--bd);color:var(--lp)}.prog .ok{background:var(--pu);color:#fff;box-shadow:none}
.badge{background:#232733;color:var(--wh)}.lv.l{background:#1e3a66}.lv.e{background:#2f6fed}.lv.h{background:#b45309}.lv.c{background:#c4262b}.hot{background:#c4262b;animation:pulse 1.4s infinite}
.chips{background:#12141a}.chip{background:#1c1f26;border-color:var(--bd);color:var(--lp)}.chip:hover{border-color:var(--pu);color:#fff}
button.b,select,input.f{background:#12141a;border-color:var(--bd);color:var(--wh)}button.b{background:#2f6fed;border-color:#2f6fed;color:#fff}
.bar{background:#101216}.p{color:#8ec5ff}.g{color:#7fc4ff}.r{color:#ff6b70}.y{color:#e0b25a}
.s4{--c:#e5484d}.s3{--c:#e8833a}.s2{--c:#d9a441}.s1{--c:#4d8dff}.s0{--c:#8b94a3}
.al{background:#12141a}.al.s4:not(.ack){box-shadow:0 0 0 1px rgba(229,72,77,.45)}.al.ack{opacity:.5}.ac{color:var(--lp)}
.toast{background:#17191e;box-shadow:0 4px 14px rgba(0,0,0,.6)}.bad{border-color:var(--bad)!important;box-shadow:none}
.al{border-left:4px solid var(--c);margin:6px 0;padding:6px 8px;border-radius:3px;animation:in .3s}.al b{color:var(--c)}.an{font-weight:700;margin:3px 0}
.tg{float:right;font-size:10px;border:1px solid var(--c);color:var(--c);padding:0 6px;border-radius:8px}
#toasts{position:fixed;top:54px;right:12px;z-index:20;display:flex;flex-direction:column;gap:6px;width:min(340px,92vw)}
.toast{border:1px solid var(--c);border-left:5px solid var(--c);padding:7px 10px;border-radius:4px;cursor:pointer;animation:tin .35s}.toast b{color:var(--c)}@keyframes tin{from{transform:translateX(120%);opacity:0}}
</style></head><body>
<header><b><i class="live"></i><span class="glitch">SOC THREAT SIM TRAINER</span> <span class="badge">SANDBOX - ALL MOCKED</span> <span class="badge lv l" id="lvl">THREAT LEVEL: LOW</span> <span class="badge" id="hal">ALERTS 0</span></b><span class="prog" id="prog"></span></header>
<main>
<section><div class="tabs" id="ptabs"></div><div class="body" id="guide"></div></section>
<section><div class="tabs" id="mtabs"><button class="on" data-t="term">Terminal</button><button data-t="html">Target: index.html</button><button data-t="env">Target: .env</button><button data-t="conf">Target: nginx.conf</button></div>
<div id="term"></div><div class="i" id="inp"><span id="ps"></span><input id="cmd" autocomplete="off" autofocus></div><div class="body" id="insp" style="display:none"></div></section>
<section><div class="tabs" id="stabs"><button class="on" data-t="spl">Splunk</button><button data-t="wsk">Wireshark</button><button data-t="alr" id="atab">Alerts (0)</button></div>
<div id="spl" style="display:flex;flex-direction:column;flex:1;min-height:0"><div class="bar"><select id="q"></select><button class="b" id="runq">Run</button></div><div class="body" id="splout"></div></div>
<div id="wsk" style="display:none;flex-direction:column;flex:1;min-height:0"><div class="bar"><input class="f" id="wf" placeholder="display filter, e.g. tcp.port == 3306 || http.request.method == &quot;PUT&quot;"><button class="b" id="wapply">Apply</button></div><div class="chips" id="chips"></div><div class="body" id="wskout"></div></div><div id="alr" style="display:none;flex-direction:column;flex:1;min-height:0"><div class="body" id="alist"></div></div></section>
</main><div id="toasts"></div><script>
const ATT="192.0.2.5",EDGE="203.0.113.10",ORG="198.51.100.20",H={db:"10.0.0.12",redis:"10.0.0.13",fs:"10.0.0.14",jump:"10.0.0.15",rdp:"10.0.0.16",mail:"10.0.0.17"};
const PORTS=[[21,"ftp","vsftpd 2.3.4","Anonymous login allowed"],[22,"ssh","OpenSSH 7.6p1",""],[23,"telnet","BusyBox telnetd","Cleartext remote admin"],[80,"http","nginx 1.18.0","Acme Shop - dev build"],[139,"netbios-ssn","Samba smbd 4.6","NetBIOS session service"],[445,"microsoft-ds","Samba 4.6.2","SMB signing not required"],[3306,"mysql","MySQL 5.7.33","Remote root-capable listener"],[3389,"ms-wbt-server","Microsoft RDP","NLA disabled"],[6379,"redis","Redis 5.0.7","No auth, no protected-mode"],[8080,"http-proxy","Node/Express 4.17","Admin/debug panel exposed"]];
const SECRETS={APP_ENV:"production",DEBUG:"true",DB_HOST:H.db,DB_USER:"app_rw",DB_PASS:"Sum3r2024!demo",REDIS_URL:"redis://"+H.redis+":6379",SMB_SHARE:"//"+H.fs+"/finance",SMB_USER:"svc_backup",SMB_PASS:"Backup#demo1",SSH_USER:"svc_deploy",SSH_KEY_PATH:"/var/www/.ssh/id_demo",RDP_ADMIN:"labadmin / Adm1n!demo",SMTP_HOST:H.mail+":25",SMTP_PASS:"Mail!demo77"};
const HTMLSRC='<!-- TODO remove before prod: build 2.3.1-dev, debug=true -->\n<html><head><title>Acme Shop - dev build</title></head>\n<body><h1>Acme Shop</h1>\n<a href="/admin">Admin</a>\n<!-- config backup: /.env  uploads: /uploads (WebDAV PUT enabled) -->\n<script>window.DEBUG=true;window.API="http://'+ORG+':8080/api"<\/script>\n</body></html>';
const CONF='server {\n  listen 80 default_server;      # answers on raw origin IP, not only via WAF  [WEAK]\n  root /var/www/html;\n  location ~ /\\. { allow all; }   # dotfiles served: exposes .env  [WEAK]\n  location /uploads { dav_methods PUT; }  # unauthenticated upload  [WEAK]\n}\n# Fix: allow only edge IP ranges, deny dotfiles, disable PUT, move secrets to a vault';
const S={ev:[],pk:[],al:[],done:new Set(),shell:false,fixed:false,t:0,ph:1};
const $=i=>document.getElementById(i);
function ts(){S.t+=Math.random()*.9+.1;return S.t.toFixed(3)}
function L(k,host,src,msg){const e={k,t:new Date().toISOString().slice(11,19),host,src,msg};S.ev.push(e);alertFor(e)}
function P(s,d,pr,port,info){S.pk.push({n:S.pk.length+1,t:ts(),s,d,pr,port,info});}
function ok(k){if(!S.done.has(k)){S.done.add(k);prog();stageEsc()}}
function out(t,c){const d=document.createElement("div");d.className=c||"";d.textContent=t;$("term").appendChild(d);$("term").scrollTop=1e9}
const PH=[
{n:"1 Recon",o:`Map the external footprint (DNS, IP, ports, banners) and look for any path that bypasses edge/WAF filtering.`,
s:[`<b>DNS &amp; direct-IP discovery.</b> <code>nslookup shop.lab.test</code> resolves the public name to the edge/WAF (${EDGE}). Then <code>nslookup direct.shop.lab.test</code>: a stale record leaks the origin (${ORG}).`,
`<b>Test the direct-IP path.</b> <code>curl -I http://shop.lab.test/.env</code> is stopped by the WAF (403). <code>curl http://${ORG}/.env</code> reaches the origin with no WAF enforcement (exposed origin, default vhost or misconfigured proxy).`,
`<b>Port discovery.</b> <code>nmap ${EDGE}</code> shows only 80/443. <code>nmap ${ORG}</code> shows 80/8080 (HTTP/alt HTTP), 21 (FTP), 22 (SSH), 23 (Telnet), 139/445 (SMB), 3389 (RDP), 3306 (MySQL), 6379 (Redis).`,
`<b>Service &amp; banner enumeration.</b> <code>nmap -sV ${ORG}</code> adds exact versions; <code>nmap -A ${ORG}</code> adds OS clue, HTTP title and script-style findings (anonymous FTP, SMB signing, Redis without auth). Focus with <code>-p 3306,6379</code>.`,
`<b>Choose the next probe.</b> An exposed 8080 admin/dev panel, an outdated web server or a reachable 3306/6379 shows where to dig.`],
w:`The WAF only protects traffic that goes through it. If the origin answers on its raw IP, attackers use leaked DNS, certificates or scans to skip edge filtering and domain-specific rules, and every extra open port is another door.`,
d:`<b>Splunk:</b> spikes of HTTP 403/404, WAF/IDS alerts, anomalous Host headers, one source touching many dest_ports. <b>Wireshark:</b> <code>tcp.flags.syn==1 &amp;&amp; tcp.flags.ack==0</code> bursts across 80, 8080, 22, 3389, 3306, 6379; <code>http.host==${ORG}</code> (raw IP instead of the domain).`,
f:`Allow the origin only from edge IP ranges, delete stale DNS records, hide banners, close 21/23/3306/6379 to the internet, and retire dev/admin panels on 8080. Verify with the nginx.conf <i>Apply remediation</i> toggle, then rescan.`},
{n:"2 Access",o:`Turn a web/config flaw into command execution, simulated as a web shell and a reverse shell.`,
s:[`<b>Spot the exposure.</b> Read the <i>Target: index.html</i> and <i>nginx.conf</i> tabs: dev comments, DEBUG flag, dotfiles served, WebDAV PUT enabled.`,
`<b>Exploit the misconfiguration.</b> <code>curl -X PUT http://${ORG}/uploads/cmd.php</code> simulates an insecure upload (real flaws: command injection, insecure upload/file-read, exposed config path).`,
`<b>Web shell.</b> <code>curl http://${ORG}/uploads/cmd.php?c=id</code>: a script reachable over HTTP (80/8080) takes commands in a parameter and passes them to the OS shell; output returns inside the HTTP response.`,
`<b>Reverse shell.</b> <code>revshell</code>: the attacker listens on ${ATT}:4444 and the target's shell (sh/bash/PowerShell) calls out. This works even when inbound ports are locked down.`],
w:`Anything that writes or reads files, or passes input to the OS, is a path to the host. Outbound traffic is often less restricted than inbound, so a callback succeeds where a direct connection would not.`,
d:`<b>Splunk:</b> access logs with suspicious payloads (PUT, <code>?c=</code>); process/EDR/syslog showing a web process spawning /bin/sh, bash or powershell.exe. <b>Wireshark:</b> <code>http.request.method=="PUT"</code>; an outbound session from the web server to an external IP/port (<code>tcp.port==4444</code>); command output inside HTTP responses.`,
f:`Disable PUT/WebDAV, block script execution in /uploads, validate input and uploads, run the web user with least privilege, restrict egress to an allow-list, remove dev builds.`},
{n:"3 Secrets",o:`See how exposed .env files and process environment variables hand an attacker valid credentials.`,
s:[`<b>Exposed before any shell.</b> <code>curl http://${ORG}/.env</code> works when the file sits in the web root.`,
`<b>Inside the shell.</b> After Phase 2 run <code>ls</code>, <code>cat .env</code>, then <code>printenv</code> (or <code>env</code>) to read injected secrets from the process environment.`,
`<b>Map the blast radius.</b> Compare the <i>Target: .env</i> tab with the services it unlocks: MySQL 3306, Redis 6379, SMB 445, SSH 22, RDP 3389, SMTP 25.`],
w:`Apps, APIs and containers keep database passwords, cloud keys, SMTP/mail credentials and API tokens in .env. Reading valid credentials beats brute force, and the attacker then authenticates legitimately, so activity looks like normal logins.`,
d:`<b>Splunk:</b> file-access/audit events reading .env, then authentication or DB login events using those credentials. <b>Wireshark:</b> <code>http.request.uri contains ".env"</code> followed by a cleartext KEY=VALUE body; session traffic to 3306/6379/445/22 right after.`,
f:`Never serve dotfiles, keep secrets in a vault, issue short-lived least-privilege credentials, rotate after any exposure, and restrict who can read process environments.`},
{n:"4 Pivot",o:`Use the shell plus harvested secrets to move across services, persist and stage data.`,
s:[`<b>Databases &amp; stores:</b> <code>mysql -h ${H.db} -u app_rw</code> (3306), <code>redis-cli -h ${H.redis}</code> (6379).`,
`<b>File shares &amp; legacy transfer:</b> <code>smbclient //${H.fs}/finance</code> (139/445; FTP 21 is also used to stage tools or pull files).`,
`<b>Remote administration:</b> <code>ssh svc_deploy@${H.jump}</code> (22), <code>xfreerdp /v:${H.rdp}</code> (3389); Telnet 23 is the legacy equivalent.`,
`<b>Persistence:</b> <code>persist</code> adds a mock scheduled task so access survives reboots (also startup scripts, backdoor accounts, SSH keys).`,
`<b>Exfiltration/staging:</b> <code>nc ${H.mail} 25</code> (SMTP; also 110 POP3 or outbound HTTP/HTTPS/custom ports, depending on egress rules).`],
w:`Flat networks plus stolen credentials let attackers use familiar protocols that blend in. Each hop usually adds privileges and another foothold.`,
d:`<b>Splunk:</b> new SSH (22) / RDP (3389) logons, service or scheduled-task creation, unusual outbound transfers. <b>Wireshark:</b> <code>tcp.port==3306 || tcp.port==6379 || tcp.port==445</code> then <code>tcp.port==22 || tcp.port==3389</code>; sustained bulk transfers.`,
f:`Segment networks, one credential per service, MFA on remote admin, SMB signing, Redis auth, disable Telnet/FTP, egress allow-lists, alert on new persistence.`},
{n:"5 SOC",o:`Correlate every stage in Splunk logs and Wireshark packets and separate true from false positives.`,
s:[`Run the Splunk dropdown queries in phase order, then use the Wireshark filter chips for the same window.`,`Line up timestamps: scan, then upload/shell, then .env read, then logins and transfers.`,`Decide TP vs FP: web-to-DB traffic on 3306 is normal unless it follows a .env read or a web-process shell.`,`Open <i>Target: nginx.conf</i>, click <i>Apply remediation</i>, rerun <code>nmap -A ${ORG}</code> and confirm the exposure is gone.`],
w:`Each attack stage leaves traces in two places, and agreement between logs (what happened) and packets (what crossed the wire) is what confirms a true positive.`,
d:`See the table below. Use <code>splunk</code> and <code>wireshark &lt;filter&gt;</code> in the terminal as shortcuts.`,
f:`Tune alerts per stage, enrich with asset context, keep full PCAP for critical segments, and rehearse this correlation as a playbook.`,
x:`<h4>Stage correlation</h4><table><tr><th>Stage<th>Splunk (logs/alerts)<th>Wireshark (packets)</tr><tr><td>Recon, direct IP, nmap<td>Spikes in HTTP 403/404 or anomalous Host headers; WAF/IDS alerts; bursty connection attempts across ports<td>Rapid TCP SYN scans (80, 8080, 22, 3389, 3306, 6379); HTTP with a raw IP in Host</tr><tr><td>Shell execution<td>Access logs with suspicious payloads; EDR/syslog of a web process spawning /bin/sh, bash or powershell.exe<td>Outbound TCP from web server to external IP/port (reverse shell) or command output in HTTP responses (web shell)</tr><tr><td>.env access &amp; secret use<td>Audit logs reading .env; later logins or DB auth using those credentials<td>Cleartext or session traffic to 3306, 6379, 445, 22 right after the .env read</tr><tr><td>Lateral movement &amp; persistence<td>New SSH/RDP logons, service or scheduled-task creation, unusual outbound transfers<td>New internal/external TCP/UDP streams, auth handshakes, bulk transfers matching the alert window</tr></table>`}];
function ph(i){S.ph=i;[...$("ptabs").children].forEach((b,j)=>b.className=j==i?"on":"");const p=PH[i];
$("guide").innerHTML="<h3>Phase "+p.n+"</h3><div class=box><b>Objective:</b> "+p.o+"</div><h4>Learner workflow</h4><ol>"+p.s.map(x=>"<li>"+x+"</li>").join("")+"</ol><h4>Why it happens</h4><p>"+p.w+"</p><h4>How defenders detect</h4><p>"+p.d+"</p><h4>Remediation</h4><p>"+p.f+"</p>"+(p.x||"")}
PH.forEach((p,i)=>{const b=document.createElement("button");b.textContent="Phase "+p.n;b.onclick=()=>ph(i);$("ptabs").appendChild(b)});
const KEYS=[["recon","Recon"],["scan","Port scan"],["origin","Origin found"],["shell","Shell"],["secret","Secrets"],["lateral","Lateral"],["persist","Persist"]];
function lvl(){const n=S.done.size,v=n>5?["CRITICAL","c"]:n>3?["HIGH","h"]:n>1?["ELEVATED","e"]:["LOW","l"],e=$("lvl");e.textContent="THREAT LEVEL: "+v[0];e.className="badge lv "+v[1]}
function prog(){lvl();$("prog").innerHTML=KEYS.map(k=>"<span class='"+(S.done.has(k[0])?"ok":"")+"'>"+k[1]+"</span>").join("")}
function insp(t){const m={html:HTMLSRC,env:Object.entries(SECRETS).map(e=>e.join("=")).join("\n"),conf:CONF};
$("insp").innerHTML="<pre>"+m[t].replace(/&/g,"&amp;").replace(/</g,"&lt;")+"</pre>"+(t=="conf"?"<button class=b id=fx>"+(S.fixed?"Revert to vulnerable":"Apply remediation")+"</button>":"")+(t=="env"?"<p class=d>All values are fake lab data.</p>":"");
if(t=="conf")$("fx").onclick=()=>{S.fixed=!S.fixed;L("remediation","edge","admin","Origin hardened="+S.fixed);insp("conf");out("[admin] remediation "+(S.fixed?"applied: origin locked to edge, dotfiles denied, PUT disabled":"reverted"),"y")}}
[...$("mtabs").children].forEach(b=>b.onclick=()=>{[...$("mtabs").children].forEach(x=>x.className="");b.className="on";const t=b.dataset.t,tm=t=="term";$("term").style.display=tm?"":"none";$("inp").style.display=tm?"":"none";$("insp").style.display=tm?"none":"";if(!tm)insp(t)});
[...$("stabs").children].forEach(b=>b.onclick=()=>{[...$("stabs").children].forEach(x=>x.className="");b.className="on";$("spl").style.display=b.dataset.t=="spl"?"flex":"none";$("wsk").style.display=b.dataset.t=="wsk"?"flex":"none";$("alr").style.display=b.dataset.t=="alr"?"flex":"none";draw()});
const Q=[["Port scan detection (P1)","index=lab sourcetype=fw | stats dc(dest_port) as ports by src_ip,dest_ip | where ports>5",e=>e.k=="scan"],["Suspicious DNS (P1)","index=lab sourcetype=dns | stats count by query | where query LIKE \"direct%\"",e=>e.k=="dns"],["Web exposure & upload (P2)","index=lab sourcetype=access (uri=\"/.env\" OR method=PUT OR uri=\"*cmd.php*\")",e=>e.k=="web"],["Shell / callback (P2)","index=lab (sourcetype=process OR sourcetype=fw) dest_port=4444 | table _time host cmd dest_ip",e=>e.k=="shell"],["Secret access (P3)","index=lab sourcetype=audit (file=\".env\" OR cmd=printenv)",e=>e.k=="secret"],["Lateral movement (P4)","index=lab src_ip=198.51.100.20 dest_port IN (3306,6379,445,22,3389,25) | stats count by dest_ip,dest_port",e=>e.k=="lateral"],["Persistence (P4)","index=lab sourcetype=audit cmd=\"crontab*\"",e=>e.k=="persist"],["WAF blocks / 403 (P1)","index=lab sourcetype=waf action=blocked | stats count by src_ip,uri",e=>e.k=="web"&&/BLOCKED/.test(e.msg)],["New SSH/RDP logons (P4)","index=lab sourcetype=auth (dest_port=22 OR dest_port=3389) | stats count by src_ip,dest_ip",e=>e.k=="lateral"&&/:(22|3389) /.test(e.msg)],["Egress / staging SMTP (P4)","index=lab sourcetype=fw dest_port IN (25,110) | stats sum(bytes) by src_ip,dest_ip",e=>e.k=="lateral"&&/:25 /.test(e.msg)],["All events","index=lab | sort _time",e=>1]];
Q.forEach((q,i)=>$("q").add(new Option(q[0],i)));
function draw(){const q=Q[$("q").value||0],r=S.ev.filter(q[2]);$("splout").innerHTML="<div class='box mono'>"+q[1].replace(/</g,"&lt;")+"</div><div class=d>"+r.length+" events</div><table><tr><th>time<th>host<th>source<th>event</tr>"+r.map(e=>"<tr><td>"+e.t+"<td>"+e.host+"<td>"+e.src+"<td>"+e.msg+"</tr>").join("")+"</table>";wdraw()}
$("runq").onclick=draw;$("q").onchange=draw;
function fld(p){if(p._f)return p._f;const i=p.info,f={proto:p.pr.toLowerCase()},dns=f.proto=="dns";let m;
f["frame.number"]=p.n;f["ip.src"]=p.s;f["ip.dst"]=p.d;f["ip.addr"]=[p.s,p.d];f[dns?"udp.port":"tcp.port"]=p.port;
if(!dns){m=i.match(/^(SYN,ACK|SYN|RST,ACK|RST|PSH,ACK|FIN,ACK|ACK)\b/);const fl=m?m[1].split(","):["PSH","ACK"];["syn","ack","rst","psh","fin"].forEach(k=>f["tcp.flags."+k]=fl.includes(k.toUpperCase())?1:0)}
m=i.match(/^(GET|PUT|POST|HEAD)\s+(\S+)\s+HTTP/);if(m){f["http.request"]=1;f["http.request.method"]=m[1];f["http.request.uri"]=m[2]}
m=i.match(/Host:\s*(\S+)/);if(m)f["http.host"]=m[1];
m=i.match(/^(\d{3})\s/);if(m&&f.proto=="http")f["http.response.code"]=+m[1];
m=i.match(/query A (\S+)/);if(m)f["dns.qry.name"]=m[1];
return p._f=f}
function tok(s){const t=[],r=/\s*(&&|\|\||==|!=|>=|<=|>|<|\(|\)|!|"[^"]*"|[^\s()!=<>&|"]+)/y;s=s.trim();let m;
while(r.lastIndex<s.length){m=r.exec(s);if(!m)throw 0;t.push({and:"&&",or:"||",not:"!"}[m[1]]||m[1])}return t}
function wf(s){if(!s.trim())return()=>1;const t=tok(s);let i=0;
const or=()=>{let a=and();while(t[i]=="||"){i++;const l=a,r=and();a=p=>l(p)||r(p)}return a},
and=()=>{let a=nt();while(t[i]=="&&"){i++;const l=a,r=nt();a=p=>l(p)&&r(p)}return a},
nt=()=>{if(t[i]=="!"){i++;const x=nt();return p=>!x(p)}return atom()},
atom=()=>{if(t[i]=="("){i++;const x=or();if(t[i++]!=")")throw 0;return x}
let k=t[i++];if(k===undefined)throw 0;if(k[0]=='"')k=k.slice(1,-1);k=k.toLowerCase();const op=t[i];
if(["==","!=","contains",">","<",">=","<="].includes(op)){i++;let v=t[i++];if(v===undefined)throw 0;if(v[0]=='"')v=v.slice(1,-1);else if(/^\d+$/.test(v))v=+v;
return p=>{const x=fld(p)[k];if(x===undefined)return false;const A=Array.isArray(x)?x:[x],e=y=>String(y)==String(v);
return op=="=="?A.some(e):op=="!="?!A.some(e):A.some(y=>op=="contains"?String(y).toLowerCase().includes(String(v).toLowerCase()):op==">"?y>v:op=="<"?y<v:op==">="?y>=v:y<=v)}}
return p=>{const f=fld(p);if(k=="tcp")return f.proto!="dns";if(k=="udp")return f.proto=="dns";if(f.proto==k)return true;if(k in f)return !!f[k];return p.info.toLowerCase().includes(k)}};
const fn=or();if(i<t.length)throw 0;return fn}
function wdraw(){const el=$("wf");let fn,bad=0;try{fn=wf(el.value)}catch(e){fn=()=>0;bad=1}el.classList.toggle("bad",bad);
$("wskout").innerHTML=(bad?"<div class=r>Invalid display filter</div>":"")+"<table><tr><th>No<th>Time<th>Source<th>Destination<th>Proto<th>Info</tr>"+S.pk.filter(fn).map(p=>"<tr><td>"+p.n+"<td>"+p.t+"<td>"+p.s+"<td>"+p.d+"<td>"+p.pr+"<td>"+p.info.replace(/</g,"&lt;")+"</tr>").join("")+"</table>"}
[["SYN scan","tcp.flags.syn==1 && tcp.flags.ack==0"],["HTTP PUT",'http.request.method=="PUT"'],["/.env request",'http.request.uri contains ".env"'],["Raw-IP Host","http.host==198.51.100.20"],["Reverse shell","tcp.port==4444"],["MySQL","tcp.port==3306"],["Redis","tcp.port==6379"],["SMB","tcp.port==445 || tcp.port==139"],["SSH/RDP","tcp.port==22 || tcp.port==3389"],["SMTP","tcp.port==25"],["DNS","dns"],["Clear",""]].forEach(c=>{const b=document.createElement("button");b.className="chip";b.textContent=c[0];b.onclick=()=>{$("wf").value=c[1];wdraw()};$("chips").appendChild(b)});
$("wapply").onclick=wdraw;$("wf").onkeydown=e=>{if(e.key=="Enter")wdraw()};
function ps(){$("ps").textContent=S.shell?"www-data@origin:~$":"learner@kali:~$"}
function scan(a,t){const pf=a.match(/-p\s*([\d,]+)/),want=pf?pf[1].split(",").map(Number):null,V=/-sV|-A/.test(a),A=/-A/.test(a),edge=t==EDGE||t=="shop.lab.test",dst=edge?EDGE:ORG,rows=[];
out("Starting Nmap (SIMULATED) against "+t,"d");ok("scan");
PORTS.concat([[443,"https","WAF-Edge TLS",""]]).sort((x,y)=>x[0]-y[0]).forEach(p=>{if(want&&!want.includes(p[0]))return;if(!edge&&p[0]==443)return;
const open=edge?(p[0]==80||p[0]==443):!S.fixed;P(ATT,dst,"TCP",p[0],"SYN -> "+p[0]);if(open)P(dst,ATT,"TCP",p[0],"SYN,ACK "+p[0]+" "+p[1]);
rows.push([open,p[0]+"/tcp  "+(open?"open    ":"filtered ")+p[1].padEnd(14)+(open&&V?(edge?"WAF-Edge reverse proxy":p[2])+(A&&p[3]&&!edge?"  | "+p[3]:""):"")])});
out("PORT     STATE    SERVICE        VERSION");rows.forEach(r=>out(r[1],r[0]?"g":"d"));
if(A&&!edge&&!S.fixed)out("OS guess: Linux 4.15 (lab). Traceroute: 1 hop. HTTP titles and script-style findings shown per port.","d");
L("scan","fw",ATT,"Scan "+dst+" dest_ports="+rows.length+" flags="+a);if(!edge&&!S.fixed)ok("origin")}
function lat(k,port,svc,msg,cmd){if(!S.done.has("secret")){out("Permission denied: no known credentials. Harvest them first (Phase 3).","r");return}
const ip=H[k];if(!S.shell){out("Note: you need a foothold on origin to pivot (Phase 2).","y");return}
P(ORG,ip,"TCP",port,"SYN "+port+" "+svc);P(ip,ORG,"TCP",port,"SYN,ACK "+svc+" session established");P(ORG,ip,svc,port,msg);
L("lateral","fw",ORG,"Connection "+ORG+" -> "+ip+":"+port+" ("+svc+") "+cmd);ok("lateral");out(msg,"g")}
const C={
help(){out("Commands: nslookup, nmap [-sV -A -p N,N] <host>, curl [-I|-X PUT] <url>, cat <file>, ls, printenv|env, revshell, mysql, redis-cli, smbclient, ssh, xfreerdp, nc <ip> 25, persist, splunk, wireshark <filter>, phase <1-4>, clear, reset","p")},
clear(){$("term").innerHTML=""},reset(){location.reload()},
ls(){out(S.shell?"index.html  .env  uploads/  app.js":"index.html (remote). Use curl to inspect the target.")},
phase(a){ph(+a[0]-1||0)},
splunk(){$("stabs").children[0].click()},wireshark(a){$("wf").value=a.join(" ");$("stabs").children[1].click();wdraw()},
nslookup(a){const h=a[a.length-1]||"";P(ATT,"10.0.0.2","DNS",53,"Standard query A "+h);L("dns","dns",ATT,"query="+h);ok("recon");
if(h=="shop.lab.test"){out("Non-authoritative answer: "+h+" -> "+EDGE+" (WAF/edge)","g");P("10.0.0.2",ATT,"DNS",53,"Response "+EDGE)}
else if(h=="direct.shop.lab.test"||h=="origin.shop.lab.test"){out(h+" -> "+ORG+"  (ORIGIN leaked - bypasses WAF!)","y");P("10.0.0.2",ATT,"DNS",53,"Response "+ORG);ok("origin")}
else out("** server can't find "+h+": NXDOMAIN","r")},
nmap(a){const t=a.filter(x=>!x.startsWith("-")&&!/^[\d,]+$/.test(x)).pop();if([EDGE,ORG,"shop.lab.test","direct.shop.lab.test"].includes(t))scan(a.join(" "),t=="direct.shop.lab.test"?ORG:t);else out("Out of lab scope. Allowed: "+EDGE+", "+ORG+" only.","r")},
curl(a){const u=a.find(x=>x.startsWith("http"))||"",edge=/shop\.lab\.test/.test(u)&&!/direct/.test(u),I=a.includes("-I"),put=a.includes("PUT");
const path=u.replace(/^https?:\/\/[^/]+/,"")||"/",dst=edge?EDGE:ORG;if(u&&(edge||u.includes(ORG)))P(ATT,dst,"HTTP",80,(put?"PUT ":I?"HEAD ":"GET ")+path+" HTTP/1.1  Host: "+(edge?"shop.lab.test":ORG));
if(!u){out("usage: curl [-I] [-X PUT] <url>");return}
if(edge&&/\.env|cmd\.php/.test(path)){out("HTTP/1.1 403 Forbidden (WAF rule 942100)","r");L("web","waf",ATT,"BLOCKED "+path);P(EDGE,ATT,"HTTP",80,"403 Forbidden");ok("recon");return}
if(edge){out(I?"HTTP/1.1 200 OK\nServer: waf-edge":HTMLSRC);L("web","waf",ATT,"GET "+path+" 200");return}
if(u.includes(ORG)&&S.fixed){out("curl: (28) Connection timed out (origin only accepts edge IPs)","r");return}
if(!u.includes(ORG)){out("Out of lab scope.","r");return}
if(path.startsWith("/.env")){out(I?"HTTP/1.1 200 OK":Object.entries(SECRETS).map(e=>e.join("=")).join("\n"),"y");L("web","origin",ATT,"GET /.env 200 bytes=412");L("secret","origin","www-data","file=.env read via HTTP");P(ORG,ATT,"HTTP",80,"200 OK  .env body KEY=VALUE cleartext");ok("secret")}
else if(put){out("HTTP/1.1 201 Created  /uploads/cmd.php (mock; no payload exists)","y");L("web","origin",ATT,"PUT /uploads/cmd.php 201");P(ORG,ATT,"HTTP",80,"201 Created");ok("shell")}
else if(path.includes("cmd.php")){out("uid=33(www-data) gid=33(www-data) groups=33(www-data)  [simulated web shell]","y");L("web","origin",ATT,"GET "+path+" 200");L("shell","origin","www-data","process: sh -c id (parent nginx/php)");P(ORG,ATT,"HTTP",80,"200 OK uid=33(www-data)");S.shell=true;ok("shell")}
else{out(I?"HTTP/1.1 200 OK\nServer: nginx/1.18.0":HTMLSRC);L("web","origin",ATT,"GET "+path+" 200")}},
revshell(){if(!S.done.has("shell")){out("No foothold yet. Complete the upload/web shell step first.","r");return}
out("[lab] listener "+ATT+":4444 <- connection from "+ORG+":51234 (SIMULATED, no payload)","y");P(ORG,ATT,"TCP",4444,"SYN 51234 -> 4444 (outbound from web server)");P(ATT,ORG,"TCP",4444,"SYN,ACK");P(ORG,ATT,"TCP",4444,"PSH,ACK interactive session");L("shell","fw",ORG,"Outbound "+ORG+" -> "+ATT+":4444 rare port from web server");L("shell","origin","www-data","process: sh spawned by nginx, fd redirected to socket");S.shell=true;ps()},
cat(a){const f=a[0];if(f=="index.html")out(HTMLSRC);else if(f==".env"){if(!S.shell){out("cat: .env: No such file (no shell)","r");return}Object.entries(SECRETS).forEach(e=>out(e.join("="),"y"));L("secret","origin","www-data","cmd=cat .env");ok("secret")}else out("cat: "+f+": No such file")},
printenv(){if(!S.shell){out("Need shell access.","r");return}Object.entries(SECRETS).forEach(e=>out(e.join("="),"y"));L("secret","origin","www-data","cmd=printenv (process environment)");ok("secret")},
mysql(){lat("db",3306,"mysql","mysql> connected as app_rw. SHOW DATABASES: shop, customers, payments","mysql -u app_rw")},
"redis-cli"(){lat("redis",6379,"redis","127.0.0.1> PING -> PONG (no auth). KEYS * -> session:*, cart:*","redis-cli KEYS *")},
smbclient(){lat("fs",445,"smb","smb: \\> ls  budget.xlsx  payroll.csv  (SMB2 tree connect as svc_backup)","smbclient //fs/finance")},
ssh(){lat("jump",22,"ssh","svc_deploy@jump:~$ session opened (key from "+SECRETS.SSH_KEY_PATH+")","ssh svc_deploy")},
xfreerdp(){lat("rdp",3389,"rdp","RDP session to "+H.rdp+" as labadmin (NLA off) - remote admin reachable","xfreerdp /v")},
nc(a){if(a[0]==H.mail)lat("mail",25,"smtp","220 mail ESMTP. MAIL FROM <svc@corp>; data staged for egress (mock)","nc smtp");else out("Out of lab scope.","r")},
persist(){if(!S.shell){out("Need shell.","r");return}out("(crontab -l; echo '*/5 * * * * /tmp/.beacon') | crontab -   [mock entry only]","y");L("persist","origin","www-data","cmd=crontab new entry */5 * * * * /tmp/.beacon");ok("persist")}};
C.env=C.printenv;
$("cmd").onkeydown=e=>{if(e.key!="Enter")return;const v=e.target.value.trim();e.target.value="";out($("ps").textContent+" "+v,"p");if(!v)return;const a=v.split(/\s+/),f=C[a[0]];f?f(a.slice(1)):out(a[0]+": command not found (try help)","r");draw();ps()};
const SV=["INFO","LOW","MEDIUM","HIGH","CRITICAL"],
RULES=[["dns",/query=(direct|origin)\./,2,"Lookup of non-public subdomain","T1590.002",1,"Check the DNS zone for stale records and decide whether the origin IP should be public.",1,"dns","VALIDATE"],
["scan",/Scan 203\./,2,"Port scan against WAF edge","T1046",1,"Edge scans are common noise: check source reputation and rate-limit or block.",0,"tcp.flags.syn==1 && tcp.flags.ack==0","VALIDATE"],
["scan",/Scan 198\./,3,"Port scan against origin server","T1046",1,"The origin should not be reachable from the internet: restrict to edge IPs and investigate the source.",0,"tcp.flags.syn==1 && tcp.flags.ack==0","LIKELY TP"],
["web",/BLOCKED/,1,"WAF blocked sensitive-file request","T1190",1,"Confirm the block, then look for the same source hitting the origin IP directly.",7,'http.request.uri contains ".env"',"VALIDATE"],
["web",/PUT \/uploads/,4,"HTTP PUT created executable file in /uploads","T1505.003",2,"Quarantine the file, disable PUT and review the web root for new scripts.",2,'http.request.method=="PUT"',"LIKELY TP"],
["web",/cmd\.php/,4,"Web shell command request (?c=)","T1505.003",2,"Isolate the host, capture the process tree and hunt for other web shell requests.",2,"http.request.uri contains cmd.php","LIKELY TP"],
["web",/\/\.env 200/,4,".env file served over HTTP","T1552.001",3,"Treat every secret in the file as compromised: rotate and block dotfile access.",2,'http.request.uri contains ".env"',"LIKELY TP"],
["shell",/process: sh/,4,"Web server process spawned a shell","T1059.004",2,"Isolate the host: a web process should never spawn sh, bash or powershell.",3,"http.request.uri contains cmd.php","LIKELY TP"],
["shell",/Outbound/,4,"Outbound connection to rare port 4444 (reverse shell)","T1571",2,"Block egress to the destination, preserve the PCAP and kill the session.",3,"tcp.port==4444","LIKELY TP"],
["secret",/cmd=/,3,"Secrets read from file or process environment","T1552",3,"Identify which secrets were exposed, rotate them and review who read them.",4,"tcp.port==3306 || tcp.port==6379","LIKELY TP"],
["lateral",/:3306 /,3,"Web host logged into MySQL with harvested credentials","T1078",4,"Web-to-DB is normal only if no .env read preceded it: compare to baseline and rotate DB credentials.",5,"tcp.port==3306","LIKELY TP"],
["lateral",/:6379 /,3,"Unauthenticated Redis access from web host","T1213",4,"Require Redis auth, inspect cached sessions and tokens, restrict the source.",5,"tcp.port==6379","LIKELY TP"],
["lateral",/:445 /,3,"SMB share access from web host","T1021.002",4,"Web servers rarely use SMB: review accessed files and enforce SMB signing.",5,"tcp.port==445 || tcp.port==139","LIKELY TP"],
["lateral",/:22 /,3,"New SSH logon from web host","T1021.004",4,"Verify the account and key, then revoke the key and review the session.",8,"tcp.port==22","LIKELY TP"],
["lateral",/:3389 /,3,"New RDP session from web host","T1021.001",4,"Confirm the admin account, enable NLA and MFA, review the session.",8,"tcp.port==3389","LIKELY TP"],
["lateral",/:25 /,4,"SMTP egress / data staging","T1048.003",4,"Block outbound SMTP from servers and inspect what was sent.",9,"tcp.port==25","LIKELY TP"],
["persist",/crontab/,4,"New scheduled task created by web user","T1053.003",4,"Remove the entry and hunt for other persistence (startup scripts, accounts, keys).",6,"","LIKELY TP"],
["remediation",/hardened=true/,0,"Remediation applied: origin locked to edge","",5,"Rerun nmap against the origin to verify the exposure is closed.",0,"","INFO"],
["remediation",/hardened=false/,1,"Remediation reverted: origin exposed again","",5,"Re-apply the remediation and rescan.",0,"","INFO"]],
ESC={3:["Correlated multi-stage activity suspected","Open an incident and pull all events for the source IP."],5:["Active intrusion: foothold and credential theft","Contain the host, rotate secrets and start the incident timeline."],7:["Full kill chain observed: containment required","Isolate affected systems and begin eradication and recovery."]};
function hx(t){return String(t).replace(/&/g,"&amp;").replace(/</g,"&lt;")}
function alertFor(e){const r=RULES.find(r=>r[0]==e.k&&r[1].test(e.msg));if(r)raise(r,e)}
function stageEsc(){const m=ESC[S.done.size];if(m){const c=S.done.size;setTimeout(()=>raise(["inc",0,4,m[0],"",5,m[1],10,"","INCIDENT"],{t:new Date().toISOString().slice(11,19),src:"SIEM",host:"correlation",msg:"stages_observed="+c}),0)}}
function raise(r,e){const a={id:"ALR-"+String(S.al.length+1).padStart(4,"0"),t:e.t,sev:r[2],name:r[3],mitre:r[4],ph:r[5],act:r[6],q:r[7],wf:r[8],tr:r[9],src:e.src,host:e.host,msg:e.msg,ack:0};S.al.unshift(a);toast(a);alr()}
function toast(a){const d=document.createElement("div");d.className="toast s"+a.sev;d.innerHTML="<b>"+SV[a.sev]+"</b> "+a.name+"<div class=d>"+a.id+" | Phase "+a.ph+" | "+a.tr+"</div>";d.onclick=()=>$("atab").click();const c=$("toasts");c.appendChild(d);setTimeout(()=>d.remove(),6500);while(c.children.length>4)c.removeChild(c.children[0])}
function alr(){const n=S.al.filter(a=>!a.ack).length;$("atab").textContent="Alerts ("+n+")";$("hal").textContent="ALERTS "+n;$("hal").className="badge"+(n?" hot":"");
$("alist").innerHTML=S.al.length?S.al.map(a=>"<div class='al s"+a.sev+(a.ack?" ack":"")+"'><div><b>"+SV[a.sev]+"</b> "+a.id+" <span class=d>"+a.t+" | Phase "+a.ph+(a.mitre?" | MITRE "+a.mitre:"")+"</span><span class=tg>"+a.tr+"</span></div><div class=an>"+a.name+"</div><div class='d mono'>"+hx(a.host+" "+a.src+": "+a.msg)+"</div><div class=ac>Analyst action: "+a.act+"</div><button class=chip data-id="+a.id+" data-a=q>Splunk</button> "+(a.wf?"<button class=chip data-id="+a.id+" data-a=w>Packets</button> ":"")+(a.ack?"":"<button class=chip data-id="+a.id+" data-a=k>Acknowledge</button>")+"</div>").join(""):"<div class=d>No alerts yet. Alerts are raised automatically as you work through the phases.</div>"}
$("alist").onclick=e=>{const b=e.target.closest&&e.target.closest("button");if(!b)return;const a=S.al.find(x=>x.id==b.dataset.id);if(!a)return;
if(b.dataset.a=="q"){$("q").value=a.q;$("stabs").children[0].click()}else if(b.dataset.a=="w"){$("wf").value=a.wf;$("stabs").children[1].click();wdraw()}else{a.ack=1;alr()}};
ph(0);prog();ps();draw();alr();out("[boot] darknet-lab circuit established: 3 hops (SIMULATED, no real traffic)","g");out("[boot] SIEM alert automation armed: alerts will appear as you work","g");out("[boot] sandbox network up: attacker "+ATT+" | edge "+EDGE+" | origin "+ORG+" | internal 10.0.0.0/24","g");out("[boot] telemetry sensors online: Splunk (index=lab), Wireshark capture","g");out("SOC Threat Sim Trainer - sandbox only. Type 'help'. Start with: nslookup shop.lab.test","p");
</script></body></html>"""

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = HTML.encode()
        self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--export", action="store_true"); ap.add_argument("--port", type=int, default=5050)
    a = ap.parse_args()
    if a.export:
        open("index.html", "w", encoding="utf-8").write(HTML); print("Wrote index.html")
    else:
        url = f"http://127.0.0.1:{a.port}"; print("Serving", url, "(Ctrl+C to stop)")
        threading.Timer(.8, lambda: webbrowser.open(url)).start()
        http.server.HTTPServer(("127.0.0.1", a.port), H).serve_forever()
