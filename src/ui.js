/**
 * Professional Wireshark-style UI for WARP & PCAP Analyzer v2
 * Dark theme, three-pane packet browser, protocol tree, hex dump,
 * statistics dashboard, AI analysis, and WARP diagnostics views.
 */

export const UI_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WARP & PCAP Analyzer</title>
<style>
/* ── Reset & Base ─────────────────────────────────────────────────────── */
*{margin:0;padding:0;box-sizing:border-box}
:root{
--bg:#0d1117;--bg2:#161b22;--bg3:#1c2128;--bg4:#21262d;
--border:#30363d;--border2:#484f58;
--text:#e6edf3;--text2:#8b949e;--text3:#6e7681;
--orange:#f38020;--orange2:#d66e1a;
--green:#3fb950;--red:#f85149;--yellow:#d29922;--blue:#58a6ff;--purple:#bc8cff;
--cyan:#39d2c0;--pink:#f778ba;
--font:Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
--mono:'JetBrains Mono',Monaco,Menlo,'Ubuntu Mono',monospace;
}
html,body{height:100%;overflow:hidden;font-family:var(--font);background:var(--bg);color:var(--text);font-size:13px}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline}
button{font-family:var(--font);cursor:pointer;border:none;background:none;color:var(--text)}
select,input{font-family:var(--font);color:var(--text);background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:6px 10px;font-size:13px;outline:none}
select:focus,input:focus{border-color:var(--orange)}

/* ── Layout ───────────────────────────────────────────────────────────── */
#app{display:flex;flex-direction:column;height:100vh}
.header{background:var(--bg2);border-bottom:1px solid var(--border);padding:0 16px;display:flex;align-items:center;height:48px;gap:12px;flex-shrink:0}
.header h1{font-size:15px;font-weight:600;white-space:nowrap}
.header h1 span{color:var(--orange);font-weight:700}
.header-actions{margin-left:auto;display:flex;gap:8px;align-items:center}
.btn{padding:6px 14px;border-radius:4px;font-size:12px;font-weight:600;transition:all .15s;display:inline-flex;align-items:center;gap:6px}
.btn-primary{background:var(--orange);color:#fff}.btn-primary:hover{background:var(--orange2)}
.btn-ghost{background:var(--bg3);border:1px solid var(--border);color:var(--text2)}.btn-ghost:hover{border-color:var(--orange);color:var(--text)}
.btn-sm{padding:4px 10px;font-size:11px}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:600}
.badge-healthy{background:#0f7a1c22;color:var(--green);border:1px solid #0f7a1c44}
.badge-degraded{background:#d2992222;color:var(--yellow);border:1px solid #d2992244}
.badge-critical{background:#f8514922;color:var(--red);border:1px solid #f8514944}
.badge-info{background:var(--bg3);color:var(--text2);border:1px solid var(--border)}

/* ── Screens ──────────────────────────────────────────────────────────── */
.screen{display:none;flex:1;overflow:hidden}
.screen.active{display:flex;flex-direction:column}

/* ── Upload Screen ────────────────────────────────────────────────────── */
#upload-screen{align-items:center;justify-content:center;gap:30px;padding:40px}
.upload-card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:50px;max-width:640px;width:100%;text-align:center}
.upload-card h2{font-size:22px;font-weight:600;margin-bottom:6px}
.upload-card p{color:var(--text2);font-size:14px;margin-bottom:24px}
.drop-zone{border:2px dashed var(--border2);border-radius:8px;padding:50px 30px;cursor:pointer;transition:all .2s;margin-bottom:20px}
.drop-zone:hover,.drop-zone.dragover{border-color:var(--orange);background:rgba(243,128,32,.05)}
.drop-zone-icon{font-size:40px;margin-bottom:12px;opacity:.6}
.drop-zone-text{color:var(--text2);font-size:13px;line-height:1.8}
.drop-zone-text strong{color:var(--text);font-weight:600}
.file-list{text-align:left;margin:16px 0;max-height:180px;overflow-y:auto}
.file-item{display:flex;justify-content:space-between;padding:8px 12px;background:var(--bg3);border-radius:4px;margin-bottom:4px;font-size:12px}
.file-item .name{font-weight:500;color:var(--text)}.file-item .size{color:var(--text3)}
.upload-btn{width:100%;padding:12px;border-radius:6px;font-size:14px;font-weight:600;background:var(--orange);color:#fff;transition:all .2s}
.upload-btn:hover:not(:disabled){background:var(--orange2)}
.upload-btn:disabled{opacity:.4;cursor:not-allowed}
.upload-progress{margin-top:16px;display:none}
.upload-progress.active{display:block}
.progress-track{height:4px;background:var(--bg4);border-radius:2px;overflow:hidden;margin:8px 0}
.progress-fill{height:100%;background:var(--orange);border-radius:2px;width:0;transition:width .3s}
.progress-text{font-size:12px;color:var(--text2);text-align:center}
.session-list{max-width:640px;width:100%}
.session-list h3{font-size:14px;font-weight:600;margin-bottom:12px;color:var(--text2)}
.session-item{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;background:var(--bg2);border:1px solid var(--border);border-radius:6px;margin-bottom:6px;cursor:pointer;transition:all .15s}
.session-item:hover{border-color:var(--orange);background:var(--bg3)}
.session-item .info{font-size:12px}.session-item .info .name{font-weight:600;color:var(--text)}.session-item .info .date{color:var(--text3);margin-top:2px}

/* ── Analysis Screen ──────────────────────────────────────────────────── */
#analysis-screen{flex-direction:column}
.tab-bar{display:flex;background:var(--bg2);border-bottom:1px solid var(--border);padding:0 12px;flex-shrink:0;overflow-x:auto}
.tab-btn{padding:10px 16px;font-size:12px;font-weight:500;color:var(--text2);border-bottom:2px solid transparent;transition:all .15s;white-space:nowrap}
.tab-btn:hover{color:var(--text);background:var(--bg3)}
.tab-btn.active{color:var(--orange);border-bottom-color:var(--orange)}
.tab-pane{display:none;flex:1;overflow:hidden}
.tab-pane.active{display:flex;flex-direction:column}

/* ── Packets Tab (Wireshark 3-pane) ───────────────────────────────────── */
.packets-layout{flex:1;display:flex;flex-direction:column;overflow:hidden}
.filter-bar{padding:6px 12px;background:var(--bg2);border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:center;flex-shrink:0}
.filter-bar input{flex:1;background:var(--bg);font-family:var(--mono);font-size:12px}
.filter-bar .filter-count{font-size:11px;color:var(--text3);white-space:nowrap}
.pane-container{flex:1;display:flex;flex-direction:column;overflow:hidden}
.pane-top{flex:2;overflow:hidden;border-bottom:1px solid var(--border);display:flex;flex-direction:column}
.pane-mid{flex:1;overflow:hidden;border-bottom:1px solid var(--border);display:flex;flex-direction:column}
.pane-bot{flex:1;overflow:hidden;display:flex;flex-direction:column}
.pane-label{font-size:11px;font-weight:600;color:var(--text3);padding:4px 12px;background:var(--bg2);border-bottom:1px solid var(--border);text-transform:uppercase;letter-spacing:.5px;flex-shrink:0}

/* Packet list table */
.pkt-table-wrap{flex:1;overflow:auto}
.pkt-table{width:100%;border-collapse:collapse;font-size:12px;font-family:var(--mono)}
.pkt-table th{position:sticky;top:0;background:var(--bg2);padding:5px 8px;text-align:left;font-size:11px;font-weight:600;color:var(--text2);border-bottom:1px solid var(--border);z-index:1;text-transform:uppercase;letter-spacing:.3px;white-space:nowrap;cursor:pointer;user-select:none}
.pkt-table th:hover{color:var(--orange)}
.pkt-table td{padding:3px 8px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;border-bottom:1px solid #1c212855;max-width:500px}
.pkt-table tr{cursor:pointer;transition:background .1s}
.pkt-table tr:hover{background:var(--bg3)}
.pkt-table tr.selected{background:var(--orange)22;outline:1px solid var(--orange)44}
/* Protocol colours */
.pkt-table tr.proto-tcp{color:#a5d6ff}.pkt-table tr.proto-udp{color:#7ee8fa}
.pkt-table tr.proto-dns{color:#79c0ff}.pkt-table tr.proto-tls,.pkt-table tr.proto-https{color:#d2a8ff}
.pkt-table tr.proto-http{color:#7ee787}.pkt-table tr.proto-icmp{color:#ffa198}
.pkt-table tr.proto-arp{color:#ffc680}.pkt-table tr.proto-dhcp{color:#d2a8ff}
.pkt-table tr.proto-ssh{color:#f0883e}.pkt-table tr.proto-warp{color:var(--orange)}
.pkt-table tr.has-warning td:last-child::after{content:" ⚠";color:var(--yellow)}

/* Protocol detail tree */
.detail-tree{flex:1;overflow:auto;padding:6px 0;font-family:var(--mono);font-size:12px;line-height:1.7}
.tree-node{padding:1px 12px;cursor:pointer;display:flex;align-items:flex-start;gap:4px}
.tree-node:hover{background:var(--bg3)}
.tree-node.selected{background:var(--orange)18}
.tree-toggle{width:14px;color:var(--text3);flex-shrink:0;text-align:center;font-size:10px}
.tree-label{color:var(--text2)}.tree-value{color:var(--text)}
.tree-layer{font-weight:600;color:var(--blue)}
.tree-children{display:none}.tree-children.open{display:block}

/* Hex dump */
.hex-wrap{flex:1;overflow:auto;padding:6px 12px;font-family:var(--mono);font-size:12px;line-height:1.7}
.hex-line{display:flex;gap:0}
.hex-offset{color:var(--text3);width:50px;flex-shrink:0;text-align:right;padding-right:10px}
.hex-bytes{flex:1;letter-spacing:.5px;color:var(--text2)}
.hex-ascii{color:var(--green);padding-left:12px;width:160px;flex-shrink:0;letter-spacing:0}
.hex-bytes .hl,.hex-ascii .hl{background:var(--orange)33;color:var(--orange);border-radius:2px}

/* ── Conversations Tab ────────────────────────────────────────────────── */
.conv-table{width:100%;border-collapse:collapse;font-size:12px;font-family:var(--mono)}
.conv-table th{position:sticky;top:0;background:var(--bg2);padding:6px 10px;text-align:left;font-size:11px;font-weight:600;color:var(--text2);border-bottom:1px solid var(--border);text-transform:uppercase;letter-spacing:.3px}
.conv-table td{padding:5px 10px;border-bottom:1px solid #1c212855}
.conv-table tr:hover{background:var(--bg3)}
.conv-bar{height:4px;border-radius:2px;background:var(--bg4);overflow:hidden;margin-top:3px}
.conv-bar-fill{height:100%;border-radius:2px;background:var(--blue)}

/* ── Stats Tab ────────────────────────────────────────────────────────── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;padding:16px}
.stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px}
.stat-card h4{font-size:12px;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:.5px;margin-bottom:12px}
.stat-row{display:flex;justify-content:space-between;padding:4px 0;font-size:12px;border-bottom:1px solid var(--border)}
.stat-row:last-child{border:none}
.stat-row .label{color:var(--text2)}.stat-row .value{font-weight:600;font-family:var(--mono)}
.stat-bar{height:6px;background:var(--bg4);border-radius:3px;margin-top:3px;overflow:hidden}
.stat-bar-fill{height:100%;border-radius:3px}
.stat-big{font-size:28px;font-weight:700;color:var(--text);margin:4px 0}
.stat-label{font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.5px}

/* ── AI Analysis Tab ──────────────────────────────────────────────────── */
.ai-wrap{flex:1;overflow:auto;padding:20px}
.ai-section{margin-bottom:24px}
.ai-section h3{font-size:15px;font-weight:600;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--border)}
.issue-card{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:10px;border-left:3px solid var(--blue)}
.issue-card.critical{border-left-color:var(--red)}.issue-card.warning{border-left-color:var(--yellow)}
.issue-card .title{font-weight:600;margin-bottom:6px;font-size:14px}
.issue-card .desc{color:var(--text2);margin-bottom:8px;line-height:1.5}
.issue-card .remed{background:var(--bg3);padding:10px;border-radius:4px;font-size:12px;line-height:1.6}
.issue-card .remed strong{color:var(--orange)}
.issue-card .remed ol{margin:6px 0 0 18px}
.issue-card .remed li{margin-bottom:4px}
.evidence-toggle{margin-top:8px}
.evidence-toggle summary{cursor:pointer;font-size:12px;color:var(--orange);font-weight:500}
.evidence-toggle summary:hover{color:var(--orange2)}
.evidence-block{margin-top:8px;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:8px 10px;font-family:var(--mono);font-size:11px;line-height:1.6;color:var(--text2);max-height:200px;overflow:auto;border-left:2px solid var(--orange)}
.evidence-header{color:var(--orange);font-weight:600;font-size:10px;margin-bottom:4px}
.timeline-list{position:relative;padding-left:24px}
.timeline-list::before{content:'';position:absolute;left:8px;top:0;bottom:0;width:2px;background:var(--border)}
.tl-item{position:relative;margin-bottom:16px;padding-left:16px}
.tl-dot{position:absolute;left:-20px;top:4px;width:10px;height:10px;border-radius:50%;border:2px solid var(--border);background:var(--bg)}
.tl-item.critical .tl-dot{border-color:var(--red);background:var(--red)33}
.tl-item.warning .tl-dot{border-color:var(--yellow);background:var(--yellow)33}
.tl-item.success .tl-dot{border-color:var(--green);background:var(--green)33}
.tl-time{font-size:11px;color:var(--text3);font-family:var(--mono)}
.tl-event{font-size:13px;font-weight:500;margin:2px 0}
.tl-detail{font-size:12px;color:var(--text2)}

/* ── Status bar ───────────────────────────────────────────────────────── */
.status-bar{background:var(--bg2);border-top:1px solid var(--border);padding:4px 16px;font-size:11px;color:var(--text3);display:flex;gap:16px;flex-shrink:0}
.status-bar span{display:inline-flex;align-items:center;gap:4px}

/* ── Utility ──────────────────────────────────────────────────────────── */
.hidden{display:none!important}
.scroll-y{overflow-y:auto}
@keyframes spin{to{transform:rotate(360deg)}}
.spinner{width:20px;height:20px;border:2px solid var(--border);border-top-color:var(--orange);border-radius:50%;animation:spin .6s linear infinite;display:inline-block}
.empty-state{flex:1;display:flex;align-items:center;justify-content:center;color:var(--text3);font-size:13px}
</style>
</head>
<body>
<div id="app">
<!-- Header -->
<div class="header">
<h1><span>WARP</span> & PCAP Analyzer</h1>
<span class="badge badge-info" id="versionBadge">v2.0</span>
<div class="header-actions">
<button class="btn btn-ghost btn-sm" id="btnSessions" title="View saved sessions">Sessions</button>
<select id="exportSelect" class="hidden" style="font-size:11px;padding:4px 8px">
<option value="">Export...</option>
<option value="json">JSON</option>
<option value="csv">CSV (Packets)</option>
<option value="har">HAR</option>
<option value="html">HTML Report</option>
</select>
<button class="btn btn-ghost btn-sm hidden" id="btnBack">New Analysis</button>
</div>
</div>

<!-- Upload Screen -->
<div class="screen active" id="upload-screen">
<div class="upload-card">
<h2>Network Capture Analyzer</h2>
<p>Upload WARP diagnostic bundles or PCAP files for AI-powered analysis</p>
<div class="drop-zone" id="dropZone">
<div class="drop-zone-icon">&#x1F4C1;</div>
<div class="drop-zone-text">
<strong>Drop files here</strong> or click to browse<br>
Supports: .zip (warp-diag) &middot; .pcap &middot; .pcapng &middot; .log &middot; .txt &middot; .json
</div>
</div>
<input type="file" id="fileInput" multiple accept=".zip,.pcap,.pcapng,.log,.txt,.json,.xml,.plist" class="hidden">
<div class="file-list hidden" id="fileList"></div>
<button class="upload-btn" id="analyzeBtn" disabled>Analyze Files</button>
<div class="upload-progress" id="uploadProgress">
<div class="progress-track"><div class="progress-fill" id="progressFill"></div></div>
<div class="progress-text" id="progressText">Preparing...</div>
</div>
</div>
<div class="session-list" id="sessionList"></div>
</div>

<!-- Analysis Screen -->
<div class="screen" id="analysis-screen">
<div class="tab-bar" id="tabBar">
<button class="tab-btn active" data-tab="packets">Packets</button>
<button class="tab-btn" data-tab="conversations">Conversations</button>
<button class="tab-btn" data-tab="stats">Statistics</button>
<button class="tab-btn" data-tab="ai">AI Analysis</button>
<button class="tab-btn" data-tab="timeline">Timeline</button>
<button class="tab-btn hidden" data-tab="warp">WARP Diagnostics</button>
</div>

<!-- Packets Tab -->
<div class="tab-pane active" id="tab-packets">
<div class="packets-layout">
<div class="filter-bar">
<input type="text" id="filterInput" placeholder="Filter: tcp, dns, ip.addr==192.168.1.1, port 443, tls.sni contains example.com">
<button class="btn btn-sm btn-primary" id="filterApply">Apply</button>
<button class="btn btn-sm btn-ghost" id="filterClear">Clear</button>
<span class="filter-count" id="filterCount"></span>
</div>
<div class="pane-container">
<div class="pane-top">
<div class="pkt-table-wrap" id="pktTableWrap">
<table class="pkt-table"><thead><tr>
<th style="width:55px">No.</th>
<th style="width:100px">Time</th>
<th style="width:140px">Source</th>
<th style="width:140px">Destination</th>
<th style="width:80px">Protocol</th>
<th style="width:55px">Length</th>
<th>Info</th>
</tr></thead><tbody id="pktBody"></tbody></table>
</div>
</div>
<div class="pane-mid">
<div class="pane-label">Packet Details</div>
<div class="detail-tree scroll-y" id="detailTree"><div class="empty-state">Select a packet to view details</div></div>
</div>
<div class="pane-bot">
<div class="pane-label">Hex Dump</div>
<div class="hex-wrap" id="hexDump"><div class="empty-state">Select a packet to view hex dump</div></div>
</div>
</div>
</div>
</div>

<!-- Conversations Tab -->
<div class="tab-pane" id="tab-conversations">
<div class="scroll-y" style="flex:1;padding:0">
<table class="conv-table"><thead><tr>
<th>Address A</th><th>Address B</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Duration</th><th>State</th>
</tr></thead><tbody id="convBody"></tbody></table>
</div>
</div>

<!-- Stats Tab -->
<div class="tab-pane" id="tab-stats">
<div class="scroll-y" style="flex:1" id="statsContent"></div>
</div>

<!-- AI Analysis Tab -->
<div class="tab-pane" id="tab-ai">
<div class="ai-wrap" id="aiContent"><div class="empty-state">AI analysis results will appear here</div></div>
</div>

<!-- Timeline Tab -->
<div class="tab-pane" id="tab-timeline">
<div class="ai-wrap" id="timelineContent"><div class="empty-state">Timeline will appear after analysis</div></div>
</div>

<!-- WARP Diagnostics Tab -->
<div class="tab-pane" id="tab-warp">
<div class="ai-wrap" id="warpContent"><div class="empty-state">WARP diagnostics data not available</div></div>
</div>
</div>

<!-- Status Bar -->
<div class="status-bar">
<span id="statusPackets">No capture loaded</span>
<span id="statusFile"></span>
<span id="statusModel"></span>
<span id="statusSession" style="margin-left:auto"></span>
</div>
</div>

<script>
(function(){
'use strict';
const API=window.location.origin;
let state={packets:[],flows:{},stats:{},ai:null,sessionId:null,selectedPkt:null,filteredPackets:null,allPackets:[]};

// ── DOM refs ────────────────────────────────────────────────────────
const $=id=>document.getElementById(id);
const dropZone=$('dropZone'),fileInput=$('fileInput'),fileListEl=$('fileList'),
analyzeBtn=$('analyzeBtn'),progressEl=$('uploadProgress'),progressFill=$('progressFill'),
progressText=$('progressText'),pktBody=$('pktBody'),detailTree=$('detailTree'),
hexDump=$('hexDump'),filterInput=$('filterInput'),filterCount=$('filterCount'),
convBody=$('convBody'),statsContent=$('statsContent'),aiContent=$('aiContent'),
timelineContent=$('timelineContent'),warpContent=$('warpContent'),
exportSelect=$('exportSelect'),sessionList=$('sessionList');

let files=[];

// ── Upload handling ─────────────────────────────────────────────────
dropZone.onclick=()=>fileInput.click();
fileInput.onchange=e=>{files=Array.from(e.target.files);showFiles()};
dropZone.ondragover=e=>{e.preventDefault();dropZone.classList.add('dragover')};
dropZone.ondragleave=()=>dropZone.classList.remove('dragover');
dropZone.ondrop=e=>{e.preventDefault();dropZone.classList.remove('dragover');files=Array.from(e.dataTransfer.files);showFiles()};

function showFiles(){
if(!files.length){fileListEl.classList.add('hidden');analyzeBtn.disabled=true;return}
fileListEl.classList.remove('hidden');
fileListEl.innerHTML=files.map(f=>'<div class="file-item"><span class="name">'+esc(f.name)+'</span><span class="size">'+fmtBytes(f.size)+'</span></div>').join('');
analyzeBtn.disabled=false;
}

analyzeBtn.onclick=async()=>{
if(!files.length)return;
analyzeBtn.disabled=true;
progressEl.classList.add('active');
setProgress(10,'Preparing upload...');
try{
const fd=new FormData();
files.forEach((f,i)=>fd.append('file'+i,f));
setProgress(25,'Uploading...');
const resp=await fetch(API+'/api/analyze',{method:'POST',body:fd});
setProgress(60,'Processing...');
if(!resp.ok){const e=await resp.json();throw new Error(e.error||'Analysis failed')}
setProgress(85,'Rendering...');
const data=await resp.json();
setProgress(100,'Complete');
await new Promise(r=>setTimeout(r,400));
loadResults(data);
}catch(e){
progressText.textContent='Error: '+e.message;
progressFill.style.background='var(--red)';
setTimeout(()=>{progressEl.classList.remove('active');progressFill.style.background='';analyzeBtn.disabled=false},3000);
}
};

function setProgress(pct,msg){progressFill.style.width=pct+'%';progressText.textContent=msg}

// ── Load results ────────────────────────────────────────────────────
function loadResults(data){
state.sessionId=data.sessionId;
state.ai=data.ai;

if(data.pcap){
state.allPackets=data.pcap.packets||[];
state.packets=state.allPackets;
state.filteredPackets=null;
state.flows=data.pcap.flows||{};
state.stats=data.pcap.stats||{};
}else{
state.allPackets=[];state.packets=[];state.flows={};state.stats={};
}

// Switch to analysis screen
$('upload-screen').classList.remove('active');
$('analysis-screen').classList.add('active');
$('btnBack').classList.remove('hidden');
exportSelect.classList.remove('hidden');

// Show/hide WARP tab
const warpTab=document.querySelector('[data-tab="warp"]');
if(data.warpFiles&&data.warpFiles.length>0){warpTab.classList.remove('hidden')}

renderPacketList();
renderConversations();
renderStats();
renderAI();
renderTimeline();
if(data.warpFiles)renderWarp(data);
updateStatusBar(data);
}

// ── Packet list rendering ───────────────────────────────────────────
function renderPacketList(){
const pkts=state.filteredPackets||state.packets;
pktBody.innerHTML='';
const frag=document.createDocumentFragment();
const baseTime=pkts.length>0?pkts[0].timestamp:0;

for(let i=0;i<pkts.length;i++){
const p=pkts[i];
const tr=document.createElement('tr');
const proto=(p.protocol||'').toLowerCase().replace(/[^a-z]/g,'');
tr.className='proto-'+proto+(p.warnings&&p.warnings.length?' has-warning':'');
tr.dataset.idx=i;

const src=p.layers?.ipv4?.src||p.layers?.ipv6?.src||p.layers?.arp?.senderIP||'';
const dst=p.layers?.ipv4?.dst||p.layers?.ipv6?.dst||p.layers?.arp?.targetIP||'';
const relTime=(p.timestamp-baseTime).toFixed(6);

tr.innerHTML='<td>'+p.number+'</td><td>'+relTime+'</td><td>'+esc(src)+'</td><td>'+esc(dst)+
'</td><td>'+esc(p.protocol)+'</td><td>'+(p.capturedLength||0)+'</td><td>'+esc(p.info||'')+'</td>';
tr.onclick=()=>selectPacket(i);
frag.appendChild(tr);
}
pktBody.appendChild(frag);

filterCount.textContent=state.filteredPackets?
(pkts.length+' of '+state.allPackets.length+' packets'):(pkts.length+' packets');
$('statusPackets').textContent='Packets: '+(state.filteredPackets?pkts.length+'/'+state.allPackets.length:pkts.length);
}

// ── Packet selection ────────────────────────────────────────────────
function selectPacket(idx){
state.selectedPkt=idx;
const pkts=state.filteredPackets||state.packets;
const p=pkts[idx];
if(!p)return;

// Highlight row
pktBody.querySelectorAll('tr.selected').forEach(r=>r.classList.remove('selected'));
const row=pktBody.querySelector('tr[data-idx="'+idx+'"]');
if(row)row.classList.add('selected');

renderDetailTree(p);
renderHexDump(p);
}

// ── Protocol detail tree ────────────────────────────────────────────
function renderDetailTree(pkt){
const layers=pkt.layers||{};
let html='';

// Frame
if(layers.frame){
html+=treeLayer('Frame '+pkt.number+': '+pkt.capturedLength+' bytes on wire',[
['Number',pkt.number],['Capture Length',pkt.capturedLength+' bytes'],
['Original Length',pkt.originalLength+' bytes'],
['Protocols',layers.frame.protocols||''],
...pkt.warnings.map(w=>['Warning',w])
]);
}
// Ethernet
if(layers.ethernet){
const e=layers.ethernet;
html+=treeLayer('Ethernet II, Src: '+e.src+', Dst: '+e.dst,[
['Destination',e.dst],['Source',e.src],
['Type',e.typeName+' (0x'+e.type.toString(16).padStart(4,'0')+')'],
...(e.vlanId!==null&&e.vlanId!==undefined?[['VLAN ID',e.vlanId]]:[])
]);
}
// IPv4
if(layers.ipv4){
const ip=layers.ipv4;
html+=treeLayer('Internet Protocol Version 4, Src: '+ip.src+', Dst: '+ip.dst,[
['Version',4],['Header Length',ip.headerLength+' bytes'],
['DSCP',ip.dscp],['ECN',ip.ecn],['Total Length',ip.totalLength],
['Identification','0x'+ip.identification.toString(16)],
['Flags','DF='+ip.flags.dontFragment+' MF='+ip.flags.moreFragments],
['Fragment Offset',ip.fragmentOffset],
['Time to Live',ip.ttl],['Protocol',ip.protocolName+' ('+ip.protocol+')'],
['Header Checksum',ip.headerChecksum],
['Source Address',ip.src],['Destination Address',ip.dst],
]);
}
// IPv6
if(layers.ipv6){
const ip=layers.ipv6;
html+=treeLayer('Internet Protocol Version 6, Src: '+ip.src+', Dst: '+ip.dst,[
['Version',6],['Traffic Class',ip.trafficClass],['Flow Label','0x'+ip.flowLabel.toString(16)],
['Payload Length',ip.payloadLength],['Next Header',ip.nextHeaderName+' ('+ip.nextHeader+')'],
['Hop Limit',ip.hopLimit],['Source',ip.src],['Destination',ip.dst],
]);
}
// ARP
if(layers.arp){
const a=layers.arp;
html+=treeLayer('Address Resolution Protocol ('+a.opcodeName+')',[
['Opcode',a.opcodeName+' ('+a.opcode+')'],
['Sender MAC',a.senderMac],['Sender IP',a.senderIP],
['Target MAC',a.targetMac],['Target IP',a.targetIP],
]);
}
// TCP
if(layers.tcp){
const t=layers.tcp;
html+=treeLayer('Transmission Control Protocol, Src Port: '+t.srcPort+', Dst Port: '+t.dstPort,[
['Source Port',t.srcPort],['Destination Port',t.dstPort],
['Sequence Number',t.seqNum],['Acknowledgment Number',t.ackNum],
['Header Length',t.headerLength+' bytes'],
['Flags','['+t.flags.join(', ')+'] (0x'+t.flagsByte.toString(16).padStart(2,'0')+')'],
['Window Size',t.windowSize],['Checksum',t.checksum],
['Payload Length',t.payloadLength+' bytes'],
...(t.options||[]).map(o=>['Option: '+o.kind,JSON.stringify(o.value!==undefined?o.value:o)])
]);
}
// UDP
if(layers.udp){
const u=layers.udp;
html+=treeLayer('User Datagram Protocol, Src Port: '+u.srcPort+', Dst Port: '+u.dstPort,[
['Source Port',u.srcPort],['Destination Port',u.dstPort],
['Length',u.length],['Checksum',u.checksum],
]);
}
// ICMP
if(layers.icmp){
const ic=layers.icmp;
html+=treeLayer('Internet Control Message Protocol',[
['Type',ic.typeName+' ('+ic.type+')'],['Code',ic.code+(ic.codeDescription?' ('+ic.codeDescription+')':'')],
['Checksum',ic.checksum],
...(ic.identifier!==undefined?[['Identifier','0x'+ic.identifier.toString(16)],['Sequence',ic.sequenceNumber]]:[])
]);
}
// ICMPv6
if(layers.icmpv6){
const ic=layers.icmpv6;
html+=treeLayer('ICMPv6',[['Type',ic.typeName+' ('+ic.type+')'],['Code',ic.code],['Checksum',ic.checksum]]);
}
// DNS
if(layers.dns){
const d=layers.dns;
const items=[
[d.isResponse?'Response':'Query','Transaction ID '+d.transactionId],
['Opcode',d.opcode],['Response Code',d.rcodeName],
['Questions',d.qdCount],['Answers',d.anCount],
['Flags','AA='+d.flags.authoritative+' TC='+d.flags.truncated+' RD='+d.flags.recursionDesired+' RA='+d.flags.recursionAvailable],
];
(d.questions||[]).forEach((q,i)=>items.push(['Question '+(i+1),q.typeName+' '+q.name]));
(d.answers||[]).forEach((a,i)=>items.push(['Answer '+(i+1),a.typeName+' '+a.name+' → '+a.rdata+' (TTL '+a.ttl+')']));
html+=treeLayer('Domain Name System ('+d.transactionId+')',items);
}
// TLS
if(layers.tls){
const t=layers.tls;
const items=[
['Content Type',t.contentTypeName+' ('+t.contentType+')'],
['Version',t.versionName],['Length',t.recordLength],
];
if(t.handshakeTypeName)items.push(['Handshake Type',t.handshakeTypeName]);
if(t.sni)items.push(['Server Name (SNI)',t.sni]);
if(t.clientVersion)items.push(['Client Version',t.clientVersion]);
if(t.serverVersion)items.push(['Server Version',t.serverVersion]);
if(t.cipherSuitesCount)items.push(['Cipher Suites',t.cipherSuitesCount+' suites']);
if(t.alpn)items.push(['ALPN',t.alpn.join(', ')]);
html+=treeLayer('Transport Layer Security',items);
}
// HTTP
if(layers.http){
const h=layers.http;
const items=[['First Line',h.firstLine]];
Object.entries(h.headers||{}).forEach(([k,v])=>items.push([k,v]));
if(h.cfRay)items.push(['CF-RAY',h.cfRay]);
html+=treeLayer('Hypertext Transfer Protocol',items);
}
// SSH
if(layers.ssh){
html+=treeLayer('SSH Protocol',[['Banner',layers.ssh.banner]]);
}
// DHCP
if(layers.dhcp){
const d=layers.dhcp;
html+=treeLayer('Dynamic Host Configuration Protocol',[
['Operation',d.op],['Transaction ID',d.transactionId],
['Client MAC',d.clientMAC],['Client IP',d.clientIP],
['Your IP',d.yourIP],['Server IP',d.serverIP],
...(d.messageType?[['Message Type',d.messageType]]:[]),
...(d.dhcpServer?[['DHCP Server',d.dhcpServer]]:[]),
...(d.leaseTime?[['Lease Time',d.leaseTime+'s']]:[]),
]);
}

detailTree.innerHTML=html||'<div class="empty-state">No decodable layers</div>';

// Toggle handlers
detailTree.querySelectorAll('.tree-node[data-layer]').forEach(node=>{
node.onclick=()=>{
const ch=node.nextElementSibling;
if(ch&&ch.classList.contains('tree-children')){
ch.classList.toggle('open');
const tog=node.querySelector('.tree-toggle');
if(tog)tog.textContent=ch.classList.contains('open')?'\\u25BE':'\\u25B8';
}
};
});
// Auto-expand all
detailTree.querySelectorAll('.tree-children').forEach(c=>c.classList.add('open'));
detailTree.querySelectorAll('.tree-toggle').forEach(t=>t.textContent='\\u25BE');
}

function treeLayer(title,fields){
let html='<div class="tree-node" data-layer="1"><span class="tree-toggle">\\u25B8</span><span class="tree-layer">'+esc(title)+'</span></div>';
html+='<div class="tree-children">';
for(const [k,v] of fields){
html+='<div class="tree-node" style="padding-left:28px"><span class="tree-label">'+esc(k)+': </span><span class="tree-value">'+esc(String(v))+'</span></div>';
}
html+='</div>';
return html;
}

// ── Hex dump ────────────────────────────────────────────────────────
function renderHexDump(pkt){
const raw=pkt.rawBytes||[];
if(!raw.length){hexDump.innerHTML='<div class="empty-state">No hex data</div>';return}
let html='';
for(let i=0;i<raw.length;i+=16){
const offset=i.toString(16).padStart(4,'0');
const hexParts=[];
for(let j=0;j<16;j++){
if(i+j<raw.length)hexParts.push(raw[i+j].toString(16).padStart(2,'0'));
else hexParts.push('  ');
}
const hexStr=hexParts.slice(0,8).join(' ')+'  '+hexParts.slice(8).join(' ');
let ascii='';
for(let j=0;j<16&&i+j<raw.length;j++){
const b=raw[i+j];ascii+=(b>=32&&b<127)?String.fromCharCode(b):'.';
}
html+='<div class="hex-line"><span class="hex-offset">'+offset+'</span><span class="hex-bytes">'+esc(hexStr)+'</span><span class="hex-ascii">'+esc(ascii)+'</span></div>';
}
hexDump.innerHTML=html;
}

// ── Filter ──────────────────────────────────────────────────────────
$('filterApply').onclick=applyFilter;
$('filterClear').onclick=()=>{filterInput.value='';state.filteredPackets=null;state.selectedPkt=null;renderPacketList();detailTree.innerHTML='<div class="empty-state">Select a packet</div>';hexDump.innerHTML='<div class="empty-state">Select a packet</div>'};
filterInput.onkeydown=e=>{if(e.key==='Enter')applyFilter()};

function applyFilter(){
const expr=filterInput.value.trim().toLowerCase();
if(!expr){state.filteredPackets=null;renderPacketList();return}
state.filteredPackets=state.allPackets.filter(p=>{
const proto=p.protocol.toLowerCase();
const info=(p.info||'').toLowerCase();
const src=(p.layers?.ipv4?.src||p.layers?.ipv6?.src||'').toLowerCase();
const dst=(p.layers?.ipv4?.dst||p.layers?.ipv6?.dst||'').toLowerCase();
const srcPort=String(p.layers?.tcp?.srcPort||p.layers?.udp?.srcPort||'');
const dstPort=String(p.layers?.tcp?.dstPort||p.layers?.udp?.dstPort||'');
const sni=(p.layers?.tls?.sni||'').toLowerCase();
const dnsName=(p.layers?.dns?.questions?.[0]?.name||'').toLowerCase();
const flags=(p.layers?.tcp?.flags||[]).join(',').toLowerCase();
const text=proto+' '+info+' '+src+' '+dst+' '+srcPort+' '+dstPort+' '+sni+' '+dnsName+' '+flags;

// Simple filter syntax
if(expr.includes('==')){
const[field,val]=expr.split('==').map(s=>s.trim());
if(field==='ip.addr'||field==='ip.src')return src===val||dst===val;
if(field==='tcp.port'||field==='port')return srcPort===val||dstPort===val;
if(field==='udp.port')return srcPort===val||dstPort===val;
if(field==='ip.dst')return dst===val;
}
if(expr.startsWith('tcp.port')||expr.startsWith('port')){
const port=expr.replace(/[^0-9]/g,'');
if(port)return srcPort===port||dstPort===port;
}
if(expr.includes('contains')){
const val=expr.split('contains')[1].trim().replace(/['"]/g,'');
return text.includes(val);
}
// Simple keyword match
return text.includes(expr);
});
state.packets=state.filteredPackets;
renderPacketList();
}

// ── Conversations ───────────────────────────────────────────────────
function renderConversations(){
const flows=Object.values(state.flows);
if(!flows.length){convBody.innerHTML='<tr><td colspan="7" style="text-align:center;color:var(--text3);padding:30px">No conversations</td></tr>';return}
flows.sort((a,b)=>(b.bytesAtoB+b.bytesBtoA)-(a.bytesAtoB+a.bytesBtoA));
const maxBytes=Math.max(...flows.map(f=>f.bytesAtoB+f.bytesBtoA),1);
convBody.innerHTML=flows.map(f=>{
const total=f.bytesAtoB+f.bytesBtoA;
const dur=f.endTime-f.startTime;
return '<tr><td>'+esc(f.srcIP)+(f.srcPort?':'+f.srcPort:'')+'</td><td>'+esc(f.dstIP)+(f.dstPort?':'+f.dstPort:'')+
'</td><td>'+f.protocol+(f.appProtocol?'/'+f.appProtocol:'')+'</td><td>'+(f.packetsAtoB+f.packetsBtoA)+
'</td><td>'+fmtBytes(total)+'<div class="conv-bar"><div class="conv-bar-fill" style="width:'+((total/maxBytes)*100).toFixed(1)+'%"></div></div></td><td>'+dur.toFixed(3)+'s</td><td>'+(f.tcpState||'-')+(f.warnings.length?' <span style="color:var(--yellow)">'+f.warnings.join(', ')+'</span>':'')+'</td></tr>';
}).join('');
}

// ── Statistics ───────────────────────────────────────────────────────
function renderStats(){
const s=state.stats;
if(!s||!s.totalPackets){statsContent.innerHTML='<div class="empty-state">No statistics available</div>';return}
const maxProto=Math.max(...Object.values(s.protocols||{}),1);
const colors=['var(--blue)','var(--green)','var(--orange)','var(--purple)','var(--cyan)','var(--pink)','var(--yellow)','var(--red)'];

let html='<div class="stats-grid">';
// Overview cards
html+='<div class="stat-card"><div class="stat-label">Total Packets</div><div class="stat-big">'+(s.totalPackets||0).toLocaleString()+'</div></div>';
html+='<div class="stat-card"><div class="stat-label">Total Bytes</div><div class="stat-big">'+fmtBytes(s.totalBytes||0)+'</div></div>';
html+='<div class="stat-card"><div class="stat-label">Duration</div><div class="stat-big">'+(s.duration||0).toFixed(3)+'s</div></div>';
html+='<div class="stat-card"><div class="stat-label">Avg Packet Size</div><div class="stat-big">'+(s.avgPacketSize||0)+' B</div></div>';

// Protocol distribution
html+='<div class="stat-card" style="grid-column:span 2"><h4>Protocol Distribution</h4>';
Object.entries(s.protocols||{}).sort((a,b)=>b[1]-a[1]).forEach(([p,c],i)=>{
const pct=((c/s.totalPackets)*100).toFixed(1);
html+='<div class="stat-row"><span class="label">'+esc(p)+'</span><span class="value">'+c+' ('+pct+'%)</span></div>';
html+='<div class="stat-bar"><div class="stat-bar-fill" style="width:'+pct+'%;background:'+colors[i%colors.length]+'"></div></div>';
});
html+='</div>';

// Top talkers
if(s.topTalkers){
html+='<div class="stat-card"><h4>Top Talkers</h4>';
const maxTalk=Math.max(...Object.values(s.topTalkers),1);
Object.entries(s.topTalkers).slice(0,10).forEach(([ip,bytes])=>{
html+='<div class="stat-row"><span class="label" style="font-family:var(--mono)">'+esc(ip)+'</span><span class="value">'+fmtBytes(bytes)+'</span></div>';
html+='<div class="stat-bar"><div class="stat-bar-fill" style="width:'+((bytes/maxTalk)*100).toFixed(1)+'%;background:var(--cyan)"></div></div>';
});
html+='</div>';
}

// Port distribution
if(s.portDistribution){
html+='<div class="stat-card"><h4>Port Distribution</h4>';
Object.entries(s.portDistribution).sort((a,b)=>b[1]-a[1]).slice(0,10).forEach(([port,c])=>{
html+='<div class="stat-row"><span class="label">'+esc(port)+'</span><span class="value">'+c+'</span></div>';
});
html+='</div>';
}

// Packet sizes
if(s.packetSizeDistribution){
html+='<div class="stat-card"><h4>Packet Size Distribution</h4>';
Object.entries(s.packetSizeDistribution).forEach(([range,c])=>{
html+='<div class="stat-row"><span class="label">'+range+' bytes</span><span class="value">'+c+'</span></div>';
});
html+='</div>';
}

// DNS queries
if(s.dnsQueries&&s.dnsQueries.length){
html+='<div class="stat-card" style="grid-column:span 2"><h4>DNS Queries ('+s.dnsQueries.length+')</h4>';
s.dnsQueries.slice(0,20).forEach(q=>{
html+='<div class="stat-row"><span class="label" style="font-family:var(--mono)">'+esc(q.query)+'</span><span class="value">'+q.type+(q.isResponse?' \\u2192 '+(q.answers.join(', ')||q.rcode):' ?')+'</span></div>';
});
html+='</div>';
}

// TLS
if(s.tlsConnections&&s.tlsConnections.length){
html+='<div class="stat-card"><h4>TLS Connections ('+s.tlsConnections.length+')</h4>';
s.tlsConnections.slice(0,15).forEach(t=>{
html+='<div class="stat-row"><span class="label" style="font-family:var(--mono)">'+esc(t.sni)+'</span><span class="value">'+esc(t.version)+'</span></div>';
});
html+='</div>';
}

// Warnings
if(s.warningsSummary&&Object.keys(s.warningsSummary).length){
html+='<div class="stat-card"><h4>Warnings</h4>';
Object.entries(s.warningsSummary).sort((a,b)=>b[1]-a[1]).forEach(([w,c])=>{
html+='<div class="stat-row"><span class="label" style="color:var(--yellow)">'+esc(w)+'</span><span class="value">'+c+'</span></div>';
});
html+='</div>';
}

html+='</div>';
statsContent.innerHTML=html;
}

// ── AI Analysis ─────────────────────────────────────────────────────
function renderAI(){
if(!state.ai){aiContent.innerHTML='<div class="empty-state">No AI analysis available</div>';return}
const pcapAI=state.ai.pcap?.analysis||state.ai.pcap?.fallback;
const warpAI=state.ai.warp?.analysis||state.ai.warp?.fallback;
const combined=state.ai.combined||{};

let html='';

// Health banner
const health=combined.health_status||pcapAI?.health_status||warpAI?.health_status||'Unknown';
html+='<div style="margin-bottom:20px"><span class="badge badge-'+health.toLowerCase()+'">'+esc(health)+'</span>';
if(combined.summary)html+='<p style="margin-top:8px;color:var(--text2)">'+esc(combined.summary)+'</p>';
if(combined.models_used)html+='<p style="margin-top:4px;font-size:11px;color:var(--text3)">Models: '+combined.models_used.join(', ')+'</p>';
html+='</div>';

// PCAP Analysis
if(pcapAI){
html+='<div class="ai-section"><h3>PCAP Analysis</h3>';
if(pcapAI.summary)html+='<p style="margin-bottom:12px;color:var(--text2)">'+esc(pcapAI.summary)+'</p>';

// Security assessment
if(pcapAI.security_assessment){
const sa=pcapAI.security_assessment;
html+='<div style="margin-bottom:12px"><strong>Security Risk: </strong><span class="badge badge-'+(sa.risk_level==='Critical'||sa.risk_level==='High'?'critical':sa.risk_level==='Medium'?'degraded':'healthy')+'">'+esc(sa.risk_level||'Unknown')+'</span></div>';
}

// Issues
if(pcapAI.issues&&pcapAI.issues.length){
pcapAI.issues.forEach(i=>{html+=renderIssue(i)});
}

// Recommendations
if(pcapAI.recommendations&&pcapAI.recommendations.length){
html+='<div style="margin-top:16px"><strong>Recommendations:</strong><ul style="margin:8px 0 0 20px;color:var(--text2)">';
pcapAI.recommendations.forEach(r=>{html+='<li style="margin-bottom:4px">'+esc(r)+'</li>'});
html+='</ul></div>';
}
html+='</div>';
}

// WARP Analysis
if(warpAI){
html+='<div class="ai-section"><h3>WARP Diagnostics Analysis</h3>';
if(warpAI.summary)html+='<p style="margin-bottom:12px;color:var(--text2)">'+esc(warpAI.summary)+'</p>';
if(warpAI.issues&&warpAI.issues.length){
warpAI.issues.forEach(i=>{html+=renderIssue(i)});
}
if(warpAI.recommendations&&warpAI.recommendations.length){
html+='<div style="margin-top:16px"><strong>Recommendations:</strong><ul style="margin:8px 0 0 20px;color:var(--text2)">';
warpAI.recommendations.forEach(r=>{html+='<li style="margin-bottom:4px">'+esc(r)+'</li>'});
html+='</ul></div>';
}
html+='</div>';
}

if(!html)html='<div class="empty-state">AI analysis not available</div>';
aiContent.innerHTML=html;
}

function renderIssue(i){
let html='<div class="issue-card '+(i.severity||'').toLowerCase()+'">';
html+='<div class="title">['+(i.severity||'Info')+'] '+esc(i.title||'')+'</div>';
html+='<div class="desc">'+esc(i.description||'')+'</div>';
if(i.root_cause)html+='<p style="margin-bottom:8px;font-size:12px"><strong>Root Cause:</strong> '+esc(i.root_cause)+'</p>';
if(i.remediation){
html+='<div class="remed"><strong>Remediation:</strong>'+formatRemed(i.remediation)+'</div>';
}
if(i.log_entries&&i.log_entries.length){
html+='<details class="evidence-toggle"><summary>View Evidence ('+i.log_entries.length+' entries)</summary>';
i.log_entries.forEach(e=>{
html+='<div class="evidence-block"><div class="evidence-header">'+esc(e.filename)+' (line '+e.lineNumber+')</div><pre style="margin:0;white-space:pre-wrap;font-size:11px">'+esc(e.content)+'</pre></div>';
});
html+='</details>';
}
html+='</div>';
return html;
}

// ── Timeline ────────────────────────────────────────────────────────
function renderTimeline(){
const pcapTL=(state.ai?.pcap?.analysis?.timeline||state.ai?.pcap?.fallback?.timeline||[]);
const warpTL=(state.ai?.warp?.analysis?.timeline||state.ai?.warp?.fallback?.timeline||[]);
const all=[...pcapTL,...warpTL];
if(!all.length){timelineContent.innerHTML='<div class="empty-state">No timeline events</div>';return}
let html='<div class="ai-section"><h3>Event Timeline ('+all.length+' events)</h3><div class="timeline-list">';
all.forEach(ev=>{
const sev=(ev.severity||'info').toLowerCase();
html+='<div class="tl-item '+sev+'"><div class="tl-dot"></div>';
html+='<div class="tl-time">'+esc(ev.timestamp||'')+'</div>';
html+='<div class="tl-event">'+esc(ev.event||ev.event_type||'')+'</div>';
if(ev.details)html+='<div class="tl-detail">'+esc(ev.details)+'</div>';
if(ev.source_file)html+='<div class="tl-detail" style="font-size:11px;color:var(--text3)">Source: '+esc(ev.source_file)+'</div>';
if(ev.log_reference){
html+='<details class="evidence-toggle"><summary>'+esc(ev.log_reference.filename)+':'+ev.log_reference.lineNumber+'</summary>';
html+='<div class="evidence-block"><pre style="margin:0;white-space:pre-wrap;font-size:11px">'+esc(ev.log_reference.content)+'</pre></div></details>';
}
html+='</div>';
});
html+='</div></div>';
timelineContent.innerHTML=html;
}

// ── WARP tab ────────────────────────────────────────────────────────
function renderWarp(data){
const warpAI=state.ai?.warp?.analysis||state.ai?.warp?.fallback;
let html='<div class="ai-section"><h3>WARP Diagnostic Files</h3>';
if(data.warpFiles){
html+='<table class="conv-table"><thead><tr><th>File</th><th>Category</th><th>Priority</th></tr></thead><tbody>';
data.warpFiles.forEach(f=>{
html+='<tr><td>'+esc(f.filename)+'</td><td>'+esc(f.category)+'</td><td>'+esc(f.priority)+'</td></tr>';
});
html+='</tbody></table>';
}
if(warpAI?.configuration_review){
const cr=warpAI.configuration_review;
html+='<h3 style="margin-top:20px">Configuration Review</h3>';
html+='<div class="stat-card">';
if(cr.warp_mode)html+='<div class="stat-row"><span class="label">WARP Mode</span><span class="value">'+esc(cr.warp_mode)+'</span></div>';
if(cr.split_tunnel)html+='<div class="stat-row"><span class="label">Split Tunnel</span><span class="value">'+esc(cr.split_tunnel)+'</span></div>';
if(cr.dns_settings)html+='<div class="stat-row"><span class="label">DNS Settings</span><span class="value">'+esc(cr.dns_settings)+'</span></div>';
if(cr.certificate_status)html+='<div class="stat-row"><span class="label">Certificate</span><span class="value">'+esc(cr.certificate_status)+'</span></div>';
html+='</div>';
}
html+='</div>';
warpContent.innerHTML=html;
}

// ── Navigation ──────────────────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(btn=>{
btn.onclick=()=>{
document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('active'));
btn.classList.add('active');
$('tab-'+btn.dataset.tab).classList.add('active');
};
});

$('btnBack').onclick=()=>{
$('analysis-screen').classList.remove('active');
$('upload-screen').classList.add('active');
$('btnBack').classList.add('hidden');
exportSelect.classList.add('hidden');
state={packets:[],flows:{},stats:{},ai:null,sessionId:null,selectedPkt:null,filteredPackets:null,allPackets:[]};
files=[];fileInput.value='';fileListEl.classList.add('hidden');analyzeBtn.disabled=true;
progressEl.classList.remove('active');
loadSessions();
};

$('btnSessions').onclick=()=>{
if($('upload-screen').classList.contains('active')){loadSessions()}
else{$('btnBack').click()}
};

// ── Export ───────────────────────────────────────────────────────────
exportSelect.onchange=async()=>{
const fmt=exportSelect.value;
if(!fmt||!state.sessionId)return;
exportSelect.value='';
try{
const resp=await fetch(API+'/api/sessions/'+state.sessionId+'/export/'+fmt);
if(!resp.ok)throw new Error('Export failed');
const blob=await resp.blob();
const disp=resp.headers.get('Content-Disposition')||'';
const nameMatch=disp.match(/filename="([^"]+)"/);
const filename=nameMatch?nameMatch[1]:'export.'+fmt;
const url=URL.createObjectURL(blob);
const a=document.createElement('a');a.href=url;a.download=filename;a.click();
URL.revokeObjectURL(url);
}catch(e){alert('Export error: '+e.message)}
};

// ── Sessions ────────────────────────────────────────────────────────
async function loadSessions(){
try{
const resp=await fetch(API+'/api/sessions');
if(!resp.ok)return;
const data=await resp.json();
if(data.sessions&&data.sessions.length){
sessionList.innerHTML='<h3>Recent Sessions</h3>'+data.sessions.map(s=>
'<div class="session-item" data-id="'+esc(s.id)+'"><div class="info"><div class="name">'+esc(s.fileName)+'</div><div class="date">'+new Date(s.createdAt).toLocaleString()+'</div></div><button class="btn btn-sm btn-ghost">Open</button></div>'
).join('');
sessionList.querySelectorAll('.session-item').forEach(el=>{
el.onclick=()=>openSession(el.dataset.id);
});
}else{sessionList.innerHTML=''}
}catch(e){console.warn('Failed to load sessions:',e)}
}

async function openSession(id){
try{
const [metaR,pktR,flowR,statR,aiR]=await Promise.all([
fetch(API+'/api/sessions/'+id),
fetch(API+'/api/sessions/'+id+'/packets?page=0'),
fetch(API+'/api/sessions/'+id+'/flows'),
fetch(API+'/api/sessions/'+id+'/stats'),
fetch(API+'/api/sessions/'+id+'/ai'),
]);
const meta=await metaR.json();
const pktData=await pktR.json();
const flowData=await flowR.json();
const statData=await statR.json();
const aiData=await aiR.json();

loadResults({
sessionId:id,
pcap:{
metadata:meta.captureMetadata,
packets:pktData.packets||[],
flows:flowData.flows||{},
stats:statData.stats||{},
warnings:meta.warnings||[]
},
ai:aiData.ai,
warpFiles:meta.hasWarpDiagnostics?[{filename:'(from session)',category:'mixed',priority:'high'}]:[],
});
}catch(e){alert('Failed to open session: '+e.message)}
}

// ── Status bar ──────────────────────────────────────────────────────
function updateStatusBar(data){
$('statusFile').textContent='File: '+(data.pcap?.metadata?.format||'N/A')+' '+fmtBytes(data.pcap?.metadata?.fileSize||0);
const models=(data.ai?.combined?.models_used||[]).join(', ');
$('statusModel').textContent=models?'Model: '+models:'';
$('statusSession').textContent=data.sessionId?'Session: '+data.sessionId:'';
}

// ── Helpers ──────────────────────────────────────────────────────────
function esc(s){if(!s)return'';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function fmtBytes(b){if(!b)return'0 B';const k=1024,s=['B','KB','MB','GB'];const i=Math.floor(Math.log(b)/Math.log(k));return(b/Math.pow(k,i)).toFixed(1)+' '+s[i]}
function formatRemed(text){if(!text)return'';const s=String(text);const steps=s.split(/(?:^|\\s)(\\d+)\\.\\s+/).filter(Boolean);if(steps.length>2){let ol='<ol>';for(let i=0;i<steps.length;i+=2){const t=steps[i+1]||steps[i];if(t&&!/^\\d+$/.test(t.trim()))ol+='<li>'+esc(t.trim())+'</li>'}return ol+'</ol>'}return'<p style="margin-top:6px">'+esc(s)+'</p>'}

// ── Init ────────────────────────────────────────────────────────────
loadSessions();
})();
</script>
</body>
</html>`;
