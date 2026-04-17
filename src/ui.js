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

/* Dark theme (default) */
:root,[data-theme="dark"]{
--bg:#0d1117;--bg2:#161b22;--bg3:#1c2128;--bg4:#21262d;
--border:#30363d;--border2:#484f58;
--text:#e6edf3;--text2:#8b949e;--text3:#6e7681;
--orange:#f38020;--orange2:#d66e1a;
--green:#3fb950;--red:#f85149;--yellow:#d29922;--blue:#58a6ff;--purple:#bc8cff;
--cyan:#39d2c0;--pink:#f778ba;
--font:Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
--mono:'JetBrains Mono',Monaco,Menlo,'Ubuntu Mono',monospace;
--shadow:0 1px 3px rgba(0,0,0,.4);
--hex-bg:#0d1117;
}

/* Light theme */
[data-theme="light"]{
--bg:#ffffff;--bg2:#f6f8fa;--bg3:#eef1f5;--bg4:#d8dee4;
--border:#d0d7de;--border2:#afb8c1;
--text:#1f2328;--text2:#57606a;--text3:#8b949e;
--orange:#d35400;--orange2:#bf4b00;
--green:#1a7f37;--red:#cf222e;--yellow:#9a6700;--blue:#0969da;--purple:#8250df;
--cyan:#0e7c6b;--pink:#bf3989;
--shadow:0 1px 3px rgba(0,0,0,.1);
--hex-bg:#f6f8fa;
}
[data-theme="light"] .pkt-table tr.proto-tcp{color:#0550ae}
[data-theme="light"] .pkt-table tr.proto-udp{color:#0e6e6b}
[data-theme="light"] .pkt-table tr.proto-dns{color:#0969da}
[data-theme="light"] .pkt-table tr.proto-tls,[data-theme="light"] .pkt-table tr.proto-https{color:#6639ba}
[data-theme="light"] .pkt-table tr.proto-http{color:#1a7f37}
[data-theme="light"] .pkt-table tr.proto-icmp{color:#cf222e}
[data-theme="light"] .pkt-table tr.proto-arp{color:#953800}
[data-theme="light"] .pkt-table tr.proto-dhcp{color:#6639ba}
[data-theme="light"] .pkt-table tr.proto-ssh{color:#953800}
[data-theme="light"] .pkt-table tr.proto-warp{color:#d35400}
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
.filter-bar{padding:6px 12px;background:var(--bg2);border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:center;flex-shrink:0;flex-wrap:wrap}
.filter-bar input{flex:1;min-width:240px;background:var(--bg);font-family:var(--mono);font-size:12px}
.filter-bar .filter-count{font-size:11px;color:var(--text3);white-space:nowrap}
.filter-chip{padding:3px 10px;border-radius:12px;font-size:11px;font-weight:500;background:var(--bg3);border:1px solid var(--border);color:var(--text2);cursor:pointer;transition:all .15s}
.filter-chip:hover{border-color:var(--orange);color:var(--orange)}
.filter-chip.active{background:var(--orange);color:#fff;border-color:var(--orange)}
.time-toggle{padding:3px 10px;border-radius:4px;font-size:11px;font-weight:500;background:var(--bg3);border:1px solid var(--border);color:var(--text2);cursor:pointer;font-family:var(--mono)}
.time-toggle:hover{border-color:var(--orange);color:var(--text)}
.goto-input{width:70px;padding:3px 8px;font-family:var(--mono);font-size:11px;text-align:center}

/* Resizable pane container */
.pane-container{flex:1;display:flex;flex-direction:column;overflow:hidden;position:relative}
.pane-top{overflow:hidden;display:flex;flex-direction:column;min-height:100px}
.pane-mid{overflow:hidden;display:flex;flex-direction:column;min-height:80px}
.pane-bot{overflow:hidden;display:flex;flex-direction:column;min-height:80px;flex:1}
.pane-resizer{height:4px;background:var(--border);cursor:ns-resize;flex-shrink:0;position:relative;transition:background .15s}
.pane-resizer:hover,.pane-resizer.dragging{background:var(--orange)}
.pane-resizer::after{content:'';position:absolute;top:-2px;bottom:-2px;left:0;right:0}
.pane-label{font-size:11px;font-weight:600;color:var(--text3);padding:5px 12px;background:var(--bg2);border-bottom:1px solid var(--border);text-transform:uppercase;letter-spacing:.5px;flex-shrink:0;display:flex;align-items:center;justify-content:space-between}
.pane-label .actions{display:flex;gap:6px;text-transform:none;letter-spacing:0}
.pane-action{background:none;border:none;color:var(--text2);font-size:11px;padding:2px 6px;border-radius:3px;cursor:pointer}
.pane-action:hover{background:var(--bg3);color:var(--text)}

/* Virtual scrolling packet list */
.pkt-viewport{flex:1;overflow:auto;position:relative;outline:none}
.pkt-viewport:focus{box-shadow:inset 0 0 0 1px var(--orange)33}
.pkt-header{display:flex;position:sticky;top:0;background:var(--bg2);z-index:2;border-bottom:1px solid var(--border);font-size:11px;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:.3px;user-select:none}
.pkt-header .col{padding:6px 8px;border-right:1px solid var(--border);cursor:pointer;white-space:nowrap;overflow:hidden}
.pkt-header .col:hover{color:var(--orange);background:var(--bg3)}
.pkt-header .col.sorted{color:var(--orange)}
.pkt-header .col .sort-arrow{font-size:9px;margin-left:4px;opacity:.6}
.pkt-spacer{position:relative}
.pkt-row{position:absolute;left:0;right:0;display:flex;font-family:var(--mono);font-size:12px;cursor:pointer;align-items:center;border-bottom:1px solid #1c212844}
.pkt-row:hover{background:var(--bg3)}
.pkt-row.selected{background:var(--orange)22;box-shadow:inset 2px 0 0 var(--orange)}
.pkt-row.same-flow{background:var(--orange)0a}
.pkt-row .cell{padding:3px 8px;border-right:1px solid transparent;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pkt-row.proto-tcp{color:#a5d6ff}.pkt-row.proto-udp{color:#7ee8fa}
.pkt-row.proto-dns{color:#79c0ff}.pkt-row.proto-tls,.pkt-row.proto-https{color:#d2a8ff}
.pkt-row.proto-http{color:#7ee787}.pkt-row.proto-icmp{color:#ffa198}
.pkt-row.proto-arp{color:#ffc680}.pkt-row.proto-dhcp{color:#d2a8ff}
.pkt-row.proto-ssh{color:#f0883e}.pkt-row.proto-warp{color:var(--orange)}
.pkt-row.has-warning .cell:last-child::after{content:" ⚠";color:var(--yellow)}
[data-theme="light"] .pkt-row.proto-tcp{color:#0550ae}
[data-theme="light"] .pkt-row.proto-udp{color:#0e6e6b}
[data-theme="light"] .pkt-row.proto-dns{color:#0969da}
[data-theme="light"] .pkt-row.proto-tls,[data-theme="light"] .pkt-row.proto-https{color:#6639ba}
[data-theme="light"] .pkt-row.proto-http{color:#1a7f37}
[data-theme="light"] .pkt-row.proto-icmp{color:#cf222e}
[data-theme="light"] .pkt-row.proto-arp{color:#953800}
[data-theme="light"] .pkt-row.proto-dhcp{color:#6639ba}
[data-theme="light"] .pkt-row.proto-ssh{color:#953800}
[data-theme="light"] .pkt-row.proto-warp{color:#d35400}

/* Legacy table class (kept for conversations/stats) */
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
.status-bar{background:var(--bg2);border-top:1px solid var(--border);padding:4px 16px;font-size:11px;color:var(--text3);display:flex;gap:16px;flex-shrink:0;align-items:center}
.status-bar span{display:inline-flex;align-items:center;gap:4px}
.status-divider{width:1px;background:var(--border);align-self:stretch;margin:2px 0}
.status-bar .k{color:var(--text2);font-weight:500}
.status-bar .v{color:var(--text);font-family:var(--mono)}

/* ── Toasts ───────────────────────────────────────────────────────────── */
#toasts{position:fixed;top:60px;right:16px;z-index:1000;display:flex;flex-direction:column;gap:8px;pointer-events:none;max-width:400px}
.toast{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:12px 14px;box-shadow:var(--shadow);font-size:13px;color:var(--text);pointer-events:auto;animation:slideIn .2s ease-out;border-left:3px solid var(--blue);max-width:400px;display:flex;gap:10px;align-items:flex-start}
.toast.error{border-left-color:var(--red)}
.toast.warning{border-left-color:var(--yellow)}
.toast.success{border-left-color:var(--green)}
.toast .ticon{font-size:16px;flex-shrink:0}
.toast .tbody{flex:1;line-height:1.4}
.toast .tclose{background:none;border:none;color:var(--text3);cursor:pointer;font-size:18px;padding:0 4px;margin-left:8px}
.toast .tclose:hover{color:var(--text)}
@keyframes slideIn{from{transform:translateX(120%);opacity:0}to{transform:translateX(0);opacity:1}}
@keyframes slideOut{to{transform:translateX(120%);opacity:0}}
.toast.closing{animation:slideOut .2s ease-in forwards}

/* ── Loading skeletons ────────────────────────────────────────────────── */
.skeleton{background:linear-gradient(90deg,var(--bg2) 0%,var(--bg3) 50%,var(--bg2) 100%);background-size:200% 100%;animation:shimmer 1.4s infinite;border-radius:4px;height:14px;margin-bottom:8px}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
.skeleton.short{width:60%}.skeleton.medium{width:80%}.skeleton.long{width:100%}

/* ── I/O Graph ────────────────────────────────────────────────────────── */
.io-graph{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px;margin:16px}
.io-graph-svg{width:100%;height:200px;display:block}
.io-grid{stroke:var(--border);stroke-width:.5}
.io-line{fill:none;stroke:var(--orange);stroke-width:2}
.io-area{fill:var(--orange);fill-opacity:.15}
.io-axis-text{fill:var(--text3);font-size:10px;font-family:var(--mono)}

/* ── Context menu ─────────────────────────────────────────────────────── */
.context-menu{position:fixed;background:var(--bg2);border:1px solid var(--border);border-radius:6px;box-shadow:var(--shadow);z-index:500;min-width:180px;padding:4px;font-size:12px;display:none}
.context-menu.open{display:block}
.ctx-item{padding:7px 12px;cursor:pointer;border-radius:3px;display:flex;justify-content:space-between;gap:12px;color:var(--text)}
.ctx-item:hover{background:var(--bg3)}
.ctx-item .shortcut{color:var(--text3);font-family:var(--mono);font-size:10px}
.ctx-separator{height:1px;background:var(--border);margin:4px 0}

/* ── Keyboard help overlay ────────────────────────────────────────────── */
.kbd-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:999;display:none;align-items:center;justify-content:center}
.kbd-overlay.open{display:flex}
.kbd-panel{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:24px;max-width:500px;width:90%;box-shadow:var(--shadow)}
.kbd-panel h3{font-size:15px;font-weight:600;margin-bottom:16px;color:var(--text)}
.kbd-row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);font-size:13px}
.kbd-row:last-child{border:none}
.kbd-row .desc{color:var(--text2)}
kbd{font-family:var(--mono);background:var(--bg3);border:1px solid var(--border);border-radius:3px;padding:1px 6px;font-size:11px;color:var(--text);margin:0 2px}

/* ── Utility ──────────────────────────────────────────────────────────── */
.hidden{display:none!important}
.scroll-y{overflow-y:auto}
@keyframes spin{to{transform:rotate(360deg)}}
.spinner{width:20px;height:20px;border:2px solid var(--border);border-top-color:var(--orange);border-radius:50%;animation:spin .6s linear infinite;display:inline-block}
.empty-state{flex:1;display:flex;align-items:center;justify-content:center;color:var(--text3);font-size:13px}
.mono-small{font-family:var(--mono);font-size:11px;color:var(--text2)}
</style>
</head>
<body>
<div id="app">
<!-- Header -->
<div class="header">
<h1><span>WARP</span> & PCAP Analyzer</h1>
<span class="badge badge-info" id="versionBadge">v2.0</span>
<div class="header-actions">
<button class="btn btn-ghost btn-sm" id="btnTheme" title="Toggle light/dark theme">
<span id="themeIcon">&#x2600;&#xFE0F;</span>
</button>
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
<input type="text" id="filterInput" placeholder="Filter: tcp, dns, ip.addr==192.168.1.1, port 443, tls.sni contains example.com, rst, error">
<button class="btn btn-sm btn-primary" id="filterApply" title="Apply filter (Enter)">Apply</button>
<button class="btn btn-sm btn-ghost" id="filterClear" title="Clear filter (Esc)">Clear</button>
<span class="filter-chip" data-filter="tcp">TCP</span>
<span class="filter-chip" data-filter="udp">UDP</span>
<span class="filter-chip" data-filter="dns">DNS</span>
<span class="filter-chip" data-filter="tls">TLS</span>
<span class="filter-chip" data-filter="http">HTTP</span>
<span class="filter-chip" data-filter="icmp">ICMP</span>
<span class="filter-chip" data-filter="rst">Errors</span>
<input type="number" class="goto-input" id="gotoInput" placeholder="Go to #" title="Go to packet number (Ctrl+G)">
<button class="time-toggle" id="timeToggle" title="Toggle time format">Relative</button>
<button class="btn btn-ghost btn-sm" id="btnHelp" title="Keyboard shortcuts (?)">?</button>
<span class="filter-count" id="filterCount"></span>
</div>
<div class="pane-container" id="paneContainer">
<div class="pane-top" id="paneTop" style="height:50%">
<div class="pane-label">Packet List <span class="actions"><button class="pane-action" id="btnFollow" title="Follow flow of selected packet">Follow Flow</button></span></div>
<div class="pkt-viewport" id="pktViewport" tabindex="0">
<div class="pkt-header" id="pktHeader"></div>
<div class="pkt-spacer" id="pktSpacer"></div>
</div>
</div>
<div class="pane-resizer" data-resize="top"></div>
<div class="pane-mid" id="paneMid" style="height:25%">
<div class="pane-label">Packet Details <span class="actions"><button class="pane-action" id="btnExpandAll" title="Expand/collapse all layers">All</button><button class="pane-action" id="btnCopyDetails" title="Copy details to clipboard">Copy</button></span></div>
<div class="detail-tree scroll-y" id="detailTree"><div class="empty-state">Select a packet to view details</div></div>
</div>
<div class="pane-resizer" data-resize="bot"></div>
<div class="pane-bot" id="paneBot">
<div class="pane-label">Hex Dump <span class="actions"><button class="pane-action" id="btnCopyHex" title="Copy hex to clipboard">Copy</button></span></div>
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
<span><span class="k">Packets:</span> <span class="v" id="statusPackets">0</span></span>
<span class="status-divider"></span>
<span><span class="k">Displayed:</span> <span class="v" id="statusDisplayed">0</span></span>
<span class="status-divider"></span>
<span><span class="k">Selected:</span> <span class="v" id="statusSelected">None</span></span>
<span class="status-divider"></span>
<span id="statusFile" class="mono-small"></span>
<span style="margin-left:auto"></span>
<span id="statusModel" class="mono-small"></span>
<span class="status-divider"></span>
<span id="statusSession" class="mono-small"></span>
</div>
</div>

<!-- Toast container -->
<div id="toasts"></div>

<!-- Context menu -->
<div class="context-menu" id="ctxMenu"></div>

<!-- Keyboard shortcuts overlay -->
<div class="kbd-overlay" id="kbdOverlay">
<div class="kbd-panel">
<h3>Keyboard Shortcuts</h3>
<div class="kbd-row"><span class="desc">Next packet</span><span><kbd>j</kbd> or <kbd>&darr;</kbd></span></div>
<div class="kbd-row"><span class="desc">Previous packet</span><span><kbd>k</kbd> or <kbd>&uarr;</kbd></span></div>
<div class="kbd-row"><span class="desc">Page down / up</span><span><kbd>Space</kbd> / <kbd>Shift+Space</kbd></span></div>
<div class="kbd-row"><span class="desc">First / last packet</span><span><kbd>g</kbd> / <kbd>G</kbd></span></div>
<div class="kbd-row"><span class="desc">Focus filter</span><span><kbd>/</kbd> or <kbd>Ctrl+F</kbd></span></div>
<div class="kbd-row"><span class="desc">Clear filter</span><span><kbd>Esc</kbd></span></div>
<div class="kbd-row"><span class="desc">Go to packet #</span><span><kbd>Ctrl+G</kbd></span></div>
<div class="kbd-row"><span class="desc">Follow flow of selected</span><span><kbd>f</kbd></span></div>
<div class="kbd-row"><span class="desc">Copy packet details</span><span><kbd>Ctrl+C</kbd></span></div>
<div class="kbd-row"><span class="desc">Toggle theme</span><span><kbd>t</kbd></span></div>
<div class="kbd-row"><span class="desc">Show this help</span><span><kbd>?</kbd></span></div>
<div class="kbd-row"><span class="desc">Close dialogs</span><span><kbd>Esc</kbd></span></div>
<button class="btn btn-ghost btn-sm" id="kbdClose" style="margin-top:16px;width:100%">Close</button>
</div>
</div>

<script>
(function(){
'use strict';
const API=window.location.origin;

// Columns for packet list (widths as fractions of total width)
const COLS=[
{id:'number',label:'No.',w:60,align:'right',sort:(a,b)=>a.number-b.number},
{id:'time',label:'Time',w:110,align:'right',sort:(a,b)=>a.timestamp-b.timestamp},
{id:'src',label:'Source',w:170,sort:(a,b)=>(getSrc(a)||'').localeCompare(getSrc(b)||'')},
{id:'dst',label:'Destination',w:170,sort:(a,b)=>(getDst(a)||'').localeCompare(getDst(b)||'')},
{id:'protocol',label:'Protocol',w:90,sort:(a,b)=>a.protocol.localeCompare(b.protocol)},
{id:'length',label:'Length',w:70,align:'right',sort:(a,b)=>a.capturedLength-b.capturedLength},
{id:'info',label:'Info',w:0,sort:(a,b)=>(a.info||'').localeCompare(b.info||'')},
];
const ROW_HEIGHT=22;   // px per packet row
const OVERSCAN=10;      // extra rows to render outside viewport for smooth scroll

let state={
packets:[],flows:{},stats:{},ai:null,sessionId:null,warpFiles:null,
selectedIdx:-1,filteredPackets:null,allPackets:[],
sortBy:null,sortDir:'asc',timeFormat:'relative', // 'relative' | 'absolute' | 'delta'
};

// ── DOM refs ────────────────────────────────────────────────────────
const $=id=>document.getElementById(id);
const dropZone=$('dropZone'),fileInput=$('fileInput'),fileListEl=$('fileList'),
analyzeBtn=$('analyzeBtn'),progressEl=$('uploadProgress'),progressFill=$('progressFill'),
progressText=$('progressText'),detailTree=$('detailTree'),hexDump=$('hexDump'),
filterInput=$('filterInput'),filterCount=$('filterCount'),convBody=$('convBody'),
statsContent=$('statsContent'),aiContent=$('aiContent'),timelineContent=$('timelineContent'),
warpContent=$('warpContent'),exportSelect=$('exportSelect'),sessionList=$('sessionList'),
pktViewport=$('pktViewport'),pktHeader=$('pktHeader'),pktSpacer=$('pktSpacer'),
toastsEl=$('toasts'),ctxMenu=$('ctxMenu'),kbdOverlay=$('kbdOverlay');

let files=[];
let renderedRows=new Map();   // idx -> DOM element (for recycling during virtual scroll)

// ── Utility helpers ─────────────────────────────────────────────────
function getSrc(p){return p.layers?.ipv4?.src||p.layers?.ipv6?.src||p.layers?.arp?.senderIP||''}
function getDst(p){return p.layers?.ipv4?.dst||p.layers?.ipv6?.dst||p.layers?.arp?.targetIP||''}

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
setProgress(5,'Preparing upload...');
try{
const fd=new FormData();
files.forEach((f,i)=>fd.append('file'+i,f));
const totalSize=files.reduce((a,f)=>a+f.size,0);
if(totalSize>50*1024*1024)toast('warning','Large upload: '+fmtBytes(totalSize)+'. This may take up to 60 seconds.');
setProgress(15,'Uploading '+fmtBytes(totalSize)+'...');

// Simulate progressive stages while server processes
let stage=15;
const stageTimer=setInterval(()=>{
if(stage<85){stage+=3;setProgress(stage,stage<35?'Uploading...':stage<55?'Decoding packets...':stage<75?'Running AI analysis...':'Finalising...')}
},800);

const resp=await fetch(API+'/api/analyze',{method:'POST',body:fd});
clearInterval(stageTimer);
setProgress(90,'Parsing response...');
if(!resp.ok){
let errMsg='Analysis failed (HTTP '+resp.status+')';
try{const e=await resp.json();errMsg=e.error||errMsg}catch(_){}
throw new Error(errMsg);
}
const data=await resp.json();
setProgress(100,'Complete');
await new Promise(r=>setTimeout(r,300));
loadResults(data);
toast('success','Analysis complete: '+(data.pcap?.totalPackets||0)+' packets decoded');
}catch(e){
progressText.textContent='Error: '+e.message;
progressFill.style.background='var(--red)';
toast('error',e.message);
setTimeout(()=>{progressEl.classList.remove('active');progressFill.style.background='var(--orange)';analyzeBtn.disabled=false;setProgress(0,'')},4000);
}
};

function setProgress(pct,msg){progressFill.style.width=pct+'%';progressText.textContent=msg}

// ── Load results ────────────────────────────────────────────────────
function loadResults(data){
state.sessionId=data.sessionId;
state.ai=data.ai;
state.warpFiles=data.warpFiles||null;

if(data.pcap){
state.allPackets=data.pcap.packets||[];
state.packets=state.allPackets;
state.filteredPackets=null;
state.flows=data.pcap.flows||{};
state.stats=data.pcap.stats||{};
}else{
state.allPackets=[];state.packets=[];state.flows={};state.stats={};
}
state.selectedIdx=-1;

$('upload-screen').classList.remove('active');
$('analysis-screen').classList.add('active');
$('btnBack').classList.remove('hidden');
exportSelect.classList.remove('hidden');

const warpTab=document.querySelector('[data-tab="warp"]');
if(state.warpFiles&&state.warpFiles.length>0)warpTab.classList.remove('hidden');
else warpTab.classList.add('hidden');

buildPacketHeader();
renderPacketList();
renderConversations();
renderStats();
renderAI();
renderTimeline();
if(state.warpFiles)renderWarp(data);
updateStatusBar(data);

// Auto-select first packet
if(state.allPackets.length>0)requestAnimationFrame(()=>selectPacket(0));
// Focus viewport for keyboard navigation
setTimeout(()=>pktViewport&&pktViewport.focus(),100);
}

// ── Packet list header ──────────────────────────────────────────────
function buildPacketHeader(){
const totalFixedW=COLS.filter(c=>c.w>0).reduce((a,c)=>a+c.w,0);
let html='';
for(const col of COLS){
const w=col.w>0?col.w+'px':'auto';
const flex=col.w===0?'flex:1;min-width:200px':'';
const sortIcon=state.sortBy===col.id?(state.sortDir==='asc'?'\u25B2':'\u25BC'):'';
const sorted=state.sortBy===col.id?' sorted':'';
html+='<div class="col'+sorted+'" data-col="'+col.id+'" style="width:'+w+';'+flex+';text-align:'+(col.align||'left')+'" title="Click to sort by '+col.label+'">'+col.label+'<span class="sort-arrow">'+sortIcon+'</span></div>';
}
pktHeader.innerHTML=html;
pktHeader.querySelectorAll('.col').forEach(el=>{
el.onclick=()=>{
const id=el.dataset.col;
if(state.sortBy===id){
if(state.sortDir==='asc')state.sortDir='desc';
else{state.sortBy=null;state.sortDir='asc'}
}else{state.sortBy=id;state.sortDir='asc'}
applySortAndFilter();
buildPacketHeader();
};
});
}

// ── Packet list rendering (virtual scrolling) ──────────────────────
function currentPackets(){return state.filteredPackets||state.packets}

function renderPacketList(){
const pkts=currentPackets();
pktSpacer.style.height=(pkts.length*ROW_HEIGHT)+'px';
// Clear rendered rows
renderedRows.forEach(el=>el.remove());
renderedRows.clear();
renderVisibleRows();

const total=state.allPackets.length;
const shown=pkts.length;
filterCount.textContent=state.filteredPackets?(shown+' of '+total+' packets'):(shown+' packets');
$('statusPackets').textContent=total.toLocaleString();
$('statusDisplayed').textContent=shown.toLocaleString()+(state.filteredPackets?' (filtered)':'');
}

function renderVisibleRows(){
const pkts=currentPackets();
if(!pkts.length){
renderedRows.forEach(el=>el.remove());renderedRows.clear();
return;
}
const scrollTop=pktViewport.scrollTop;
const headerH=pktHeader.offsetHeight||28;
const viewH=pktViewport.clientHeight-headerH;
const startIdx=Math.max(0,Math.floor((scrollTop-headerH)/ROW_HEIGHT)-OVERSCAN);
const endIdx=Math.min(pkts.length-1,Math.ceil((scrollTop-headerH+viewH)/ROW_HEIGHT)+OVERSCAN);

// Remove rows out of range
for(const [idx,el] of renderedRows){
if(idx<startIdx||idx>endIdx){el.remove();renderedRows.delete(idx)}
}

// Build base time for relative timestamps
const baseTime=pkts[0].timestamp;
const selFlowId=state.selectedIdx>=0?pkts[state.selectedIdx]?.flowId:null;

// Add rows in range
for(let i=startIdx;i<=endIdx;i++){
if(renderedRows.has(i))continue;
const p=pkts[i];
const row=buildRow(p,i,baseTime,pkts,selFlowId);
pktSpacer.appendChild(row);
renderedRows.set(i,row);
}

// Update selection highlight (scroll might have remounted)
if(state.selectedIdx>=0){
const selRow=renderedRows.get(state.selectedIdx);
if(selRow)selRow.classList.add('selected');
}
}

function buildRow(p,idx,baseTime,pkts,selFlowId){
const row=document.createElement('div');
const proto=(p.protocol||'').toLowerCase().replace(/[^a-z]/g,'');
let cls='pkt-row proto-'+proto;
if(p.warnings&&p.warnings.length)cls+=' has-warning';
if(selFlowId&&p.flowId===selFlowId&&idx!==state.selectedIdx)cls+=' same-flow';
row.className=cls;
row.style.top=(idx*ROW_HEIGHT)+'px';
row.style.height=ROW_HEIGHT+'px';
row.dataset.idx=idx;

const timeStr=formatTime(p,baseTime,idx,pkts);
let html='';
html+='<div class="cell" style="width:60px;text-align:right">'+p.number+'</div>';
html+='<div class="cell" style="width:110px;text-align:right">'+timeStr+'</div>';
html+='<div class="cell" style="width:170px">'+esc(getSrc(p))+'</div>';
html+='<div class="cell" style="width:170px">'+esc(getDst(p))+'</div>';
html+='<div class="cell" style="width:90px">'+esc(p.protocol||'')+'</div>';
html+='<div class="cell" style="width:70px;text-align:right">'+(p.capturedLength||0)+'</div>';
html+='<div class="cell" style="flex:1;min-width:200px">'+esc(p.info||'')+'</div>';
row.innerHTML=html;

row.onclick=()=>selectPacket(idx);
row.oncontextmenu=e=>{e.preventDefault();showContextMenu(e,p,idx)};
return row;
}

function formatTime(p,baseTime,idx,pkts){
if(state.timeFormat==='absolute'){
const d=new Date(p.timestamp*1000);
return d.toISOString().substring(11,23);
}
if(state.timeFormat==='delta'&&idx>0){
const prev=pkts[idx-1];
return (p.timestamp-prev.timestamp).toFixed(6);
}
return (p.timestamp-baseTime).toFixed(6);
}

// Handle viewport scroll (debounced via rAF)
let scrollRaf=null;
pktViewport.addEventListener('scroll',()=>{
if(scrollRaf)return;
scrollRaf=requestAnimationFrame(()=>{scrollRaf=null;renderVisibleRows()});
});
// Re-render on resize
let resizeRaf=null;
window.addEventListener('resize',()=>{
if(resizeRaf)return;
resizeRaf=requestAnimationFrame(()=>{resizeRaf=null;renderVisibleRows()});
});

// ── Sort & filter ────────────────────────────────────────────────────
function applySortAndFilter(){
let base=state.allPackets;
if(state.filteredPackets){
// Re-filter (filter is stored in input)
applyFilterExpr(filterInput.value.trim().toLowerCase());
base=state.filteredPackets;
}
if(state.sortBy){
const col=COLS.find(c=>c.id===state.sortBy);
if(col&&col.sort){
const arr=[...base];
arr.sort((a,b)=>{const r=col.sort(a,b);return state.sortDir==='asc'?r:-r});
if(state.filteredPackets)state.filteredPackets=arr;
else state.packets=arr;
}
}
state.selectedIdx=-1;
renderPacketList();
}

// ── Packet selection ────────────────────────────────────────────────
function selectPacket(idx){
const pkts=currentPackets();
if(idx<0||idx>=pkts.length)return;
const prev=state.selectedIdx;
state.selectedIdx=idx;
const p=pkts[idx];

// Update selection highlighting (clear all selected, add new)
if(prev>=0){
const prevRow=renderedRows.get(prev);
if(prevRow)prevRow.classList.remove('selected');
}
// Rebuild same-flow highlights: clear all, re-render visible
renderedRows.forEach(el=>el.classList.remove('same-flow'));
const selFlowId=p.flowId;
renderedRows.forEach((el,i)=>{
const pp=pkts[i];
if(pp&&pp.flowId===selFlowId&&i!==idx)el.classList.add('same-flow');
});
const row=renderedRows.get(idx);
if(row)row.classList.add('selected');

// Scroll into view if not visible
scrollPacketIntoView(idx);

renderDetailTree(p);
renderHexDump(p);

// Update status bar
$('statusSelected').textContent='#'+p.number+' '+p.protocol+' '+p.capturedLength+'B';
}

function scrollPacketIntoView(idx){
const headerH=pktHeader.offsetHeight||28;
const rowTop=idx*ROW_HEIGHT+headerH;
const rowBot=rowTop+ROW_HEIGHT;
const viewTop=pktViewport.scrollTop;
const viewBot=viewTop+pktViewport.clientHeight;
if(rowTop<viewTop+headerH){
pktViewport.scrollTop=rowTop-headerH;
}else if(rowBot>viewBot){
pktViewport.scrollTop=rowBot-pktViewport.clientHeight;
}
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
$('filterClear').onclick=clearFilter;
filterInput.onkeydown=e=>{if(e.key==='Enter'){applyFilter()}else if(e.key==='Escape'){clearFilter();filterInput.blur()}};
// Debounced live filter
let filterDebounce=null;
filterInput.addEventListener('input',()=>{
clearTimeout(filterDebounce);
filterDebounce=setTimeout(applyFilter,300);
});

// Quick filter chips
document.querySelectorAll('.filter-chip').forEach(chip=>{
chip.onclick=()=>{
const f=chip.dataset.filter;
if(filterInput.value===f){clearFilter();return}
filterInput.value=f;
applyFilter();
};
});

function clearFilter(){
filterInput.value='';
state.filteredPackets=null;
state.selectedIdx=-1;
document.querySelectorAll('.filter-chip').forEach(c=>c.classList.remove('active'));
renderPacketList();
detailTree.innerHTML='<div class="empty-state">Select a packet</div>';
hexDump.innerHTML='<div class="empty-state">Select a packet</div>';
$('statusSelected').textContent='None';
}

function applyFilter(){
const expr=filterInput.value.trim().toLowerCase();
// Update chip active state
document.querySelectorAll('.filter-chip').forEach(c=>c.classList.toggle('active',c.dataset.filter===expr));
if(!expr){state.filteredPackets=null;state.selectedIdx=-1;renderPacketList();return}
applyFilterExpr(expr);
state.selectedIdx=-1;
renderPacketList();
}

function applyFilterExpr(expr){
state.filteredPackets=state.allPackets.filter(p=>matchesFilter(p,expr));
}

function matchesFilter(p,expr){
const proto=(p.protocol||'').toLowerCase();
const info=(p.info||'').toLowerCase();
const src=(getSrc(p)||'').toLowerCase();
const dst=(getDst(p)||'').toLowerCase();
const srcPort=String(p.layers?.tcp?.srcPort||p.layers?.udp?.srcPort||'');
const dstPort=String(p.layers?.tcp?.dstPort||p.layers?.udp?.dstPort||'');
const sni=(p.layers?.tls?.sni||'').toLowerCase();
const dnsName=(p.layers?.dns?.questions?.[0]?.name||'').toLowerCase();
const flags=(p.layers?.tcp?.flags||[]).join(',').toLowerCase();
const hasWarning=p.warnings&&p.warnings.length>0;
const flowId=(p.flowId||'').toLowerCase();
const text=proto+' '+info+' '+src+' '+dst+' '+srcPort+' '+dstPort+' '+sni+' '+dnsName+' '+flags+' '+flowId;

// Flow-exact filter (set via Follow Flow)
if(expr.startsWith('flow:')){
return flowId===expr.substring(5);
}

if(expr==='error'||expr==='errors'||expr==='warn'||expr==='warnings')return hasWarning;
if(expr==='rst'||expr==='reset')return flags.includes('rst');
if(expr==='syn')return flags.includes('syn')&&!flags.includes('ack');

// Field operators
if(expr.includes('==')){
const[field,val]=expr.split('==').map(s=>s.trim());
if(field==='ip.addr'||field==='ip.src')return src===val||dst===val;
if(field==='ip.dst')return dst===val;
if(field==='tcp.port'||field==='port'||field==='udp.port')return srcPort===val||dstPort===val;
if(field==='proto'||field==='protocol')return proto===val;
if(field==='tls.sni')return sni===val;
if(field==='dns.qry.name')return dnsName===val;
}
if(expr.includes('contains')){
const [field,rawVal]=expr.split('contains').map(s=>s.trim());
const val=rawVal.replace(/['"]/g,'');
if(field==='tls.sni')return sni.includes(val);
if(field==='dns.qry.name')return dnsName.includes(val);
if(field==='ip.addr')return src.includes(val)||dst.includes(val);
return text.includes(val);
}
if(expr.startsWith('port ')){
const port=expr.replace(/[^0-9]/g,'');
if(port)return srcPort===port||dstPort===port;
}
// Simple keyword match
return text.includes(expr);
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

let html='';

// I/O Graph (packets over time) — rendered from actual packet timestamps
html+='<div class="io-graph"><h4 style="font-size:12px;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px">Packet Rate Over Time</h4>'+buildIoGraph()+'</div>';

html+='<div class="stats-grid">';
// Overview cards
html+='<div class="stat-card"><div class="stat-label">Total Packets</div><div class="stat-big">'+(s.totalPackets||0).toLocaleString()+'</div></div>';
html+='<div class="stat-card"><div class="stat-label">Total Bytes</div><div class="stat-big">'+fmtBytes(s.totalBytes||0)+'</div></div>';
html+='<div class="stat-card"><div class="stat-label">Duration</div><div class="stat-big">'+(s.duration||0).toFixed(3)+'s</div></div>';
html+='<div class="stat-card"><div class="stat-label">Avg Packet Size</div><div class="stat-big">'+(s.avgPacketSize||0)+' B</div></div>';
html+='<div class="stat-card"><div class="stat-label">Throughput</div><div class="stat-big">'+fmtRate(s.totalBytes,s.duration)+'</div></div>';
html+='<div class="stat-card"><div class="stat-label">Packet Rate</div><div class="stat-big">'+((s.totalPackets||0)/Math.max(s.duration||1,.001)).toFixed(1)+'/s</div></div>';

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

// Endpoints — per-host packet/byte totals derived from flows
const endpoints=buildEndpoints();
if(endpoints.length){
html+='<div class="stat-card" style="grid-column:span 2"><h4>Endpoints ('+endpoints.length+')</h4>';
html+='<table style="width:100%;font-size:12px;font-family:var(--mono)"><thead><tr>';
html+='<th style="text-align:left;padding:4px 8px;color:var(--text2);font-weight:600;border-bottom:1px solid var(--border)">Address</th>';
html+='<th style="text-align:right;padding:4px 8px;color:var(--text2);font-weight:600;border-bottom:1px solid var(--border)">Packets</th>';
html+='<th style="text-align:right;padding:4px 8px;color:var(--text2);font-weight:600;border-bottom:1px solid var(--border)">Bytes TX</th>';
html+='<th style="text-align:right;padding:4px 8px;color:var(--text2);font-weight:600;border-bottom:1px solid var(--border)">Bytes RX</th>';
html+='<th style="text-align:right;padding:4px 8px;color:var(--text2);font-weight:600;border-bottom:1px solid var(--border)">Total</th>';
html+='</tr></thead><tbody>';
endpoints.slice(0,25).forEach(ep=>{
html+='<tr><td style="padding:3px 8px">'+esc(ep.addr)+'</td><td style="padding:3px 8px;text-align:right">'+ep.packets+'</td><td style="padding:3px 8px;text-align:right">'+fmtBytes(ep.bytesTx)+'</td><td style="padding:3px 8px;text-align:right">'+fmtBytes(ep.bytesRx)+'</td><td style="padding:3px 8px;text-align:right">'+fmtBytes(ep.bytesTx+ep.bytesRx)+'</td></tr>';
});
html+='</tbody></table></div>';
}

html+='</div>';
statsContent.innerHTML=html;
}

// Build I/O graph SVG from packet timestamps (rate over time)
function buildIoGraph(){
const pkts=state.allPackets;
if(!pkts||pkts.length<2)return '<div style="color:var(--text3);padding:20px;text-align:center">Not enough packets for I/O graph</div>';

const W=800,H=180,padL=50,padR=10,padT=10,padB=28;
const baseTime=pkts[0].timestamp;
const endTime=pkts[pkts.length-1].timestamp;
const duration=Math.max(endTime-baseTime,.001);
const buckets=Math.min(100,Math.max(10,Math.floor(duration*2)));
const bucketW=duration/buckets;
const counts=new Array(buckets).fill(0);
for(const p of pkts){
const b=Math.min(buckets-1,Math.floor((p.timestamp-baseTime)/bucketW));
counts[b]++;
}
const maxCount=Math.max(...counts,1);
const plotW=W-padL-padR;
const plotH=H-padT-padB;

// Build path
let pathD='M '+padL+','+(padT+plotH);
let areaD='M '+padL+','+(padT+plotH);
for(let i=0;i<buckets;i++){
const x=padL+(i+.5)*(plotW/buckets);
const y=padT+plotH-(counts[i]/maxCount)*plotH;
if(i===0){pathD='M '+x+','+y;areaD+=' L '+x+','+y}
else{pathD+=' L '+x+','+y;areaD+=' L '+x+','+y}
}
areaD+=' L '+(padL+plotW)+','+(padT+plotH)+' Z';

// Y-axis labels
let gridLines='';
for(let i=0;i<=4;i++){
const y=padT+plotH*(i/4);
const v=Math.round(maxCount*(1-i/4));
gridLines+='<line class="io-grid" x1="'+padL+'" y1="'+y+'" x2="'+(padL+plotW)+'" y2="'+y+'"/>';
gridLines+='<text class="io-axis-text" x="'+(padL-6)+'" y="'+(y+3)+'" text-anchor="end">'+v+'</text>';
}
// X-axis labels
let xLabels='';
for(let i=0;i<=4;i++){
const x=padL+plotW*(i/4);
const t=duration*(i/4);
xLabels+='<text class="io-axis-text" x="'+x+'" y="'+(H-8)+'" text-anchor="middle">'+t.toFixed(1)+'s</text>';
}

return '<svg class="io-graph-svg" viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="none">'+
gridLines+
'<path class="io-area" d="'+areaD+'"/>'+
'<path class="io-line" d="'+pathD+'"/>'+
xLabels+
'<text class="io-axis-text" x="'+(padL-45)+'" y="'+(padT+plotH/2)+'" transform="rotate(-90 '+(padL-45)+' '+(padT+plotH/2)+')" text-anchor="middle">packets/bucket</text>'+
'</svg>';
}

// Build endpoint statistics from flows
function buildEndpoints(){
const eps={};
for(const f of Object.values(state.flows||{})){
if(f.srcIP){
if(!eps[f.srcIP])eps[f.srcIP]={addr:f.srcIP,packets:0,bytesTx:0,bytesRx:0};
eps[f.srcIP].packets+=f.packetsAtoB;
eps[f.srcIP].bytesTx+=f.bytesAtoB;
eps[f.srcIP].bytesRx+=f.bytesBtoA;
}
if(f.dstIP){
if(!eps[f.dstIP])eps[f.dstIP]={addr:f.dstIP,packets:0,bytesTx:0,bytesRx:0};
eps[f.dstIP].packets+=f.packetsBtoA;
eps[f.dstIP].bytesTx+=f.bytesBtoA;
eps[f.dstIP].bytesRx+=f.bytesAtoB;
}
}
return Object.values(eps).sort((a,b)=>(b.bytesTx+b.bytesRx)-(a.bytesTx+a.bytesRx));
}

function fmtRate(bytes,seconds){
if(!bytes||!seconds)return '0 B/s';
const bps=bytes/Math.max(seconds,.001);
if(bps<1024)return bps.toFixed(0)+' B/s';
if(bps<1024*1024)return (bps/1024).toFixed(1)+' KB/s';
return (bps/1048576).toFixed(2)+' MB/s';
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
toast('success','Exported '+filename);
}catch(e){toast('error','Export failed: '+e.message)}
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
}catch(e){toast('error','Failed to open session: '+e.message)}
}

// ── Status bar ──────────────────────────────────────────────────────
function updateStatusBar(data){
const fmt=data.pcap?.metadata?.format||'';
const sz=fmtBytes(data.pcap?.metadata?.fileSize||0);
$('statusFile').textContent=fmt?(fmt+' '+sz):'';
const models=(data.ai?.combined?.models_used||[]).join(', ');
$('statusModel').textContent=models||'';
$('statusSession').textContent=data.sessionId?data.sessionId.substring(0,20):'';
}

// ── Helpers ──────────────────────────────────────────────────────────
function esc(s){if(!s)return'';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function fmtBytes(b){if(!b)return'0 B';const k=1024,s=['B','KB','MB','GB'];const i=Math.floor(Math.log(b)/Math.log(k));return(b/Math.pow(k,i)).toFixed(1)+' '+s[i]}
function formatRemed(text){if(!text)return'';const s=String(text);const steps=s.split(/(?:^|\\s)(\\d+)\\.\\s+/).filter(Boolean);if(steps.length>2){let ol='<ol>';for(let i=0;i<steps.length;i+=2){const t=steps[i+1]||steps[i];if(t&&!/^\\d+$/.test(t.trim()))ol+='<li>'+esc(t.trim())+'</li>'}return ol+'</ol>'}return'<p style="margin-top:6px">'+esc(s)+'</p>'}

// ── Toasts ──────────────────────────────────────────────────────────
function toast(type,message,timeout){
timeout=timeout||(type==='error'?6000:3500);
const el=document.createElement('div');
el.className='toast '+type;
const icons={error:'\u2716',warning:'\u26A0',success:'\u2714',info:'\u2139'};
el.innerHTML='<span class="ticon">'+(icons[type]||icons.info)+'</span><div class="tbody">'+esc(message)+'</div><button class="tclose">\u00D7</button>';
el.querySelector('.tclose').onclick=()=>removeToast(el);
toastsEl.appendChild(el);
if(timeout>0)setTimeout(()=>removeToast(el),timeout);
}
function removeToast(el){
if(!el.parentNode)return;
el.classList.add('closing');
setTimeout(()=>el.remove(),200);
}

// ── Resizable panes ─────────────────────────────────────────────────
function initResizers(){
let dragging=null,startY=0,startTop=0,startMid=0;
const paneTop=$('paneTop'),paneMid=$('paneMid'),paneBot=$('paneBot');
const container=$('paneContainer');

document.querySelectorAll('.pane-resizer').forEach(r=>{
r.addEventListener('mousedown',e=>{
e.preventDefault();
dragging=r.dataset.resize;
startY=e.clientY;
startTop=paneTop.offsetHeight;
startMid=paneMid.offsetHeight;
r.classList.add('dragging');
document.body.style.cursor='ns-resize';
document.body.style.userSelect='none';
});
});
document.addEventListener('mousemove',e=>{
if(!dragging)return;
const dy=e.clientY-startY;
const totalH=container.clientHeight;
if(dragging==='top'){
const newTop=Math.max(100,Math.min(totalH-200,startTop+dy));
paneTop.style.height=newTop+'px';
}else if(dragging==='bot'){
const newMid=Math.max(80,Math.min(totalH-startTop-120,startMid+dy));
paneMid.style.height=newMid+'px';
}
renderVisibleRows();
});
document.addEventListener('mouseup',()=>{
if(dragging){
document.querySelectorAll('.pane-resizer').forEach(r=>r.classList.remove('dragging'));
document.body.style.cursor='';document.body.style.userSelect='';
// Save to localStorage
localStorage.setItem('wpa-panes',JSON.stringify({top:paneTop.offsetHeight,mid:paneMid.offsetHeight}));
dragging=null;
}
});
// Restore saved pane heights
try{
const saved=JSON.parse(localStorage.getItem('wpa-panes')||'{}');
if(saved.top)paneTop.style.height=saved.top+'px';
if(saved.mid)paneMid.style.height=saved.mid+'px';
}catch(_){}
}

// ── Time format toggle ──────────────────────────────────────────────
$('timeToggle').onclick=()=>{
const formats=['relative','absolute','delta'];
const labels={relative:'Relative',absolute:'Absolute',delta:'Delta'};
const idx=formats.indexOf(state.timeFormat);
state.timeFormat=formats[(idx+1)%formats.length];
$('timeToggle').textContent=labels[state.timeFormat];
renderedRows.forEach(el=>el.remove());renderedRows.clear();
renderVisibleRows();
};

// ── Goto packet ─────────────────────────────────────────────────────
$('gotoInput').onkeydown=e=>{
if(e.key==='Enter'){
const n=parseInt(e.target.value,10);
if(!isNaN(n))gotoPacket(n);
e.target.value='';
}
};
function gotoPacket(num){
const pkts=currentPackets();
const idx=pkts.findIndex(p=>p.number===num);
if(idx>=0){selectPacket(idx);scrollPacketIntoView(idx);pktViewport.focus()}
else toast('warning','Packet #'+num+' not found in current view');
}

// ── Follow flow ─────────────────────────────────────────────────────
$('btnFollow').onclick=()=>followSelectedFlow();
function followSelectedFlow(){
const pkts=currentPackets();
const p=pkts[state.selectedIdx];
if(!p||!p.flowId){toast('warning','Select a packet with a flow first');return}
filterInput.value='flow:'+p.flowId.toLowerCase();
applyFilter();
toast('info','Following flow: '+p.flowId);
}

// ── Context menu ────────────────────────────────────────────────────
function showContextMenu(e,p,idx){
hideContextMenu();
const items=[
{label:'Select this packet',action:()=>selectPacket(idx)},
{label:'Follow this flow',shortcut:'f',action:()=>{selectPacket(idx);followSelectedFlow()}},
{label:'Filter by source: '+getSrc(p),action:()=>{filterInput.value='ip.src=='+getSrc(p);applyFilter()},if:getSrc(p)},
{label:'Filter by destination: '+getDst(p),action:()=>{filterInput.value='ip.dst=='+getDst(p);applyFilter()},if:getDst(p)},
{label:'Filter by protocol: '+p.protocol,action:()=>{filterInput.value='proto=='+p.protocol.toLowerCase();applyFilter()}},
{sep:true},
{label:'Copy packet info',action:()=>copyText('#'+p.number+' '+p.protocol+' '+getSrc(p)+' -> '+getDst(p)+' '+p.info)},
{label:'Copy as JSON',action:()=>copyText(JSON.stringify(p,null,2))},
];
let html='';
for(const it of items){
if(it.sep){html+='<div class="ctx-separator"></div>';continue}
if(it.if===false||it.if==='')continue;
html+='<div class="ctx-item" data-i="'+items.indexOf(it)+'">'+esc(it.label)+(it.shortcut?'<span class="shortcut">'+it.shortcut+'</span>':'')+'</div>';
}
ctxMenu.innerHTML=html;
ctxMenu.style.left=Math.min(e.clientX,window.innerWidth-200)+'px';
ctxMenu.style.top=Math.min(e.clientY,window.innerHeight-250)+'px';
ctxMenu.classList.add('open');
ctxMenu.querySelectorAll('.ctx-item').forEach(el=>{
el.onclick=()=>{
const i=parseInt(el.dataset.i,10);
items[i].action();hideContextMenu();
};
});
}
function hideContextMenu(){ctxMenu.classList.remove('open')}
document.addEventListener('click',e=>{if(!ctxMenu.contains(e.target))hideContextMenu()});

// ── Copy actions ────────────────────────────────────────────────────
function copyText(text){
if(navigator.clipboard){
navigator.clipboard.writeText(text).then(()=>toast('success','Copied to clipboard')).catch(()=>toast('error','Copy failed'));
}else{
const ta=document.createElement('textarea');ta.value=text;document.body.appendChild(ta);
ta.select();try{document.execCommand('copy');toast('success','Copied to clipboard')}catch(_){toast('error','Copy failed')}
document.body.removeChild(ta);
}
}
$('btnCopyDetails').onclick=()=>{
const p=currentPackets()[state.selectedIdx];
if(!p){toast('warning','Select a packet first');return}
copyText(JSON.stringify(p.layers,null,2));
};
$('btnCopyHex').onclick=()=>{
const p=currentPackets()[state.selectedIdx];
if(!p||!p.rawBytes){toast('warning','Select a packet first');return}
const hex=p.rawBytes.map(b=>b.toString(16).padStart(2,'0')).join(' ');
copyText(hex);
};
$('btnExpandAll').onclick=()=>{
const open=detailTree.querySelectorAll('.tree-children.open').length;
const all=detailTree.querySelectorAll('.tree-children').length;
const shouldOpen=open<all;
detailTree.querySelectorAll('.tree-children').forEach(c=>c.classList.toggle('open',shouldOpen));
detailTree.querySelectorAll('.tree-toggle').forEach(t=>t.textContent=shouldOpen?'\u25BE':'\u25B8');
};

// ── Keyboard shortcuts ──────────────────────────────────────────────
document.addEventListener('keydown',e=>{
// Don't hijack when typing in input/textarea
const isInput=e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA';
// Esc always works
if(e.key==='Escape'){
if(kbdOverlay.classList.contains('open')){kbdOverlay.classList.remove('open');e.preventDefault();return}
if(ctxMenu.classList.contains('open')){hideContextMenu();e.preventDefault();return}
if(isInput){e.target.blur();return}
if(filterInput.value){clearFilter();return}
}
if(isInput)return;
// Only apply shortcuts when analysis screen is visible
if(!$('analysis-screen').classList.contains('active'))return;

const pkts=currentPackets();
const maxIdx=pkts.length-1;

if(e.key==='j'||e.key==='ArrowDown'){
e.preventDefault();
if(state.selectedIdx<maxIdx)selectPacket(state.selectedIdx+1);
else if(state.selectedIdx===-1&&pkts.length>0)selectPacket(0);
}else if(e.key==='k'||e.key==='ArrowUp'){
e.preventDefault();
if(state.selectedIdx>0)selectPacket(state.selectedIdx-1);
}else if(e.key===' '){
e.preventDefault();
const page=Math.floor(pktViewport.clientHeight/ROW_HEIGHT)-2;
const next=Math.min(maxIdx,(state.selectedIdx<0?0:state.selectedIdx)+(e.shiftKey?-page:page));
selectPacket(next);
}else if(e.key==='g'&&!e.shiftKey&&!e.ctrlKey&&!e.metaKey){
e.preventDefault();selectPacket(0);
}else if(e.key==='G'||(e.key==='g'&&e.shiftKey)){
e.preventDefault();selectPacket(maxIdx);
}else if(e.key==='/'||(e.key==='f'&&(e.ctrlKey||e.metaKey))){
e.preventDefault();filterInput.focus();filterInput.select();
}else if(e.key==='g'&&(e.ctrlKey||e.metaKey)){
e.preventDefault();$('gotoInput').focus();
}else if(e.key==='f'&&!e.ctrlKey&&!e.metaKey){
e.preventDefault();followSelectedFlow();
}else if(e.key==='c'&&(e.ctrlKey||e.metaKey)&&!window.getSelection().toString()){
e.preventDefault();$('btnCopyDetails').click();
}else if(e.key==='t'){
e.preventDefault();$('btnTheme').click();
}else if(e.key==='?'){
e.preventDefault();kbdOverlay.classList.add('open');
}
});

$('btnHelp').onclick=()=>kbdOverlay.classList.add('open');
$('kbdClose').onclick=()=>kbdOverlay.classList.remove('open');
kbdOverlay.onclick=e=>{if(e.target===kbdOverlay)kbdOverlay.classList.remove('open')};

// ── Theme toggle ────────────────────────────────────────────────────
function initTheme(){
const saved=localStorage.getItem('wpa-theme');
const theme=saved||(window.matchMedia('(prefers-color-scheme:light)').matches?'light':'dark');
applyTheme(theme);
}
function applyTheme(theme){
document.documentElement.setAttribute('data-theme',theme);
localStorage.setItem('wpa-theme',theme);
$('themeIcon').textContent=theme==='dark'?'\u2600\uFE0F':'\u{1F319}';
}
$('btnTheme').onclick=()=>{
const current=document.documentElement.getAttribute('data-theme')||'dark';
applyTheme(current==='dark'?'light':'dark');
};

// ── Init ────────────────────────────────────────────────────────────
initTheme();
initResizers();
loadSessions();
})();
</script>
</body>
</html>`;
