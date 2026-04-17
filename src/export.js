/**
 * Multi-format Export
 * Exports session analysis data as CSV, JSON, HAR, or printable HTML report.
 */

/**
 * Export session data in the requested format.
 * @param {Object} session  Full session data from getFullSession()
 * @param {string} format   'json' | 'csv' | 'har' | 'html'
 * @returns {{ body: string, contentType: string, filename: string }}
 */
export function exportSession(session, format) {
	switch (format) {
		case 'json': return exportJSON(session);
		case 'csv': return exportCSV(session);
		case 'har': return exportHAR(session);
		case 'html': return exportHTML(session);
		default:
			throw new Error(`Unsupported export format: ${format}. Use json, csv, har, or html.`);
	}
}

// ── JSON export ────────────────────────────────────────────────────────────────

function exportJSON(session) {
	const data = {
		exportedAt: new Date().toISOString(),
		session: {
			id: session.meta.id,
			fileName: session.meta.fileName,
			fileSize: session.meta.fileSize,
			createdAt: session.meta.createdAt,
			captureMetadata: session.meta.captureMetadata,
		},
		statistics: session.stats,
		flows: session.flows,
		aiAnalysis: session.ai,
		warpDiagnostics: session.warp,
		packets: session.packets?.map(p => ({
			number: p.number,
			timestamp: p.timestamp,
			protocol: p.protocol,
			info: p.info,
			capturedLength: p.capturedLength,
			originalLength: p.originalLength,
			layers: p.layers,
			warnings: p.warnings,
			flowId: p.flowId,
		})),
	};

	return {
		body: JSON.stringify(data, null, 2),
		contentType: 'application/json',
		filename: `${session.meta.fileName || 'analysis'}-export.json`,
	};
}

// ── CSV export ─────────────────────────────────────────────────────────────────

function exportCSV(session) {
	const packets = session.packets || [];
	const headers = [
		'No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length',
		'Info', 'Src Port', 'Dst Port', 'TCP Flags', 'Flow ID', 'Warnings',
	];

	const rows = packets.map(p => {
		const src = p.layers.ipv4?.src || p.layers.ipv6?.src || p.layers.arp?.senderIP || '';
		const dst = p.layers.ipv4?.dst || p.layers.ipv6?.dst || p.layers.arp?.targetIP || '';
		const srcPort = p.layers.tcp?.srcPort || p.layers.udp?.srcPort || '';
		const dstPort = p.layers.tcp?.dstPort || p.layers.udp?.dstPort || '';
		const flags = p.layers.tcp?.flags?.join(',') || '';

		return [
			p.number,
			p.timestamp,
			src,
			dst,
			p.protocol,
			p.capturedLength,
			csvEscape(p.info),
			srcPort,
			dstPort,
			flags,
			csvEscape(p.flowId),
			csvEscape(p.warnings?.join('; ') || ''),
		].join(',');
	});

	const csv = [headers.join(','), ...rows].join('\n');

	return {
		body: csv,
		contentType: 'text/csv',
		filename: `${session.meta.fileName || 'packets'}-export.csv`,
	};
}

function csvEscape(str) {
	if (!str) return '';
	str = String(str);
	if (str.includes(',') || str.includes('"') || str.includes('\n')) {
		return '"' + str.replace(/"/g, '""') + '"';
	}
	return str;
}

// ── HAR export ─────────────────────────────────────────────────────────────────

function exportHAR(session) {
	const packets = session.packets || [];

	// Build entries from HTTP requests/responses
	const httpPackets = packets.filter(p => p.layers.http);
	const entries = httpPackets.map(p => {
		const http = p.layers.http;
		const src = p.layers.ipv4?.src || p.layers.ipv6?.src || '';
		const dst = p.layers.ipv4?.dst || p.layers.ipv6?.dst || '';
		const dstPort = p.layers.tcp?.dstPort || 80;

		const entry = {
			startedDateTime: new Date(p.timestamp * 1000).toISOString(),
			time: 0,
			request: {
				method: http.method || 'GET',
				url: buildUrl(http, dst, dstPort),
				httpVersion: http.version || 'HTTP/1.1',
				cookies: [],
				headers: Object.entries(http.headers || {}).map(([k, v]) => ({ name: k, value: v })),
				queryString: [],
				headersSize: -1,
				bodySize: -1,
			},
			response: {
				status: http.statusCode || 0,
				statusText: http.statusText || '',
				httpVersion: http.version || 'HTTP/1.1',
				cookies: [],
				headers: [],
				content: { size: 0, mimeType: '' },
				redirectURL: '',
				headersSize: -1,
				bodySize: -1,
			},
			cache: {},
			timings: { send: 0, wait: 0, receive: 0 },
			serverIPAddress: dst,
			connection: `${dstPort}`,
			comment: `Packet ${p.number}`,
		};

		if (http.isResponse) {
			entry.response.status = http.statusCode;
			entry.response.statusText = http.statusText || '';
			entry.response.headers = Object.entries(http.headers || {}).map(([k, v]) => ({ name: k, value: v }));
			entry.response.content.mimeType = http.headers?.['Content-Type'] || http.headers?.['content-type'] || '';
		}

		return entry;
	});

	// Also include TLS SNI as pseudo-entries
	const tlsPackets = packets.filter(p => p.layers.tls?.sni);
	const tlsEntries = tlsPackets.map(p => ({
		startedDateTime: new Date(p.timestamp * 1000).toISOString(),
		time: 0,
		request: {
			method: 'CONNECT',
			url: `https://${p.layers.tls.sni}/`,
			httpVersion: p.layers.tls.versionName || 'TLS',
			cookies: [], headers: [], queryString: [],
			headersSize: -1, bodySize: -1,
		},
		response: { status: 0, statusText: '', httpVersion: '', cookies: [], headers: [], content: { size: 0, mimeType: '' }, redirectURL: '', headersSize: -1, bodySize: -1 },
		cache: {},
		timings: { send: 0, wait: 0, receive: 0 },
		comment: `TLS ClientHello - Packet ${p.number}`,
	}));

	const har = {
		log: {
			version: '1.2',
			creator: { name: 'WARP & PCAP Analyzer', version: '2.0.0' },
			entries: [...entries, ...tlsEntries].sort((a, b) => new Date(a.startedDateTime) - new Date(b.startedDateTime)),
			comment: `Exported from session ${session.meta.id}`,
		},
	};

	return {
		body: JSON.stringify(har, null, 2),
		contentType: 'application/json',
		filename: `${session.meta.fileName || 'capture'}-export.har`,
	};
}

function buildUrl(http, ip, port) {
	const host = http.headers?.['Host'] || http.headers?.['host'] || ip;
	const scheme = port === 443 ? 'https' : 'http';
	const uri = http.uri || '/';
	return `${scheme}://${host}${uri}`;
}

// ── HTML report export ─────────────────────────────────────────────────────────

function exportHTML(session) {
	const meta = session.meta;
	const stats = session.stats || {};
	const ai = session.ai?.analysis || session.ai?.fallback || {};
	const packets = session.packets || [];
	const flows = session.flows || {};

	const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PCAP Analysis Report - ${esc(meta.fileName)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Inter,-apple-system,BlinkMacSystemFont,sans-serif;background:#fff;color:#1a1a2e;padding:40px;max-width:1200px;margin:0 auto;font-size:14px;line-height:1.6}
h1{font-size:28px;font-weight:700;margin-bottom:8px;color:#0d1117}
h2{font-size:20px;font-weight:600;margin:30px 0 15px;padding-bottom:8px;border-bottom:2px solid #f38020;color:#1a1a2e}
h3{font-size:16px;font-weight:600;margin:20px 0 10px;color:#1a1a2e}
.subtitle{color:#6b7280;font-size:14px;margin-bottom:30px}
.badge{display:inline-block;padding:4px 12px;border-radius:4px;font-size:12px;font-weight:600;text-transform:uppercase}
.badge-healthy{background:#d1f5d3;color:#0f7a1c}
.badge-degraded{background:#ffe8b8;color:#8a5700}
.badge-critical{background:#ffd4d4;color:#c41e3a}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin:15px 0}
.stat-card{background:#f8f9fa;border:1px solid #e0e0e0;border-radius:6px;padding:15px}
.stat-label{font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:0.5px}
.stat-value{font-size:24px;font-weight:700;color:#1a1a2e;margin-top:4px}
.issue{border:1px solid #e0e0e0;border-radius:6px;padding:16px;margin:10px 0;border-left:4px solid #3e74ff}
.issue.critical{border-left-color:#c41e3a}.issue.warning{border-left-color:#f38020}
.issue-title{font-weight:600;margin-bottom:6px}
.issue-desc{color:#4b5563;margin-bottom:8px}
.remediation{background:#f8f9fa;padding:12px;border-radius:4px;border-left:3px solid #f38020}
table{width:100%;border-collapse:collapse;margin:15px 0;font-size:13px}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #e0e0e0}
th{background:#f8f9fa;font-weight:600;color:#1a1a2e;font-size:12px;text-transform:uppercase;letter-spacing:0.3px}
tr:hover{background:#f8f9fa}
.mono{font-family:Monaco,Menlo,monospace;font-size:12px}
.footer{margin-top:40px;padding-top:20px;border-top:1px solid #e0e0e0;color:#6b7280;font-size:12px;text-align:center}
@media print{body{padding:20px}h2{page-break-before:auto}table{page-break-inside:auto}}
</style>
</head>
<body>
<h1>Network Capture Analysis Report</h1>
<p class="subtitle">
File: ${esc(meta.fileName)} | Size: ${formatBytes(meta.fileSize)} | Generated: ${new Date().toLocaleString()}<br>
Session: ${esc(meta.id)} | Created: ${meta.createdAt}
</p>

<h2>Health Status</h2>
<span class="badge badge-${(ai.health_status || 'unknown').toLowerCase()}">${esc(ai.health_status || 'Unknown')}</span>
<p style="margin-top:10px">${esc(ai.summary || 'No summary available')}</p>

<h2>Capture Statistics</h2>
<div class="stats-grid">
<div class="stat-card"><div class="stat-label">Total Packets</div><div class="stat-value">${stats.totalPackets?.toLocaleString() || 0}</div></div>
<div class="stat-card"><div class="stat-label">Total Bytes</div><div class="stat-value">${formatBytes(stats.totalBytes || 0)}</div></div>
<div class="stat-card"><div class="stat-label">Duration</div><div class="stat-value">${stats.duration?.toFixed(3) || 0}s</div></div>
<div class="stat-card"><div class="stat-label">Avg Packet Size</div><div class="stat-value">${stats.avgPacketSize || 0} B</div></div>
<div class="stat-card"><div class="stat-label">Protocols</div><div class="stat-value">${Object.keys(stats.protocols || {}).length}</div></div>
<div class="stat-card"><div class="stat-label">Flows</div><div class="stat-value">${Object.keys(flows).length}</div></div>
</div>

${stats.protocols ? `<h3>Protocol Distribution</h3>
<table><tr><th>Protocol</th><th>Packets</th><th>% of Total</th></tr>
${Object.entries(stats.protocols).sort((a,b)=>b[1]-a[1]).map(([p,c])=>`<tr><td>${esc(p)}</td><td>${c}</td><td>${((c/stats.totalPackets)*100).toFixed(1)}%</td></tr>`).join('')}
</table>` : ''}

${(ai.issues?.length > 0) ? `<h2>Issues Detected (${ai.issues.length})</h2>
${ai.issues.map(i => `<div class="issue ${(i.severity||'').toLowerCase()}">
<div class="issue-title">${severityIcon(i.severity)} ${esc(i.title||'')}</div>
<div class="issue-desc">${esc(i.description||'')}</div>
${i.root_cause ? `<p><strong>Root Cause:</strong> ${esc(i.root_cause)}</p>` : ''}
${i.remediation ? `<div class="remediation"><strong>Remediation:</strong> ${formatRemed(i.remediation)}</div>` : ''}
</div>`).join('')}` : ''}

${(ai.recommendations?.length > 0) ? `<h2>Recommendations</h2><ul>${ai.recommendations.map(r=>`<li>${esc(r)}</li>`).join('')}</ul>` : ''}

${Object.keys(flows).length > 0 ? `<h2>Top Conversations</h2>
<table><tr><th>Flow</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>State</th></tr>
${Object.values(flows).sort((a,b)=>(b.bytesAtoB+b.bytesBtoA)-(a.bytesAtoB+a.bytesBtoA)).slice(0,25).map(f=>
`<tr><td class="mono">${esc(f.srcIP)}:${f.srcPort} ↔ ${esc(f.dstIP)}:${f.dstPort}</td><td>${f.protocol}${f.appProtocol?'/'+f.appProtocol:''}</td><td>${f.packetsAtoB+f.packetsBtoA}</td><td>${formatBytes(f.bytesAtoB+f.bytesBtoA)}</td><td>${f.tcpState||'N/A'}</td></tr>`).join('')}
</table>` : ''}

<h2>Packet Summary (first ${Math.min(100, packets.length)} of ${packets.length})</h2>
<table><tr><th>No.</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Info</th></tr>
${packets.slice(0,100).map(p=>{
const src=p.layers.ipv4?.src||p.layers.ipv6?.src||p.layers.arp?.senderIP||'';
const dst=p.layers.ipv4?.dst||p.layers.ipv6?.dst||p.layers.arp?.targetIP||'';
return `<tr><td>${p.number}</td><td class="mono">${p.timestamp.toFixed(6)}</td><td class="mono">${esc(src)}</td><td class="mono">${esc(dst)}</td><td>${esc(p.protocol)}</td><td>${p.capturedLength}</td><td class="mono" style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(p.info)}</td></tr>`;
}).join('')}
</table>

<div class="footer">
Generated by WARP & PCAP Analyzer v2.0 | Powered by Cloudflare Workers AI
</div>
</body></html>`;

	return {
		body: html,
		contentType: 'text/html',
		filename: `${session.meta.fileName || 'analysis'}-report.html`,
	};
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function esc(str) {
	if (!str) return '';
	return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function formatBytes(bytes) {
	if (!bytes || bytes === 0) return '0 B';
	const k = 1024;
	const sizes = ['B', 'KB', 'MB', 'GB'];
	const i = Math.floor(Math.log(bytes) / Math.log(k));
	return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function severityIcon(sev) {
	if (sev === 'Critical') return '[CRITICAL]';
	if (sev === 'Warning') return '[WARNING]';
	return '[INFO]';
}

function formatRemed(text) {
	if (!text) return '';
	const steps = String(text).split(/\d+\.\s+/).filter(Boolean);
	if (steps.length > 1) {
		return '<ol>' + steps.map(s => `<li>${esc(s.trim())}</li>`).join('') + '</ol>';
	}
	return esc(text);
}
