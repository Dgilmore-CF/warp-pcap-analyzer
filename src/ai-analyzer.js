/**
 * Multi-model AI Analysis Engine
 * Uses different Workers AI models optimised for each analysis type:
 *   - Llama 4 Scout 17B: Deep reasoning on WARP diagnostics (largest context)
 *   - Llama 3.3 70B Fast: Quick PCAP security assessment
 *   - DeepSeek R1 32B: Complex root-cause analysis
 *
 * Each model is called via the Workers AI binding with structured JSON output.
 */

// ── Model registry ─────────────────────────────────────────────────────────────

const MODELS = {
	LLAMA4_SCOUT: '@cf/meta/llama-4-scout-17b-16e-instruct',
	LLAMA33_FAST: '@cf/meta/llama-3.3-70b-instruct-fp8-fast',
	DEEPSEEK_R1: '@cf/deepseek-ai/deepseek-r1-distill-qwen-32b',
};

const MODEL_CONFIG = {
	[MODELS.LLAMA4_SCOUT]: { contextWindow: 131000, maxTokens: 4096, label: 'Llama 4 Scout 17B' },
	[MODELS.LLAMA33_FAST]: { contextWindow: 24000, maxTokens: 3072, label: 'Llama 3.3 70B Fast' },
	[MODELS.DEEPSEEK_R1]: { contextWindow: 80000, maxTokens: 4096, label: 'DeepSeek R1 32B' },
};

// ── Routing logic ──────────────────────────────────────────────────────────────

/**
 * Select the best model for a given analysis type and input size.
 */
function selectModel(analysisType, estimatedTokens) {
	switch (analysisType) {
		case 'pcap_security':
			return estimatedTokens > 20000 ? MODELS.LLAMA4_SCOUT : MODELS.LLAMA33_FAST;
		case 'pcap_deep':
			return MODELS.LLAMA4_SCOUT;
		case 'warp_diagnostics':
			return MODELS.LLAMA4_SCOUT;
		case 'root_cause':
			return estimatedTokens > 60000 ? MODELS.LLAMA4_SCOUT : MODELS.DEEPSEEK_R1;
		default:
			return MODELS.LLAMA4_SCOUT;
	}
}

// ── System prompts ─────────────────────────────────────────────────────────────

const PCAP_ANALYSIS_PROMPT = `You are an expert network packet analyst and security engineer. You analyse PCAP captures with the precision of Wireshark combined with security threat intelligence.

When analysing packet data:
1. Identify security threats, anomalies, and misconfigurations
2. Detect performance issues (retransmissions, high latency, window scaling problems)
3. Classify each finding by severity: Critical, Warning, Info
4. Provide evidence by referencing specific packet numbers, IPs, ports, and timestamps
5. For TCP flows: note handshake issues, resets, zero windows, retransmissions
6. For DNS: detect tunnelling, unusual queries, NXDOMAIN storms, slow responses
7. For TLS: identify outdated versions, weak ciphers, certificate issues, failed handshakes
8. For Cloudflare WARP traffic (port 2408): assess tunnel health and performance

For evidence_keywords, use EXACT packet identifiers like "Packet 42", IP addresses, port numbers, DNS names, and error messages from the data. These are used to highlight relevant packets in the UI.

Respond ONLY with valid JSON, no markdown fences.`;

const WARP_DIAGNOSTICS_PROMPT = `You are an expert Cloudflare WARP and Zero Trust diagnostics engineer. You analyse WARP client diagnostic bundles to identify connectivity, performance, and configuration issues.

Analyse the following diagnostic data and:
1. Identify root causes, not just symptoms
2. Classify issues by severity: Critical (service down), Warning (degraded), Info (observation)
3. Provide specific, numbered remediation steps
4. Note timestamps and event sequences
5. Cross-reference across log files (e.g., daemon.log errors matching connectivity.txt failures)
6. Look for: tunnel failures, auth issues, DNS problems, split tunnel misconfig, certificate errors, firewall blocks, MTU issues

For evidence_keywords, use EXACT error messages, IP addresses, timestamps, and distinctive strings from the logs. These drive the log evidence viewer in the UI.

Respond ONLY with valid JSON, no markdown fences.`;

// ── Public API ─────────────────────────────────────────────────────────────────

/**
 * Analyse PCAP decoded data with AI.
 * @param {Object} ai         Workers AI binding
 * @param {Object} pcapData   { stats, flows, packets (summary), metadata }
 * @returns {Promise<Object>}
 */
export async function analyzePcapWithAI(ai, pcapData) {
	const context = buildPcapContext(pcapData);
	const estimatedTokens = Math.ceil(context.length / 3.5);
	const model = selectModel('pcap_deep', estimatedTokens);
	const config = MODEL_CONFIG[model];

	const maxContextChars = Math.floor((config.contextWindow - 2000) * 3.5);
	const truncatedContext = context.length > maxContextChars
		? context.substring(0, maxContextChars) + '\n\n[Context truncated due to size]'
		: context;

	const userPrompt = `Analyse this network capture and provide a comprehensive security and performance assessment.

${truncatedContext}

Provide your analysis as JSON with this exact structure:
{
  "summary": "Brief overall assessment of the capture",
  "health_status": "Healthy|Degraded|Critical",
  "capture_profile": {
    "duration_seconds": 0,
    "total_packets": 0,
    "protocols_seen": ["TCP", "UDP", "DNS"],
    "unique_hosts": 0,
    "primary_activity": "Description of main network activity"
  },
  "issues": [
    {
      "severity": "Critical|Warning|Info",
      "category": "Security|Performance|Configuration|Protocol|DNS|TLS",
      "title": "Issue title",
      "description": "Detailed description with packet references",
      "root_cause": "Root cause analysis",
      "remediation": "1. Step one 2. Step two 3. Step three",
      "evidence_keywords": ["Packet 42", "192.168.1.1", "RST", "specific error text"],
      "affected_packets": [42, 43, 44]
    }
  ],
  "security_assessment": {
    "risk_level": "Low|Medium|High|Critical",
    "findings": ["Finding 1", "Finding 2"],
    "recommendations": ["Rec 1", "Rec 2"]
  },
  "performance_assessment": {
    "overall": "Good|Fair|Poor",
    "latency": "Description",
    "throughput": "Description",
    "retransmissions": "Description"
  },
  "timeline": [
    {
      "timestamp": "timestamp or relative time",
      "event": "Event description",
      "severity": "Critical|Warning|Info|Success",
      "packet_ref": 1,
      "details": "Additional context"
    }
  ],
  "recommendations": ["Recommendation 1", "Recommendation 2"]
}`;

	try {
		const response = await ai.run(model, {
			messages: [
				{ role: 'system', content: PCAP_ANALYSIS_PROMPT },
				{ role: 'user', content: userPrompt },
			],
			temperature: 0.1,
			max_tokens: config.maxTokens,
		});

		const result = parseAIResponse(response);

		return {
			success: true,
			analysis: result,
			model: config.label,
			modelId: model,
			tokensEstimated: estimatedTokens,
		};
	} catch (error) {
		console.error('PCAP AI analysis failed:', error);
		return {
			success: false,
			error: error.message,
			model: config.label,
			fallback: generatePcapFallbackAnalysis(pcapData),
		};
	}
}

/**
 * Analyse WARP diagnostic files with AI.
 * @param {Object} ai        Workers AI binding
 * @param {Array}  logFiles   Array of { filename, content, category, priority, keyInfo }
 * @param {Object} pcapMeta   Optional PCAP metadata from the diag bundle
 * @returns {Promise<Object>}
 */
export async function analyzeWarpDiagnostics(ai, logFiles, pcapMeta) {
	const context = buildWarpContext(logFiles, pcapMeta);
	const estimatedTokens = Math.ceil(context.length / 3.5);
	const model = selectModel('warp_diagnostics', estimatedTokens);
	const config = MODEL_CONFIG[model];

	const maxContextChars = Math.floor((config.contextWindow - 2000) * 3.5);
	const truncatedContext = context.length > maxContextChars
		? context.substring(0, maxContextChars) + '\n\n[Context truncated due to size]'
		: context;

	const userPrompt = `Analyse these Cloudflare WARP diagnostic files and provide a comprehensive report.

## Files Included
${logFiles.map(f => `- ${f.filename} (${f.category}, ${f.priority} priority)`).join('\n')}

${pcapMeta ? `## Embedded PCAP\n${JSON.stringify(pcapMeta, null, 2)}\n` : ''}

## Diagnostic Content
${truncatedContext}

Provide your analysis as JSON:
{
  "summary": "Brief overall assessment",
  "health_status": "Healthy|Degraded|Critical",
  "issues": [
    {
      "severity": "Critical|Warning|Info",
      "category": "Connection|DNS|Performance|Configuration|Security|Network",
      "title": "Issue title",
      "description": "Detailed description",
      "root_cause": "Root cause analysis",
      "remediation": "1. Step one 2. Step two",
      "affected_files": ["daemon.log"],
      "timestamps": ["2024-01-01T00:00:00"],
      "evidence_keywords": ["exact error message", "IP address", "specific log text"]
    }
  ],
  "timeline": [
    {
      "timestamp": "ISO timestamp or log timestamp",
      "event": "Event description",
      "event_type": "Connection|Configuration|Error|State|Network|DNS|Info",
      "severity": "Critical|Warning|Info|Success",
      "source_file": "filename.log",
      "details": "Additional context"
    }
  ],
  "recommendations": ["Recommendation 1", "Recommendation 2"],
  "configuration_review": {
    "split_tunnel": "Correct|Misconfigured|Not configured",
    "dns_settings": "Description",
    "certificate_status": "Valid|Issues found|Unknown",
    "warp_mode": "Mode name",
    "notes": ["Note 1"]
  }
}`;

	try {
		const response = await ai.run(model, {
			messages: [
				{ role: 'system', content: WARP_DIAGNOSTICS_PROMPT },
				{ role: 'user', content: userPrompt },
			],
			temperature: 0.1,
			max_tokens: config.maxTokens,
		});

		const result = parseAIResponse(response);

		if (result.issues) {
			result.issues = result.issues.map(issue => enrichIssueWithLogEvidence(issue, logFiles));
		}
		if (result.timeline) {
			result.timeline = enrichTimelineWithLogReferences(result.timeline, logFiles);
		}

		return {
			success: true,
			analysis: result,
			model: config.label,
			modelId: model,
			tokensEstimated: estimatedTokens,
			filesAnalyzed: logFiles.length,
		};
	} catch (error) {
		console.error('WARP AI analysis failed:', error);
		return {
			success: false,
			error: error.message,
			model: config.label,
			fallback: generateWarpFallbackAnalysis(logFiles, pcapMeta),
		};
	}
}

// ── Context builders ───────────────────────────────────────────────────────────

function buildPcapContext(pcapData) {
	const sections = [];

	sections.push(`## Capture Metadata
Format: ${pcapData.metadata?.format || 'Unknown'}
Total Packets: ${pcapData.stats?.totalPackets || 0}
Duration: ${pcapData.stats?.duration?.toFixed(3) || 0}s
Total Bytes: ${pcapData.stats?.totalBytes || 0}
Average Packet Size: ${pcapData.stats?.avgPacketSize || 0} bytes`);

	if (pcapData.stats?.protocols) {
		sections.push(`## Protocol Distribution
${Object.entries(pcapData.stats.protocols).sort((a, b) => b[1] - a[1]).map(([p, c]) => `- ${p}: ${c} packets`).join('\n')}`);
	}

	if (pcapData.stats?.topTalkers) {
		sections.push(`## Top Talkers (by bytes)
${Object.entries(pcapData.stats.topTalkers).slice(0, 10).map(([ip, bytes]) => `- ${ip}: ${bytes} bytes`).join('\n')}`);
	}

	if (pcapData.stats?.dnsQueries?.length > 0) {
		const queries = pcapData.stats.dnsQueries.slice(0, 50);
		sections.push(`## DNS Queries (${pcapData.stats.dnsQueries.length} total, showing ${queries.length})
${queries.map(q => `- Packet ${q.packet}: ${q.isResponse ? 'Response' : 'Query'} ${q.type} ${q.query}${q.rcode !== 'No Error' ? ` [${q.rcode}]` : ''}${q.answers.length ? ` → ${q.answers.join(', ')}` : ''}`).join('\n')}`);
	}

	if (pcapData.stats?.tlsConnections?.length > 0) {
		sections.push(`## TLS Connections
${pcapData.stats.tlsConnections.slice(0, 30).map(t => `- Packet ${t.packet}: ${t.version} SNI=${t.sni}${t.alpn ? ` ALPN=[${t.alpn.join(',')}]` : ''}`).join('\n')}`);
	}

	if (pcapData.stats?.httpRequests?.length > 0) {
		sections.push(`## HTTP Requests
${pcapData.stats.httpRequests.slice(0, 30).map(r => `- Packet ${r.packet}: ${r.method} ${r.host}${r.uri}`).join('\n')}`);
	}

	if (pcapData.stats?.warningsSummary && Object.keys(pcapData.stats.warningsSummary).length > 0) {
		sections.push(`## Packet Warnings
${Object.entries(pcapData.stats.warningsSummary).map(([w, c]) => `- ${w}: ${c} occurrences`).join('\n')}`);
	}

	if (pcapData.flows) {
		const flowList = Object.values(pcapData.flows);
		const topFlows = flowList.sort((a, b) => (b.bytesAtoB + b.bytesBtoA) - (a.bytesAtoB + a.bytesBtoA)).slice(0, 20);
		sections.push(`## Top Flows (${flowList.length} total, showing ${topFlows.length})
${topFlows.map(f => `- ${f.id}: ${f.packetsAtoB + f.packetsBtoA} pkts, ${f.bytesAtoB + f.bytesBtoA} bytes, ${f.protocol}${f.appProtocol ? `/${f.appProtocol}` : ''} [${f.tcpState || 'N/A'}]${f.warnings.length ? ` ⚠ ${f.warnings.join(', ')}` : ''}`).join('\n')}`);
	}

	if (pcapData.packets) {
		const sample = [];
		const warnings = pcapData.packets.filter(p => p.warnings.length > 0).slice(0, 50);
		const firstN = pcapData.packets.slice(0, Math.min(100, pcapData.packets.length));
		const seen = new Set();
		for (const p of [...firstN, ...warnings]) {
			if (!seen.has(p.number)) { seen.add(p.number); sample.push(p); }
		}
		sample.sort((a, b) => a.number - b.number);

		sections.push(`## Packet Samples (${sample.length} of ${pcapData.packets.length})
${sample.map(p => `[Packet ${p.number}] ${p.protocol} | ${p.info}${p.warnings.length ? ` | ⚠ ${p.warnings.join('; ')}` : ''}`).join('\n')}`);
	}

	return sections.join('\n\n');
}

function buildWarpContext(logFiles) {
	const sections = { keyLogs: '', networkConfig: '', connectionInfo: '' };

	for (const file of logFiles) {
		const maxLen = 5000;
		const lines = file.content.split('\n');
		let numbered = '';
		let charCount = 0;

		for (let i = 0; i < lines.length && charCount < maxLen; i++) {
			const line = lines[i];
			if (line.trim()) {
				numbered += `[Line ${i + 1}] ${line}\n`;
				charCount += line.length;
			}
		}
		if (charCount >= maxLen) numbered += '... (truncated)\n';

		const header = `\n### ${file.filename} [${file.category}/${file.priority}]\n`;
		if (file.category === 'connection') sections.connectionInfo += header + numbered;
		else if (file.category === 'network') sections.networkConfig += header + numbered;
		else sections.keyLogs += header + numbered;
	}

	return `## Connection & Status\n${sections.connectionInfo}\n\n## Network Configuration\n${sections.networkConfig}\n\n## Logs & Configuration\n${sections.keyLogs}`;
}

// ── Evidence enrichment ────────────────────────────────────────────────────────

function enrichIssueWithLogEvidence(issue, logFiles) {
	const logEntries = [];
	const keywords = issue.evidence_keywords || [];
	const affectedFiles = issue.affected_files || [];
	const timestamps = issue.timestamps || [];

	const filesToSearch = affectedFiles.length > 0
		? logFiles.filter(f => affectedFiles.some(af => f.filename.includes(af)))
		: logFiles;

	const seenLines = new Set();

	for (const file of filesToSearch) {
		const lines = file.content.split('\n');
		const matched = [];

		for (let i = 0; i < lines.length && matched.length < 15; i++) {
			const line = lines[i];
			const lower = line.toLowerCase();
			const key = `${file.filename}:${i}`;
			if (seenLines.has(key)) continue;

			let score = 0;
			for (const kw of keywords) {
				if (kw && lower.includes(String(kw).toLowerCase())) score += 10;
			}
			for (const ts of timestamps) {
				if (ts && line.includes(ts)) score += 8;
			}
			if (lower.includes('error') || lower.includes('fail')) score += 3;
			if (lower.includes('critical')) score += 4;

			if (score > 0) {
				seenLines.add(key);
				const ctx = [];
				for (let j = Math.max(0, i - 2); j <= Math.min(lines.length - 1, i + 2); j++) {
					if (lines[j].trim()) ctx.push((j === i ? '>>> ' : '    ') + lines[j]);
				}
				matched.push({ filename: file.filename, lineNumber: i + 1, content: ctx.join('\n').substring(0, 800), matchScore: score });
			}
		}

		matched.sort((a, b) => b.matchScore - a.matchScore);
		logEntries.push(...matched);
	}

	return { ...issue, log_entries: logEntries.slice(0, 25) };
}

function enrichTimelineWithLogReferences(timeline, logFiles) {
	return timeline.map(event => {
		const enriched = { ...event };
		const terms = [];
		if (event.timestamp) terms.push(event.timestamp);
		if (event.details) terms.push(event.details);

		const targets = event.source_file
			? logFiles.filter(f => f.filename.includes(event.source_file))
			: logFiles;

		let best = null;
		let bestScore = 0;

		for (const file of targets) {
			const lines = file.content.split('\n');
			for (let i = 0; i < lines.length; i++) {
				const lower = lines[i].toLowerCase();
				let score = 0;
				for (const t of terms) {
					if (t && lower.includes(String(t).toLowerCase())) score += 5;
				}
				if (event.timestamp && lines[i].includes(event.timestamp)) score += 20;
				if (score > bestScore) {
					bestScore = score;
					best = { filename: file.filename, lineNumber: i + 1, content: lines[i].trim() };
				}
			}
		}

		if (best) enriched.log_reference = best;
		return enriched;
	});
}

// ── Response parsing ───────────────────────────────────────────────────────────

function parseAIResponse(response) {
	try {
		let text = '';
		if (response.response) text = response.response;
		else if (response.result?.response) text = response.result.response;
		else if (typeof response === 'string') text = response;

		text = text.replace(/```json\s*/gi, '').replace(/```\s*/g, '').trim();

		const jsonMatch = text.match(/\{[\s\S]*\}/);
		if (jsonMatch) return JSON.parse(jsonMatch[0]);

		return { summary: text, health_status: 'Unknown', issues: [], timeline: [], recommendations: [] };
	} catch (e) {
		console.error('AI response parse error:', e);
		return { summary: 'Analysis completed but response parsing failed', health_status: 'Unknown', issues: [], timeline: [], recommendations: [], raw_response: String(response) };
	}
}

// ── Fallback analysis ──────────────────────────────────────────────────────────

function generatePcapFallbackAnalysis(pcapData) {
	const issues = [];
	const stats = pcapData.stats || {};

	const rstCount = stats.warningsSummary?.['TCP Reset'] || 0;
	if (rstCount > 0) {
		issues.push({ severity: rstCount > 10 ? 'Critical' : 'Warning', category: 'Protocol', title: `${rstCount} TCP Reset(s) detected`, description: 'TCP connections being forcefully terminated', root_cause: 'Firewall blocking, application crash, or misconfiguration', remediation: '1. Check firewall rules 2. Verify application health 3. Review TCP keepalive settings', evidence_keywords: ['RST'] });
	}

	const dnsErrors = (stats.dnsQueries || []).filter(q => q.rcode && q.rcode !== 'No Error');
	if (dnsErrors.length > 0) {
		issues.push({ severity: 'Warning', category: 'DNS', title: `${dnsErrors.length} DNS error(s)`, description: `DNS failures: ${dnsErrors.map(q => `${q.query} (${q.rcode})`).join(', ')}`, root_cause: 'DNS misconfiguration or non-existent domains', remediation: '1. Verify DNS settings 2. Check domain registrations 3. Test alternative resolvers', evidence_keywords: dnsErrors.map(q => q.query) });
	}

	const zeroWin = stats.warningsSummary?.['Zero window (possible flow control issue)'] || 0;
	if (zeroWin > 0) {
		issues.push({ severity: 'Warning', category: 'Performance', title: 'TCP Zero Window conditions', description: `${zeroWin} zero-window packets indicating flow control issues`, root_cause: 'Receiver buffer full', remediation: '1. Check application performance 2. Increase TCP buffer sizes 3. Review bandwidth', evidence_keywords: ['Zero window'] });
	}

	return {
		summary: `Rule-based: ${stats.totalPackets || 0} packets, ${Object.keys(stats.protocols || {}).length} protocols. ${issues.length} issues.`,
		health_status: issues.some(i => i.severity === 'Critical') ? 'Critical' : issues.length > 0 ? 'Degraded' : 'Healthy',
		issues, timeline: [], recommendations: ['Use AI-enabled analysis for deeper insights', 'Examine packets in the browser'],
		note: 'AI unavailable. Rule-based fallback.',
	};
}

function generateWarpFallbackAnalysis(logFiles) {
	const issues = [];
	for (const file of logFiles) {
		const c = file.content.toLowerCase();
		if (c.includes('failed to connect') || c.includes('connection refused'))
			issues.push({ severity: 'Critical', category: 'Connection', title: 'Connection failure', description: `Issues in ${file.filename}`, root_cause: 'Unable to establish tunnel', remediation: '1. Check network 2. Verify firewall 3. Restart WARP', affected_files: [file.filename], evidence_keywords: ['failed to connect', 'connection refused'] });
		if (c.includes('dns timeout') || c.includes('nxdomain'))
			issues.push({ severity: 'Warning', category: 'DNS', title: 'DNS resolution problems', description: `DNS errors in ${file.filename}`, root_cause: 'DNS resolver issues', remediation: '1. Verify DNS settings 2. Check config 3. Test alt resolver', affected_files: [file.filename], evidence_keywords: ['dns timeout', 'nxdomain'] });
		if (c.includes('certificate') && (c.includes('invalid') || c.includes('expired')))
			issues.push({ severity: 'Critical', category: 'Security', title: 'Certificate failure', description: `Cert issues in ${file.filename}`, root_cause: 'Invalid/expired TLS certificate', remediation: '1. Install root cert 2. Update system certs 3. Check system time', affected_files: [file.filename], evidence_keywords: ['certificate', 'invalid', 'expired'] });
	}
	const enriched = issues.map(i => enrichIssueWithLogEvidence(i, logFiles));
	return { summary: `Fallback: ${logFiles.length} files, ${issues.length} issues.`, health_status: issues.some(i => i.severity === 'Critical') ? 'Critical' : issues.length > 0 ? 'Degraded' : 'Healthy', issues: enriched, timeline: [], recommendations: ['Review logs manually', 'Check WARP docs'], note: 'AI unavailable.' };
}

export { MODELS, MODEL_CONFIG };
