/**
 * WARP Diagnostic Analyzer
 * Specialized deep-parsing and analysis for Cloudflare WARP diagnostic bundles.
 *
 * Extracts structured data from 20+ known WARP file formats:
 *  - Connection state (warp-status, daemon.log, boringtun.log)
 *  - Network config (ifconfig, ipconfig, netstat, route)
 *  - DNS state (resolv.conf, dns-check, daemon_dns.log)
 *  - Account & settings (warp-settings, warp-account, mdm)
 *  - Device posture (warp-device-posture)
 *  - System info (sysinfo.json, platform, version)
 *
 * Produces rule-based findings independent of AI, plus a structured snapshot
 * for the UI to visualise. AI sees both the raw logs AND the pre-parsed
 * structure for higher-quality diagnosis.
 */

// ── Log severity classification ────────────────────────────────────────────────

const SEVERITY_PATTERNS = {
	critical: [/\bFATAL\b/i, /\bCRIT\b/i, /\bCRITICAL\b/i, /\bpanic(?:ked|king)?\b/i],
	error: [/\bERROR\b/, /\bERR\b/, /\bfailed\b/i, /\bfailure\b/i, /\bexception\b/i, /cannot\s+\w+/i, /unable\s+to/i, /refused\b/i],
	warning: [/\bWARN(ING)?\b/i, /\btimeout\b/i, /\bretry(ing)?\b/i, /\bdeprecated\b/i, /\bdegraded\b/i],
	info: [/\bINFO\b/i, /\bNOTICE\b/i],
	debug: [/\bDEBUG\b/i, /\bTRACE\b/i, /\bVERBOSE\b/i],
};

// Common WARP daemon event patterns
const DAEMON_EVENTS = [
	{ pattern: /connected to warp|tunnel established|register successful/i, type: 'Connected', severity: 'success' },
	{ pattern: /disconnected|tunnel.*down|connection.*lost/i, type: 'Disconnected', severity: 'warning' },
	{ pattern: /registration.*failed|failed to register/i, type: 'Registration Failed', severity: 'critical' },
	{ pattern: /auth(entication)?\s+(failed|error)/i, type: 'Auth Failed', severity: 'critical' },
	{ pattern: /certificate\s+(expired|invalid|error)/i, type: 'Certificate Error', severity: 'critical' },
	{ pattern: /dns\s+(timeout|error|failure|failed)/i, type: 'DNS Error', severity: 'error' },
	{ pattern: /nxdomain/i, type: 'DNS NXDOMAIN', severity: 'warning' },
	{ pattern: /mtu\s+(too\s+)?(small|exceeded|blackhole)/i, type: 'MTU Issue', severity: 'warning' },
	{ pattern: /captive\s+portal/i, type: 'Captive Portal', severity: 'info' },
	{ pattern: /split.*tunnel.*changed|include.*list.*updated|exclude.*list/i, type: 'Split Tunnel Change', severity: 'info' },
	{ pattern: /mode\s+changed|switching\s+mode/i, type: 'Mode Change', severity: 'info' },
	{ pattern: /warp\s+(enabled|disabled|paused|resumed)/i, type: 'State Change', severity: 'info' },
	{ pattern: /posture\s+check\s+(failed|passed)/i, type: 'Posture Check', severity: 'info' },
	{ pattern: /firewall.*block|firewall.*drop/i, type: 'Firewall Block', severity: 'warning' },
	{ pattern: /interface\s+(up|down)/i, type: 'Interface Change', severity: 'info' },
	{ pattern: /handshake\s+(complete|initiated|failed)/i, type: 'Handshake', severity: 'info' },
];

// Timestamp extraction patterns (in order of specificity)
const TIMESTAMP_PATTERNS = [
	/^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)/,
	/^\[(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]/,
	/^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/,  // syslog-style: Jan  1 12:34:56
	/^(\d{2}:\d{2}:\d{2}(?:\.\d+)?)/,           // time only
];

// ── Main analysis function ─────────────────────────────────────────────────────

/**
 * Analyse a full set of extracted WARP diagnostic files.
 * @param {Array<{filename:string,content:string,category:string,priority:string}>} files
 * @returns {Object} structured snapshot + findings
 */
export function analyzeWarpBundle(files) {
	const snapshot = {
		connection: {},
		account: {},
		device: {},
		network: { interfaces: [], routes: [], dns: {} },
		settings: {},
		posture: { checks: [] },
		tunnel: {},
		mdm: null,
		diagnostics: {
			evidence: [],
			resourceErrors: [],
			runtimePanics: [],
			watchdog: { hangEvents: 0, forcedRestarts: 0, panicCount: 0, maxReportedHangCount: 0 },
			ipc: { failures: [], affectedFiles: [], processPresent: false },
			wmi: { degraded: false, timeouts: [], errors: [] },
			collectionTimeouts: [],
			socketErrors: [],
			transport: { masqueFailures: 0, h2Successes: 0, fallbacks: [] },
			ipv6Failures: [],
			endpointAgents: [],
		},
		causalChain: [],
		bottomLine: '',
		timeline: [],
		files: [],
		findings: [],
		rawProperties: {}, // flat map of ALL parsed key→value pairs across all files
	};

	// Pass 1 — file-type specific parsers
	for (const file of files) {
		const meta = { filename: file.filename, category: file.category, priority: file.priority, size: file.content.length };
		snapshot.files.push(meta);

		try {
			parseFileIntoSnapshot(file, snapshot);
		} catch (e) {
			console.warn(`Failed to parse ${file.filename}:`, e.message);
		}
	}

	// Pass 2 — universal key-value extraction from EVERY file.
	// Populates snapshot.rawProperties so the dashboard can find fields
	// regardless of which file they originated in.
	extractUniversalKeyValues(files, snapshot);
	analyzeDiagnosticSignals(files, snapshot);

	// Pass 3 — fill in gaps using the flat property map
	fillGapsFromRaw(snapshot);

	// Sort timeline by timestamp
	snapshot.timeline.sort((a, b) => (a.parsedTs || 0) - (b.parsedTs || 0));

	// Generate rule-based findings from the snapshot
	snapshot.findings = deriveFindings(snapshot, files);
	buildProfessionalSummary(snapshot);

	// Assign health status
	snapshot.health = computeHealth(snapshot.findings);

	return snapshot;
}

function addDiagnosticEvidence(snap, file, lineNumber, type, excerpt) {
	const key = `${file.filename}:${lineNumber}:${type}`;
	const existing = snap.diagnostics.evidence.find(e => e.key === key);
	if (existing) return existing.id;

	const id = `E${String(snap.diagnostics.evidence.length + 1).padStart(4, '0')}`;
	snap.diagnostics.evidence.push({
		id,
		key,
		type,
		file: file.filename,
		lineStart: lineNumber,
		lineEnd: lineNumber,
		timestamp: extractTimestamp(excerpt).str,
		excerpt: excerpt.trim().substring(0, 700),
	});
	return id;
}

// ── Diagnostic signal analysis ─────────────────────────────────────────────────
// Scans the raw log/text files for the high-signal failure signatures that drive
// a prescriptive, root-cause-oriented debrief (Windows resource exhaustion,
// watchdog hang/restart loops, IPC pipe loss, WMI degradation, collection
// timeouts, captive-portal probe failures, endpoint-security agents, etc.).

// Endpoint-security / kernel-driver agents that commonly leak kernel pool or
// insert WFP filter layers that interfere with WARP.
const ENDPOINT_AGENT_SIGNATURES = [
	{ re: /crowdstrike|csfalcon|falcon sensor|csagent/i, name: 'CrowdStrike Falcon', kind: 'EDR', kernel: true },
	{ re: /rapid7|insight agent|ir_agent/i, name: 'Rapid7 Insight Agent', kind: 'EDR', kernel: true },
	{ re: /carbon\s?black|cbdefense|cb\.exe/i, name: 'Carbon Black', kind: 'EDR', kernel: true },
	{ re: /sentinelone|sentinel agent/i, name: 'SentinelOne', kind: 'EDR', kernel: true },
	{ re: /cylance/i, name: 'Cylance', kind: 'EDR', kernel: true },
	{ re: /mcafee|trellix/i, name: 'McAfee/Trellix', kind: 'AV', kernel: true },
	{ re: /symantec|sep\b|norton/i, name: 'Symantec Endpoint Protection', kind: 'AV', kernel: true },
	{ re: /trend\s?micro|tmccsf/i, name: 'Trend Micro', kind: 'AV', kernel: true },
	{ re: /sophos/i, name: 'Sophos', kind: 'AV', kernel: true },
	{ re: /eset/i, name: 'ESET', kind: 'AV', kernel: true },
	{ re: /zscaler/i, name: 'Zscaler', kind: 'Proxy/ZTNA', kernel: true },
	{ re: /netskope/i, name: 'Netskope', kind: 'Proxy/ZTNA', kernel: true },
	{ re: /cisco\s?(secure|umbrella|anyconnect)|acumbrella/i, name: 'Cisco Secure Client / Umbrella', kind: 'Proxy/VPN', kernel: true },
	{ re: /palo\s?alto|globalprotect|gpsvc/i, name: 'Palo Alto GlobalProtect', kind: 'VPN', kernel: true },
	{ re: /forticlient|fortinet/i, name: 'FortiClient', kind: 'VPN', kernel: true },
];

// Co-management / MDM signatures.
const MANAGEMENT_SIGNATURES = [
	{ re: /configuration manager client|ccmexec|sccm/i, name: 'SCCM / Configuration Manager' },
	{ re: /intune|microsoft policy platform|ms policy platform/i, name: 'Microsoft Intune' },
	{ re: /jamf/i, name: 'Jamf' },
	{ re: /workspace\s?one|airwatch/i, name: 'Workspace ONE' },
	{ re: /kandji/i, name: 'Kandji' },
];

// Resolve the most useful version string for a detected endpoint agent.
// Prefers the primary "sensor/agent platform" build over sub-component versions.
function detectAgentVersion(sig, content) {
	const preferred = {
		'CrowdStrike Falcon': [/CrowdStrike Sensor Platform\s+([\d.]+)/i, /Falcon Sensor[^\n]*?([\d.]+)/i, /CrowdStrike[^\n]*?([\d.]+)/i],
		'Rapid7 Insight Agent': [/Rapid7 Insight Agent\s+([\d.]+)/i],
		'SentinelOne': [/SentinelOne[^\n]*?([\d.]+)/i],
		'Zscaler': [/Zscaler[^\n]*?([\d.]+)/i],
		'Netskope': [/Netskope[^\n]*?([\d.]+)/i],
		'Cisco Secure Client / Umbrella': [/(?:Cisco Secure Client|AnyConnect|Umbrella)[^\n]*?([\d.]+)/i],
		'Palo Alto GlobalProtect': [/GlobalProtect[^\n]*?([\d.]+)/i],
		'FortiClient': [/FortiClient[^\n]*?([\d.]+)/i],
	};
	const patterns = preferred[sig.name] || [new RegExp(sig.name.split(/[ /]/)[0] + '[^\\n]*?([\\d.]+\\.[\\d.]+)', 'i')];
	for (const re of patterns) {
		const m = content.match(re);
		if (m && /\d+\.\d+/.test(m[1])) return m[1].replace(/\.$/, '');
	}
	return null;
}

function analyzeDiagnosticSignals(files, snap) {
	const diag = snap.diagnostics;
	const version = snap.connection.warpVersion || '';

	// Real logged-in user from qwinsta / user-sessions (more reliable than the
	// keyring "WARPSecret" artifact that leaks into universal key/value scan).
	const sessFile = files.find(f => /user-sessions\.txt|qwinsta|who\.txt|users\.txt/i.test(f.filename));
	if (sessFile) {
		for (const line of sessFile.content.split('\n')) {
			// ">console  cachambers  1  Active" — active console session
			const m = line.match(/^[>\s]*(?:console|rdp-tcp#?\d*|:\d+|tty\d+|seat\d+)\s+([A-Za-z][\w.\\-]{1,40})\s+\d+\s+(?:Active|Conn)/i);
			if (m && !/^services$/i.test(m[1])) { snap.diagnostics.loginUser = m[1]; break; }
		}
	}

	for (const file of files) {
		if (!file.content) continue;
		const bn = file.filename.toLowerCase().split('/').pop().split('\\').pop();
		const isLog = bn.endsWith('.log') || bn === 'warp-diag-log.txt';
		const lines = file.content.split('\n');
		// For very large logs, scanning every line is fine here — patterns are cheap
		// and we cap evidence capture per type below.

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			if (!line) continue;
			const lineNum = i + 1;

			// ---- Windows kernel resource exhaustion (error 1450 / WSAENOBUFS) ----
			if (/\b(?:code:\s*)?1450\b/.test(line) || /Insufficient system resources/i.test(line) || /\bWSAENOBUFS\b/i.test(line)) {
				diag.resourceErrors.push({ file: file.filename, line: lineNum, ts: extractTimestamp(line).str, text: line.trim().substring(0, 400) });
				if (diag.resourceErrors.length <= 5) addDiagnosticEvidence(snap, file, lineNum, 'resource_exhaustion', line);
			}
			// Other socket/handle exhaustion signals
			if (/\b(?:code:\s*)?10055\b/.test(line) || /No buffer space available/i.test(line)) {
				diag.socketErrors.push({ file: file.filename, line: lineNum, kind: 'WSAENOBUFS', text: line.trim().substring(0, 300) });
			}
			if (/\b(?:code:\s*)?10013\b/.test(line) || /\bWSAEACCES\b/i.test(line) || /forbidden by its access permissions/i.test(line)) {
				diag.socketErrors.push({ file: file.filename, line: lineNum, kind: 'WSAEACCES', text: line.trim().substring(0, 300) });
			}

			// ---- Runtime panics ----
			if (/panicked at/i.test(line)) {
				const loc = (line.match(/panicked at\s+([^\s:]+(?::\d+:\d+)?)/i) || [])[1] || '';
				const msgLine = (lines[i + 1] || '').trim();
				diag.runtimePanics.push({
					file: file.filename, line: lineNum, ts: extractTimestamp(line).str,
					location: loc, message: (msgLine || line).substring(0, 300),
					isIoDriver: /io[\\/]driver\.rs/i.test(line) || /polling the I\/O driver/i.test(msgLine),
					isWatchdog: /watchdog/i.test(line) || /watchdog/i.test(msgLine) || /bus has been hung/i.test(msgLine),
				});
				diag.watchdog.panicCount++;
				if (diag.runtimePanics.length <= 6) addDiagnosticEvidence(snap, file, lineNum, 'panic', line + '\n' + msgLine);
			}

			// ---- Watchdog hang / restart loop ----
			if (/hung daemon|hung for too long|Watchdog reports hung|hang_count|Process has been hung/i.test(line)) {
				diag.watchdog.hangEvents++;
				const hc = line.match(/hang_count=(\d+)/);
				if (hc) diag.watchdog.maxReportedHangCount = Math.max(diag.watchdog.maxReportedHangCount, parseInt(hc[1], 10));
			}
			if (/Watchdog is shutting down an overly hung daemon/i.test(line)) {
				diag.watchdog.forcedRestarts++;
				if (diag.watchdog.forcedRestarts <= 5) addDiagnosticEvidence(snap, file, lineNum, 'watchdog_restart', line);
			}
			if (/Starting warp service/i.test(line)) {
				diag.watchdog.serviceStarts = (diag.watchdog.serviceStarts || 0) + 1;
			}

			// ---- IPC named pipe absence ----
			if (/Failed to communicate with WARP service over IPC/i.test(line) || /IPC.*os error 2/i.test(line) || /cannot find the file specified.*os error 2/i.test(line)) {
				diag.ipc.failures.push({ file: file.filename, line: lineNum, text: line.trim().substring(0, 300) });
				if (bn.startsWith('warp-') || bn === 'daemon_info_collection_error.txt') {
					if (!diag.ipc.affectedFiles.includes(file.filename)) diag.ipc.affectedFiles.push(file.filename);
				}
				if (diag.ipc.failures.length <= 3) addDiagnosticEvidence(snap, file, lineNum, 'ipc_failure', line);
			}

			// ---- WMI degradation ----
			if (/WMI Probe:\s*TIMEOUT/i.test(line) || /COM subsystem (is )?(likely )?degraded/i.test(line)) {
				diag.wmi.degraded = true;
				diag.wmi.timeouts.push({ file: file.filename, line: lineNum, text: line.trim().substring(0, 200) });
			}
			if (/WMI repository verification failed/i.test(line) || /0x80041003/i.test(line)) {
				diag.wmi.degraded = true;
				diag.wmi.errors.push({ file: file.filename, line: lineNum, text: line.trim().substring(0, 200) });
			}

			// ---- Collection command timeouts (systeminfo, Get-Service, etc.) ----
			if (/Command timed out: deadline has elapsed/i.test(line)) {
				diag.collectionTimeouts.push({ file: file.filename });
			}

			// ---- Captive portal probe failures ----
			if (/captive_portal/i.test(line) || bn.startsWith('captive-portal')) {
				if (/Failed HTTP request|HTTPS test request failed|TimedOut|PermissionDenied|NetworkUnreachable/i.test(line)) {
					diag.captivePortal = diag.captivePortal || { failures: 0, recovered: false, firstTs: '', lastFailTs: '', recoveredTs: '' };
					diag.captivePortal.failures++;
					const ts = extractTimestamp(line).str;
					if (ts) { if (!diag.captivePortal.firstTs) diag.captivePortal.firstTs = ts; diag.captivePortal.lastFailTs = ts; }
				}
				if (/Captive portal detection completed|NoCaptivePortalDetected/i.test(line)) {
					diag.captivePortal = diag.captivePortal || { failures: 0, recovered: false, firstTs: '', lastFailTs: '', recoveredTs: '' };
					diag.captivePortal.recovered = true;
					diag.captivePortal.recoveredTs = extractTimestamp(line).str;
				}
			}
			if (/NetworkUnreachable.*(?:\[|:)[0-9a-f:]+\]?:\d+/i.test(line) && /2606:4700|:80|:443/i.test(line)) {
				diag.ipv6Failures.push({ file: file.filename, line: lineNum });
			}

			// ---- Transport (MASQUE/h2 fallback) ----
			if (/masque/i.test(line) && /(fail|error|fallback|falling back)/i.test(line)) {
				diag.transport.masqueFailures++;
				diag.transport.fallbacks.push(line.trim().substring(0, 160));
			}

			if (i > 60000) break; // hard safety cap per file
		}

		// ---- Endpoint agents & management from inventory-style files ----
		if (/installed_applications|antivirus|services\.txt|drivers\.txt|processes\.txt|com-api-adapters/i.test(bn)) {
			for (const sig of ENDPOINT_AGENT_SIGNATURES) {
				if (!sig.re.test(file.content)) continue;
				const existing = diag.endpointAgents.find(a => a.name === sig.name);
				const version = detectAgentVersion(sig, file.content);
				if (existing) {
					if (!existing.version && version) existing.version = version;
				} else {
					diag.endpointAgents.push({ name: sig.name, kind: sig.kind, kernel: sig.kernel, version, source: bn });
				}
			}
			for (const sig of MANAGEMENT_SIGNATURES) {
				if (sig.re.test(file.content)) {
					diag.management = diag.management || [];
					if (!diag.management.includes(sig.name)) diag.management.push(sig.name);
				}
			}
		}
	}

	// IPC process presence: warp-svc / CloudflareWARP in the process list while
	// IPC is failing = "process alive but pipe gone".
	const procFile = files.find(f => /processes\.txt|tasklist/i.test(f.filename));
	if (procFile && /warp-svc|CloudflareWARP|warp_svc/i.test(procFile.content)) {
		diag.ipc.processPresent = true;
		// Find the warp-svc line and extract the largest standalone integer that
		// looks like a PID (Windows `ps`/tasklist puts PID before the image name).
		const procLine = procFile.content.split('\n').find(l => /warp-svc/i.test(l)) || '';
		const nums = (procLine.match(/\b(\d{2,7})\b/g) || []).map(n => parseInt(n, 10));
		// PID is the last number before the "warp-svc" token
		const idx = procLine.toLowerCase().indexOf('warp-svc');
		const before = procLine.substring(0, idx);
		const beforeNums = (before.match(/\b(\d{2,7})\b/g) || []);
		if (beforeNums.length) diag.ipc.pid = beforeNums[beforeNums.length - 1];
		else if (nums.length) diag.ipc.pid = String(nums[nums.length - 1]);
	}

	// Deduplicate collection timeouts by file
	diag.collectionTimeoutFiles = [...new Set(diag.collectionTimeouts.map(t => t.file.split(/[\\/]/).pop()))];

	// Endpoint-security agents also frequently appear in antivirus.txt (SecurityCenter2)
	// Record WARP version-derived context for later steps.
	if (version) diag.warpVersion = version;
}

// ── Causal chain + prescriptive summary ────────────────────────────────────────
// Builds the root-cause → effect → symptom → user-impact chain, a plain-English
// "bottom line", and the ordered recommended steps that make up the debrief.

function buildProfessionalSummary(snap) {
	const d = snap.diagnostics;
	const steps = [];
	let bottomLine = '';
	const chain = [];

	const hasResourceExhaustion = d.resourceErrors.length > 0;
	const ioDriverPanic = d.runtimePanics.some(p => p.isIoDriver);
	const watchdogLoop = d.watchdog.forcedRestarts > 0 || d.watchdog.panicCount > 0 || d.watchdog.hangEvents > 5;
	const ipcGone = d.ipc.failures.length > 0;
	const wmiDegraded = d.wmi.degraded;
	const kernelAgents = d.endpointAgents.filter(a => a.kernel);

	// Scenario A — the classic host resource exhaustion cascade
	if (hasResourceExhaustion || (ioDriverPanic && watchdogLoop)) {
		chain.push({
			stage: 'Root cause', title: 'Windows error 1450',
			detail: 'Insufficient system resources', sub: 'Kernel pool / handle exhaustion', cls: 'root',
		});
		chain.push({
			stage: 'Effect', title: ioDriverPanic ? 'Tokio I/O driver panics' : 'WARP daemon I/O stalls',
			detail: 'WARP daemon main loop hangs',
			sub: d.watchdog.forcedRestarts > 0 ? `Watchdog forces ${d.watchdog.forcedRestarts} restart${d.watchdog.forcedRestarts === 1 ? '' : 's'}` : 'Watchdog intervenes', cls: 'effect',
		});
		chain.push({
			stage: 'Log symptom', title: 'IPC: os error 2',
			detail: '"The system cannot find the file specified."', sub: '', cls: 'symptom',
		});
		chain.push({
			stage: 'User impact', title: 'No WARP connectivity',
			detail: 'Client shows disconnected', sub: 'Cannot reconnect', cls: 'impact',
		});

		const restartTxt = d.watchdog.forcedRestarts > 0 ? ` and left it unresponsive after ${d.watchdog.forcedRestarts} forced restart${d.watchdog.forcedRestarts === 1 ? '' : 's'}` : '';
		bottomLine = `The Windows host ran out of kernel system resources (error 1450), which crashed the WARP daemon's I/O subsystem${restartTxt}. WARP itself was healthy — a reboot will restore connectivity immediately. The real fix is identifying which kernel-level driver is leaking system resources` +
			(kernelAgents.length ? `, most likely one of the endpoint security agents on this machine (${kernelAgents.map(a => a.name).join(', ')}).` : '.');

		steps.push({
			title: 'Reboot the device.',
			body: 'This clears the exhausted kernel pool and restores WARP connectivity immediately. Do not attempt to restart only the WARP service — the host resource condition will cause it to hang again within minutes.',
		});
		steps.push({
			title: 'After reboot, confirm WARP connects and stays connected.',
			body: 'Open the Cloudflare WARP tray icon and verify it shows "Connected." Browse to cloudflare.com/cdn-cgi/trace and confirm warp=on and gateway=on.',
		});
		steps.push({
			title: 'Watch for recurrence.',
			body: 'If the machine degrades again within an hour or two, the resource leak is ongoing. Note the elapsed time between reboot and the next connectivity loss — this is useful data for escalation.',
		});
		steps.push({
			title: 'Monitor kernel memory during degradation.',
			body: 'Open Task Manager → Performance → Memory and, in Resource Monitor (resmon.exe), watch Nonpaged pool. If it climbs continuously rather than leveling off, a kernel driver is leaking. Run poolmon.exe (Windows Driver Kit) to identify the leaking pool tag — look for the tag whose Bytes column keeps growing.',
		});
		if (kernelAgents.length) {
			steps.push({
				title: 'Isolate the leaking driver.',
				body: `${kernelAgents.map(a => a.name).join(', ')}${kernelAgents.length ? ' and the WARP WFP network filter' : ''} all load kernel components and are the most likely candidates. Work with your endpoint security team to test with each agent temporarily suspended (per your org's exception process) to isolate the source. Windows Event ID 2019 (nonpaged pool) or 2020 (paged pool) in the System log confirms pool depletion and may name the allocation owner.`,
			});
			const cs = kernelAgents.find(a => /crowdstrike/i.test(a.name));
			if (cs) {
				steps.push({
					title: 'Upgrade CrowdStrike Falcon if behind on sensor version.',
					body: `The device is running sensor ${cs.version || '(version not captured)'}. Check against the latest generally available sensor; known pool-leak issues have been addressed in recent releases.`,
				});
			}
		}
	}
	// Scenario B — WARP disconnected without host resource exhaustion
	else if ((snap.connection.status || '').toLowerCase().match(/disconnect|disabled|error/) || ipcGone) {
		chain.push({ stage: 'Root cause', title: 'WARP service not reachable', detail: ipcGone ? 'IPC pipe unavailable' : 'Tunnel not established', sub: '', cls: 'root' });
		chain.push({ stage: 'Effect', title: 'Daemon/UI cannot communicate', detail: 'Status queries fail', sub: '', cls: 'effect' });
		chain.push({ stage: 'Log symptom', title: ipcGone ? 'IPC: os error 2' : 'Disconnected', detail: '', sub: '', cls: 'symptom' });
		chain.push({ stage: 'User impact', title: 'No WARP connectivity', detail: 'Client shows disconnected', sub: '', cls: 'impact' });
		bottomLine = 'WARP is not connected at capture time. Restart the WARP service and confirm reconnection; if it fails to re-establish, review the daemon log and network reachability to the Cloudflare edge.';
		steps.push({ title: 'Restart the WARP service.', body: 'From the tray icon disconnect and reconnect, or restart the CloudflareWARP service. Confirm the client reaches "Connected".' });
		steps.push({ title: 'Verify reachability.', body: 'Confirm UDP/443 (and QUIC) egress to the Cloudflare edge is permitted and that DNS resolves the client/gateway endpoints.' });
		steps.push({ title: 'Re-register if needed.', body: 'If authentication or registration errors persist, re-register the device against your Zero Trust organization.' });
	}
	// Scenario C — healthy / minor
	else {
		bottomLine = snap.findings && snap.findings.some(f => f.severity === 'Warning')
			? 'WARP is connected but shows degraded signals. Review the findings below; none are service-down blocking issues at capture time.'
			: 'WARP appears healthy at capture time. No blocking issues were detected in the diagnostics.';
		steps.push({ title: 'No action required.', body: 'The tunnel is operating normally. Keep the client updated and re-capture a fresh warp-diag if symptoms recur.' });
	}

	// MDM step is appended for any managed/co-managed device without mdm.xml
	if ((d.management && d.management.length) && !snap.mdm) {
		steps.push({
			title: 'Consider deploying WARP via MDM policy.',
			body: `The device is managed by ${d.management.join(' and ')} but no Cloudflare mdm.xml was found. Push mdm.xml (organization, service mode, split-tunnel rules) to lock the configuration and simplify future troubleshooting. See Cloudflare Zero Trust: Deploy WARP via MDM.`,
		});
	}

	snap.causalChain = chain;
	snap.bottomLine = bottomLine;
	snap.recommendedSteps = steps;

	// Timeline of the failure (key excerpts) for the appendix
	snap.keyLogExcerpts = buildKeyLogExcerpts(snap);
}

function buildKeyLogExcerpts(snap) {
	const ev = snap.diagnostics.evidence || [];
	// Prefer the highest-signal evidence types in a sensible order
	const order = ['resource_exhaustion', 'panic', 'watchdog_restart', 'ipc_failure'];
	const sorted = [...ev].sort((a, b) => {
		const oa = order.indexOf(a.type); const ob = order.indexOf(b.type);
		return (oa === -1 ? 99 : oa) - (ob === -1 ? 99 : ob);
	});
	return sorted.slice(0, 12).map(e => ({
		ts: e.timestamp || '', type: e.type, file: e.file.split(/[\\/]/).pop(), excerpt: e.excerpt,
	}));
}

// Scan every file for "key: value" or "key = value" pairs and build a flat map.
// Accepts multiple separators: : = → |
// Keys are lowercased and normalised (underscores, spaces collapsed).
function extractUniversalKeyValues(files, snap) {
	const props = snap.rawProperties;
	for (const file of files) {
		// Skip binary-ish files
		if (!file.content || file.content.length === 0) continue;
		// Skip very large logs for this pass to save CPU
		const maxBytes = 64 * 1024;
		const text = file.content.length > maxBytes ? file.content.substring(0, maxBytes) : file.content;

		const lines = text.split('\n');
		for (const line of lines) {
			// Match "key: value" or "key = value" or "key -> value"
			// Require key to not contain too many weird chars
			const m = line.match(/^\s*([A-Za-z][A-Za-z0-9 _\-./]{0,60})\s*[:=]\s+(.+?)\s*$/);
			if (!m) continue;
			const rawKey = m[1].trim();
			const val = m[2].trim();
			if (!val || val.length > 500) continue;
			// Skip keys that look like markup
			if (rawKey.length < 2) continue;
			const key = rawKey.toLowerCase().replace(/[\s\-/]+/g, '_');
			// First occurrence wins unless existing is empty
			if (!props[key] || props[key] === '-' || props[key] === 'unknown') {
				props[key] = val;
			}
			// Also track multi-value under the original key
			if (!props.__sources) props.__sources = {};
			if (!props.__sources[key]) props.__sources[key] = file.filename;
		}
	}
}

// Fill empty snapshot fields from the rawProperties map using many possible key names.
function fillGapsFromRaw(snap) {
	const p = snap.rawProperties;
	const c = snap.connection;
	const a = snap.account;
	const d = snap.device;
	const dns = snap.network.dns;

	const tryKeys = (keys) => {
		for (const k of keys) {
			const v = p[k];
			if (v && v !== '-' && v.toLowerCase() !== 'unknown') return v;
		}
		return null;
	};

	c.status = c.status || tryKeys(['status', 'warp_status', 'connection_status', 'warp_connection_status', 'status_update', 'tunnel_state', 'state']);
	c.mode = c.mode || tryKeys(['mode', 'warp_mode', 'current_mode', 'operation_mode']);
	c.warpVersion = c.warpVersion || tryKeys(['version', 'warp_version', 'client_version', 'build', 'app_version']);
	c.accountType = c.accountType || tryKeys(['account_type', 'accounttype', 'license']);
	c.colo = c.colo || tryKeys(['colo', 'edge_location', 'pop', 'datacenter', 'data_center']);
	c.endpoint = c.endpoint || tryKeys(['endpoint', 'warp_endpoint', 'gateway_endpoint', 'server']);
	c.myIp = c.myIp || tryKeys(['my_ip', 'public_ip', 'external_ip', 'your_ip', 'current_ip']);
	c.gatewayIp = c.gatewayIp || tryKeys(['gateway_ip', 'gateway', 'default_gateway']);
	c.alwaysOn = c.alwaysOn || tryKeys(['always_on', 'alwayson']);
	c.switchLocked = c.switchLocked || tryKeys(['switch_locked', 'switchlocked']);

	a.team = a.team || tryKeys(['team', 'team_name', 'organization', 'organisation', 'org']);
	a.accountId = a.accountId || tryKeys(['account_id', 'accountid', 'registered_account_id']);
	a.deviceId = a.deviceId || tryKeys(['device_id', 'deviceid']);
	// Prefer the real logged-in console user (qwinsta) over keyring artifacts
	// like "WARPSecret" that leak into the universal key/value scan.
	const badUsers = /^(warpsecret|system|none|n\/a|-)$/i;
	if (snap.diagnostics && snap.diagnostics.loginUser) a.user = snap.diagnostics.loginUser;
	if (!a.user || badUsers.test(a.user)) {
		const cand = tryKeys(['user', 'email', 'user_email', 'user_id', 'active_user', 'username']);
		if (cand && !badUsers.test(cand)) a.user = cand;
	}
	a.registration = a.registration || tryKeys(['registration', 'registered', 'registration_status']);
	a.publicKey = a.publicKey || tryKeys(['public_key', 'publickey']);
	a.license = a.license || tryKeys(['license', 'license_type']);
	a.organization = a.organization || tryKeys(['organization', 'organisation', 'org']);

	d.platform = d.platform || tryKeys(['platform', 'os', 'operating_system', 'os_name']);
	d.captureTime = d.captureTime || tryKeys(['capture_time', 'date', 'timestamp', 'diag_time']);

	dns.protocol = dns.protocol || tryKeys(['dns_protocol', 'dns_over_https', 'dns_over_tls', 'dns_mode', 'doh', 'dot']);

	// Scan for IP patterns in all log content if still missing IPs
	if (!c.myIp || !c.gatewayIp) {
		for (const [key, val] of Object.entries(p)) {
			if (typeof val !== 'string') continue;
			const ipMatch = val.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
			if (!ipMatch) continue;
			if (!c.myIp && /my_ip|public_ip|external|current/i.test(key)) c.myIp = ipMatch[1];
			if (!c.gatewayIp && /gateway/i.test(key)) c.gatewayIp = ipMatch[1];
		}
	}
}

// ── File-type specific parsers ─────────────────────────────────────────────────

function parseFileIntoSnapshot(file, snap) {
	const bn = file.filename.toLowerCase().split('/').pop().split('\\').pop();

	// === Cloudflare WARP specific files ===
	if (bn === 'warp-status.txt') {
		parseWarpStatus(file.content, snap);
	} else if (bn === 'warp-account.txt') {
		parseWarpAccount(file.content, snap);
	} else if (bn === 'warp-settings.txt') {
		parseWarpSettings(file.content, snap);
	} else if (bn === 'warp-tunnel-stats.txt') {
		parseTunnelStats(file.content, snap);
	} else if (bn === 'warp-network.txt') {
		parseWarpNetwork(file.content, snap);
	} else if (bn === 'warp-dns-stats.txt' || bn === 'dns_stats.log' || bn === 'daemon_dns.log') {
		parseWarpDnsStats(file.content, snap);
	} else if (bn === 'warp-dns-fallbacks.txt') {
		snap.network.dns.fallbacks = file.content.split('\n').filter(l => l.trim()).slice(0, 30);
	} else if (bn === 'warp-stats.txt') {
		parseWarpStatsJson(file.content, snap);
	} else if (bn === 'warp-device-posture.txt') {
		parseDevicePosture(file.content, snap);
	} else if (bn === 'warp-dex-data.txt') {
		parseDexData(file.content, snap);
	} else if (bn === 'warp-dns-lock.json') {
		try { snap.network.dns.lock = JSON.parse(file.content); } catch { }
	} else if (bn === 'connectivity.txt') {
		parseConnectivity(file.content, snap);
	} else if (bn === 'conf-active.json') {
		parseConfActive(file.content, snap);
	} else if (bn === 'conf-pre-login.json') {
		try { snap.settings.preLogin = JSON.parse(file.content); } catch { }
	} else if (bn === 'registration_cache.json') {
		parseRegistrationCache(file.content, snap);
	} else if (bn === 'connection_stats.log') {
		parseConnectionStats(file.content, snap);
	} else if (bn === 'dex.log' || bn === 'dex.1.log' || bn === 'dex.2.log') {
		parseDexLog(file.content, snap);
	}
	// === Network config files (macOS/Linux/Windows) ===
	else if (bn === 'ifconfig.txt' || bn === 'ipconfig.txt') {
		parseInterfaces(file.content, snap);
	} else if (bn === 'interfaces-config.txt' || bn === 'v4interfaces.txt' || bn === 'v6interfaces.txt') {
		parseWindowsInterfacesConfig(file.content, snap);
	} else if (bn === 'route.txt' || bn === 'routetable.txt' || bn.includes('route-table')) {
		parseRoutes(file.content, snap);
	} else if (bn === 'netstat.txt') {
		parseNetstat(file.content, snap);
	} else if (bn === 'resolv.conf') {
		parseResolvConf(file.content, snap);
	} else if (bn === 'dns-client.txt') {
		parseDnsClient(file.content, snap);
	} else if (bn === 'dns-check.txt' || bn === 'dns.log') {
		parseDnsCheck(file.content, snap);
	}
	// === System info ===
	else if (bn === 'sysinfo.json') {
		parseSysInfo(file.content, snap);
	} else if (bn === 'platform.txt') {
		snap.device.platform = (file.content.trim().split('\n')[0] || '').trim();
	} else if (bn === 'windows-version.txt') {
		parseWindowsVersion(file.content, snap);
	} else if (bn === 'systeminfo.txt') {
		parseSystemInfo(file.content, snap);
	} else if (bn === 'version.txt') {
		parseVersionFile(file.content, snap);
	} else if (bn === 'date.txt') {
		snap.device.captureTime = file.content.trim();
	} else if (bn === 'timezone.txt') {
		snap.device.timezone = file.content.trim();
	} else if (bn === 'users.json') {
		try { snap.device.users = JSON.parse(file.content); } catch { }
	}
	// === MDM & certificates ===
	else if (bn.includes('mdm')) {
		parseMdm(file.content, snap);
	} else if (bn === 'override_warp.txt') {
		snap.settings.override = file.content.trim();
	} else if (bn === 'installed_cert.pem' || bn.endsWith('.pem')) {
		parseCertificate(file.content, file.filename, snap);
	}
	// === Traceroute / ARP ===
	else if (bn === 'traceroute.txt' || bn.includes('traceroute')) {
		parseTraceroute(file.content, file.filename, snap);
	} else if (bn === 'arp.txt') {
		parseArp(file.content, snap);
	}
	// === Daemon/tunnel logs ===
	else if (bn.startsWith('daemon.') || bn.startsWith('warp-svc.') || bn.startsWith('boringtun.') || bn === 'tunnel.log' || bn === 'warp-diag-log.txt') {
		parseDaemonLog(file.content, file.filename, snap);
	}
}

function parseWarpStatus(content, snap) {
	const c = snap.connection;
	const trimmed = content.trim();

	// Rust Result format: "Ok(Connected)" or "Err(...)"
	const rustMatch = trimmed.match(/^Ok\(([^)]+)\)/);
	if (rustMatch) {
		c.status = rustMatch[1];
		return;
	}
	const errMatch = trimmed.match(/^Err\(([^)]+)\)/);
	if (errMatch) {
		c.status = 'Error';
		c.statusError = errMatch[1];
		return;
	}

	// JSON format (some clients)
	if (trimmed.startsWith('{')) {
		try {
			const json = JSON.parse(trimmed);
			if (json.status) c.status = String(json.status);
			if (json.mode) c.mode = String(json.mode);
			if (json.account) c.accountType = String(json.account);
			if (json.team) snap.account.team = String(json.team);
			return;
		} catch { }
	}

	// First non-empty non-separator line often has the status
	const lines = content.split('\n').map(l => l.trim()).filter(l => l && !/^[=\-*]+$/.test(l));
	if (lines.length > 0 && !c.status) {
		const first = lines[0];
		for (const kw of ['connected', 'disconnected', 'connecting', 'disabled', 'registering', 'paused']) {
			if (first.toLowerCase().includes(kw)) {
				c.status = kw[0].toUpperCase() + kw.slice(1);
				break;
			}
		}
	}

	// Key:value lines
	for (const line of lines) {
		const m = line.match(/^([^:=]+?)\s*[:=]\s*(.+)$/);
		if (!m) continue;
		const key = m[1].trim().toLowerCase();
		const val = m[2].trim();
		if (!val) continue;

		if (['status', 'warp status', 'connection status', 'status update', 'warp connection status'].includes(key)) c.status = val;
		else if (['mode', 'warp mode', 'operation mode'].includes(key)) c.mode = val;
		else if (['account', 'account type', 'accounttype'].includes(key)) c.accountType = val;
		else if (key === 'team' || key === 'team name') snap.account.team = val;
	}
}

function parseWarpAccount(content, snap) {
	const a = snap.account;
	const trimmed = content.trim();

	// JSON
	if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
		try {
			const json = JSON.parse(trimmed);
			Object.assign(a, json);
			return;
		} catch { }
	}

	// Rust Debug format: "Account: Team { id: AccountId(X), managed: Y, organization: \"Z\" }"
	// Also extracts Alternate networks from same line
	for (const line of content.split('\n')) {
		// Standard key: value
		const kv = line.match(/^([A-Za-z][A-Za-z0-9 ]+?)\s*:\s*(.+)$/);
		if (kv) {
			const key = kv[1].trim().toLowerCase();
			const val = kv[2].trim();
			if (!val) continue;

			if (key === 'id' || key === 'registered id') a.id = val;
			else if (key === 'device id' || key === 'deviceid') a.deviceId = val;
			else if (key === 'public key' || key === 'publickey') a.publicKey = val;
			else if (key === 'managed') a.managed = val;
			else if (key === 'account') {
				// Rust Debug: Team { id: AccountId(X), managed: NotManaged, organization: "Y" }
				const teamMatch = val.match(/Team\s*\{([^}]+)\}/);
				if (teamMatch) {
					const body = teamMatch[1];
					const idM = body.match(/id:\s*AccountId\(([^)]+)\)/);
					if (idM) a.accountId = idM[1].trim();
					const orgM = body.match(/organization:\s*"([^"]+)"/);
					if (orgM) { a.organization = orgM[1]; a.team = a.team || orgM[1]; }
					const managedM = body.match(/managed:\s*(\w+)/);
					if (managedM) a.accountManaged = managedM[1];
					a.accountType = 'Team';
				} else {
					a.accountType = val;
				}
			}
			else if (key === 'team' || key === 'team name') a.team = val;
			else if (key === 'account id' || key === 'accountid' || key === 'registered account id') a.accountId = val;
			else if (key === 'registration' || key === 'registered' || key === 'registration status') a.registration = val;
			else if (key === 'user id' || key === 'email' || key === 'user email' || key === 'user') a.user = val;
			else if (key === 'license' || key === 'license type') a.license = val;
			else if (key === 'organization' || key === 'organisation' || key === 'org') a.organization = val;
			else if (key === 'role' || key === 'user role') a.role = val;
			else if (key === 'alternate networks') a.alternateNetworks = val;
		}
	}
}

function parseWarpSettings(content, snap) {
	// Real format: "(source)\tKey: Value" with multi-line values for lists
	const s = snap.settings;
	const lines = content.split('\n');
	let currentListKey = null;
	let currentList = [];

	for (const line of lines) {
		// Skip blank lines but commit any pending list
		if (!line.trim()) {
			if (currentListKey && currentList.length) {
				s[currentListKey] = currentList;
				currentListKey = null;
				currentList = [];
			}
			continue;
		}

		// Main line: optional "(source)\t" prefix + "Key: Value"
		const main = line.match(/^(?:\(([^)]+)\)\s*)?([A-Za-z][A-Za-z0-9 \-\+/.,']+?)\s*:\s*(.*)$/);
		if (main && !line.startsWith('  ')) {
			// Commit pending list
			if (currentListKey && currentList.length) {
				s[currentListKey] = currentList;
				currentListKey = null;
				currentList = [];
			}
			const key = main[2].trim();
			const val = main[3].trim();
			const normKey = key.toLowerCase().replace(/\s+/g, '_');

			if (val) {
				s[normKey] = val;
				// Specific important fields
				if (/^mode$/i.test(key)) snap.connection.mode = val;
				else if (/always\s*on/i.test(key)) snap.connection.alwaysOn = val;
				else if (/switch\s*locked/i.test(key)) snap.connection.switchLocked = val;
				else if (/tunnel\s*protocol/i.test(key)) snap.tunnel.protocol = val;
				else if (/^organization$/i.test(key)) snap.account.organization = snap.account.organization || val;
				else if (/^profile\s*id$/i.test(key)) s.profileId = val;
				else if (/captive\s*portal/i.test(key)) s.captivePortal = val;
				else if (/support\s*url/i.test(key)) s.supportUrl = val;
				else if (/resolve\s*via/i.test(key)) {
					// "<gateway-id>.cloudflare-gateway.com @ [ns1, ns2]"
					const gw = val.match(/([\w-]+\.cloudflare-gateway\.com)\s*@\s*\[([^\]]+)\]/);
					if (gw) {
						snap.network.dns.gatewayHost = gw[1];
						snap.network.dns.nameservers = snap.network.dns.nameservers || [];
						gw[2].split(',').forEach(ns => {
							const t = ns.trim();
							if (t) snap.network.dns.nameservers.push(t);
						});
					}
				}
			} else {
				// Value empty — this header introduces a multi-line list
				currentListKey = normKey;
				currentList = [];
				// Special sub-case: "Exclude mode, with hosts/ips:"
				if (/exclude/i.test(key)) {
					snap.settings.splitTunnel = snap.settings.splitTunnel || {};
					snap.settings.splitTunnel.mode = 'exclude';
					currentListKey = 'exclude_list';
				} else if (/include/i.test(key) && /host|ip/i.test(key)) {
					snap.settings.splitTunnel = snap.settings.splitTunnel || {};
					snap.settings.splitTunnel.mode = 'include';
					currentListKey = 'include_list';
				}
			}
		} else if (line.startsWith('  ') || line.startsWith('\t')) {
			// Continuation of a list
			if (currentListKey) currentList.push(line.trim());
		}
	}

	// Commit any trailing list
	if (currentListKey && currentList.length) {
		s[currentListKey] = currentList;
	}

	// Normalise split tunnel
	if (s.exclude_list) {
		snap.settings.splitTunnel = snap.settings.splitTunnel || { mode: 'exclude' };
		snap.settings.splitTunnel.exclude = s.exclude_list;
	}
	if (s.include_list) {
		snap.settings.splitTunnel = snap.settings.splitTunnel || { mode: 'include' };
		snap.settings.splitTunnel.include = s.include_list;
	}
}

function parseTunnelStats(content, snap) {
	const t = snap.tunnel;
	for (const line of content.split('\n')) {
		const m = line.match(/^([^:]+):\s*(.+)$/);
		if (!m) continue;
		const key = m[1].trim().toLowerCase();
		const val = m[2].trim();

		if (key === 'tunnel protocol') t.protocol = val;
		else if (key === 'endpoints') {
			t.endpoints = val.split(',').map(s => s.trim()).filter(Boolean);
			if (t.endpoints.length > 0 && !snap.connection.endpoint) snap.connection.endpoint = t.endpoints[0];
		}
		else if (key.includes('time since') && key.includes('handshake')) t.timeSinceHandshake = val;
		else if (key === 'sent') t.sent = val;
		else if (key === 'received') t.received = val;
		else if (key.includes('sent') && key.includes('received')) {
			// "Sent: 1.0MB; Received: 843.7kB" on one line
			const sentM = val.match(/Sent:\s*(\S+)/i);
			const rcvM = val.match(/Received:\s*(\S+)/i);
			if (sentM) t.sent = sentM[1];
			if (rcvM) t.received = rcvM[1];
		}
		else if (key.includes('estimated latency') || key === 'latency') t.estimatedLatency = val;
		else if (key.includes('estimated loss') || key === 'loss') t.estimatedLoss = val;
	}

	// Also scan for "Sent: X; Received: Y" on single lines
	const sentRcvM = content.match(/Sent:\s*(\S+);\s*Received:\s*(\S+)/i);
	if (sentRcvM) { t.sent = t.sent || sentRcvM[1]; t.received = t.received || sentRcvM[2]; }
}

function parseWarpNetwork(content, snap) {
	const n = snap.network;
	for (const line of content.split('\n')) {
		// "IPv4: [Interface; IP; Name; Interface GUID: X; Interface Index: Y; Gateway: Some(Z)]"
		const ipv4M = line.match(/^IPv4:\s*\[([^\]]+)\]/);
		if (ipv4M) {
			const parts = ipv4M[1].split(';').map(s => s.trim());
			const iface = parts[0];
			const ip = parts[1];
			const gw = (parts.find(p => p.startsWith('Gateway:')) || '').match(/Some\(([^)]+)\)/);
			if (ip) snap.connection.primaryLocalIp = ip;
			if (gw) snap.connection.gatewayIp = snap.connection.gatewayIp || gw[1];
			n.primaryInterface = iface;
		}
		// "DNS servers:" followed by indented list
		if (/^DNS\s+servers:/i.test(line)) {
			n.dns.nameservers = n.dns.nameservers || [];
		}
		const dnsM = line.match(/^\s+([\d.:]+)(?::\d+)?$/);
		if (dnsM && n.dns.nameservers) {
			n.dns.nameservers.push(dnsM[1]);
		}
		// "Captive Network?: false"
		const cpM = line.match(/^Captive\s*Network.*?:\s*(\w+)/i);
		if (cpM) n.captiveNetwork = cpM[1].toLowerCase() === 'true';
	}
}

function parseConfActive(content, snap) {
	try {
		const json = JSON.parse(content);

		// Interface IPs
		if (json.interface) {
			if (json.interface.v4) snap.connection.warpIpv4 = json.interface.v4;
			if (json.interface.v6) snap.connection.warpIpv6 = json.interface.v6;
		}

		// Endpoints
		if (Array.isArray(json.endpoints)) {
			snap.tunnel.endpoints = json.endpoints.map(e => e.v4 || e.v6).filter(Boolean);
			if (!snap.connection.endpoint && json.endpoints[0]) {
				snap.connection.endpoint = json.endpoints[0].v4 || json.endpoints[0].v6;
			}
		}

		// Public key
		if (json.own_public_key) snap.account.publicKey = snap.account.publicKey || json.own_public_key;
		if (json.public_key) snap.account.gatewayPublicKey = json.public_key;

		// Registration ID
		if (json.registration_id && Array.isArray(json.registration_id)) {
			snap.account.deviceId = snap.account.deviceId || json.registration_id[0];
		}

		// Account
		if (json.account) {
			snap.account.accountType = json.account.account_type || snap.account.accountType;
			snap.account.accountId = json.account.id || snap.account.accountId;
			snap.account.organization = json.account.organization || snap.account.organization;
			snap.account.team = snap.account.team || json.account.organization;
			snap.account.managed = json.account.managed;
		}

		// Policy (operation mode, tunnel protocol, split tunnel etc.)
		if (json.policy) {
			const p = json.policy;
			if (p.operation_mode) snap.connection.mode = snap.connection.mode || humanizeMode(p.operation_mode);
			if (p.tunnel_protocol) snap.tunnel.protocol = snap.tunnel.protocol || p.tunnel_protocol;
			if (p.switch_locked !== undefined) snap.connection.switchLocked = String(p.switch_locked);
			if (p.auto_connect !== undefined) snap.connection.autoConnect = String(p.auto_connect);
			if (p.captive_portal !== undefined) snap.settings.captivePortal = String(p.captive_portal);
			if (p.gateway_id) snap.account.gatewayId = p.gateway_id;
			if (p.support_url) snap.settings.supportUrl = p.support_url;
			if (p.organization) snap.account.organization = snap.account.organization || p.organization;
			if (p.profile_id) snap.settings.profileId = p.profile_id;
			if (p.allow_mode_switch !== undefined) snap.settings.allowModeSwitch = p.allow_mode_switch;
			if (p.allow_updates !== undefined) snap.settings.allowUpdates = p.allow_updates;
			if (p.allowed_to_leave !== undefined) snap.settings.allowedToLeave = p.allowed_to_leave;
			if (p.post_quantum) snap.tunnel.postQuantum = p.post_quantum;

			// Split tunnel
			if (Array.isArray(p.exclude) && p.exclude.length > 0) {
				snap.settings.splitTunnel = {
					mode: 'exclude',
					exclude: p.exclude.map(x => x.address + (x.description ? ` (${x.description})` : '')),
					includeAlways: (p.always_include || []).map(x => x.ip),
					excludeAlways: (p.always_exclude || []).map(x => x.ip),
				};
			}
			if (Array.isArray(p.include) && p.include.length > 0) {
				snap.settings.splitTunnel = snap.settings.splitTunnel || { mode: 'include' };
				snap.settings.splitTunnel.include = p.include.map(x => x.address || x);
			}

			// Fallback domains
			if (Array.isArray(p.fallback_domains)) {
				snap.network.dns.fallbackDomains = p.fallback_domains.map(f => f.suffix).filter(Boolean);
			}

			// DEX tests
			if (Array.isArray(p.dex_tests)) {
				snap.tunnel.dexTests = p.dex_tests.map(t => ({
					name: t.name,
					interval: t.interval,
					enabled: t.enabled,
					host: t.data?.host,
					method: t.data?.method,
				}));
			}
		}
		if (Array.isArray(json.dex_tests) && !snap.tunnel.dexTests) {
			snap.tunnel.dexTests = json.dex_tests.map(t => ({
				name: t.name, interval: t.interval, enabled: t.enabled,
				host: t.data?.host, method: t.data?.method,
			}));
		}

		// Valid until (registration expiry)
		if (json.valid_until) snap.account.validUntil = json.valid_until;

		// Install root CA
		if (json.install_root_ca !== undefined) snap.settings.installRootCa = json.install_root_ca;
	} catch (e) {
		console.warn('conf-active.json parse error:', e.message);
	}
}

function humanizeMode(raw) {
	const m = {
		'WarpWithDnsOverHttps': 'WARP with DoH',
		'Warp': 'WARP',
		'DnsOverHttps': 'DNS over HTTPS',
		'Proxy': 'Proxy',
		'Off': 'Off',
	};
	return m[raw] || raw;
}

function parseRegistrationCache(content, snap) {
	try {
		const json = JSON.parse(content);
		if (json.active_user) snap.account.user = snap.account.user || json.active_user;
		if (json.user_registrations) {
			for (const [user, reg] of Object.entries(json.user_registrations)) {
				if (reg.active_org && !snap.account.organization) snap.account.organization = reg.active_org;
				if (reg.active_org && !snap.account.team) snap.account.team = reg.active_org;
			}
		}
	} catch { }
}

function parseConnectionStats(content, snap) {
	// Each line: "2025-10-07T19:23:54.126Z warp-connection-stats: Time since handshake: 0.82s, tx: 248 B, rx: 0 B, loss: 0.0 %, latency: 207 ms"
	const lines = content.split('\n').filter(l => l.trim());
	if (!lines.length) return;

	const samples = [];
	for (const line of lines) {
		const m = line.match(/Time since handshake:\s*([\d.]+)s,\s*tx:\s*([\d.]+\s*\w*),\s*rx:\s*([\d.]+\s*\w*),\s*loss:\s*([\d.]+)\s*%,\s*latency:\s*([\d.]+)\s*ms/i);
		if (m) {
			const tsM = line.match(/^(\S+Z)/);
			samples.push({
				timestamp: tsM ? tsM[1] : '',
				handshakeAge: parseFloat(m[1]),
				tx: m[2].trim(),
				rx: m[3].trim(),
				loss: parseFloat(m[4]),
				latencyMs: parseFloat(m[5]),
			});
		}
	}

	if (samples.length === 0) return;

	// Compute aggregates from last 100 samples (most recent)
	const recent = samples.slice(-100);
	const avgLatency = recent.reduce((a, s) => a + s.latencyMs, 0) / recent.length;
	const maxLatency = Math.max(...recent.map(s => s.latencyMs));
	const avgLoss = recent.reduce((a, s) => a + s.loss, 0) / recent.length;
	// Count zero-rx samples (potential tunnel issue)
	const zeroRx = recent.filter(s => s.rx === '0 B' || s.rx === '0B' || s.rx === '0 b').length;

	snap.tunnel.connectionSamples = samples.length;
	snap.tunnel.avgLatencyMs = Math.round(avgLatency);
	snap.tunnel.maxLatencyMs = Math.round(maxLatency);
	snap.tunnel.avgLossPct = +avgLoss.toFixed(2);
	snap.tunnel.zeroRxSamples = zeroRx;
	snap.tunnel.zeroRxPct = Math.round((zeroRx / recent.length) * 100);
	snap.tunnel.latestSample = samples[samples.length - 1];
}

function parseWarpDnsStats(content, snap) {
	// Could be warp-dns-stats.txt (key:value) or dns_stats.log (per-line stats)
	const dns = snap.network.dns;
	// Per-line format: "Queries: N, Success: P%, TimedOut: P%, ..."
	const statsLines = content.split('\n').filter(l => l.includes('Queries:') && l.includes('Success'));
	if (statsLines.length > 0) {
		// Use the last (most recent) sample
		const last = statsLines[statsLines.length - 1];
		const qM = last.match(/Queries:\s*(\d+)/);
		const sM = last.match(/Success:\s*([\d.]+)\s*%/);
		const tM = last.match(/TimedOut:\s*([\d.]+)\s*%/);
		const nM = last.match(/NoRecordsFound:\s*([\d.]+)\s*%/);
		const dM = last.match(/Avg Duration:\s*([\d.]+)\s*ms/);
		if (qM) dns.queries = parseInt(qM[1], 10);
		if (sM) dns.successPct = parseFloat(sM[1]);
		if (tM) dns.timeoutPct = parseFloat(tM[1]);
		if (nM) dns.noRecordsPct = parseFloat(nM[1]);
		if (dM) dns.avgDurationMs = parseFloat(dM[1]);
		return;
	}
	// Simple key:value format
	for (const line of content.split('\n')) {
		const m = line.match(/^([^:]+):\s*(.+)$/);
		if (!m) continue;
		const key = m[1].trim().toLowerCase();
		const val = m[2].trim();
		if (key === 'queries') dns.queries = parseInt(val, 10);
		else if (key === 'average duration') dns.avgDuration = val;
		else if (key === 'success') dns.successPct = parseFloat(val);
		else if (key === 'timed out') dns.timeoutPct = parseFloat(val);
		else if (key === 'no records found') dns.noRecordsPct = parseFloat(val);
		else if (key === 'other error') dns.otherErrorPct = parseFloat(val);
	}
}

function parseWarpStatsJson(content, snap) {
	try {
		const json = JSON.parse(content);
		snap.tunnel.metrics = json;
	} catch { }
}

function parseDexData(content, snap) {
	try {
		const json = JSON.parse(content);
		if (Array.isArray(json)) {
			snap.tunnel.dexTestsDetailed = json.map(t => ({
				name: t.definition?.name,
				host: t.definition?.data?.host,
				interval: t.definition?.interval,
				enabled: t.definition?.enabled,
				result: t.result,
				lastRun: t.last_run,
			}));
		}
	} catch { }
}

function parseDexLog(content, snap) {
	// Extract DEX test results from log lines
	const lines = content.split('\n').slice(-50);
	const results = [];
	for (const line of lines) {
		const m = line.match(/DEX\s+(\w+)\s*:?\s*([\s\S]+)/i);
		if (m) results.push({ line: line.trim().substring(0, 200) });
	}
	if (results.length) snap.tunnel.dexLogs = results;
}

function parseWindowsInterfacesConfig(content, snap) {
	// netsh output: "Configuration for interface "X"" blocks
	const blocks = content.split(/\n(?=Configuration for interface)/);
	for (const block of blocks) {
		const nameM = block.match(/Configuration for interface "([^"]+)"/);
		if (!nameM) continue;
		const iface = { name: nameM[1], addresses: [] };

		const ipM = block.match(/IP Address:\s+([\d.]+)/);
		if (ipM) iface.addresses.push({ family: 'IPv4', addr: ipM[1] });

		const maskM = block.match(/Subnet Prefix:\s+(\S+)/);
		if (maskM && iface.addresses[0]) iface.addresses[0].netmask = maskM[1];

		const gwM = block.match(/Default Gateway:\s+([\d.]+)/);
		if (gwM) iface.gateway = gwM[1];

		const dhcpM = block.match(/DHCP enabled:\s+(\w+)/);
		if (dhcpM) iface.dhcp = dhcpM[1].toLowerCase() === 'yes';

		const metricM = block.match(/InterfaceMetric:\s+(\d+)/);
		if (metricM) iface.metric = parseInt(metricM[1], 10);

		const dnsM = block.matchAll(/(?:Statically Configured DNS Servers:|^\s{30,})\s+([\d.]+)/g);
		const dnsList = [];
		for (const d of dnsM) dnsList.push(d[1]);
		if (dnsList.length) iface.dns = dnsList;

		// Detect WARP interface
		if (/cloudflare|warp|utun|wg\d/i.test(iface.name)) iface.isWarp = true;

		// Considered "up" if it has an IP (netsh doesn't always show state)
		iface.up = iface.addresses.length > 0;

		snap.network.interfaces.push(iface);

		// Populate gateway at snapshot level from default route interface
		if (iface.gateway && !snap.connection.gatewayIp) snap.connection.gatewayIp = iface.gateway;
	}
}

function parseDnsClient(content, snap) {
	// PowerShell Get-DnsClient output — just record interface DNS binding
	const lines = content.split('\n');
	const binds = [];
	for (const line of lines) {
		// "CloudflareWARP                      14                          {}                       True             False"
		const m = line.match(/^(\S+(?:\s+\S+)*?)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\w+)\s+(\w+)/);
		if (m && !line.startsWith('Interface') && !line.startsWith('-')) {
			binds.push({ interface: m[1].trim(), index: parseInt(m[2], 10) });
		}
	}
	if (binds.length) snap.network.dnsClients = binds;
}

function parseWindowsVersion(content, snap) {
	const text = content.trim();
	if (text && !text.toLowerCase().startsWith('cannot')) {
		snap.device.platform = snap.device.platform || text;
	}
}

function parseSystemInfo(content, snap) {
	// Windows `systeminfo` command output
	for (const line of content.split('\n').slice(0, 50)) {
		const m = line.match(/^([^:]+):\s+(.+)$/);
		if (!m) continue;
		const key = m[1].trim().toLowerCase();
		const val = m[2].trim();
		if (key === 'os name') snap.device.platform = snap.device.platform || val;
		else if (key === 'os version') snap.device.osVersion = val;
		else if (key === 'system manufacturer') snap.device.manufacturer = val;
		else if (key === 'system model') snap.device.model = val;
		else if (key === 'system type') snap.device.architecture = val;
		else if (key === 'total physical memory') snap.device.memory = val;
		else if (key === 'host name') snap.device.hostname = val;
		else if (key === 'domain') snap.device.domain = val;
	}
}

function parseVersionFile(content, snap) {
	// Real format:
	//   Version: 2025.7.106.1
	//   Commit: 87c544699d5cc7909f4bfec70ad4a602aa4ffee9
	//   2025.7.106.1
	const vM = content.match(/Version:\s*(\S+)/i);
	const cM = content.match(/Commit:\s*(\S+)/i);
	if (vM) snap.connection.warpVersion = vM[1];
	else snap.connection.warpVersion = content.trim().split('\n').filter(l => l.trim())[0] || content.trim();
	if (cM) snap.connection.warpCommit = cM[1];
}

function parseConnectivity(content, snap) {
	// Real WARP connectivity.txt format has several sections:
	//   - "Tunnel Endpoint" with a bare IP on next line
	//   - "DNS Resolution" with "Resolved 'X' to:" and indented list
	//   - "Trace Result" with tab-indented "key=value" Cloudflare trace fields
	//   - "Error Tracing 'X' via Y: reqwest::Error { ... TimedOut }"
	const c = snap.connection;
	const tests = [];
	const traces = [];
	const sections = content.split(/^={5,}$/m);

	// Parse Cloudflare trace key=value fields from tab-indented lines
	let currentTrace = null;
	const lines = content.split('\n');
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		const traceStart = line.match(/^Trace '([^']+)'\s+via\s+(\S+):/);
		if (traceStart) {
			if (currentTrace) traces.push(currentTrace);
			currentTrace = { target: traceStart[1], via: traceStart[2].replace(/:$/, ''), fields: {} };
			continue;
		}
		const errStart = line.match(/^Error Tracing '([^']+)' via (\S+):\s*(.*)/);
		if (errStart) {
			if (currentTrace) { traces.push(currentTrace); currentTrace = null; }
			const errType = (line + ' ' + (lines[i + 1] || '')).match(/TimedOut|ConnectionRefused|DnsError|NetworkUnreachable/);
			tests.push({ target: errStart[1], via: errStart[2].replace(/:$/, ''), result: errType ? errType[0] : 'Error' });
			continue;
		}
		// Tab-indented key=value line within a trace
		const tabKv = line.match(/^\t([a-z_]+)=(.+)$/i);
		if (tabKv && currentTrace) {
			currentTrace.fields[tabKv[1]] = tabKv[2].trim();
		}
	}
	if (currentTrace) traces.push(currentTrace);

	// Extract key info from successful traces
	for (const t of traces) {
		const f = t.fields;
		if (f.colo && !c.colo) c.colo = f.colo;
		if (f.ip && !c.myIp) c.myIp = f.ip;
		if (f.loc && !c.location) c.location = f.loc;
		if (f.warp === 'on' && !c.warpOnTrace) c.warpOnTrace = true;
		if (f.gateway === 'on' && !c.gatewayOnTrace) c.gatewayOnTrace = true;
		if (f.tls) c.tlsVersion = f.tls;
		if (f.rtt !== undefined && !c.traceRtt) c.traceRtt = parseInt(f.rtt, 10);
	}

	// "Tunnel Endpoint" section: next non-blank line is the endpoint
	const tunnelEpIdx = lines.findIndex(l => /Tunnel\s*Endpoint/i.test(l));
	if (tunnelEpIdx >= 0) {
		for (let i = tunnelEpIdx + 1; i < Math.min(tunnelEpIdx + 5, lines.length); i++) {
			const l = lines[i].trim();
			if (!l || /^={5,}/.test(l)) continue;
			if (/^[\d.]+$/.test(l) || /^[0-9a-f:]+$/i.test(l)) {
				c.endpoint = c.endpoint || l;
				break;
			}
		}
	}

	// DNS Resolved entries
	const dnsResolved = [];
	for (let i = 0; i < lines.length; i++) {
		const m = lines[i].match(/Resolved '([^']+)' to:/);
		if (m) {
			const answers = [];
			for (let j = i + 1; j < lines.length; j++) {
				const addr = lines[j].match(/^\t-\s+(\S+)/);
				if (addr) answers.push(addr[1].replace(/:\d+$/, ''));
				else if (lines[j].trim() && !lines[j].startsWith('\t')) break;
			}
			dnsResolved.push({ host: m[1], answers });
		}
	}
	if (dnsResolved.length) snap.network.dns.resolved = dnsResolved;

	// Generic patterns as fallback
	for (const line of lines) {
		const epMatch = line.match(/\b(\S+\.cloudflareclient\.com|\S+\.cloudflare-gateway\.com)\b/);
		if (epMatch && !c.endpoint) c.endpoint = c.endpoint || epMatch[1];
	}

	// Store traces (trimmed)
	if (traces.length) c.traces = traces.slice(0, 20).map(t => ({
		target: t.target, via: t.via,
		colo: t.fields.colo, ip: t.fields.ip, warp: t.fields.warp,
		gateway: t.fields.gateway, tls: t.fields.tls, rtt: t.fields.rtt,
	}));
	if (tests.length) c.connectivityTests = tests;
}

function parseWarpStats(content, snap) {
	const t = snap.tunnel;
	for (const line of content.split('\n')) {
		const lower = line.toLowerCase();
		const m = line.match(/^([^:=]+)[:=]\s*(.+)$/);
		if (!m) continue;
		const key = m[1].trim().toLowerCase();
		const val = m[2].trim();
		if (key.includes('bytes') || key.includes('packets') || key.includes('handshake') || key.includes('rx') || key.includes('tx') || key.includes('rtt') || key.includes('latency')) {
			t[key.replace(/\s+/g, '_')] = val;
		}
	}
}

function parseDevicePosture(content, snap) {
	// Device posture is often JSON
	try {
		const json = JSON.parse(content);
		if (Array.isArray(json)) {
			snap.posture.checks = json;
		} else if (json.checks) {
			snap.posture = { ...snap.posture, ...json };
		} else {
			snap.posture.data = json;
		}
		return;
	} catch { /* fall through to line-based parse */ }

	// Line-based: "check_name: pass/fail"
	for (const line of content.split('\n')) {
		const m = line.match(/^([^:]+):\s*(pass|fail|passed|failed|true|false|allowed|denied)/i);
		if (m) {
			snap.posture.checks.push({
				name: m[1].trim(),
				status: m[2].toLowerCase(),
				passed: /pass|true|allowed/i.test(m[2]),
			});
		}
	}
}

function parseInterfaces(content, snap) {
	// Parse ifconfig-style output
	const blocks = content.split(/\n(?=\S)/);
	for (const block of blocks) {
		if (!block.trim()) continue;
		const nameM = block.match(/^(\S+?):/m) || block.match(/^([A-Za-z0-9_]+)\s/);
		if (!nameM) continue;
		const iface = { name: nameM[1].replace(/:$/, ''), addresses: [] };

		// IPv4
		const ipv4Matches = block.matchAll(/inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\s+netmask\s+(\S+))?/g);
		for (const m of ipv4Matches) iface.addresses.push({ family: 'IPv4', addr: m[1], netmask: m[2] || null });

		// IPv6
		const ipv6Matches = block.matchAll(/inet6\s+([0-9a-f:]+)/gi);
		for (const m of ipv6Matches) iface.addresses.push({ family: 'IPv6', addr: m[1] });

		// MAC
		const macM = block.match(/ether\s+([0-9a-f:]{17})|HWaddr\s+([0-9a-f:]{17})/i);
		if (macM) iface.mac = (macM[1] || macM[2]).toLowerCase();

		// MTU
		const mtuM = block.match(/mtu\s+(\d+)/i);
		if (mtuM) iface.mtu = parseInt(mtuM[1], 10);

		// Status flags
		if (/UP[\s,]/i.test(block)) iface.up = true;
		if (/DOWN/i.test(block)) iface.up = false;

		// Detect WARP interface
		if (/^(CloudflareWARP|utun|wg\d|warp)/i.test(iface.name)) iface.isWarp = true;

		if (iface.name) snap.network.interfaces.push(iface);
	}

	// Windows ipconfig style
	if (snap.network.interfaces.length === 0) {
		const winBlocks = content.split(/\n(?=\w+.*adapter\s)/i);
		for (const block of winBlocks) {
			const nameM = block.match(/adapter\s+([^:]+):/i);
			if (!nameM) continue;
			const iface = { name: nameM[1].trim(), addresses: [] };
			const ipv4 = block.match(/IPv4[^:]*:\s*([\d.]+)/i);
			if (ipv4) iface.addresses.push({ family: 'IPv4', addr: ipv4[1] });
			const ipv6 = block.match(/IPv6[^:]*:\s*([0-9a-f:]+)/i);
			if (ipv6) iface.addresses.push({ family: 'IPv6', addr: ipv6[1] });
			const mac = block.match(/Physical\s+Address[^:]*:\s*([0-9a-f-]{17})/i);
			if (mac) iface.mac = mac[1].replace(/-/g, ':').toLowerCase();
			if (/cloudflare|warp/i.test(iface.name)) iface.isWarp = true;
			snap.network.interfaces.push(iface);
		}
	}
}

function parseRoutes(content, snap) {
	for (const line of content.split('\n')) {
		if (!line.trim() || /^(Destination|Kernel|Routing|Internet|default|={3,}|-{3,})/i.test(line.split(/\s+/)[0])) {
			// Include `default` routes specifically
		}
		// Unix: destination gateway flags iface
		const m = line.match(/^(default|\d{1,3}(?:\.\d{1,3}){3}(?:\/\d+)?)\s+(\S+)?\s+.*?\s+(\S+)$/);
		if (m) {
			snap.network.routes.push({ dest: m[1], gateway: m[2], iface: m[3] });
		}
	}
}

function parseNetstat(content, snap) {
	const conns = [];
	for (const line of content.split('\n')) {
		const m = line.match(/^(tcp|udp)\S*\s+\d+\s+\d+\s+([\d.]+[:.]\d+)\s+([\d.]+[:.]\d+)\s+(\S+)?/i);
		if (m) {
			conns.push({ proto: m[1].toLowerCase(), local: m[2], remote: m[3], state: m[4] || '' });
		}
	}
	if (conns.length) snap.network.connections = conns;
}

function parseResolvConf(content, snap) {
	const dns = snap.network.dns;
	dns.nameservers = [];
	dns.search = [];
	for (const line of content.split('\n')) {
		const trimmed = line.trim();
		if (trimmed.startsWith('#') || !trimmed) continue;
		const m = trimmed.match(/^(nameserver|search|domain)\s+(.+)$/i);
		if (!m) continue;
		if (m[1].toLowerCase() === 'nameserver') dns.nameservers.push(m[2].trim());
		else if (m[1].toLowerCase() === 'search') dns.search.push(...m[2].split(/\s+/));
		else if (m[1].toLowerCase() === 'domain') dns.domain = m[2].trim();
	}
}

function parseDnsCheck(content, snap) {
	const dns = snap.network.dns;
	if (!dns.tests) dns.tests = [];
	const lines = content.split('\n');
	let current = null;

	for (const line of lines) {
		// dig-style ANSWER section
		const qM = line.match(/;\s*(\S+)\.?\s+IN\s+(A|AAAA|TXT|MX|CNAME|SRV|NS)/i);
		if (qM) { current = { query: qM[1], type: qM[2].toUpperCase(), answers: [] }; dns.tests.push(current); continue; }
		// nslookup-style
		const nsM = line.match(/^(Name|Address|Server):\s*(.+)$/i);
		if (nsM && current) {
			if (nsM[1].toLowerCase() === 'address') current.answers.push(nsM[2].trim());
		}
		// Simple test result lines
		const t = line.match(/^(\S+)\s+.*?(failed|timeout|success|nxdomain|servfail|refused)/i);
		if (t) dns.tests.push({ target: t[1], result: t[2] });
	}

	// Summary counts
	if (dns.tests.length) {
		dns.testsTotal = dns.tests.length;
		dns.testsFailed = dns.tests.filter(t => /fail|timeout|nxdomain|servfail|refused/i.test(t.result || '')).length;
	}
}

function parseSysInfo(content, snap) {
	try {
		const info = JSON.parse(content);
		snap.device = { ...snap.device, ...info };
	} catch { /* ignore */ }
}

function parseMdm(content, snap) {
	// MDM is usually plist XML or JSON
	try {
		if (content.trim().startsWith('{')) {
			snap.mdm = JSON.parse(content);
			return;
		}
	} catch { /* fall through */ }

	// Extract key/string pairs from plist XML
	const pairs = {};
	const plistRegex = /<key>([^<]+)<\/key>\s*<(string|integer|true|false|array)\/?>([\s\S]*?)<\/\2>|<key>([^<]+)<\/key>\s*<(true|false)\s*\/>/g;
	let m;
	while ((m = plistRegex.exec(content)) !== null) {
		if (m[1]) pairs[m[1]] = m[2] === 'true' ? true : m[2] === 'false' ? false : m[3];
		else if (m[4]) pairs[m[4]] = m[5] === 'true';
	}
	if (Object.keys(pairs).length > 0) snap.mdm = pairs;
}

function parseCertificate(content, filename, snap) {
	const info = { filename };
	const subject = content.match(/Subject:\s*(.+)/);
	if (subject) info.subject = subject[1].trim();
	const issuer = content.match(/Issuer:\s*(.+)/);
	if (issuer) info.issuer = issuer[1].trim();
	const notBefore = content.match(/Not Before[:\s]+(.+)/);
	if (notBefore) info.notBefore = notBefore[1].trim();
	const notAfter = content.match(/Not After[:\s]+(.+)/);
	if (notAfter) info.notAfter = notAfter[1].trim();
	if (!snap.device.certificates) snap.device.certificates = [];
	snap.device.certificates.push(info);
}

function parseTraceroute(content, filename, snap) {
	const target = (filename.match(/traceroute[_\-](.+?)\.(txt|log)/i) || [])[1] || 'unknown';
	const hops = [];
	for (const line of content.split('\n')) {
		// Hop line: " 1  192.168.1.1  (192.168.1.1)  1.234 ms"
		const m = line.match(/^\s*(\d+)\s+(\S+)(?:\s+\(([^)]+)\))?\s+(.+)$/);
		if (m) {
			const latencies = (m[4].match(/[\d.]+\s*ms/g) || []).map(s => parseFloat(s));
			hops.push({
				hop: parseInt(m[1], 10),
				host: m[2] === '*' ? null : m[2],
				ip: m[3] || null,
				latencyMs: latencies.length ? Math.min(...latencies) : null,
				timeout: m[2] === '*',
			});
		}
	}
	if (!snap.network.traceroutes) snap.network.traceroutes = [];
	if (hops.length) snap.network.traceroutes.push({ target, hops });
}

function parseArp(content, snap) {
	const entries = [];
	for (const line of content.split('\n')) {
		const m = line.match(/(\S+)\s+\(([\d.]+)\)\s+at\s+([0-9a-f:]{17})/i) ||
			line.match(/^([\d.]+)\s+\S+\s+([0-9a-f:-]{17})/i);
		if (m) {
			if (m.length === 4) entries.push({ hostname: m[1], ip: m[2], mac: m[3] });
			else entries.push({ ip: m[1], mac: m[2].replace(/-/g, ':') });
		}
	}
	if (entries.length) snap.network.arp = entries;
}

function parseDaemonLog(content, filename, snap) {
	const lines = content.split('\n');
	// For performance, only analyse last 2000 lines of very long logs
	const toScan = lines.length > 3000 ? lines.slice(-2000) : lines;
	const offset = lines.length - toScan.length;

	for (let i = 0; i < toScan.length; i++) {
		const line = toScan[i];
		if (!line.trim()) continue;

		const lineNum = offset + i + 1;
		const severity = classifySeverity(line);
		const ts = extractTimestamp(line);

		// Match known event patterns
		for (const ev of DAEMON_EVENTS) {
			if (ev.pattern.test(line)) {
				snap.timeline.push({
					timestamp: ts.str,
					parsedTs: ts.parsed,
					type: ev.type,
					severity: ev.severity,
					source: filename,
					lineNumber: lineNum,
					message: line.trim().substring(0, 300),
				});
				break;
			}
		}

		// Also capture high-severity lines not matching known patterns
		if ((severity === 'critical' || severity === 'error') &&
			!snap.timeline.find(t => t.lineNumber === lineNum && t.source === filename)) {
			snap.timeline.push({
				timestamp: ts.str,
				parsedTs: ts.parsed,
				type: severity === 'critical' ? 'Critical Error' : 'Error',
				severity: severity === 'critical' ? 'critical' : 'error',
				source: filename,
				lineNumber: lineNum,
				message: line.trim().substring(0, 300),
			});
		}
	}
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function classifySeverity(line) {
	for (const [sev, patterns] of Object.entries(SEVERITY_PATTERNS)) {
		for (const p of patterns) if (p.test(line)) return sev;
	}
	return 'info';
}

function extractTimestamp(line) {
	for (const p of TIMESTAMP_PATTERNS) {
		const m = line.match(p);
		if (m) {
			const str = m[1];
			let parsed = Date.parse(str);
			if (!isNaN(parsed)) return { str, parsed };
			return { str, parsed: 0 };
		}
	}
	return { str: '', parsed: 0 };
}

// ── Rule-based findings ────────────────────────────────────────────────────────

function deriveFindings(snap, files) {
	const findings = [];
	const d = snap.diagnostics;

	// ── Prescriptive diagnostic findings (debrief-style) ───────────────────────
	// These carry extra fields consumed by the UI/PDF debrief:
	//   what_logs_show  — verbatim/near-verbatim log evidence
	//   what_experienced — plain-English description of user impact

	// 1) Windows kernel resource exhaustion (error 1450)
	if (d.resourceErrors.length > 0) {
		const first = d.resourceErrors[0];
		const logLines = [];
		if (first) logLines.push(`${first.ts || ''} ERROR: unexpected error when polling the I/O driver: Os { code: 1450, message: "Insufficient system resources exist to complete the requested service." }`.trim());
		if (d.watchdog.forcedRestarts > 0) logLines.push(`watchdog: Process has been hung for too long, restarting it manually`);
		logLines.push(`-- ${d.watchdog.hangEvents} "hung daemon" events, ${d.watchdog.forcedRestarts} forced restart(s), ${d.watchdog.panicCount} panic(s) total --`);
		if (d.collectionTimeoutFiles && d.collectionTimeoutFiles.length) logLines.push(`${d.collectionTimeoutFiles.slice(0, 4).join(', ')} — timed out at 30s`);
		if (d.wmi.degraded) logLines.push('WMI health probe: TIMEOUT (COM subsystem degraded)');
		findings.push({
			severity: 'Critical', blocking: true, category: 'System',
			title: 'Windows kernel resource exhaustion (error 1450)',
			description: `${d.resourceErrors.length} occurrence(s) of Windows error 1450 (insufficient system resources). The host ran out of kernel nonpaged pool or handle capacity, cascading into WARP, WMI and PowerShell.`,
			what_logs_show: logLines.join('\n'),
			what_experienced: 'The whole machine was degrading — applications sluggish, management tools stalling. WARP appeared connected briefly after each restart, then dropped and could not recover.',
			root_cause: 'The Windows host exhausted kernel memory (nonpaged pool) or handle capacity — most often caused by a leaking kernel-mode driver (endpoint security agent or network filter).',
			remediation: '1. Reboot to clear the exhausted kernel pool 2. Monitor Nonpaged pool in Resource Monitor during degradation 3. Use poolmon.exe to find the leaking pool tag 4. Isolate the offending kernel driver (EDR/AV/WFP) 5. Update the offending agent',
			evidence_keywords: ['1450', 'Insufficient system resources', 'I/O driver'],
			affected_files: [...new Set(d.resourceErrors.map(e => e.file))],
		});
	}

	// 2) WARP daemon hang / restart / panic loop
	if (d.watchdog.forcedRestarts > 0 || (d.watchdog.panicCount > 0 && d.watchdog.hangEvents > 3)) {
		const logLines = [];
		if (d.warpVersion) logLines.push(`INFO warp_svc: Starting warp service version=${d.warpVersion}`);
		logLines.push(`WARN watchdog: hung daemon (hang events: ${d.watchdog.hangEvents}${d.watchdog.maxReportedHangCount ? `, max hang_count=${d.watchdog.maxReportedHangCount}` : ''})`);
		const wd = d.runtimePanics.find(p => p.isWatchdog);
		if (wd) logLines.push(`ERROR: panicked at ${wd.location} — ${wd.message}`);
		findings.push({
			severity: 'Critical', blocking: true, category: 'Connection',
			title: 'WARP daemon in a hang/restart/panic loop',
			description: `The watchdog recorded ${d.watchdog.hangEvents} hang event(s), ${d.watchdog.panicCount} panic(s) and ${d.watchdog.forcedRestarts} forced restart(s). Each restart briefly restored the connection before hanging again.`,
			what_logs_show: logLines.join('\n'),
			what_experienced: "WARP's internal watchdog detected the main processing loop had stalled and restarted the service. Each restart briefly restored connectivity, but the underlying host condition persisted and the daemon hung again. After the final crash the IPC pipe was never recreated.",
			root_cause: 'The daemon main loop stalled repeatedly because of the underlying host resource condition; the watchdog force-restarted it but could not fix the host-level cause.',
			remediation: '1. Fix the host resource condition (reboot + isolate leaking driver) 2. Do not rely on service restarts alone 3. Re-capture a fresh warp-diag during active degradation if it recurs',
			evidence_keywords: ['watchdog', 'hung daemon', 'panicked', 'overly hung daemon'],
			affected_files: [...new Set(d.runtimePanics.map(p => p.file))],
		});
	}

	// 3) IPC named pipe absent at capture time
	if (d.ipc.failures.length > 0) {
		const affected = (d.ipc.affectedFiles || []).map(f => f.split(/[\\/]/).pop());
		findings.push({
			severity: 'Critical', blocking: true, category: 'Connection',
			title: 'WARP IPC named pipe absent at capture time',
			description: `${d.ipc.failures.length} status file(s) returned "IPC: os error 2".${d.ipc.processPresent ? ` The warp-svc process IS present${d.ipc.pid ? ` (pid ${d.ipc.pid})` : ''} — running but the named pipe was not recreated after the last crash.` : ''}`,
			what_logs_show: `Failed to communicate with WARP service over IPC:\n  The system cannot find the file specified. (os error 2)\n-- Returned by: ${affected.slice(0, 10).join(', ') || 'warp-status and other status files'} --${d.ipc.processPresent ? `\nNote: warp-svc process IS present${d.ipc.pid ? ` (pid ${d.ipc.pid})` : ''}; the service is running but the pipe was not recreated.` : ''}`,
			what_experienced: 'The WARP UI reported the client as disconnected and would not respond to connect/disconnect attempts. The tray icon appeared stuck. This is a symptom of the daemon crash — the process exists but the UI-to-service channel is gone.',
			root_cause: 'After the final daemon crash the IPC named pipe was not recreated, so the GUI and CLI could not talk to the service.',
			remediation: '1. Reboot (recreates the pipe and clears the host condition) 2. Confirm warp-svc restarts cleanly 3. If it recurs without reboot, the host resource condition is the driver',
			evidence_keywords: ['os error 2', 'IPC', 'cannot find the file specified'],
			affected_files: [...new Set(d.ipc.failures.map(e => e.file))],
		});
	}

	// 4) WMI subsystem degraded
	if (d.wmi.degraded) {
		findings.push({
			severity: 'Warning', category: 'System',
			title: 'WMI subsystem degraded',
			description: 'WMI probes timed out and/or repository verification failed. WARP operations that use WMI (DDNS registration, posture checks) will also hang.',
			what_logs_show: [
				...d.wmi.timeouts.slice(0, 1).map(t => t.text),
				...d.wmi.errors.slice(0, 1).map(e => e.text),
			].filter(Boolean).join('\n') || 'WMI Probe: TIMEOUT (COM subsystem degraded)',
			what_experienced: 'Management and inventory tools that rely on WMI stalled or returned errors. This is a corroborating symptom of the same host resource condition, not a separate problem.',
			root_cause: 'The COM/WMI subsystem was starved by the same kernel resource exhaustion affecting WARP.',
			remediation: '1. Reboot to restore WMI 2. If WMI stays broken after reboot, run winmgmt /salvagerepository',
			evidence_keywords: ['WMI', '0x80041003', 'COM subsystem'],
		});
	}

	// 5) Early captive-portal probe failures — transient
	if (d.captivePortal && d.captivePortal.failures > 0) {
		const recovered = d.captivePortal.recovered;
		findings.push({
			severity: recovered ? 'Info' : 'Warning', category: 'Network',
			title: recovered ? 'Early captive-portal probe failures — transient, resolved before crash' : 'Captive-portal probe failures',
			description: `${d.captivePortal.failures} captive-portal probe failure(s) recorded${d.captivePortal.firstTs ? ` starting ${d.captivePortal.firstTs}` : ''}.${recovered ? ` All checks recovered${d.captivePortal.recoveredTs ? ` by ${d.captivePortal.recoveredTs}` : ''}.` : ''}`,
			what_logs_show: `captive_portal: Failed HTTP request — TimedOut / HTTPS test request failed (WSAEACCES / os error 10013)${recovered ? `\ncaptive_portal: Captive portal detection completed — NoCaptivePortalDetected` : ''}`,
			what_experienced: 'Shortly after startup, connectivity probes timed out and hit socket-access-forbidden errors. This looks alarming but is an early corroborating signal of the same resource/socket condition — not an actual captive portal.',
			root_cause: 'Ephemeral-port or socket exhaustion and/or endpoint-security WFP filtering interfered with early probes — the same root cause, seen early.',
			remediation: recovered ? '1. No action — the checks recovered on their own 2. Treat as an early indicator of the resource condition' : '1. Complete any captive-portal login 2. Check WFP/endpoint-security filtering',
			evidence_keywords: ['captive_portal', '10013', 'WSAEACCES', 'TimedOut'],
		});
	}

	// 6) Endpoint-security / kernel-driver agents present (contributing factor)
	const kernelAgents = (d.endpointAgents || []).filter(a => a.kernel);
	if (kernelAgents.length && (d.resourceErrors.length > 0 || d.socketErrors.length > 0)) {
		findings.push({
			severity: 'Info', category: 'Security',
			title: 'Endpoint-security agents with kernel components detected',
			description: `Detected: ${kernelAgents.map(a => a.name + (a.version ? ` ${a.version}` : '')).join(', ')}. These load kernel-mode drivers / WFP filters and are the most likely source of the kernel resource leak.`,
			what_logs_show: kernelAgents.map(a => `${a.name}${a.version ? ' ' + a.version : ''} (${a.kind}) [${a.source}]`).join('\n'),
			what_experienced: 'Not directly user-visible, but these agents are prime suspects for the kernel pool leak that crashed WARP.',
			root_cause: 'Kernel-mode security drivers are a common cause of nonpaged-pool leaks and WFP interference.',
			remediation: '1. Update each agent to the latest release 2. Test with each temporarily suspended (per security policy) to isolate the leaker 3. Check Event ID 2019/2020 for the owning pool tag',
			evidence_keywords: kernelAgents.map(a => a.name),
		});
	}

	// 7) No MDM deployment configuration present (informational)
	if ((d.management && d.management.length) && !snap.mdm) {
		findings.push({
			severity: 'Info', category: 'Configuration',
			title: 'No MDM deployment configuration present',
			description: `WARP is enrolled via the Team Name flow, not a managed deployment profile. The device is managed by ${d.management.join(' and ')} but no Cloudflare mdm.xml was found.`,
			what_logs_show: 'C:\\ProgramData\\Cloudflare\\mdm.xml not found',
			what_experienced: 'Not causing the current issue, but WARP settings are not centrally enforced.',
			root_cause: 'No Cloudflare-specific MDM policy has been pushed to a co-managed device.',
			remediation: '1. Deploy mdm.xml via your MDM to lock organization, service mode and split-tunnel rules',
			evidence_keywords: ['mdm.xml', ...d.management],
		});
	}

	// Connection status
	const status = (snap.connection.status || '').toLowerCase();
	if (status === 'disconnected' || status === 'disabled') {
		findings.push({
			severity: 'Critical',
			category: 'Connection',
			title: 'WARP is disconnected',
			description: `Current status is "${snap.connection.status}". Tunnel is not active.`,
			root_cause: 'WARP client is not connected. User may have disabled it or tunnel establishment failed.',
			remediation: '1. Check user has not paused WARP 2. Review daemon.log for connection errors 3. Verify network reachability to engage.cloudflareclient.com 4. Check certificate and account registration status',
			evidence_keywords: ['disconnected', 'tunnel'],
		});
	} else if (status.includes('connecting') || status.includes('registering')) {
		findings.push({
			severity: 'Warning',
			category: 'Connection',
			title: 'WARP stuck in transient state',
			description: `Status is "${snap.connection.status}" — client is not fully established.`,
			root_cause: 'Connection or registration in progress but not complete at capture time.',
			remediation: '1. Check network connectivity 2. Review registration logs 3. Verify firewall allows QUIC/UDP 443',
			evidence_keywords: ['connecting', 'registering'],
		});
	}

	// Timeline-based: recent disconnects or auth failures
	const recentBadEvents = snap.timeline.filter(t =>
		['Disconnected', 'Registration Failed', 'Auth Failed', 'Certificate Error', 'Critical Error'].includes(t.type)
	);
	if (recentBadEvents.length > 0) {
		const latest = recentBadEvents[recentBadEvents.length - 1];
		findings.push({
			severity: latest.severity === 'critical' ? 'Critical' : 'Warning',
			category: 'Connection',
			title: `${recentBadEvents.length} critical event(s) in daemon logs`,
			description: `Including: ${[...new Set(recentBadEvents.map(e => e.type))].join(', ')}`,
			root_cause: 'Recurring tunnel instability, authentication, or certificate problems.',
			remediation: '1. Review timeline for event clustering 2. Check system clock drift (certificates) 3. Re-register device if auth repeatedly fails',
			evidence_keywords: recentBadEvents.slice(0, 3).map(e => e.message.substring(0, 50)),
			affected_files: [...new Set(recentBadEvents.map(e => e.source))],
		});
	}

	// DNS issues — legacy testsFailed count
	if (snap.network.dns.testsFailed > 0) {
		findings.push({
			severity: snap.network.dns.testsFailed > 5 ? 'Critical' : 'Warning',
			category: 'DNS',
			title: `${snap.network.dns.testsFailed} DNS resolution failures`,
			description: `${snap.network.dns.testsFailed} of ${snap.network.dns.testsTotal} DNS tests failed.`,
			root_cause: 'DNS resolver not responding or blocking WARP domains.',
			remediation: '1. Verify DNS is going through WARP (DoH/DoT) 2. Check for DNS filters on the network 3. Test resolution manually with `dig`',
			evidence_keywords: ['timeout', 'nxdomain', 'servfail', 'refused'],
		});
	}

	// DNS stats-based findings (warp-dns-stats.txt / dns_stats.log)
	const dns = snap.network.dns;
	if (dns.timeoutPct !== undefined && dns.timeoutPct > 5) {
		findings.push({
			severity: dns.timeoutPct > 20 ? 'Critical' : 'Warning',
			category: 'DNS',
			title: `${dns.timeoutPct}% DNS query timeouts`,
			description: `${dns.timeoutPct}% of DNS queries are timing out (${dns.queries || '?'} queries total).`,
			root_cause: 'WARP DNS resolver is not responding reliably. Could be network path issues or gateway overload.',
			remediation: '1. Check connectivity to the Cloudflare Gateway DNS 2. Verify no local DNS hijacking 3. Review daemon_dns.log for specific failures',
			evidence_keywords: ['timeout', 'dns', 'doh_err_timeout'],
		});
	}
	if (dns.noRecordsPct !== undefined && dns.noRecordsPct > 15) {
		findings.push({
			severity: 'Warning',
			category: 'DNS',
			title: `${dns.noRecordsPct}% DNS queries returning no records`,
			description: `${dns.noRecordsPct}% of queries returned NXDOMAIN or empty. Could indicate DNS filtering by Gateway, or clients querying nonexistent internal names.`,
			root_cause: 'Clients requesting names not resolvable by Cloudflare Gateway. Potentially missing fallback domains or internal DNS not configured.',
			remediation: '1. Review fallback_domains in warp-settings.txt 2. Check if internal names need local resolver fallback 3. Review Gateway DNS policies for blocks',
			evidence_keywords: ['nxdomain', 'no records found'],
		});
	}

	// Tunnel stats findings — zero RX indicates one-way traffic / broken return path
	const tun = snap.tunnel;
	if (tun.zeroRxPct !== undefined && tun.zeroRxPct > 80 && tun.connectionSamples > 10) {
		findings.push({
			severity: 'Critical',
			category: 'Performance',
			title: `Tunnel receiving no data (${tun.zeroRxPct}% zero-RX samples)`,
			description: `${tun.zeroRxSamples} of recent connection stats samples show 0 bytes received. The client is sending keepalives but getting no response.`,
			root_cause: 'Return path is broken. The tunnel is sending packets out but receiving none back. Possible firewall asymmetry, NAT issue, or MTU blackhole.',
			remediation: '1. Check stateful firewall rules on egress/return path 2. Test with MTU reduction 3. Verify WARP endpoint IP is reachable from client 4. Review boringtun.log for handshake issues',
			evidence_keywords: ['rx: 0 B', 'handshake'],
		});
	}

	// High latency
	if (tun.avgLatencyMs !== undefined && tun.avgLatencyMs > 200) {
		findings.push({
			severity: tun.avgLatencyMs > 500 ? 'Critical' : 'Warning',
			category: 'Performance',
			title: `High tunnel latency (${tun.avgLatencyMs}ms avg, ${tun.maxLatencyMs}ms peak)`,
			description: `Average WARP tunnel RTT is ${tun.avgLatencyMs}ms, well above the expected <100ms for healthy WARP.`,
			root_cause: 'User is connecting to a distant Cloudflare colo, network congestion, or WireGuard is not being preferred over MASQUE.',
			remediation: '1. Check assigned colo matches user geography 2. Compare with baseline from a known-good location 3. Review tunnel protocol (WireGuard should be preferred)',
			evidence_keywords: ['latency'],
		});
	}

	// Packet loss
	if (tun.avgLossPct !== undefined && tun.avgLossPct > 1) {
		findings.push({
			severity: tun.avgLossPct > 5 ? 'Critical' : 'Warning',
			category: 'Performance',
			title: `Packet loss on tunnel (${tun.avgLossPct}%)`,
			description: `Average tunnel packet loss is ${tun.avgLossPct}% over recent samples.`,
			root_cause: 'Network between client and WARP edge is unreliable, or MTU is mismatched.',
			remediation: '1. Test raw UDP connectivity to endpoint 2. Try MTU reduction 3. Check for upstream congestion',
			evidence_keywords: ['loss', 'retrans'],
		});
	}

	// Connectivity test failures (TimedOut to engage/connectivity endpoints)
	const connTests = snap.connection.connectivityTests || [];
	const timeouts = connTests.filter(t => /timeout/i.test(t.result || ''));
	if (timeouts.length > 0) {
		findings.push({
			severity: timeouts.length === connTests.length ? 'Critical' : 'Warning',
			category: 'Connection',
			title: `${timeouts.length} connectivity endpoint(s) timing out`,
			description: `Out of ${connTests.length} Cloudflare endpoint connectivity tests, ${timeouts.length} timed out. Targets: ${[...new Set(timeouts.map(t => t.target))].slice(0, 5).join(', ')}`,
			root_cause: 'Some Cloudflare control plane endpoints are unreachable from this client. Could indicate firewall blocks, NAT issues, or partial network outage.',
			remediation: '1. Verify egress firewall allows HTTPS to *.cloudflareclient.com 2. Check DNS resolution for these hosts 3. Compare IPv4 vs IPv6 reachability (many timeouts are IPv4-specific)',
			evidence_keywords: [...new Set(timeouts.map(t => t.target))].slice(0, 3),
		});
	}

	// Registration approaching expiry
	if (snap.account.validUntil) {
		const exp = Date.parse(snap.account.validUntil);
		if (!isNaN(exp)) {
			const hoursLeft = (exp - Date.now()) / 3600000;
			if (hoursLeft < 0) {
				findings.push({
					severity: 'Critical',
					category: 'Security',
					title: `Registration expired ${Math.abs(hoursLeft / 24).toFixed(1)} day(s) ago`,
					description: `Account registration (conf-active.json valid_until) expired ${snap.account.validUntil}.`,
					root_cause: 'Device registration has expired and was not renewed automatically.',
					remediation: '1. Trigger a WARP re-registration 2. Check daemon.log for auth refresh failures',
					evidence_keywords: ['registration', 'expired', 'valid_until'],
				});
			} else if (hoursLeft < 24) {
				findings.push({
					severity: 'Info',
					category: 'Configuration',
					title: `Registration expires in ${hoursLeft.toFixed(1)} hours`,
					description: `Device registration is nearing expiry at ${snap.account.validUntil}. WARP should renew automatically.`,
					root_cause: 'Normal registration lifecycle; informational.',
					remediation: '1. Monitor for successful renewal 2. If it fails, check daemon.log',
					evidence_keywords: ['valid_until'],
				});
			}
		}
	}

	// Captive portal detected
	if (snap.network.captiveNetwork === true) {
		findings.push({
			severity: 'Warning',
			category: 'Network',
			title: 'Captive portal detected',
			description: 'WARP detected a captive portal on the network. Tunnel may be blocked until the portal is cleared.',
			root_cause: 'User is on a guest/hotel/airport network that intercepts traffic for authentication.',
			remediation: '1. User must complete captive portal login 2. WARP will retry automatically after auth',
			evidence_keywords: ['captive portal'],
		});
	}

	// Missing WARP interface
	const hasWarpIface = (snap.network.interfaces || []).some(i => i.isWarp && i.up !== false);
	if (!hasWarpIface && snap.network.interfaces.length > 0) {
		findings.push({
			severity: 'Critical',
			category: 'Network',
			title: 'No active WARP network interface',
			description: 'CloudflareWARP/utun/wireguard interface is missing or down.',
			root_cause: 'Tunnel interface failed to initialise, was torn down, or was removed by the OS.',
			remediation: '1. Restart WARP 2. Check OS-level permissions (especially macOS System Extensions) 3. Review boringtun.log for interface setup errors',
			evidence_keywords: ['interface', 'utun', 'CloudflareWARP'],
		});
	}

	// MTU issues
	const mtuIssues = snap.timeline.filter(t => t.type === 'MTU Issue');
	if (mtuIssues.length > 0) {
		findings.push({
			severity: 'Warning',
			category: 'Network',
			title: 'MTU/blackhole indicators detected',
			description: `${mtuIssues.length} MTU-related event(s) in logs.`,
			root_cause: 'Path MTU discovery failing or MTU too large for the network path.',
			remediation: '1. Reduce MTU on WARP interface (e.g. 1280 for IPv6, 1420 for IPv4) 2. Check for PMTUD-blocking firewalls 3. Test with DF-bit pings',
			evidence_keywords: ['MTU', 'blackhole', 'fragmentation'],
		});
	}

	// Device posture failures
	const failedPosture = (snap.posture.checks || []).filter(c => c.passed === false);
	if (failedPosture.length > 0) {
		findings.push({
			severity: 'Warning',
			category: 'Security',
			title: `${failedPosture.length} device posture check(s) failing`,
			description: `Failed checks: ${failedPosture.map(c => c.name).join(', ')}`,
			root_cause: 'Device does not meet posture policy requirements.',
			remediation: '1. Review Zero Trust posture policies 2. Remediate failing checks 3. Check if client supports all configured check types',
			evidence_keywords: failedPosture.map(c => c.name),
		});
	}

	// Split tunnel sanity check
	const st = snap.settings.splitTunnel;
	if (st && st.mode === 'exclude' && (st.exclude || []).length === 0) {
		findings.push({
			severity: 'Info',
			category: 'Configuration',
			title: 'Exclude-mode split tunnel with empty list',
			description: 'Split tunnel is set to exclude mode but the exclusion list is empty — all traffic is tunnelled.',
			root_cause: 'Policy mis-configuration — intended exclusions not applied.',
			remediation: '1. Review Zero Trust → Settings → Network → Split Tunnels 2. Verify MDM is pushing the expected config',
			evidence_keywords: ['split_tunnel', 'exclude'],
		});
	}

	// Certificate nearing expiry
	for (const cert of (snap.device.certificates || [])) {
		if (cert.notAfter) {
			const exp = Date.parse(cert.notAfter);
			const now = Date.now();
			const daysLeft = (exp - now) / 86400000;
			if (!isNaN(daysLeft)) {
				if (daysLeft < 0) {
					findings.push({
						severity: 'Critical',
						category: 'Security',
						title: `Certificate expired ${Math.abs(daysLeft).toFixed(0)} day(s) ago`,
						description: `${cert.filename} — expired ${cert.notAfter}`,
						root_cause: 'Installed Cloudflare root / device certificate has expired.',
						remediation: '1. Re-enrol the device with the latest cert bundle 2. Push updated cert via MDM',
						evidence_keywords: ['certificate', 'expired', cert.filename],
					});
				} else if (daysLeft < 30) {
					findings.push({
						severity: 'Warning',
						category: 'Security',
						title: `Certificate expires in ${daysLeft.toFixed(0)} day(s)`,
						description: `${cert.filename} — expires ${cert.notAfter}`,
						root_cause: 'Certificate will expire soon; plan rollover.',
						remediation: '1. Schedule certificate renewal / re-enrolment 2. Confirm MDM has the new cert',
						evidence_keywords: ['certificate', cert.filename],
					});
				}
			}
		}
	}

	return findings;
}

function computeHealth(findings) {
	if (findings.some(f => f.severity === 'Critical' || f.blocking)) return 'Critical';
	if (findings.some(f => f.severity === 'Warning')) return 'Degraded';
	return 'Healthy';
}

// ── Enhanced log evidence search (used by AI analyzer) ─────────────────────────

export function findLogEvidence(files, keywords, maxPerKeyword = 5) {
	const results = [];
	const seen = new Set();

	for (const kw of keywords) {
		if (!kw) continue;
		const needle = String(kw).toLowerCase();
		if (needle.length < 3) continue;

		for (const file of files) {
			const lines = file.content.split('\n');
			let matchCount = 0;
			for (let i = 0; i < lines.length && matchCount < maxPerKeyword; i++) {
				if (lines[i].toLowerCase().includes(needle)) {
					const key = `${file.filename}:${i}`;
					if (seen.has(key)) continue;
					seen.add(key);

					// Include 1 line of context before/after
					const context = [];
					for (let j = Math.max(0, i - 1); j <= Math.min(lines.length - 1, i + 1); j++) {
						if (lines[j].trim()) context.push({ lineNumber: j + 1, content: lines[j], isMatch: j === i });
					}

					results.push({
						filename: file.filename,
						lineNumber: i + 1,
						keyword: kw,
						context,
						severity: classifySeverity(lines[i]),
					});
					matchCount++;
				}
			}
		}
	}

	return results.slice(0, 50);
}
