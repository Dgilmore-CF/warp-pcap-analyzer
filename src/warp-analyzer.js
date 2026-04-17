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
	critical: [/\bFATAL\b/i, /\bCRIT\b/i, /\bCRITICAL\b/i, /\bpanic\b/i, /unreachable\b/i],
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

	// Pass 3 — fill in gaps using the flat property map
	fillGapsFromRaw(snapshot);

	// Sort timeline by timestamp
	snapshot.timeline.sort((a, b) => (a.parsedTs || 0) - (b.parsedTs || 0));

	// Generate rule-based findings from the snapshot
	snapshot.findings = deriveFindings(snapshot, files);

	// Assign health status
	snapshot.health = computeHealth(snapshot.findings);

	return snapshot;
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
	a.user = a.user || tryKeys(['user', 'email', 'user_email', 'user_id']);
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
	const bn = file.filename.toLowerCase().split('/').pop();

	if (bn === 'warp-status.txt' || bn.endsWith('/warp-status.txt')) {
		parseWarpStatus(file.content, snap);
	} else if (bn === 'warp-account.txt' || bn.endsWith('/warp-account.txt')) {
		parseWarpAccount(file.content, snap);
	} else if (bn === 'warp-settings.txt' || bn.endsWith('/warp-settings.txt')) {
		parseWarpSettings(file.content, snap);
	} else if (bn === 'connectivity.txt' || bn.endsWith('/connectivity.txt')) {
		parseConnectivity(file.content, snap);
	} else if (bn === 'warp-stats.txt' || bn === 'stats.log') {
		parseWarpStats(file.content, snap);
	} else if (bn === 'warp-device-posture.txt' || bn.endsWith('/warp-device-posture.txt')) {
		parseDevicePosture(file.content, snap);
	} else if (bn === 'ifconfig.txt' || bn === 'ipconfig.txt') {
		parseInterfaces(file.content, snap);
	} else if (bn === 'route.txt' || bn.includes('route-table')) {
		parseRoutes(file.content, snap);
	} else if (bn === 'netstat.txt') {
		parseNetstat(file.content, snap);
	} else if (bn === 'resolv.conf') {
		parseResolvConf(file.content, snap);
	} else if (bn === 'dns-check.txt' || bn === 'dns.log' || bn === 'daemon_dns.log') {
		parseDnsCheck(file.content, snap);
	} else if (bn === 'sysinfo.json') {
		parseSysInfo(file.content, snap);
	} else if (bn === 'platform.txt') {
		snap.device.platform = (file.content.trim().split('\n')[0] || '').trim();
	} else if (bn === 'version.txt') {
		snap.connection.warpVersion = file.content.trim();
	} else if (bn === 'date.txt') {
		snap.device.captureTime = file.content.trim();
	} else if (bn.includes('mdm')) {
		parseMdm(file.content, snap);
	} else if (bn === 'override_warp.txt') {
		snap.settings.override = file.content.trim();
	} else if (bn === 'installed_cert.pem' || bn.endsWith('.pem')) {
		parseCertificate(file.content, file.filename, snap);
	} else if (bn.includes('traceroute')) {
		parseTraceroute(file.content, file.filename, snap);
	} else if (bn === 'arp.txt') {
		parseArp(file.content, snap);
	} else if (bn === 'daemon.log' || bn === 'warp-svc.log' || bn === 'boringtun.log' || bn === 'tunnel.log') {
		parseDaemonLog(file.content, file.filename, snap);
	}
}

function parseWarpStatus(content, snap) {
	const c = snap.connection;
	// Try JSON first (newer clients sometimes output JSON)
	const trimmed = content.trim();
	if (trimmed.startsWith('{')) {
		try {
			const json = JSON.parse(trimmed);
			if (json.status) c.status = String(json.status);
			if (json.mode) c.mode = String(json.mode);
			if (json.account) c.accountType = String(json.account);
			if (json.team) snap.account.team = String(json.team);
			return;
		} catch { /* fall through */ }
	}

	// First non-empty non-separator line is often the status
	const lines = content.split('\n').map(l => l.trim()).filter(l => l && !/^[=\-*]+$/.test(l));
	if (lines.length > 0 && !c.status) {
		// "Status update: Connected" or "Connected" on first line
		const first = lines[0];
		const statusKeywords = ['connected', 'disconnected', 'connecting', 'disabled', 'registering', 'paused'];
		for (const kw of statusKeywords) {
			if (first.toLowerCase().includes(kw)) {
				c.status = kw[0].toUpperCase() + kw.slice(1);
				break;
			}
		}
	}

	// Parse all lines as flexible key:value or key = value
	for (const line of lines) {
		const m = line.match(/^([^:=]+?)\s*[:=]\s*(.+)$/);
		if (!m) continue;
		const key = m[1].trim().toLowerCase();
		const val = m[2].trim();
		if (!val) continue;

		if (key === 'status' || key === 'warp status' || key === 'connection status' || key === 'status update' || key === 'warp connection status') c.status = val;
		else if (key === 'mode' || key === 'warp mode' || key === 'operation mode') c.mode = val;
		else if (key === 'account' || key === 'account type' || key === 'accounttype') c.accountType = val;
		else if (key === 'team' || key === 'team name') snap.account.team = val;
		else if (key === 'registered account id' || key === 'account id') snap.account.accountId = val;
		else if (key.includes('always') && key.includes('on')) c.alwaysOn = val;
		else if (key.includes('switch') && key.includes('lock')) c.switchLocked = val;
		else if (key.includes('dns protocol') || key.includes('dns over') || key === 'dns mode') snap.network.dns.protocol = val;
		else if (key === 'warp+' || key === 'warp plus') c.warpPlus = val;
		else if (key === 'posture' || key === 'device posture') c.postureStatus = val;
		else if (key === 'dex' || key === 'digital experience monitoring') c.dex = val;
		else if (key === 'location') c.location = val;
		else if (key === 'device id') snap.account.deviceId = val;
		else if (key === 'id' || key === 'registered id') snap.account.id = val;
		else if (key === 'version' || key === 'client version' || key === 'warp version') c.warpVersion = val;
		else if (key === 'organization' || key === 'organisation') snap.account.organization = val;
	}
}

function parseWarpAccount(content, snap) {
	const a = snap.account;
	// Try JSON first
	const trimmed = content.trim();
	if (trimmed.startsWith('{')) {
		try {
			const json = JSON.parse(trimmed);
			Object.assign(a, json);
			return;
		} catch { /* fall through */ }
	}

	for (const line of content.split('\n')) {
		const m = line.match(/^([^:=]+?)\s*[:=]\s*(.+)$/);
		if (!m) continue;
		const key = m[1].trim().toLowerCase();
		const val = m[2].trim();
		if (!val) continue;

		if (key === 'team' || key === 'team name' || key.includes('team')) a.team = val;
		else if (key === 'account id' || key === 'accountid' || key === 'registered account id') a.accountId = val;
		else if (key === 'registration' || key === 'registered' || key === 'registration status') a.registration = val;
		else if (key === 'device id' || key === 'deviceid') a.deviceId = val;
		else if (key === 'public key' || key === 'publickey') a.publicKey = val;
		else if (key === 'user id' || key === 'email' || key === 'user email' || key === 'user') a.user = val;
		else if (key === 'license' || key === 'license type' || key === 'account type') a.license = val;
		else if (key === 'organization' || key === 'organisation' || key === 'org') a.organization = val;
		else if (key === 'id' || key === 'registered id') a.id = val;
		else if (key === 'role' || key === 'user role') a.role = val;
	}
}

function parseWarpSettings(content, snap) {
	// Try JSON first
	try {
		const json = JSON.parse(content);
		snap.settings = { ...snap.settings, ...json };
		// Extract specific fields of interest
		if (json.split_tunnel || json.include_list || json.exclude_list) {
			snap.settings.splitTunnel = {
				mode: json.split_tunnel_mode || (json.include_list ? 'include' : json.exclude_list ? 'exclude' : 'none'),
				include: json.include_list || [],
				exclude: json.exclude_list || [],
			};
		}
		return;
	} catch { /* not JSON */ }

	// Parse key-value lines
	for (const line of content.split('\n')) {
		const m = line.match(/^([^:=]+)[:=]\s*(.+)$/);
		if (!m) continue;
		const key = m[1].trim().toLowerCase().replace(/\s+/g, '_');
		const val = m[2].trim();
		snap.settings[key] = val;
	}
}

function parseConnectivity(content, snap) {
	const c = snap.connection;
	const tests = [];

	for (const line of content.split('\n')) {
		const trimmed = line.trim();
		if (!trimmed) continue;

		// Colo / edge location — many possible patterns
		const coloPatterns = [
			/colo[:\s=]+([A-Z]{3,4}\d*)/i,
			/\b([A-Z]{3})\b.*?(?:data\s*cent(?:er|re)|edge|pop)/i,
			/edge\s*(?:location|pop|cent(?:er|re))[:\s=]+([A-Z]{3,5})/i,
		];
		for (const p of coloPatterns) {
			const m = trimmed.match(p);
			if (m && !c.colo) { c.colo = m[1].toUpperCase(); break; }
		}

		// Endpoint
		const epMatch = trimmed.match(/(?:engage|tunnel|endpoint)[:\s=]+(\S+\.cloudflareclient\.com|\S+\.cloudflare\.com|[\d.]+:?\d*)/i) ||
			trimmed.match(/endpoint[:\s=]+(\S+)/i);
		if (epMatch && !c.endpoint) c.endpoint = epMatch[1];

		// My IP (public)
		const myipMatch = trimmed.match(/(?:my|public|external|your)\s*ip[:\s=]+([\d.]+)/i) ||
			trimmed.match(/cf-connecting-ip[:\s=]+([\d.]+)/i);
		if (myipMatch && !c.myIp) c.myIp = myipMatch[1];

		// Gateway
		const gwMatch = trimmed.match(/(?:default\s*)?gateway[:\s=]+([\d.]+)/i);
		if (gwMatch && !c.gatewayIp) c.gatewayIp = gwMatch[1];

		// Connectivity test results — multiple patterns
		// "https://www.cloudflare.com: reachable"
		// "[OK] https://www.cloudflare.com"
		// "PASS: dns lookup"
		let test = trimmed.match(/^(https?:\/\/\S+|\S+\.\w+)\s*[:\-]\s*(reachable|unreachable|ok|fail|failed|success|passed|timeout)/i);
		if (!test) test = trimmed.match(/^\[?(OK|PASS|FAIL|ERROR|TIMEOUT|WARN)\]?\s*[:\-]?\s*(.+)$/i);
		if (test) {
			const target = test[1].startsWith('http') || /^\w+\.\w/.test(test[1]) ? test[1] : test[2];
			const result = test[1].startsWith('http') ? test[2] : test[1];
			tests.push({ target: target.substring(0, 100), result });
		}

		// Latency measurements like "cloudflare.com: 12.3 ms"
		const lat = trimmed.match(/(\S+).*?(\d+(?:\.\d+)?)\s*ms\b/i);
		if (lat && !test) tests.push({ target: lat[1].substring(0, 100), latencyMs: parseFloat(lat[2]) });
	}

	if (tests.length > 0) c.connectivityTests = tests;
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

	// DNS issues
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
	if (findings.some(f => f.severity === 'Critical')) return 'Critical';
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
