/**
 * File Parsers — ZIP extraction, text parsing, and WARP file categorisation.
 * PCAP decoding has been moved to pcap-decoder.js for full protocol analysis.
 */

import { unzipSync } from 'fflate';

/**
 * Extract files from a ZIP archive.
 * @param {ArrayBuffer} zipData
 * @returns {Map<string, Uint8Array>}
 */
export function extractZipFiles(zipData) {
	try {
		const uint8 = new Uint8Array(zipData);
		const files = unzipSync(uint8);
		const map = new Map();
		for (const [filename, data] of Object.entries(files)) {
			// Skip directories and hidden files
			if (filename.endsWith('/') || filename.includes('__MACOSX')) continue;
			map.set(filename, data);
		}
		return map;
	} catch (e) {
		throw new Error(`Failed to extract ZIP: ${e.message}`);
	}
}

/**
 * Decode binary data to UTF-8 text.
 * @param {Uint8Array} data
 * @returns {string}
 */
export function parseTextFile(data) {
	return new TextDecoder('utf-8').decode(data);
}

/**
 * Categorise a WARP diagnostic file by name.
 * Returns category and priority for analysis ordering.
 * @param {string} filename
 * @returns {{ category: string, priority: string }}
 */
export function categorizeWarpFile(filename) {
	const lower = filename.toLowerCase();
	const basename = lower.split('/').pop();

	const categories = {
		connection: {
			patterns: ['daemon.log', 'connectivity.txt', 'warp-status.txt', 'boringtun.log', 'warp-svc.log', 'tunnel.log'],
			priority: 'high',
		},
		dns: {
			patterns: ['daemon_dns.log', 'dns-check.txt', 'dns_stats.log', 'dig.txt', 'resolv.conf', 'dns.log', 'nslookup'],
			priority: 'high',
		},
		network: {
			patterns: ['ifconfig.txt', 'ipconfig.txt', 'netstat.txt', 'route.txt', 'traceroute.txt', 'arp.txt', 'route-table'],
			priority: 'medium',
		},
		config: {
			patterns: ['warp-settings.txt', 'warp-account.txt', 'mdm.plist', 'mdm.xml', 'override_warp.txt', 'managed_config'],
			priority: 'medium',
		},
		system: {
			patterns: ['sysinfo.json', 'platform.txt', 'version.txt', 'date.txt', 'os-info', 'uname'],
			priority: 'low',
		},
		performance: {
			patterns: ['stats.log', 'warp-stats.txt', 'warp-bus-metrics.txt', 'metrics', 'perf'],
			priority: 'medium',
		},
		security: {
			patterns: ['warp-device-posture.txt', 'firewall-rules.txt', 'installed_cert.pem', 'cert-check', 'posture'],
			priority: 'medium',
		},
		pcap: {
			patterns: ['.pcap', '.pcapng', '.qlog'],
			priority: 'high',
		},
	};

	for (const [category, config] of Object.entries(categories)) {
		if (config.patterns.some(p => basename.includes(p) || lower.includes(p))) {
			return { category, priority: config.priority };
		}
	}

	// Heuristics for unrecognised files
	if (lower.endsWith('.log')) return { category: 'logs', priority: 'medium' };
	if (lower.endsWith('.json')) return { category: 'config', priority: 'medium' };
	if (lower.endsWith('.txt')) return { category: 'other', priority: 'low' };

	return { category: 'other', priority: 'low' };
}

/**
 * Extract structured key information from known WARP file formats.
 * @param {string} filename
 * @param {string} content
 * @returns {Object}
 */
export function extractKeyInfo(filename, content) {
	const info = {};

	try {
		if (filename.includes('warp-status.txt')) {
			for (const line of content.split('\n')) {
				if (line.includes('Status:')) info.status = line.split(':').slice(1).join(':').trim();
				if (line.includes('Mode:')) info.mode = line.split(':').slice(1).join(':').trim();
				if (line.includes('Account:')) info.account = line.split(':').slice(1).join(':').trim();
				if (line.includes('Team:')) info.team = line.split(':').slice(1).join(':').trim();
				if (line.includes('Gateway')) info.gateway = line.split(':').slice(1).join(':').trim();
			}
		}

		if (filename.includes('warp-settings.txt')) {
			try {
				info.settings = JSON.parse(content);
			} catch {
				for (const m of content.matchAll(/(\w+):\s*(.+)/g)) {
					info[m[1]] = m[2].trim();
				}
			}
		}

		if (filename.includes('connectivity.txt')) {
			const ep = content.match(/endpoint[:\s]+([^\s\n]+)/i);
			if (ep) info.endpoint = ep[1];
			const colo = content.match(/colo[:\s]+([^\s\n]+)/i);
			if (colo) info.colo = colo[1];
		}

		if (filename.includes('version.txt')) {
			info.warpVersion = content.trim();
		}

		if (filename.includes('sysinfo.json')) {
			try { info.systemInfo = JSON.parse(content); } catch { /* skip */ }
		}

		if (filename.includes('platform.txt')) {
			info.platform = content.trim().split('\n')[0];
		}
	} catch (e) {
		info.parseError = e.message;
	}

	return info;
}
