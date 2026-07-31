/**
 * HAR Analyzer
 * Rule-based analysis of a normalized HAR (from har-parser.js). Produces a
 * snapshot mirroring the WARP analyzer's shape so the UI can reuse the same
 * findings / timeline / health / bottom-line components, plus HAR-specific
 * data: per-request entries, a timing waterfall, performance rollups, and
 * Cloudflare/Access-aware detection.
 *
 * Independent of AI — findings are deterministic and evidence-backed.
 */

import { parseHar, normalizeHar } from './har-parser.js';

// Thresholds (ms) for flagging slow requests.
const SLOW_TOTAL_MS = 3000;
const SLOW_TTFB_MS = 1500;

/**
 * Analyze raw HAR text end-to-end.
 * @param {string} harText
 * @returns {object} snapshot
 */
export function analyzeHar(harText) {
	const har = parseHar(harText);
	const norm = normalizeHar(har);
	return buildSnapshot(norm);
}

/**
 * Build the snapshot from an already-normalized HAR (entries redacted).
 */
export function buildSnapshot(norm) {
	const entries = norm.entries || [];
	const findings = [];
	const timeline = [];

	// ── Rollups ────────────────────────────────────────────────────────────
	const perf = computePerf(entries);
	const byStatusClass = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0, other: 0, failed: 0 };
	const failures = [];
	const slow = [];
	const redirects = [];
	const corsIssues = [];
	const mixedContent = [];
	const domains = {};

	for (const e of entries) {
		const s = e.response.status;
		const cls = s >= 200 && s < 300 ? '2xx' : s >= 300 && s < 400 ? '3xx' : s >= 400 && s < 500 ? '4xx' : s >= 500 && s < 600 ? '5xx' : 'other';
		if (s === 0 || e.response._error) { byStatusClass.failed++; }
		else byStatusClass[cls]++;

		// domain rollup
		const d = e.request.host || '(unknown)';
		domains[d] = domains[d] || { host: d, count: 0, bytes: 0, errors: 0, time: 0 };
		domains[d].count++;
		domains[d].bytes += Math.max(0, e.response.contentSize || 0);
		domains[d].time += e.time || 0;
		if (s >= 400 || s === 0) domains[d].errors++;

		// failures (4xx/5xx/network)
		if (s >= 400 || s === 0 || e.response._error) {
			failures.push(e);
		}
		// slow
		if (e.time >= SLOW_TOTAL_MS || (e.timings.wait || 0) >= SLOW_TTFB_MS) slow.push(e);
		// redirects
		if (cls === '3xx' && e.response.redirectURL) redirects.push(e);
		// mixed content: https page fetching http subresource is a heuristic on scheme
		if (e.request.scheme === 'http' && perf.pageIsHttps) mixedContent.push(e);
	}

	// ── CORS detection (needs a light header scan) ───────────────────────────
	for (const e of entries) {
		const reqOrigin = header(e.request.headers, 'origin');
		if (!reqOrigin) continue;
		const allow = header(e.response.headers, 'access-control-allow-origin');
		if (e.response.status >= 200 && !allow) {
			corsIssues.push(e);
		}
	}

	// ── Cloudflare / Access awareness ────────────────────────────────────────
	const accessChallenges = entries.filter(e =>
		(e.response.status === 302 && /cloudflareaccess\.com/i.test(e.response.redirectURL || '')) ||
		/cloudflareaccess\.com/i.test(e.request.host || ''));
	const cfMitigated = entries.filter(e => e.cf && e.cf.mitigated);
	const cfEntries = entries.filter(e => e.cf && e.cf.isCloudflare);

	// ── Findings ─────────────────────────────────────────────────────────────
	// 1. Server errors (5xx) — blocking
	const server5xx = failures.filter(e => e.response.status >= 500);
	if (server5xx.length) {
		findings.push({
			severity: 'Critical', blocking: true, category: 'Errors',
			title: `${server5xx.length} server error(s) (5xx)`,
			what_logs_show: sampleReqLines(server5xx, 5),
			what_experienced: 'The server returned 5xx errors. These are backend/origin failures — the request reached the server but it could not fulfil it. If these are Cloudflare-fronted, check origin health and Cloudflare error pages (cf-ray links the request in Cloudflare logs).',
			description: `${server5xx.length} request(s) returned HTTP 5xx.`,
		});
	}
	// 2. Client errors (4xx) — warning (401/403 called out)
	const auth4xx = failures.filter(e => e.response.status === 401 || e.response.status === 403);
	const other4xx = failures.filter(e => e.response.status >= 400 && e.response.status < 500 && e.response.status !== 401 && e.response.status !== 403);
	if (auth4xx.length) {
		findings.push({
			severity: 'Warning', blocking: false, category: 'Auth',
			title: `${auth4xx.length} authorization failure(s) (401/403)`,
			what_logs_show: sampleReqLines(auth4xx, 5),
			what_experienced: 'Requests were rejected as unauthenticated (401) or forbidden (403). With Cloudflare Access this often means a missing/expired session (CF_Authorization) or a policy denial. A 302 to *.cloudflareaccess.com indicates the user needs to re-authenticate.',
			description: `${auth4xx.length} request(s) returned 401/403.`,
		});
	}
	if (other4xx.length) {
		findings.push({
			severity: 'Warning', blocking: false, category: 'Errors',
			title: `${other4xx.length} client error(s) (4xx)`,
			what_logs_show: sampleReqLines(other4xx.slice(0, 6), 6),
			what_experienced: 'Client-side request errors (e.g. 404 not found, 400 bad request, 429 rate limited). Frequently these are broken links, missing assets, or API contract mismatches.',
			description: `${other4xx.length} request(s) returned 4xx (excluding 401/403).`,
		});
	}
	// 3. Network failures (status 0 / _error)
	const netFail = entries.filter(e => e.response.status === 0 || e.response._error);
	if (netFail.length) {
		findings.push({
			severity: 'Critical', blocking: true, category: 'Connectivity',
			title: `${netFail.length} request(s) failed to complete`,
			what_logs_show: netFail.slice(0, 6).map(e => `${e.request.method} ${trunc(e.request.url, 90)}  ->  ${e.response._error || 'no response (status 0)'}`).join('\n'),
			what_experienced: 'These requests never received a response — DNS failure, connection refused/reset, TLS failure, or the request was blocked (extension, firewall, or WARP/Gateway policy). If WARP is on, correlate with the WARP diagnostics for the same time window.',
			description: `${netFail.length} request(s) had no response.`,
		});
	}
	// 4. Access challenges
	if (accessChallenges.length) {
		findings.push({
			severity: 'Warning', blocking: false, category: 'Access',
			title: `${accessChallenges.length} Cloudflare Access challenge(s)`,
			what_logs_show: accessChallenges.slice(0, 5).map(e => `${e.response.status} ${trunc(e.request.url, 70)}  ->  ${trunc(e.response.redirectURL || e.request.host, 70)}`).join('\n'),
			what_experienced: 'The user was redirected to a Cloudflare Access login. This is expected on first access or after session expiry; if it loops, the identity provider or Access policy may be misconfigured, or third-party cookies are blocked.',
			description: `${accessChallenges.length} redirect(s) to a Cloudflare Access login.`,
		});
	}
	// 5. WAF / mitigation
	if (cfMitigated.length) {
		findings.push({
			severity: 'Warning', blocking: false, category: 'Security',
			title: `${cfMitigated.length} request(s) mitigated by Cloudflare (WAF/Bot)`,
			what_logs_show: cfMitigated.slice(0, 5).map(e => `${e.response.status} ${trunc(e.request.url, 70)}  cf-mitigated=${e.cf.mitigated}  cf-ray=${e.cf.ray || '-'}`).join('\n'),
			what_experienced: 'Cloudflare challenged or blocked these requests (WAF, Bot Management, or rate limiting). Use the cf-ray to find the matching Security Event in the Cloudflare dashboard.',
			description: `${cfMitigated.length} request(s) carried cf-mitigated.`,
		});
	}
	// 6. Slow requests
	if (slow.length) {
		const worst = [...slow].sort((a, b) => b.time - a.time).slice(0, 6);
		findings.push({
			severity: slow.length > entries.length * 0.15 ? 'Warning' : 'Info', blocking: false, category: 'Performance',
			title: `${slow.length} slow request(s) (>${SLOW_TOTAL_MS / 1000}s total or >${SLOW_TTFB_MS}ms TTFB)`,
			what_logs_show: worst.map(e => `${msFmt(e.time)}  (wait ${msFmt(e.timings.wait)})  ${e.request.method} ${trunc(e.request.url, 70)}`).join('\n'),
			what_experienced: 'These requests dominated page load time. High "wait" (TTFB) points at server/origin latency; high "connect"/"ssl" points at network or TLS handshake cost (relevant when WARP/Gateway is in path).',
			description: `${slow.length} slow request(s).`,
		});
	}
	// 7. Redirect chains
	if (redirects.length >= 3) {
		findings.push({
			severity: 'Info', blocking: false, category: 'Performance',
			title: `${redirects.length} redirect(s) observed`,
			what_logs_show: redirects.slice(0, 6).map(e => `${e.response.status} ${trunc(e.request.url, 60)}  ->  ${trunc(e.response.redirectURL, 60)}`).join('\n'),
			what_experienced: 'Redirects add round-trips. Long chains (or loops) hurt performance and can break auth flows. Check for http->https->auth->app hops that could be collapsed.',
			description: `${redirects.length} redirect responses.`,
		});
	}
	// 8. CORS
	if (corsIssues.length) {
		findings.push({
			severity: 'Warning', blocking: false, category: 'Errors',
			title: `${corsIssues.length} possible CORS issue(s)`,
			what_logs_show: corsIssues.slice(0, 5).map(e => `${e.request.method} ${trunc(e.request.url, 80)}  (no Access-Control-Allow-Origin)`).join('\n'),
			what_experienced: 'Cross-origin requests returned without an Access-Control-Allow-Origin header, so the browser likely blocked the response. This is a server/CDN config issue on the target, not the client.',
			description: `${corsIssues.length} cross-origin response(s) missing CORS headers.`,
		});
	}
	// 9. Mixed content
	if (mixedContent.length) {
		findings.push({
			severity: 'Warning', blocking: false, category: 'Security',
			title: `${mixedContent.length} mixed-content request(s)`,
			what_logs_show: mixedContent.slice(0, 5).map(e => `${e.request.method} ${trunc(e.request.url, 90)}`).join('\n'),
			what_experienced: 'An HTTPS page requested HTTP subresources; browsers block or upgrade these. Fix by serving all resources over HTTPS.',
			description: `${mixedContent.length} insecure subresource request(s) on a secure page.`,
		});
	}
	// 10. Security hygiene — redacted secrets present in the HAR
	const r = norm.redactions || {};
	const totalRedactions = (r.headers || 0) + (r.cookies || 0) + (r.params || 0) + (r.bodies || 0);
	if (totalRedactions > 0) {
		findings.push({
			severity: 'Warning', blocking: false, category: 'Security',
			title: 'Sensitive data present in HAR (redacted before storage)',
			what_logs_show: [
				`${r.cookies || 0} cookie value(s), ${r.headers || 0} auth header(s), ${r.params || 0} sensitive query param(s), ${r.bodies || 0} response body token(s)`,
				norm.redactionSamples && norm.redactionSamples.length ? 'Redacted: ' + norm.redactionSamples.join(', ') : '',
			].filter(Boolean).join('\n'),
			what_experienced: 'HAR files capture live credentials (session cookies, Authorization/JWT tokens). These were redacted before this session was saved, but the ORIGINAL file on disk still contains them — treat it as a secret, and rotate anything already shared.',
			description: `${totalRedactions} sensitive value(s) detected and redacted.`,
		});
	}

	// ── Timeline (page + notable events) ─────────────────────────────────────
	entries.forEach(e => {
		if (!e.startedDateTime) return;
		const s = e.response.status;
		let sev = 'info';
		if (s >= 500 || s === 0 || e.response._error) sev = 'error';
		else if (s >= 400) sev = 'warning';
		else if (e.time >= SLOW_TOTAL_MS) sev = 'warning';
		else if (s >= 200 && s < 300) sev = 'success';
		// Only surface non-2xx or slow to keep the timeline signal-dense.
		if (sev === 'success' && e.time < SLOW_TOTAL_MS) return;
		timeline.push({
			timestamp: e.startedDateTime,
			event: `${s || 'ERR'} ${e.request.method} ${e.request.host}`,
			severity: sev,
			details: `${trunc(e.request.path, 80)}  ·  ${msFmt(e.time)}${e.cf && e.cf.ray ? '  ·  cf-ray ' + e.cf.ray : ''}`,
		});
	});
	timeline.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

	// ── Health + bottom line ─────────────────────────────────────────────────
	const health = computeHealth(findings);
	const bottomLine = buildBottomLine({ entries, byStatusClass, server5xx, auth4xx, netFail, slow, accessChallenges, cfMitigated, perf });

	// ── Waterfall data (top-N by start, or all if small) ─────────────────────
	const waterfall = buildWaterfall(entries);

	return {
		kind: 'har',
		health,
		bottomLine,
		summary: bottomLine,
		findings,
		timeline,
		entries,          // redacted, safe to persist
		waterfall,
		perf: {
			...perf,
			byStatusClass,
			domains: Object.values(domains).sort((a, b) => b.count - a.count).slice(0, 25),
			counts: {
				total: entries.length,
				failed: byStatusClass.failed + byStatusClass['5xx'] + byStatusClass['4xx'],
				slow: slow.length,
				redirects: redirects.length,
			},
		},
		cloudflare: {
			totalCfRequests: cfEntries.length,
			mitigated: cfMitigated.length,
			accessChallenges: accessChallenges.length,
			accessUser: (cfEntries.find(e => e.cf.accessUser) || {}).cf?.accessUser || '',
		},
		redactions: norm.redactions,
		meta: {
			creator: norm.creator,
			browser: norm.browser,
			pages: (norm.pages || []).length,
		},
	};
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function computePerf(entries) {
	let totalBytes = 0, totalTime = 0, firstStart = null, lastEnd = null, pageIsHttps = false;
	const mimeBytes = {};
	for (const e of entries) {
		totalBytes += Math.max(0, e.response.contentSize || 0);
		totalTime += e.time || 0;
		if (e.request.scheme === 'https') pageIsHttps = true;
		const type = mimeGroup(e.response.mimeType);
		mimeBytes[type] = (mimeBytes[type] || 0) + Math.max(0, e.response.contentSize || 0);
		const st = e.startedDateTime ? new Date(e.startedDateTime).getTime() : NaN;
		if (!isNaN(st)) {
			if (firstStart == null || st < firstStart) firstStart = st;
			const end = st + (e.time || 0);
			if (lastEnd == null || end > lastEnd) lastEnd = end;
		}
	}
	const wallClock = firstStart != null && lastEnd != null ? Math.round(lastEnd - firstStart) : 0;
	return { totalBytes, totalTime: Math.round(totalTime), wallClock, mimeBytes, pageIsHttps };
}

function buildWaterfall(entries) {
	const withTime = entries.filter(e => e.startedDateTime);
	if (!withTime.length) return { origin: 0, rows: [] };
	const origin = Math.min(...withTime.map(e => new Date(e.startedDateTime).getTime()));
	const rows = withTime.slice(0, 300).map(e => ({
		index: e.index,
		start: new Date(e.startedDateTime).getTime() - origin,
		time: e.time,
		timings: e.timings,
		method: e.request.method,
		host: e.request.host,
		path: e.request.path,
		status: e.response.status,
		mime: mimeGroup(e.response.mimeType),
		error: !!(e.response.status === 0 || e.response._error || e.response.status >= 400),
	}));
	return { origin, rows, span: Math.max(...rows.map(r => r.start + r.time), 1) };
}

function computeHealth(findings) {
	if (findings.some(f => f.blocking || f.severity === 'Critical')) return 'Critical';
	if (findings.some(f => f.severity === 'Warning')) return 'Degraded';
	return 'Healthy';
}

function buildBottomLine(x) {
	const parts = [];
	const n = x.entries.length;
	if (n === 0) return 'The HAR contained no requests.';
	if (x.netFail.length) parts.push(`${x.netFail.length} request(s) failed to complete (no response) — a connectivity/TLS/policy block, not just a slow server.`);
	if (x.server5xx.length) parts.push(`${x.server5xx.length} server error(s) (5xx) indicate an origin/backend problem.`);
	if (x.auth4xx.length) parts.push(`${x.auth4xx.length} auth failure(s) (401/403)${x.accessChallenges.length ? ' with Cloudflare Access re-login redirects' : ''}.`);
	if (x.cfMitigated.length) parts.push(`${x.cfMitigated.length} request(s) were mitigated by Cloudflare security.`);
	if (!parts.length) {
		if (x.slow.length) return `All ${n} requests completed, but ${x.slow.length} were slow — the session is functional but performance-bound. Focus on the highest-TTFB requests in the waterfall.`;
		return `All ${n} requests completed successfully with no errors detected. If the user still reports a problem, it is likely outside the HTTP layer (rendering, client script, or a resource not captured in this HAR).`;
	}
	return parts.join(' ') + ` Start with the blocking findings below; use each cf-ray to correlate with Cloudflare logs.`;
}

function header(headers, name) {
	const n = name.toLowerCase();
	const h = (headers || []).find(x => (x.name || '').toLowerCase() === n);
	return h ? h.value : '';
}

function sampleReqLines(list, max) {
	return list.slice(0, max).map(e =>
		`${e.response.status} ${e.request.method} ${trunc(e.request.url, 80)}${e.cf && e.cf.ray ? '  cf-ray=' + e.cf.ray : ''}`
	).join('\n');
}

function mimeGroup(m) {
	if (!m) return 'other';
	if (/html/.test(m)) return 'html';
	if (/css/.test(m)) return 'css';
	if (/javascript|ecmascript/.test(m)) return 'js';
	if (/json|xml/.test(m)) return 'xhr';
	if (/image|img/.test(m)) return 'image';
	if (/font/.test(m)) return 'font';
	if (/video|audio/.test(m)) return 'media';
	return 'other';
}

function trunc(s, n) { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '\u2026' : s; }
function msFmt(ms) { ms = Math.round(ms || 0); return ms >= 1000 ? (ms / 1000).toFixed(2) + 's' : ms + 'ms'; }
