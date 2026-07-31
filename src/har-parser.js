/**
 * HAR (HTTP Archive) Parser
 * Parses an uploaded .har file (HAR 1.2 spec) into a normalized entries model
 * that har-analyzer.js consumes. Redacts sensitive values (cookies, auth
 * headers, tokens) IN PLACE so secrets are never persisted to KV, while
 * recording what was redacted so the analyzer can raise a security finding.
 *
 * HAR spec: http://www.softwareishard.com/blog/har-12-spec/
 */

// Header names whose values are secrets and must be redacted before storage.
const SENSITIVE_HEADERS = new Set([
	'authorization', 'proxy-authorization', 'cookie', 'set-cookie',
	'x-api-key', 'x-auth-token', 'x-access-token', 'x-csrf-token',
	'x-xsrf-token', 'api-key', 'auth-token', 'cf-access-jwt-assertion',
	'cf_authorization',
]);

// Query-string / body param names that commonly carry secrets.
const SENSITIVE_PARAMS = /^(access_?token|refresh_?token|id_?token|api_?key|apikey|password|passwd|pwd|secret|client_?secret|session|sig|signature|auth)$/i;

// Patterns that look like bearer/JWT/long tokens embedded in values.
const TOKEN_VALUE = /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})\b|\bBearer\s+[A-Za-z0-9._-]{12,}\b/;

const REDACTED = '[REDACTED]';

/**
 * Parse raw HAR text into a validated HAR object.
 * @param {string} text
 * @returns {{ log: object }} parsed HAR
 * @throws if not valid HAR
 */
export function parseHar(text) {
	let obj;
	try {
		obj = JSON.parse(text);
	} catch (e) {
		throw new Error('File is not valid JSON: ' + e.message);
	}
	if (!obj || typeof obj !== 'object' || !obj.log || !Array.isArray(obj.log.entries)) {
		throw new Error('Not a valid HAR file (missing log.entries)');
	}
	return obj;
}

/**
 * Quick content sniff: does this text look like a HAR file?
 * Used by the ingest layer to detect HAR when the extension is ambiguous.
 */
export function looksLikeHar(text) {
	if (!text) return false;
	// Cheap check first — avoid parsing megabytes if the markers aren't present.
	const head = text.slice(0, 4096);
	if (!/"log"\s*:/.test(head) || !/"entries"\s*:/.test(head)) return false;
	try {
		const o = JSON.parse(text);
		return !!(o && o.log && Array.isArray(o.log.entries));
	} catch {
		return false;
	}
}

/**
 * Normalize + redact a parsed HAR into the analyzer's entry model.
 * @param {object} har parsed HAR (from parseHar)
 * @returns {{ entries: Array, pages: Array, creator: object, browser: object,
 *             redactions: { headers: number, params: number, cookies: number, bodies: number },
 *             redactionSamples: Array<string> }}
 */
export function normalizeHar(har) {
	const log = har.log || {};
	const redactions = { headers: 0, params: 0, cookies: 0, bodies: 0 };
	const redactionSamples = [];
	const noteRedaction = (kind, label) => {
		redactions[kind]++;
		if (redactionSamples.length < 12 && label && !redactionSamples.includes(label)) {
			redactionSamples.push(label);
		}
	};

	const entries = (log.entries || []).map((e, i) => normalizeEntry(e, i, noteRedaction));

	return {
		entries,
		pages: log.pages || [],
		creator: log.creator || {},
		browser: log.browser || {},
		redactions,
		redactionSamples,
	};
}

function normalizeEntry(e, index, noteRedaction) {
	const req = e.request || {};
	const res = e.response || {};
	const timings = e.timings || {};

	const url = req.url || '';
	let host = '', pathName = '', scheme = '';
	try {
		const u = new URL(url);
		host = u.host; pathName = u.pathname + u.search; scheme = u.protocol.replace(':', '');
	} catch {
		host = (url.match(/^https?:\/\/([^/]+)/) || [])[1] || '';
		scheme = url.startsWith('https') ? 'https' : (url.startsWith('http') ? 'http' : '');
	}

	const reqHeaders = redactHeaders(req.headers || [], noteRedaction);
	const resHeaders = redactHeaders(res.headers || [], noteRedaction);
	const queryString = redactParams(req.queryString || [], noteRedaction);
	const cookiesReq = redactCookies(req.cookies || [], noteRedaction);
	const cookiesRes = redactCookies(res.cookies || [], noteRedaction);

	// Response body: keep only small text bodies; redact if it looks like it holds tokens.
	const content = res.content || {};
	let bodyText = '';
	const mimeType = (content.mimeType || '').split(';')[0].trim();
	if (typeof content.text === 'string' && content.text.length <= 8192 && /json|text|xml|javascript|html|urlencoded/i.test(mimeType)) {
		bodyText = content.text;
		if (TOKEN_VALUE.test(bodyText)) { bodyText = bodyText.replace(TOKEN_VALUE, REDACTED); noteRedaction('bodies', host + ' response body'); }
	}

	const t = {
		blocked: num(timings.blocked), dns: num(timings.dns), connect: num(timings.connect),
		ssl: num(timings.ssl), send: num(timings.send), wait: num(timings.wait), receive: num(timings.receive),
	};
	// Total time: prefer entry.time, else sum of non-negative phases.
	const total = e.time != null && e.time >= 0
		? e.time
		: Object.values(t).reduce((s, v) => s + (v > 0 ? v : 0), 0);

	const status = res.status || 0;
	const cfHeaders = extractCfHeaders(resHeaders);

	return {
		index,
		startedDateTime: e.startedDateTime || '',
		time: Math.round(total),
		timings: t,
		request: {
			method: req.method || 'GET',
			url,
			host,
			path: pathName,
			scheme,
			httpVersion: req.httpVersion || '',
			headers: reqHeaders,
			queryString,
			cookies: cookiesReq,
			headersSize: req.headersSize ?? -1,
			bodySize: req.bodySize ?? -1,
			postDataMime: (req.postData && (req.postData.mimeType || '').split(';')[0]) || '',
		},
		response: {
			status,
			statusText: res.statusText || '',
			httpVersion: res.httpVersion || '',
			headers: resHeaders,
			cookies: cookiesRes,
			mimeType,
			bodyText,
			bodySize: res.bodySize ?? -1,
			contentSize: content.size ?? -1,
			redirectURL: res.redirectURL || '',
			_error: res._error || e._error || '',
		},
		serverIP: e.serverIPAddress || '',
		connection: e.connection || '',
		cf: cfHeaders,
	};
}

function redactHeaders(headers, noteRedaction) {
	return headers.map(h => {
		const name = (h.name || '').toLowerCase();
		let value = h.value || '';
		if (SENSITIVE_HEADERS.has(name)) {
			noteRedaction(name === 'cookie' || name === 'set-cookie' ? 'cookies' : 'headers', h.name);
			value = REDACTED;
		} else if (TOKEN_VALUE.test(value)) {
			noteRedaction('headers', h.name);
			value = value.replace(TOKEN_VALUE, REDACTED);
		}
		return { name: h.name, value };
	});
}

function redactParams(params, noteRedaction) {
	return params.map(p => {
		let value = p.value || '';
		if (SENSITIVE_PARAMS.test(p.name || '') || TOKEN_VALUE.test(value)) {
			noteRedaction('params', p.name);
			value = REDACTED;
		}
		return { name: p.name, value };
	});
}

function redactCookies(cookies, noteRedaction) {
	return cookies.map(c => {
		noteRedaction('cookies', c.name);
		return { name: c.name, value: REDACTED, domain: c.domain || '', httpOnly: !!c.httpOnly, secure: !!c.secure };
	});
}

/**
 * Pull Cloudflare-relevant response headers into a compact object for the
 * analyzer (cf-ray, cf-cache-status, cf-mitigated, server, etc.).
 */
function extractCfHeaders(resHeaders) {
	const out = {};
	for (const h of resHeaders) {
		const n = (h.name || '').toLowerCase();
		if (n === 'cf-ray') out.ray = h.value;
		else if (n === 'cf-cache-status') out.cacheStatus = h.value;
		else if (n === 'cf-mitigated') out.mitigated = h.value;
		else if (n === 'server') out.server = h.value;
		else if (n === 'cf-worker') out.worker = h.value;
		else if (n === 'cf-access-authenticated-user-email') out.accessUser = h.value;
	}
	out.isCloudflare = !!(out.ray || /cloudflare/i.test(out.server || ''));
	return out;
}

function num(v) { return typeof v === 'number' && v >= 0 ? v : 0; }
