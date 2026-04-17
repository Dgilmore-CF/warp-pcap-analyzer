/**
 * KV-based Session Persistence
 * Stores analysis results, decoded packets, and metadata in Workers KV.
 * Sessions are scoped to the authenticated user's email.
 *
 * KV key layout:
 *   session:{id}:meta        → Session metadata (file info, created, owner)
 *   session:{id}:packets:{n} → Packet chunks (500 per key)
 *   session:{id}:flows       → Flow/conversation data
 *   session:{id}:stats       → Protocol statistics
 *   session:{id}:ai          → AI analysis results
 *   session:{id}:warp        → WARP diagnostics data
 *   user:{email}:sessions    → List of session IDs for this user
 */

const PACKETS_PER_CHUNK = 500;
const SESSION_TTL = 7 * 24 * 60 * 60; // 7 days in seconds
const MAX_SESSIONS_PER_USER = 50;

/**
 * Generate a unique session ID.
 */
export function generateSessionId() {
	const ts = Date.now().toString(36);
	const rand = crypto.randomUUID().split('-')[0];
	return `${ts}-${rand}`;
}

/**
 * Create a new session and store initial data.
 * @param {KVNamespace} kv
 * @param {string} userEmail
 * @param {Object} sessionData - { fileName, fileSize, fileType, metadata, packets, flows, stats, warpFiles? }
 * @returns {Promise<string>} Session ID
 */
export async function createSession(kv, userEmail, sessionData) {
	const sessionId = generateSessionId();
	const now = new Date().toISOString();

	// Store metadata
	const meta = {
		id: sessionId,
		owner: userEmail,
		createdAt: now,
		updatedAt: now,
		fileName: sessionData.fileName || 'Unknown',
		fileSize: sessionData.fileSize || 0,
		fileType: sessionData.fileType || 'unknown',
		captureMetadata: sessionData.metadata || {},
		totalPackets: sessionData.packets?.length || 0,
		totalFlows: Object.keys(sessionData.flows || {}).length,
		hasAiAnalysis: false,
		hasWarpDiagnostics: !!sessionData.warpFiles?.length,
		warnings: sessionData.warnings || [],
		status: 'processing',
	};

	const writes = [];

	// Meta
	writes.push(kv.put(`session:${sessionId}:meta`, JSON.stringify(meta), { expirationTtl: SESSION_TTL }));

	// Packets (chunked)
	if (sessionData.packets?.length > 0) {
		// Strip rawHex and rawAscii from stored packets to save space
		// These can be regenerated from the original data if needed
		const leanPackets = sessionData.packets.map(pkt => ({
			...pkt,
			rawHex: pkt.rawHex, // Keep hex for hex dump view
			rawAscii: undefined, // Can reconstruct from hex
		}));

		const chunks = Math.ceil(leanPackets.length / PACKETS_PER_CHUNK);
		for (let i = 0; i < chunks; i++) {
			const start = i * PACKETS_PER_CHUNK;
			const chunk = leanPackets.slice(start, start + PACKETS_PER_CHUNK);
			writes.push(kv.put(
				`session:${sessionId}:packets:${i}`,
				JSON.stringify(chunk),
				{ expirationTtl: SESSION_TTL }
			));
		}
		meta.packetChunks = chunks;
		// Update meta with chunk count
		writes[0] = kv.put(`session:${sessionId}:meta`, JSON.stringify(meta), { expirationTtl: SESSION_TTL });
	}

	// Flows
	if (sessionData.flows) {
		writes.push(kv.put(`session:${sessionId}:flows`, JSON.stringify(sessionData.flows), { expirationTtl: SESSION_TTL }));
	}

	// Statistics
	if (sessionData.stats) {
		writes.push(kv.put(`session:${sessionId}:stats`, JSON.stringify(sessionData.stats), { expirationTtl: SESSION_TTL }));
	}

	// WARP diagnostics data
	if (sessionData.warpFiles?.length > 0) {
		writes.push(kv.put(`session:${sessionId}:warp`, JSON.stringify({
			files: sessionData.warpFiles.map(f => ({
				filename: f.filename,
				category: f.category,
				priority: f.priority,
				content: f.content?.substring(0, 10000), // Limit stored content
				keyInfo: f.keyInfo,
			})),
		}), { expirationTtl: SESSION_TTL }));
	}

	// Add to user's session list
	writes.push(addSessionToUser(kv, userEmail, sessionId, meta.fileName, now));

	await Promise.all(writes);
	return sessionId;
}

/**
 * Update session with AI analysis results.
 */
export async function updateSessionAI(kv, sessionId, aiResults) {
	const metaStr = await kv.get(`session:${sessionId}:meta`);
	if (!metaStr) throw new Error('Session not found');

	const meta = JSON.parse(metaStr);
	meta.hasAiAnalysis = true;
	meta.updatedAt = new Date().toISOString();
	meta.status = 'complete';

	await Promise.all([
		kv.put(`session:${sessionId}:meta`, JSON.stringify(meta), { expirationTtl: SESSION_TTL }),
		kv.put(`session:${sessionId}:ai`, JSON.stringify(aiResults), { expirationTtl: SESSION_TTL }),
	]);
}

/**
 * Get session metadata.
 */
export async function getSessionMeta(kv, sessionId) {
	const data = await kv.get(`session:${sessionId}:meta`);
	return data ? JSON.parse(data) : null;
}

/**
 * Get a page of packets from a session.
 * @param {KVNamespace} kv
 * @param {string}      sessionId
 * @param {number}      page       0-based page number (each page = PACKETS_PER_CHUNK)
 * @returns {Promise<Array>}
 */
export async function getSessionPackets(kv, sessionId, page = 0) {
	const data = await kv.get(`session:${sessionId}:packets:${page}`);
	return data ? JSON.parse(data) : [];
}

/**
 * Get all packets (for small captures).
 */
export async function getAllSessionPackets(kv, sessionId) {
	const meta = await getSessionMeta(kv, sessionId);
	if (!meta) return [];

	const chunks = meta.packetChunks || Math.ceil(meta.totalPackets / PACKETS_PER_CHUNK);
	const reads = [];
	for (let i = 0; i < chunks; i++) {
		reads.push(kv.get(`session:${sessionId}:packets:${i}`));
	}

	const results = await Promise.all(reads);
	const packets = [];
	for (const r of results) {
		if (r) packets.push(...JSON.parse(r));
	}
	return packets;
}

/**
 * Get session flows.
 */
export async function getSessionFlows(kv, sessionId) {
	const data = await kv.get(`session:${sessionId}:flows`);
	return data ? JSON.parse(data) : {};
}

/**
 * Get session statistics.
 */
export async function getSessionStats(kv, sessionId) {
	const data = await kv.get(`session:${sessionId}:stats`);
	return data ? JSON.parse(data) : {};
}

/**
 * Get session AI analysis.
 */
export async function getSessionAI(kv, sessionId) {
	const data = await kv.get(`session:${sessionId}:ai`);
	return data ? JSON.parse(data) : null;
}

/**
 * Get session WARP diagnostics data.
 */
export async function getSessionWarp(kv, sessionId) {
	const data = await kv.get(`session:${sessionId}:warp`);
	return data ? JSON.parse(data) : null;
}

/**
 * Get full session data (for export or small captures).
 */
export async function getFullSession(kv, sessionId) {
	const [meta, flows, stats, ai, warp] = await Promise.all([
		getSessionMeta(kv, sessionId),
		getSessionFlows(kv, sessionId),
		getSessionStats(kv, sessionId),
		getSessionAI(kv, sessionId),
		getSessionWarp(kv, sessionId),
	]);

	if (!meta) return null;

	const packets = await getAllSessionPackets(kv, sessionId);

	return { meta, packets, flows, stats, ai, warp };
}

/**
 * List sessions for a user.
 */
export async function listUserSessions(kv, userEmail) {
	const data = await kv.get(`user:${userEmail}:sessions`);
	if (!data) return [];

	const sessions = JSON.parse(data);
	// Return most recent first
	return sessions.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

/**
 * Delete a session and all its data.
 */
export async function deleteSession(kv, sessionId, userEmail) {
	const meta = await getSessionMeta(kv, sessionId);
	if (!meta) return false;
	if (meta.owner !== userEmail) return false;

	const deletes = [
		kv.delete(`session:${sessionId}:meta`),
		kv.delete(`session:${sessionId}:flows`),
		kv.delete(`session:${sessionId}:stats`),
		kv.delete(`session:${sessionId}:ai`),
		kv.delete(`session:${sessionId}:warp`),
	];

	// Delete packet chunks
	const chunks = meta.packetChunks || Math.ceil(meta.totalPackets / PACKETS_PER_CHUNK);
	for (let i = 0; i < chunks; i++) {
		deletes.push(kv.delete(`session:${sessionId}:packets:${i}`));
	}

	await Promise.all(deletes);

	// Remove from user's session list
	await removeSessionFromUser(kv, userEmail, sessionId);

	return true;
}

/**
 * Check if user owns a session.
 */
export async function isSessionOwner(kv, sessionId, userEmail) {
	const meta = await getSessionMeta(kv, sessionId);
	if (!meta) return false;
	// Dev mode bypass
	if (userEmail === 'dev@localhost') return true;
	return meta.owner === userEmail;
}

// ── Internal helpers ───────────────────────────────────────────────────────────

async function addSessionToUser(kv, userEmail, sessionId, fileName, createdAt) {
	const data = await kv.get(`user:${userEmail}:sessions`);
	let sessions = data ? JSON.parse(data) : [];

	sessions.unshift({ id: sessionId, fileName, createdAt });

	// Enforce max sessions per user
	if (sessions.length > MAX_SESSIONS_PER_USER) {
		const removed = sessions.splice(MAX_SESSIONS_PER_USER);
		// Clean up old sessions asynchronously
		for (const old of removed) {
			try { await deleteSessionData(kv, old.id); } catch (e) { /* best effort */ }
		}
	}

	await kv.put(`user:${userEmail}:sessions`, JSON.stringify(sessions), { expirationTtl: SESSION_TTL });
}

async function removeSessionFromUser(kv, userEmail, sessionId) {
	const data = await kv.get(`user:${userEmail}:sessions`);
	if (!data) return;

	let sessions = JSON.parse(data);
	sessions = sessions.filter(s => s.id !== sessionId);
	await kv.put(`user:${userEmail}:sessions`, JSON.stringify(sessions), { expirationTtl: SESSION_TTL });
}

async function deleteSessionData(kv, sessionId) {
	// Best-effort cleanup of a session's KV entries
	const meta = await kv.get(`session:${sessionId}:meta`);
	const deletes = [
		kv.delete(`session:${sessionId}:meta`),
		kv.delete(`session:${sessionId}:flows`),
		kv.delete(`session:${sessionId}:stats`),
		kv.delete(`session:${sessionId}:ai`),
		kv.delete(`session:${sessionId}:warp`),
	];
	if (meta) {
		const m = JSON.parse(meta);
		const chunks = m.packetChunks || 0;
		for (let i = 0; i < chunks; i++) {
			deletes.push(kv.delete(`session:${sessionId}:packets:${i}`));
		}
	}
	await Promise.all(deletes);
}

export { PACKETS_PER_CHUNK };
