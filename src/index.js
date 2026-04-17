/**
 * WARP & PCAP Analyzer v2 — Cloudflare Worker
 *
 * Routes:
 *   GET  /                          → UI (HTML) or API info (JSON)
 *   POST /api/analyze               → Upload & analyse (unified)
 *   GET  /api/sessions              → List user sessions
 *   GET  /api/sessions/:id          → Session metadata
 *   GET  /api/sessions/:id/packets  → Packet data (paginated)
 *   GET  /api/sessions/:id/flows    → Flow/conversation data
 *   GET  /api/sessions/:id/stats    → Protocol statistics
 *   GET  /api/sessions/:id/ai       → AI analysis results
 *   GET  /api/sessions/:id/warp     → WARP diagnostics data
 *   GET  /api/sessions/:id/export/:fmt → Export (json|csv|har|html)
 *   DELETE /api/sessions/:id        → Delete session
 *   OPTIONS *                       → CORS preflight
 */

import { extractZipFiles, parseTextFile, categorizeWarpFile, extractKeyInfo } from './parsers.js';
import { decodePcapFile } from './pcap-decoder.js';
import { analyzePcapWithAI, analyzeWarpDiagnostics } from './ai-analyzer.js';
import { analyzeWarpBundle, findLogEvidence } from './warp-analyzer.js';
import { verifyAccessJWT } from './auth.js';
import {
	createSession, generateSessionId, getSessionMeta, getSessionPackets,
	getAllSessionPackets, getSessionFlows, getSessionStats, getSessionAI,
	getSessionWarp, getFullSession, listUserSessions, deleteSession,
	updateSessionAI, isSessionOwner, PACKETS_PER_CHUNK,
} from './session.js';
import { exportSession } from './export.js';
import { UI_HTML } from './ui.js';

// ── CORS ───────────────────────────────────────────────────────────────────────

const CORS = {
	'Access-Control-Allow-Origin': '*',
	'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
	'Access-Control-Allow-Headers': 'Content-Type, Cf-Access-Jwt-Assertion',
	'Access-Control-Max-Age': '86400',
};

function json(data, status = 200) {
	return new Response(JSON.stringify(data), {
		status,
		headers: { ...CORS, 'Content-Type': 'application/json' },
	});
}

function err(message, status = 400) {
	return json({ error: message }, status);
}

function isPcapFile(name) {
	const l = name.toLowerCase();
	return l.endsWith('.pcap') || l.endsWith('.pcapng');
}

// ── Router ─────────────────────────────────────────────────────────────────────

export default {
	async fetch(request, env, ctx) {
		try {
		return await handleRequest(request, env, ctx);
		} catch (e) {
			console.error('Unhandled Worker error:', e);
			return err(`Internal error: ${e.message}`, 500);
		}
	},
};

async function handleRequest(request, env, ctx) {
		// CORS preflight
		if (request.method === 'OPTIONS') {
			return new Response(null, { headers: CORS });
		}

		const url = new URL(request.url);
		const path = url.pathname;

		// Serve UI for browser GET /
		if (request.method === 'GET' && path === '/') {
			const accept = request.headers.get('accept') || '';
			if (accept.includes('text/html')) {
				return new Response(UI_HTML, {
					headers: { ...CORS, 'Content-Type': 'text/html; charset=utf-8' },
				});
			}
			return json({
				name: 'WARP & PCAP Analyzer',
				version: '2.0.0',
				description: 'Professional network capture analysis with Wireshark-style UI and AI-powered diagnostics',
				models: ['Llama 4 Scout 17B', 'Llama 3.3 70B Fast', 'DeepSeek R1 32B'],
				endpoints: {
					ui: 'GET / (browser)',
					analyze: 'POST /api/analyze (multipart/form-data)',
					sessions: 'GET /api/sessions',
					session: 'GET /api/sessions/:id',
					packets: 'GET /api/sessions/:id/packets?page=0',
					flows: 'GET /api/sessions/:id/flows',
					stats: 'GET /api/sessions/:id/stats',
					ai: 'GET /api/sessions/:id/ai',
					warp: 'GET /api/sessions/:id/warp',
					export: 'GET /api/sessions/:id/export/:format',
					delete: 'DELETE /api/sessions/:id',
				},
			});
		}

		// ── Auth check for API routes ──────────────────────────────────────────
		if (path.startsWith('/api/')) {
			const authResult = await verifyAccessJWT(request, env);
			if (!authResult.authenticated) {
				return err(authResult.error || 'Authentication required', 401);
			}

			const userEmail = authResult.identity.email;

			// ── POST /api/analyze ──────────────────────────────────────────────
			if (request.method === 'POST' && path === '/api/analyze') {
				return handleAnalyze(request, env, ctx, userEmail);
			}

			// ── GET /api/sessions ──────────────────────────────────────────────
			if (request.method === 'GET' && path === '/api/sessions') {
				if (!env.SESSIONS) return err('Session storage not configured', 500);
				const sessions = await listUserSessions(env.SESSIONS, userEmail);
				return json({ sessions });
			}

			// ── Session-specific routes ────────────────────────────────────────
			const sessionMatch = path.match(/^\/api\/sessions\/([^/]+)(?:\/(.+))?$/);
			if (sessionMatch) {
				const sessionId = sessionMatch[1];
				const sub = sessionMatch[2] || '';

				if (!env.SESSIONS) return err('Session storage not configured', 500);

				// Verify ownership
				const owns = await isSessionOwner(env.SESSIONS, sessionId, userEmail);
				if (!owns) return err('Session not found or access denied', 404);

				if (request.method === 'DELETE' && !sub) {
					const deleted = await deleteSession(env.SESSIONS, sessionId, userEmail);
					return json({ deleted });
				}

				if (request.method === 'GET') {
					switch (sub) {
						case '': {
							const meta = await getSessionMeta(env.SESSIONS, sessionId);
							return json(meta);
						}
						case 'packets': {
							const page = parseInt(url.searchParams.get('page') || '0', 10);
							const packets = await getSessionPackets(env.SESSIONS, sessionId, page);
							const meta = await getSessionMeta(env.SESSIONS, sessionId);
							return json({
								packets,
								page,
								pageSize: PACKETS_PER_CHUNK,
								totalPackets: meta?.totalPackets || 0,
								totalPages: Math.ceil((meta?.totalPackets || 0) / PACKETS_PER_CHUNK),
							});
						}
						case 'flows': {
							const flows = await getSessionFlows(env.SESSIONS, sessionId);
							return json({ flows });
						}
						case 'stats': {
							const stats = await getSessionStats(env.SESSIONS, sessionId);
							return json({ stats });
						}
						case 'ai': {
							const ai = await getSessionAI(env.SESSIONS, sessionId);
							return json({ ai });
						}
						case 'warp': {
							const warp = await getSessionWarp(env.SESSIONS, sessionId);
							return json({ warp });
						}
						default: {
							// Export routes: export/json, export/csv, etc.
							const exportMatch = sub.match(/^export\/(\w+)$/);
							if (exportMatch) {
								const format = exportMatch[1];
								try {
									const full = await getFullSession(env.SESSIONS, sessionId);
									if (!full) return err('Session data not found', 404);
									const result = exportSession(full, format);
									return new Response(result.body, {
										headers: {
											...CORS,
											'Content-Type': result.contentType,
											'Content-Disposition': `attachment; filename="${result.filename}"`,
										},
									});
								} catch (e) {
									return err(e.message, 400);
								}
							}
							return err('Unknown session endpoint', 404);
						}
					}
				}
			}

			return err('Not found', 404);
		}

		// Fallback: serve UI for any non-API GET
		if (request.method === 'GET') {
			return new Response(UI_HTML, {
				headers: { ...CORS, 'Content-Type': 'text/html; charset=utf-8' },
			});
		}

		return err('Method not allowed', 405);
}

// ── Analysis handler ───────────────────────────────────────────────────────────

async function handleAnalyze(request, env, ctx, userEmail) {
	console.log('[analyze] START - user:', userEmail);
	const contentType = request.headers.get('content-type') || '';
	if (!contentType.includes('multipart/form-data')) {
		return err('Content-Type must be multipart/form-data');
	}

	if (!env.AI) return err('AI binding not configured', 500);

	try {
		console.log('[analyze] Parsing form data...');
		const formData = await request.formData();
		const files = [];

		for (const [, value] of formData.entries()) {
			if (value instanceof File) {
				files.push({ name: value.name, data: await value.arrayBuffer(), type: value.type });
			}
		}

		console.log(`[analyze] ${files.length} file(s) received:`, files.map(f => `${f.name} (${f.data.byteLength} bytes)`));

		if (files.length === 0) return err('No files uploaded');

		// ── Process files ──────────────────────────────────────────────────────
		const allLogFiles = [];
		const allPcapDecoded = [];
		let primaryFileName = files[0].name;
		let primaryFileSize = files[0].data.byteLength;
		let fileType = 'unknown';

		for (const file of files) {
			if (file.name.endsWith('.zip') || file.type === 'application/zip') {
				fileType = 'warp-diag';
				console.log('[analyze] Extracting ZIP...');
				const extracted = extractZipFiles(file.data);
				console.log(`[analyze] ZIP extracted: ${extracted.size} files`);

				for (const [filename, data] of extracted) {
					if (isPcapFile(filename)) {
						console.log(`[analyze] Decoding PCAP: ${filename} (${data.length} bytes)`);
						const decoded = decodePcapFile(new Uint8Array(data));
						console.log(`[analyze] PCAP decoded: ${decoded.packets.length} packets`);
						allPcapDecoded.push({ filename, ...decoded });
					} else {
					try {
							const fullContent = parseTextFile(data);
							// Smart truncation: keep beginning and end for logs (most diagnostic info
							// is in recent events); keep full content for small config files.
							let content = fullContent;
							const MAX_KEEP = 256 * 1024;  // 256KB per file — enough for daemon.log analysis
							if (fullContent.length > MAX_KEEP) {
								const head = fullContent.substring(0, 32 * 1024);
								const tail = fullContent.substring(fullContent.length - (MAX_KEEP - 32 * 1024));
								content = head + '\n\n...[truncated ' + (fullContent.length - MAX_KEEP) + ' bytes]...\n\n' + tail;
							}
							const cat = categorizeWarpFile(filename);
							const keyInfo = extractKeyInfo(filename, content);
							allLogFiles.push({ filename, content, category: cat.category, priority: cat.priority, keyInfo, originalSize: fullContent.length });
						} catch (e) {
							console.warn(`Failed to parse ${filename}:`, e.message);
						}
				}
			}
		} else if (isPcapFile(file.name)) {
				fileType = 'pcap';
				console.log(`[analyze] Decoding standalone PCAP: ${file.name} (${file.data.byteLength} bytes)`);
				const decoded = decodePcapFile(new Uint8Array(file.data));
				console.log(`[analyze] PCAP decoded: ${decoded.packets.length} packets`);
				allPcapDecoded.push({ filename: file.name, ...decoded });
			} else {
				fileType = fileType === 'unknown' ? 'log' : fileType;
				try {
					const content = parseTextFile(new Uint8Array(file.data));
					const cat = categorizeWarpFile(file.name);
					const keyInfo = extractKeyInfo(file.name, content);
					allLogFiles.push({ filename: file.name, content, category: cat.category, priority: cat.priority, keyInfo });
				} catch (e) {
					console.warn(`Failed to parse ${file.name}:`, e.message);
				}
			}
		}

		console.log(`[analyze] Processing complete: ${allLogFiles.length} logs, ${allPcapDecoded.length} PCAPs`);

		if (allLogFiles.length === 0 && allPcapDecoded.length === 0) {
			return err('No valid files found in upload');
		}

		// ── Merge PCAP data if multiple captures ───────────────────────────────
		let pcapResult = null;
		if (allPcapDecoded.length > 0) {
			if (allPcapDecoded.length === 1) {
				pcapResult = allPcapDecoded[0];
			} else {
				// Merge packets from all captures
				const mergedPackets = [];
				const mergedFlows = {};
				const allWarnings = [];
				let baseMetadata = allPcapDecoded[0].metadata;

				for (const dec of allPcapDecoded) {
					mergedPackets.push(...dec.packets);
					Object.assign(mergedFlows, dec.flows);
					allWarnings.push(...dec.warnings);
				}

				// Re-number merged packets
				mergedPackets.sort((a, b) => a.timestamp - b.timestamp);
				mergedPackets.forEach((p, i) => p.number = i + 1);

				pcapResult = {
					filename: allPcapDecoded.map(d => d.filename).join(', '),
					metadata: { ...baseMetadata, totalPackets: mergedPackets.length, mergedFrom: allPcapDecoded.length },
					packets: mergedPackets,
					flows: mergedFlows,
					stats: allPcapDecoded[0].stats, // Will be recalculated
					warnings: allWarnings,
				};
			}
		}

		// ── Deep WARP analysis (rule-based, synchronous) ───────────────────────
		let warpSnapshot = null;
		if (allLogFiles.length > 0) {
			console.log('[analyze] Running WARP bundle analysis...');
			warpSnapshot = analyzeWarpBundle(allLogFiles);
			console.log(`[analyze] WARP snapshot: health=${warpSnapshot.health}, ${warpSnapshot.findings.length} findings, ${warpSnapshot.timeline.length} timeline events`);
		}

		// ── Run AI analysis ────────────────────────────────────────────────────
		console.log('[analyze] Starting AI analysis...');
		const aiResult = await runAIAnalysis(env.AI, pcapResult, allLogFiles, warpSnapshot);
		console.log('[analyze] AI complete, success:', aiResult.success);

		// ── Create session in background (don't block response) ────────────────
		let sessionId = null;
		if (env.SESSIONS) {
			sessionId = generateSessionId();
			ctx.waitUntil(
				createSession(env.SESSIONS, userEmail, {
					fileName: primaryFileName,
					fileSize: primaryFileSize,
					fileType,
					metadata: pcapResult?.metadata || {},
					packets: pcapResult?.packets || [],
					flows: pcapResult?.flows || {},
					stats: pcapResult?.stats || {},
					warnings: pcapResult?.warnings || [],
					warpFiles: allLogFiles,
					warpSnapshot,
				}, sessionId).then(async () => {
					try {
						await updateSessionAI(env.SESSIONS, sessionId, aiResult);
					} catch (e) {
						console.error('Failed to store AI results:', e);
					}
				}).catch(e => console.error('Session creation failed:', e))
			);
		}

		// ── Build response ─────────────────────────────────────────────────────
		const response = {
			sessionId,
			timestamp: new Date().toISOString(),
			fileType,
			filesProcessed: {
				logFiles: allLogFiles.length,
				pcapFiles: allPcapDecoded.length,
				total: allLogFiles.length + allPcapDecoded.length,
			},
		};

		if (pcapResult) {
			// Cap inline packets and strip rawBytes to keep response size manageable
			const INLINE_LIMIT = 500;
			const inlinePackets = pcapResult.packets.slice(0, INLINE_LIMIT).map(pkt => {
				const { rawBytes, ...rest } = pkt;
				// Only include rawBytes for first 200 packets (hex dump)
				if (pkt.number <= 200) {
					return { ...rest, rawBytes };
				}
				return rest;
			});

			response.pcap = {
				metadata: pcapResult.metadata,
				stats: pcapResult.stats,
				totalPackets: pcapResult.packets.length,
				packets: inlinePackets,
				flows: pcapResult.flows,
				warnings: pcapResult.warnings,
			};
		}

		response.ai = aiResult;
		response.success = aiResult.success !== false;

		if (allLogFiles.length > 0) {
			response.warpFiles = allLogFiles.map(f => ({
				filename: f.filename,
				category: f.category,
				priority: f.priority,
				size: f.originalSize || f.content.length,
				// Include full content so UI can show log viewer
				content: f.content,
			}));
			// Include full structured WARP snapshot for the UI
			if (warpSnapshot) response.warp = warpSnapshot;
		}

		console.log('[analyze] Sending response, sessionId:', sessionId);
		return json(response);

	} catch (error) {
		console.error('[analyze] CAUGHT ERROR:', error.message, error.stack);
		return err(`Analysis failed: ${error.message}`, 500);
	}
}

// ── AI dispatch ────────────────────────────────────────────────────────────────

async function runAIAnalysis(ai, pcapResult, logFiles, warpSnapshot) {
	const results = {};

	try {
		// Run PCAP and WARP analysis in parallel to reduce total latency
		const promises = [];

		if (pcapResult && pcapResult.packets.length > 0) {
			promises.push(
				analyzePcapWithAI(ai, pcapResult)
					.then(r => { results.pcap = r; })
					.catch(e => { results.pcap = { success: false, error: e.message }; })
			);
		}

		if (logFiles.length > 0) {
			const priorityFiles = [
				...logFiles.filter(f => f.priority === 'high').slice(0, 10),
				...logFiles.filter(f => f.priority === 'medium').slice(0, 5),
			];
			const pcapMeta = pcapResult?.metadata || null;
			promises.push(
				analyzeWarpDiagnostics(ai, priorityFiles, pcapMeta, warpSnapshot)
					.then(r => { results.warp = r; })
					.catch(e => { results.warp = { success: false, error: e.message }; })
			);
		}

		await Promise.all(promises);

		const pcapAnalysis = results.pcap?.analysis || results.pcap?.fallback;
		const warpAnalysis = results.warp?.analysis || results.warp?.fallback;

		results.combined = {
			health_status: determineOverallHealth(pcapAnalysis, warpAnalysis),
			summary: buildCombinedSummary(pcapAnalysis, warpAnalysis),
			models_used: [results.pcap?.model, results.warp?.model].filter(Boolean),
		};

		results.success = true;
	} catch (error) {
		console.error('AI analysis error:', error);
		results.success = false;
		results.error = error.message;
	}

	return results;
}

function determineOverallHealth(pcap, warp) {
	const statuses = [pcap?.health_status, warp?.health_status].filter(Boolean);
	if (statuses.includes('Critical')) return 'Critical';
	if (statuses.includes('Degraded')) return 'Degraded';
	if (statuses.length > 0) return statuses[0];
	return 'Unknown';
}

function buildCombinedSummary(pcap, warp) {
	const parts = [];
	if (pcap?.summary) parts.push(`PCAP: ${pcap.summary}`);
	if (warp?.summary) parts.push(`WARP: ${warp.summary}`);
	return parts.join(' | ') || 'Analysis complete';
}
