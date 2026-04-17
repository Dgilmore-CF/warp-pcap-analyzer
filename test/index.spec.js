import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index.js';

describe('WARP & PCAP Analyzer v2', () => {
	it('GET / returns API info as JSON', async () => {
		const request = new Request('http://example.com', { method: 'GET' });
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(200);
		const data = await response.json();
		expect(data.name).toBe('WARP & PCAP Analyzer');
		expect(data.version).toBe('2.0.0');
		expect(data.endpoints).toBeDefined();
		expect(data.endpoints.analyze).toContain('POST');
	});

	it('GET / returns HTML for browser requests', async () => {
		const request = new Request('http://example.com', {
			method: 'GET',
			headers: { Accept: 'text/html' },
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(200);
		expect(response.headers.get('Content-Type')).toContain('text/html');
		const html = await response.text();
		expect(html).toContain('WARP');
		expect(html).toContain('PCAP Analyzer');
	});

	it('OPTIONS returns CORS headers', async () => {
		const request = new Request('http://example.com', { method: 'OPTIONS' });
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(200);
		expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
		expect(response.headers.get('Access-Control-Allow-Methods')).toContain('POST');
		expect(response.headers.get('Access-Control-Allow-Methods')).toContain('DELETE');
	});

	it('POST /api/analyze rejects non-multipart requests', async () => {
		const request = new Request('http://example.com/api/analyze', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ test: 'data' }),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(400);
		const data = await response.json();
		expect(data.error).toContain('multipart/form-data');
	});

	it('POST /api/analyze returns error when AI binding missing', async () => {
		const formData = new FormData();
		formData.append('file', new File(['test'], 'test.log', { type: 'text/plain' }));

		const request = new Request('http://example.com/api/analyze', {
			method: 'POST',
			body: formData,
		});

		const envNoAI = { ...env, AI: undefined };
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, envNoAI, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(500);
		const data = await response.json();
		expect(data.error).toContain('AI binding not configured');
	});

	it('GET /api/sessions returns sessions list (auth bypass in dev)', async () => {
		const request = new Request('http://example.com/api/sessions', { method: 'GET' });
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		// Should either return sessions or a config error (no KV in test)
		const status = response.status;
		expect([200, 500]).toContain(status);
	});

	it('GET /api/nonexistent returns 404', async () => {
		const request = new Request('http://example.com/api/nonexistent', { method: 'GET' });
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(404);
	});

	it('integration: GET / returns API info via SELF', async () => {
		const response = await SELF.fetch('http://example.com');
		expect(response.status).toBe(200);
		const data = await response.json();
		expect(data.version).toBe('2.0.0');
	});
});
