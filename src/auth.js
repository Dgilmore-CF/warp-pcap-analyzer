/**
 * Cloudflare Access JWT Authentication
 * Verifies CF Access JWTs using the team's JWKS endpoint.
 * Extracts user identity for session ownership.
 */

// Cache JWKS keys for 10 minutes to avoid repeated fetches
let jwksCache = null;
let jwksCacheTime = 0;
const JWKS_CACHE_TTL = 600_000; // 10 minutes

/**
 * Verify a Cloudflare Access JWT and return user identity.
 * @param {Request} request   Incoming request
 * @param {Object}  env       Worker environment bindings
 * @returns {Promise<{ authenticated: boolean, identity?: Object, error?: string }>}
 */
export async function verifyAccessJWT(request, env) {
	const teamDomain = env.CF_ACCESS_TEAM_DOMAIN;
	const audience = env.CF_ACCESS_AUD;

	// If Access is not configured, allow through (dev mode)
	if (!teamDomain || !audience) {
		return {
			authenticated: true,
			identity: {
				email: 'dev@localhost',
				name: 'Developer',
				sub: 'dev-local',
			},
			bypass: true,
		};
	}

	// Get JWT from the standard Cloudflare Access header
	const token = request.headers.get('Cf-Access-Jwt-Assertion');
	if (!token) {
		// Also check cookie (for browser sessions)
		const cookie = request.headers.get('Cookie') || '';
		const cfAuth = cookie.split(';').find(c => c.trim().startsWith('CF_Authorization='));
		if (!cfAuth) {
			return { authenticated: false, error: 'No Access token found. Ensure Cloudflare Access is configured.' };
		}
		const cookieToken = cfAuth.split('=')[1]?.trim();
		if (!cookieToken) {
			return { authenticated: false, error: 'Invalid Access cookie.' };
		}
		return await validateToken(cookieToken, teamDomain, audience);
	}

	return await validateToken(token, teamDomain, audience);
}

/**
 * Validate a JWT token against the team's JWKS.
 */
async function validateToken(token, teamDomain, audience) {
	try {
		// Split the JWT
		const parts = token.split('.');
		if (parts.length !== 3) {
			return { authenticated: false, error: 'Malformed JWT: expected 3 parts' };
		}

		const [headerB64, payloadB64, signatureB64] = parts;

		// Decode header
		const header = JSON.parse(atob(base64UrlToBase64(headerB64)));
		if (!header.kid) {
			return { authenticated: false, error: 'JWT header missing kid' };
		}

		// Decode payload (before verification, for audience check)
		const payload = JSON.parse(atob(base64UrlToBase64(payloadB64)));

		// Check expiration
		const now = Math.floor(Date.now() / 1000);
		if (payload.exp && payload.exp < now) {
			return { authenticated: false, error: 'Token expired' };
		}

		// Check not-before
		if (payload.nbf && payload.nbf > now + 30) {
			return { authenticated: false, error: 'Token not yet valid' };
		}

		// Check audience
		const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
		if (!aud.includes(audience)) {
			return { authenticated: false, error: 'Token audience mismatch' };
		}

		// Fetch JWKS
		const jwks = await getJWKS(teamDomain);
		const key = jwks.find(k => k.kid === header.kid);
		if (!key) {
			// Invalidate cache and retry once
			jwksCache = null;
			const freshJwks = await getJWKS(teamDomain);
			const freshKey = freshJwks.find(k => k.kid === header.kid);
			if (!freshKey) {
				return { authenticated: false, error: 'No matching key found in JWKS' };
			}
			return await verifySignature(headerB64, payloadB64, signatureB64, freshKey, payload);
		}

		return await verifySignature(headerB64, payloadB64, signatureB64, key, payload);

	} catch (e) {
		return { authenticated: false, error: `JWT verification failed: ${e.message}` };
	}
}

/**
 * Verify the JWT signature using Web Crypto API.
 */
async function verifySignature(headerB64, payloadB64, signatureB64, jwk, payload) {
	const algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };

	const cryptoKey = await crypto.subtle.importKey(
		'jwk',
		{ kty: jwk.kty, n: jwk.n, e: jwk.e, alg: jwk.alg || 'RS256', ext: true },
		algorithm,
		false,
		['verify']
	);

	const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
	const signature = base64UrlDecode(signatureB64);

	const valid = await crypto.subtle.verify(algorithm, cryptoKey, signature, data);

	if (!valid) {
		return { authenticated: false, error: 'Invalid JWT signature' };
	}

	return {
		authenticated: true,
		identity: {
			email: payload.email || payload.sub,
			name: payload.name || payload.email || payload.sub,
			sub: payload.sub,
			iss: payload.iss,
			iat: payload.iat,
			exp: payload.exp,
			groups: payload.custom?.groups || [],
		},
	};
}

/**
 * Fetch and cache the JWKS from Cloudflare Access.
 */
async function getJWKS(teamDomain) {
	const now = Date.now();
	if (jwksCache && (now - jwksCacheTime) < JWKS_CACHE_TTL) {
		return jwksCache;
	}

	const domain = teamDomain.includes('.') ? teamDomain : `${teamDomain}.cloudflareaccess.com`;
	const url = `https://${domain}/cdn-cgi/access/certs`;

	const response = await fetch(url);
	if (!response.ok) {
		throw new Error(`Failed to fetch JWKS from ${url}: ${response.status}`);
	}

	const data = await response.json();
	jwksCache = data.keys || data.public_certs?.map(c => c.kid ? c : null).filter(Boolean) || [];

	// If the response has public_certs format (older API), convert
	if (data.public_certs && !data.keys) {
		// Fall back to the keys array from the standard JWKS endpoint
		const jwksUrl = `https://${domain}/cdn-cgi/access/certs`;
		const jwksResp = await fetch(jwksUrl, { headers: { Accept: 'application/json' } });
		if (jwksResp.ok) {
			const jwksData = await jwksResp.json();
			if (jwksData.keys) jwksCache = jwksData.keys;
		}
	}

	jwksCacheTime = now;
	return jwksCache;
}

/**
 * Get user identity from request (convenience wrapper).
 * Returns null if not authenticated.
 */
export async function getUserIdentity(request, env) {
	const result = await verifyAccessJWT(request, env);
	if (!result.authenticated) return null;
	return result.identity;
}

// ── Base64 URL helpers ─────────────────────────────────────────────────────────

function base64UrlToBase64(str) {
	return str.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - str.length % 4) % 4);
}

function base64UrlDecode(str) {
	const binary = atob(base64UrlToBase64(str));
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes.buffer;
}
