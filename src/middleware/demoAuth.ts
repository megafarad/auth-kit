import {Response, NextFunction} from 'express';
import dotenv from 'dotenv';
import {RequestWithCredentials} from './extractCredentials';
import {Principal} from "../core/auth";
import crypto from 'crypto';
import {NonceStore} from "../hmac/nonceStore";
import {v5 as uuidv5} from 'uuid';
import {makeVerifyUserJwt} from "../jwt/verifyUserJwt";

dotenv.config();

const allScopes = ['call:dial', 'appointments:getAvailable', 'appointments:make', 'appointments:cancel']

export interface RequestWithPrincipal extends RequestWithCredentials {
    principal?: Principal;
}

const verifyUserJWT = process.env.JWKS_URL ?
    makeVerifyUserJwt({jwksUrl: process.env.JWKS_URL}) : undefined;

export function demoAuth(nonceStore: NonceStore) {
    return async function demoAuth(req: RequestWithPrincipal, res: Response, next: NextFunction): Promise<void> {
        // HMAC demo auth (preshared key in DEMO_HMAC_KEY)
        if (req.credentials?.type === 'hmac') {
            if (!process.env.DEMO_HMAC_KEY) {
                res.status(500).json({error: 'Missing DEMO_HMAC_KEY environment variable'});
                return;
            }

            const { signature, timestamp, algorithm, nonce } = req.credentials;
            const nowMillis = Date.now();
            const tsNum = Number(timestamp);
            const allowedSkewMillis = 30000; // 5 minutes for demo

            if (!Number.isFinite(tsNum)) {
                res.status(401).json({ error: 'Invalid timestamp' });
                return;
            }
            if (Math.abs(nowMillis - tsNum) > allowedSkewMillis) {
                res.status(401).json({ error: 'Timestamp outside allowed skew' });
                return;
            }
            if (!nonce || nonce.length < 8) {
                res.status(400).json({ error: 'Missing or invalid nonce' });
                return;
            }

            const seenAt = await nonceStore.getNonce(nonce);

            if (seenAt && Math.abs(nowMillis - seenAt) <= allowedSkewMillis) {
                res.status(401).json({ error: 'Nonce already seen' });
                return;
            }

            await nonceStore.setNonce(nonce, nowMillis);

            const algo = (algorithm || 'sha256').toLowerCase();
            if (algo !== 'sha256') {
                res.status(400).json({ error: 'Unsupported HMAC algorithm (demo supports sha256 only)' });
                return;
            }

            // Compute body hash (demo: uses JSON.stringify(req.body) if present)
            const bodyString = req.body ? JSON.stringify(req.body) : '';
            const bodyHashHex = crypto.createHash('sha256').update(bodyString, 'utf8').digest('hex');

            // Canonical string to sign: METHOD \n ORIGINAL_URL \n TIMESTAMP \n NONCE \n BODY_SHA256
            const canonical = `${req.method}\n${req.originalUrl}\n${timestamp}\n${nonce}\n${bodyHashHex}`;

            const expected = crypto
                .createHmac('sha256', process.env.DEMO_HMAC_KEY)
                .update(canonical, 'utf8')
                .digest();

            let provided: Buffer;
            try {
                // Expect Base64 in x-signature for this demo
                provided = Buffer.from(signature, 'base64');
            } catch {
                res.status(400).json({ error: 'Invalid signature encoding (expected Base64)' });
                return;
            }

            if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
                res.status(401).json({ error: 'Invalid HMAC signature' });
                return;
            }

            req.principal = {
                kind: 'service',
                id: uuidv5(process.env.DEMO_HMAC_KEY, uuidv5.URL),
                name: 'demoHmac',
                superKey: false,
                memberships: [
                    {
                        tenantId: 1,
                        scopes: allScopes
                    }
                ]
            }
            next();
            return;
        }

        // Bearer token demo auth
        if (req.credentials?.type === 'bearerToken') {
            if (!process.env.DEMO_BEARER_TOKEN && !process.env.JWKS_URL) {
                res.status(500).json({error: 'Missing DEMO_BEARER_TOKEN & JWKS_URL environment variable'});
                return;
            }
            if (req.credentials.token === process.env.DEMO_BEARER_TOKEN) {
                req.principal = {
                    kind: 'user',
                    userId: uuidv5(process.env.DEMO_BEARER_TOKEN, uuidv5.URL),
                    superUser: false,
                    memberships: [
                        {
                            tenantId: 1,
                            role: 'admin',
                            scopes: []
                        }
                    ]
                }
                next();
                return;
            }

            try {
                const decoded = await verifyUserJWT?.(req.credentials.token);
                if (!decoded) {
                    res.status(500).json({error: 'Missing JWKS_URL environment variable'});
                    return;
                }

                req.principal = {
                    kind: 'user',
                    userId: decoded.sub,
                    superUser: false,
                    memberships: [{
                        tenantId: 1,
                        role: 'evaluator',
                        scopes: []
                    }]
                }
                next();
                return;
            } catch (e) {
                res.status(401).json({error: 'Invalid JWT'});
                return;
            }
        }

        // API key demo auth
        if (req.credentials?.type === 'apiKey') {
            if (!process.env.DEMO_API_KEY) {
                res.status(500).json({error: 'Missing DEMO_API_KEY environment variable'});
                return;
            }
            if (req.credentials.apiKey === process.env.DEMO_API_KEY) {
                req.principal = {
                    kind: 'service',
                    id: uuidv5(process.env.DEMO_API_KEY, uuidv5.URL),
                    name: 'demoKey',
                    superKey: false,
                    memberships: [
                        {
                            tenantId: 1,
                            scopes: allScopes
                        }
                    ]
                }
                next();
                return;
            }
        }

        req.principal = {
            kind: 'public'
        }
        next();
        return;
    }
}
