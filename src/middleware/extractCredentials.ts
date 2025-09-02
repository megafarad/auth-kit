import {Request, Response, NextFunction} from "express";

export type ApiKeyCredentials = {
    type: 'apiKey';
    apiKey: string;
}

export type BearerTokenCredentials = {
    type: 'bearerToken';
    token: string;
}

export type HmacCredentials = {
    type: 'hmac';
    signature: string;
    timestamp: string;
    algorithm?: 'sha256' | string;
    nonce?: string;
}

export type Credentials = ApiKeyCredentials | BearerTokenCredentials | HmacCredentials;

export interface RequestWithCredentials extends Request {
    credentials?: Credentials;
}

export function extractCredentials(req: RequestWithCredentials, res: Response, next: NextFunction) {
    const authHeader = req.headers['authorization'];
    const apiKeyHeader = req.headers['x-api-key'];
    const hmacSignature = req.headers['x-signature'];
    const hmacTimestamp = req.headers['x-timestamp'];
    const hmacAlg = req.headers['x-signature-alg'];
    const hmacNonce = req.headers['x-nonce'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        req.credentials = {
            type: 'bearerToken',
            token: token
        }
    } else if (typeof apiKeyHeader === 'string') {
        req.credentials = {
            type: 'apiKey',
            apiKey: apiKeyHeader
        }
    } else if (typeof hmacSignature === 'string' && typeof hmacTimestamp === 'string') {
        req.credentials = {
            type: 'hmac',
            signature: hmacSignature,
            timestamp: hmacTimestamp,
            algorithm: typeof hmacAlg === 'string' ? hmacAlg : 'sha256',
            nonce: typeof hmacNonce === 'string' ? hmacNonce : undefined
        }
    }
    next();
}