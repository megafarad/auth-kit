import {Request, Response, NextFunction} from "express";

export type ApiKeyCredentials = {
    type: 'apiKey';
    apiKey: string;
}

export type BearerTokenCredentials = {
    type: 'bearerToken';
    token: string;
}

export type Credentials = ApiKeyCredentials | BearerTokenCredentials;

export interface RequestWithCredentials extends Request {
    credentials?: Credentials;
}

export function extractCredentials(req: RequestWithCredentials, res: Response, next: NextFunction) {
    const authHeader = req.headers['authorization'];
    const apiKeyHeader = req.headers['x-api-key'];
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
    }
    next();
}