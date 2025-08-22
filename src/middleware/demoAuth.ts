import { Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import {RequestWithCredentials} from './extractCredentials';
import {Principal} from "../core/auth";

dotenv.config();

export interface RequestWithPrincipal extends RequestWithCredentials {
    principal?: Principal;
}

export function demoAuth(req: RequestWithPrincipal, res: Response, next: NextFunction) {
    if (req.credentials?.type === 'bearerToken' && req.credentials.token === process.env.DEMO_BEARER_TOKEN) {
        req.principal = {
            kind: 'user',
            userId: 'demoUser',
            superUser: false,
            memberships: [
                {
                    tenantId: 1,
                    role: 'admin',
                    scopes: []
                }
            ]
        }
    } else {
        req.principal = {
            kind: 'public'
        }
    }
    next();
}