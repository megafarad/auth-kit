import {Response, NextFunction} from 'express';
import dotenv from 'dotenv';
import {RequestWithCredentials} from './extractCredentials';
import {Principal} from "../core/auth";

dotenv.config();

export interface RequestWithPrincipal extends RequestWithCredentials {
    principal?: Principal;
}

export function demoAuth(req: RequestWithPrincipal, res: Response, next: NextFunction) {
    if (!process.env.DEMO_BEARER_TOKEN || !process.env.DEMO_API_KEY) {
        console.error('Missing environment variables');
        res.status(500).json({error: 'Missing environment variables'});
    } else if (req.credentials?.type === 'bearerToken' && req.credentials.token === process.env.DEMO_BEARER_TOKEN) {
        console.log('Demo user authenticated');
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
        next();
    } else if (req.credentials?.type === 'apiKey' && req.credentials.apiKey === process.env.DEMO_API_KEY) {
        console.log('Demo service authenticated');
        req.principal = {
            kind: 'service',
            name: 'demoKey',
            superKey: false,
            memberships: [
                {
                    tenantId: 1,
                    scopes: ['appointments:getAvailable', 'appointments:make']
                }
            ]
        }
        next();
    } else {
        console.log('Public user authenticated');
        req.principal = {
            kind: 'public'
        }
        next();
    }
}