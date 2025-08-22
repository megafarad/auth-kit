import {Role} from "../core/auth";
import {RequestWithPrincipal} from "./demoAuth";
import {Response, NextFunction} from "express";

export interface MembershipCriteria {
    roles: Role[];
    scopes: string[];
}

export function membershipChecker(criteria: MembershipCriteria) {
    return function(req: RequestWithPrincipal, res: Response, next: NextFunction) {
        const tenantIdString = req.params['tenantId'];
        if (!tenantIdString || !Number.isInteger(Number(tenantIdString))) {
            res.status(400).json({error: 'Invalid tenantId'});
        }
        const tenantId = Number(tenantIdString);
        if (req.principal?.kind === 'user') {
            if (req.principal.superUser) {
                next();
            } else {
                const userMembership = req.principal.memberships.find(m =>
                    m.tenantId === tenantId);
                if (userMembership) {
                    if (!criteria.roles.includes(userMembership.role)) {
                        if (criteria.scopes.some(scope => userMembership.scopes.includes(scope))) {
                            next();
                        } else {
                            res.status(403).json({error: 'Forbidden'});
                        }
                    } else {
                        next();
                    }
                } else {
                    res.status(403).json({error: 'Forbidden'});
                }
            }
        } else if (req.principal?.kind === 'service') {
            if (req.principal.superKey) {
                next();
            } else {
                const serviceMembership = req.principal.memberships.find(m =>
                    m.tenantId === tenantId);
                if (serviceMembership) {
                    if (criteria.scopes.some(scope => serviceMembership.scopes.includes(scope))) {
                        next();
                    } else {
                        res.status(403).json({error: 'Forbidden'});
                    }
                } else {
                    res.status(403).json({error: 'Forbidden'});
                }
            }
        } else if (req.principal?.kind === 'public') {
            if (req.credentials) {
                res.status(403).json({error: 'Forbidden'});
            } else {
                res.status(401).json({error: 'Unauthorized'});
            }
        }
    }
}