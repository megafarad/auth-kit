export type Role = 'admin' | 'editor' | 'viewer';

export interface ServiceMembership {
    tenantId: number;
    scopes: string[];
}

export interface ServiceRecord {
    id: string;
    name: string;
    prefix: string;
    hash: string;
    memberships: ServiceMembership[];
    createdAt: Date;
    lastUsedAt?: Date;
    expiresAt?: Date;
    isSuperKey: boolean;
}

export interface InsertServiceRequest {
    name: string;
    prefix: string;
    hash: string;
    memberships: ServiceMembership[];
    createdAt: Date;
    expiresAt?: Date;
}

export interface UpdateServiceRequest {
    id: string;
    name: string;
    prefix: string;
    hash: string;
    memberships: ServiceMembership[];
    updatedAt: Date;
    expiresAt?: Date;
}

export interface UserMembership {
    tenantId: number;
    role: Role;
    scopes: string[];
}

export interface UserRecord {
    id: string;
    authUserId: string;
    email: string;
    memberships: UserMembership[];
    isSuperUser: boolean;
}

export interface InsertUserRequest {
    authUserId: string;
    email: string;
    memberships: UserMembership[];
}

export interface TenantRecord {
    id: number;
    name: string;
    status: string;
    createdBy: string;
    createdAt: Date;
    updatedBy?: string;
    updatedAt?: Date;
}

export interface InsertTenantRequest {
    name: string;
    status: string;
    createdBy: string;
    createdAt: Date;
}

export type UserPrincipal = {
    kind: 'user';
    userId: string;
    superUser: boolean;
    memberships: UserMembership[];
}

export type ServicePrincipal = {
    kind: 'service';
    id: string;
    name: string;
    superKey: boolean;
    memberships: ServiceMembership[];
}

export type PublicPrincipal = {
    kind: 'public';
}

export type Principal = UserPrincipal | ServicePrincipal | PublicPrincipal;