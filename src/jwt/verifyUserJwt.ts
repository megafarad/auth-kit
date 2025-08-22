import {createRemoteJWKSet, JWTPayload, jwtVerify} from 'jose';

export interface MakeVerifyUserJwtOptions {
    jwksUrl: string;
    issuer?: string;
    audience?: string;
}

export interface DecodedJWT {
    sub: string;
    email?: string;
    raw: JWTPayload;
}

export function makeVerifyUserJwt(options: MakeVerifyUserJwtOptions): (token: string) => Promise<DecodedJWT> {
    const {jwksUrl, issuer, audience} = options;
    const JWKS = createRemoteJWKSet(new URL(jwksUrl));
    return async function verifyUserJwt(token: string) {
        const {payload} = await jwtVerify(token, JWKS, {
            issuer,
            audience,
        });
        return {
            sub: payload.sub!,
            email: payload.email as string | undefined,
            raw: payload
        };
    }
}