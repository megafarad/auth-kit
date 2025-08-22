import {randomBytes} from 'node:crypto';

export interface ApiKey {
    key: string;
    prefix: string;
    secret: string;
}

function base64url(buffer: Buffer) {
    return buffer.toString('base64')
        .replace(/\+/g,'-')
        .replace(/\//g,'_')
        .replace(/=+$/,'');
}

export function generateApiKey(): ApiKey {
    const prefix = base64url(randomBytes(6));
    const secret = base64url(randomBytes(48));
    const key = `mfk_${prefix}.${secret}`;
    return {
        key,
        prefix,
        secret
    };
}
