import TTLCache from '@isaacs/ttlcache'
import {NonceStore} from "./nonceStore";

export class DemoNonceStore implements NonceStore {
    private cache: TTLCache<string, number>;

    constructor(ttl: number) {
        this.cache = new TTLCache({
            ttl
        });
    }

    async getNonce(nonce: string): Promise<number | undefined> {
        return this.cache.get(nonce);
    }

    async setNonce(nonce: string, seenAt: number): Promise<void> {
        this.cache.set(nonce, seenAt);
    }

    static create(ttl: number): NonceStore  {
        return new DemoNonceStore(ttl)
    }
}