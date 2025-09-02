export interface NonceStore {
    getNonce(nonce: string): Promise<number | undefined>;
    setNonce(nonce: string, seenAt: number): Promise<void>;
}