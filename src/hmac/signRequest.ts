import crypto  from "crypto";

export type SignRequestResult = {
    headers: {
        'x-signature': string;
        'x-signature-alg': string;
        'x-timestamp': string;
        'x-nonce': string;
    }
    bodyString: string;
}

export function generateNonce(bytes: number = 16): string {
    return crypto.randomBytes(bytes).toString('hex');
}

export function signRequest(options: {
    method: string;
    urlPath: string;
    body?: unknown;
    key: string;
    nonce?: string;
}): SignRequestResult {
    const { method, urlPath, body, key } = options;
    const nonce = options.nonce ?? generateNonce();

    const bodyString = body != null ? JSON.stringify(body) : '';
    const bodyHashHex = crypto
        .createHash('sha256')
        .update(bodyString, 'utf8')
        .digest('hex');

    const timestamp = Date.now().toString();
    const canonical = `${method}\n${urlPath}\n${timestamp}\n${nonce}\n${bodyHashHex}`;

    const signature = crypto
        .createHmac('sha256', key)
        .update(canonical, 'utf8')
        .digest('base64');

    return {
        headers: {
            'x-timestamp': timestamp,
            'x-nonce': nonce,
            'x-signature': signature,
            'x-signature-alg': 'sha256'
        },
        bodyString
    }
}
