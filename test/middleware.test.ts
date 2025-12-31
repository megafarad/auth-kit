import express from "express";
import request from "supertest";
import {extractCredentials, demoAuth, membershipChecker, DemoNonceStore, generateNonce, signRequest} from "../src";

function buildApp(scopes: string[]) {
    const app = express();
    app.use(express.json());
    const router = express.Router();

    router.get('/tenant/:tenantId/secured', extractCredentials, demoAuth(DemoNonceStore.create(60 * 5 * 1000)),
        membershipChecker({roles: ['admin'], scopes: scopes}), (req, res) => {
            res.json({
                message: 'Hello World'
            });
        });

    router.post('/tenant/:tenantId/secured', extractCredentials, demoAuth(DemoNonceStore.create(60 * 5 * 1000)),
        membershipChecker({roles: ['admin'], scopes: scopes}), (req, res) => {
            res.json({
                message: 'Hello World'
            });
        })
    app.use('/api', router);

    return app;
}

describe('middleware', () => {
    it('should return 401/Unauthorized when no credentials are provided', async () => {
        const app = buildApp([]);
        await request(app)
            .get('/api/tenant/1/secured')
            .expect(401)
            .expect({error: 'Unauthorized'});
    });

    it('should return 401/Unauthorized when credentials are provided but are not valid', async () => {
        const app = buildApp([]);
        await request(app).get('/api/tenant/1/secured').set('Authorization',
            'Bearer invalidToken').expect(401).expect({error: 'Invalid JWT'});
    });

    it('should return 200/Okay when credentials are provided and authorized', async () => {
        const app = buildApp([]);
        await request(app).get('/api/tenant/1/secured').set('Authorization',
            `Bearer ${process.env.DEMO_BEARER_TOKEN!}`).expect(200).expect({message: 'Hello World'});
    });

    it('should return 400/Bad Request when tenantId is not an integer', async () => {
        const app = buildApp([]);
        await request(app).get('/api/tenant/invalid/secured').set('Authorization',
            `Bearer ${process.env.DEMO_BEARER_TOKEN!}`).expect(400).expect({error: 'Invalid tenantId'});
    });

    it('should authorize a service key', async () => {
        const app = buildApp(['appointments:getAvailable']);
        await request(app).get('/api/tenant/1/secured').set('X-API-Key',
            process.env.DEMO_API_KEY!).expect(200).expect({message: 'Hello World'});
    });

    it('should accept an HMAC signature', async () => {
        const app = buildApp(['appointments:getAvailable']);
        const body = {
            appointmentId: 123,
            start: '2023-01-01T00:00:00Z',
            end: '2023-01-01T01:00:00Z'
        }
        const signedRequest = signRequest({
            method: 'POST',
            urlPath: '/api/tenant/1/secured',
            body: body,
            key: process.env.DEMO_HMAC_KEY!,
            nonce: generateNonce()
        });
        await request(app).post('/api/tenant/1/secured')
            .send(body)
            .set('Content-Type', 'application/json')
            .set('X-Signature', signedRequest.headers['x-signature'])
            .set('X-Signature-Alg', signedRequest.headers['x-signature-alg'])
            .set('X-Timestamp', signedRequest.headers['x-timestamp'])
            .set('X-Nonce', signedRequest.headers['x-nonce'])
            .expect(200)
            .expect({message: 'Hello World'});
    });

    it('should reject a replayed HMAC signature', async () => {
        const app = buildApp(['appointments:getAvailable']);
        const body = {
            appointmentId: 123,
            start: '2023-01-01T00:00:00Z',
            end: '2023-01-01T01:00:00Z'
        }
        const nonce = generateNonce();

        const signedRequest = signRequest({
            method: 'POST',
            urlPath: '/api/tenant/1/secured',
            body: body,
            key: process.env.DEMO_HMAC_KEY!,
            nonce: nonce
        });

        await request(app).post('/api/tenant/1/secured')
            .send(body)
            .set('Content-Type', 'application/json')
            .set('X-Signature', signedRequest.headers['x-signature'])
            .set('X-Signature-Alg', signedRequest.headers['x-signature-alg'])
            .set('X-Timestamp', signedRequest.headers['x-timestamp'])
            .set('X-Nonce', signedRequest.headers['x-nonce']);

        const replayedRequest = signRequest({
            method: 'POST',
            urlPath: '/api/tenant/1/secured',
            body: body,
            key: process.env.DEMO_HMAC_KEY!,
            nonce: nonce
        });

        await request(app).post('/api/tenant/1/secured')
            .send(body)
            .set('Content-Type', 'application/json')
            .set('X-Signature', replayedRequest.headers['x-signature'])
            .set('X-Signature-Alg', replayedRequest.headers['x-signature-alg'])
            .set('X-Timestamp', replayedRequest.headers['x-timestamp'])
            .set('X-Nonce', replayedRequest.headers['x-nonce'])
            .expect(401)
            .expect({error: 'Nonce already seen'});

    });
});
