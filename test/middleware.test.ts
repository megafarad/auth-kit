import express from "express";
import request from "supertest";
import {extractCredentials, demoAuth, membershipChecker} from "../src";

function buildApp() {
    const app = express();
    app.get('/tenant/:tenantId/secured', extractCredentials, demoAuth,
        membershipChecker({roles: ['admin'], scopes: []}), (req, res) => {
        res.json({
            message: 'Hello World'
        });
    });
    return app;
}

describe('middleware', () => {
    it('should return 401/Unauthorized when no credentials are provided', async () => {
        const app = buildApp();
        await request(app)
            .get('/tenant/1/secured')
            .expect(401)
            .expect({error: 'Unauthorized'});
    });

    it('should  return 403/Forbidden when credentials are provided but not authorized', async () => {
        const app = buildApp();
        await request(app).get('/tenant/1/secured').set('Authorization',
            'Bearer invalidToken').expect(403).expect({error: 'Forbidden'});
    });

    it('should return 200/Okay when credentials are provided and authorized', async () => {
        const app = buildApp();
        await request(app).get('/tenant/1/secured').set('Authorization',
            'Bearer test123').expect(200).expect({message: 'Hello World'});
    });

    it('should return 400/Bad Request when tenantId is not an integer', async () => {
        const app = buildApp();
        await request(app).get('/tenant/invalid/secured').set('Authorization',
            'Bearer test123').expect(400).expect({error: 'Invalid tenantId'});
    });
});