import express from "express";
import request from "supertest";
import {extractCredentials, demoAuth, membershipChecker} from "../src";

function buildApp() {
    const app = express();
    app.use(extractCredentials, demoAuth, membershipChecker({roles: ['admin'], scopes: []}));
    app.get('/tenant/:tenantId/secured', (req, res) => {
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
    })
});