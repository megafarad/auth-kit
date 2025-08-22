# @sirhc77/auth-kit

Utilities for securing a Node + Express app, written in TypeScript.

This kit focuses on common authentication and authorization building blocks you can compose in your Express applications, with first-class TypeScript support.

- API key hashing and verification (Argon2)
- JWT creation and verification (JOSE)
- Environment-driven configuration (dotenv)
- Express-oriented helpers and middleware primitives
- Optional integration points for Supabase (via `@supabase/supabase-js`)

> Note: This package provides utilities you can compose into your own auth flows. See the “Usage Patterns” section for typical setups you can adapt.

---

## Installation
```
bash
npm install @sirhc77/auth-kit
```
This package is published under the MIT license and built for Node + Express projects using TypeScript.

Related libraries used internally:
- express
- argon2
- jose
- dotenv
- @supabase/supabase-js (optional usage)

You don’t need to install these separately unless you use them directly in your app.

---

## Quick start
```
ts
import express from 'express';
// import { ... } from '@sirhc77/auth-kit'; // See Usage Patterns below

const app = express();
app.use(express.json());

// TODO: wire up the auth-kit utilities you need here

app.get('/health', (_req, res) => res.json({ ok: true }));

app.listen(3000, () => {
  console.log('Server listening on http://localhost:3000');
});
```
---

## Usage patterns

Right now, this package provides the following utilities:

### Utility functions

- `generateApiKey`: A utility function for generating API keys.
- `hashSecret`: A utility function for hashing secrets using Argon2.
- `makeVerifyUserJwt`: A utility function that creates a JWT verifier. The JWT verifier validates a token against a public JWT key, for an optional issuer and audience.

### Express middleware

- `extractCredentials`: A middleware that extracts credentials from a request, be it from an Authorization header or an API key.
- `demoAuth`: A middleware that verifies a user against a DEMO_BEARER_TOKEN environment variable.
- `membershipChecker`: A middleware that checks if a user is of a specific role or has a scope for a specific tenant. NOTE: This middleware requires a `tenantId` path parameter.

### Example middleware usage

```ts
import { extractCredentials, demoAuth, membershipChecker } from '@sirhc77/auth-kit';
import express from 'express';

const app = express();

app.get('/tenant/:tenant_id/secured', extractCredentials, demoAuth, membershipChecker({roles: ['admin'], scopes: []}), (req, res) => {
    res.json({ ok: true });    
})

```

---

## Environment variables

Typical environment variables you may want for auth flows:

- DEMO_BEARER_TOKEN

Load them using dotenv in your app’s entry point:
```
ts
import 'dotenv/config';
// or:
// import dotenv from 'dotenv';
// dotenv.config();
```
---

## TypeScript

This package ships TypeScript typings:
- Types are emitted to `dist/index.d.ts`
- Works out of the box with `tsconfig.json` defaults for Node projects

---

## Building

This library is built with the TypeScript compiler.
```
bash
npm run build
```
The build outputs ESM-compatible JavaScript and type declarations to `dist/`.

---

## Example project structure

You can organize your app as follows:
```

src/
  app.ts            # Express app setup
  auth/             # Your auth composition using auth-kit utilities
    passwords.ts
    tokens.ts
    middleware.ts
  routes/
    public.ts
    private.ts
```
---

## Security considerations

- Always use strong secrets/keys for JWT signing (consider rotating keys and using JWKs).
- Prefer HTTPS in production; set secure cookie flags if you use cookies.
- Use Argon2 with sane parameters (memory/time cost) appropriate for your environment.
- Never log sensitive values (passwords, secrets, tokens).
- Validate and sanitize user input.

---

## Contributing

Issues and PRs are welcome. If contributing:
- Keep the API surface minimal and composable.
- Favor explicit, typed interfaces and well-documented functions.
- Include examples and edge cases in descriptions.

---

## License

MIT © Chris Carrington
```
