import * as argon2 from 'argon2';
import dotenv from 'dotenv';
dotenv.config();

const PEPPER = process.env.API_KEY_PEPPER!;

export async function hashSecret(secret: string, salt: string) {
    return argon2.hash(`${secret}:${salt}:${PEPPER}`, {
        type: argon2.argon2id,
        memoryCost: 2 ** 16,
        timeCost: 3
    });
}