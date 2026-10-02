'use strict';

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env'), quiet: true });
const { z } = require('zod');

const bool = z
  .enum(['true', 'false'])
  .transform((v) => v === 'true');

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(1).max(30).default(7),
  BCRYPT_ROUNDS: z.coerce.number().int().min(4).max(15).default(12),
  CORS_ORIGINS: z.string().default('http://localhost:3000'),
  COOKIE_SECURE: bool.default(true),
  TRUST_PROXY: z.coerce.number().int().min(0).default(0),
  RATE_LIMIT_AUTH_MAX: z.coerce.number().int().min(1).default(20),
  RATE_LIMIT_API_MAX: z.coerce.number().int().min(1).default(300),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  const issues = parsed.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n');
  // Fail fast: running with a weak or missing secret is worse than not running.
  throw new Error(`Invalid environment configuration:\n${issues}`);
}

const env = parsed.data;

if (env.NODE_ENV === 'production' && env.BCRYPT_ROUNDS < 12) {
  throw new Error('BCRYPT_ROUNDS must be at least 12 in production');
}

module.exports = Object.freeze({
  env: env.NODE_ENV,
  isTest: env.NODE_ENV === 'test',
  isProduction: env.NODE_ENV === 'production',
  port: env.PORT,
  databaseUrl: env.DATABASE_URL,
  jwtSecret: env.JWT_SECRET,
  accessTokenTtlSeconds: env.ACCESS_TOKEN_TTL_SECONDS,
  refreshTokenTtlDays: env.REFRESH_TOKEN_TTL_DAYS,
  bcryptRounds: env.BCRYPT_ROUNDS,
  corsOrigins: env.CORS_ORIGINS.split(',').map((o) => o.trim()).filter(Boolean),
  cookieSecure: env.COOKIE_SECURE,
  trustProxy: env.TRUST_PROXY,
  rateLimitAuthMax: env.RATE_LIMIT_AUTH_MAX,
  rateLimitApiMax: env.RATE_LIMIT_API_MAX,
  clientDir: path.join(__dirname, '..', '..', 'client'),
});
