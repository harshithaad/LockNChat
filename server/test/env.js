'use strict';

// Test configuration. Runs before any module is loaded, so config.js sees it.
process.env.NODE_ENV = 'test';
process.env.DATABASE_URL =
  process.env.TEST_DATABASE_URL || 'postgres://locknchat:locknchat@localhost:5433/locknchat_test';
process.env.JWT_SECRET = 'test-secret-that-is-definitely-long-enough-0123456789';
process.env.BCRYPT_ROUNDS = '4'; // fast hashing in tests only; production enforces >= 12
process.env.CORS_ORIGINS = 'http://localhost:3000';
process.env.RATE_LIMIT_AUTH_MAX = process.env.RATE_LIMIT_AUTH_MAX || '1000';
process.env.RATE_LIMIT_API_MAX = process.env.RATE_LIMIT_API_MAX || '10000';
