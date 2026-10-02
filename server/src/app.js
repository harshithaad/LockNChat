'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');
const config = require('./config');
const {
  securityHeaders,
  corsPolicy,
  noStore,
  createApiLimiter,
} = require('./middleware/security');
const { notFound, errorHandler } = require('./middleware/errors');
const healthRouter = require('./routes/health');
const { createAuthRouter } = require('./routes/auth');
const usersRouter = require('./routes/users');
const conversationsRouter = require('./routes/conversations');

function createApp() {
  const app = express();

  app.disable('x-powered-by');
  // Needed for correct client IPs (rate limiting) behind a reverse proxy.
  app.set('trust proxy', config.trustProxy);

  app.use(securityHeaders);

  const api = express.Router();
  api.use(corsPolicy);
  api.use(noStore);
  api.use(createApiLimiter());
  api.use(express.json({ limit: '16kb' }));
  api.use(cookieParser());

  api.use('/health', healthRouter);
  api.use('/auth', createAuthRouter());
  api.use('/users', usersRouter);
  api.use('/conversations', conversationsRouter);
  api.use(notFound);

  app.use('/api', api);

  // The browser client is plain static files served from the same origin.
  app.use(express.static(config.clientDir, { index: 'index.html', dotfiles: 'ignore' }));

  app.use(notFound);
  app.use(errorHandler);

  return app;
}

module.exports = { createApp };
