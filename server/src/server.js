'use strict';

const http = require('http');
const config = require('./config');
const { createApp } = require('./app');
const { pool } = require('./db/pool');

const app = createApp();
const server = http.createServer(app);

server.listen(config.port, () => {
  console.log(`LockNChat listening on http://localhost:${config.port}`);
});

function shutdown(signal) {
  console.log(`${signal} received, shutting down`);
  server.close(() => {
    pool.end().finally(() => process.exit(0));
  });
  // Force exit if connections refuse to close.
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
