'use strict';

const { AppError } = require('../lib/errors');
const config = require('../config');

function notFound(req, res, next) {
  next(new AppError(404, 'not_found', 'Resource not found'));
}

// Errors raised by body-parser that are the client's fault.
const BODY_PARSER_ERRORS = {
  'entity.too.large': [413, 'payload_too_large', 'Request body is too large'],
  'entity.parse.failed': [400, 'invalid_json', 'Request body is not valid JSON'],
  'encoding.unsupported': [415, 'unsupported_encoding', 'Unsupported content encoding'],
};

/**
 * Central error handler. Known errors get a stable JSON shape; anything else is
 * logged server-side and reported as a generic 500 so stack traces, SQL and
 * internal details never reach the client.
 */
// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  if (res.headersSent) return next(err);

  if (err instanceof AppError) {
    const body = { error: { code: err.code, message: err.message } };
    if (err.details) body.error.details = err.details;
    return res.status(err.status).json(body);
  }

  const known = BODY_PARSER_ERRORS[err.type];
  if (known) {
    const [status, code, message] = known;
    return res.status(status).json({ error: { code, message } });
  }

  if (!config.isTest) console.error(err);
  return res.status(500).json({ error: { code: 'internal_error', message: 'Something went wrong' } });
}

module.exports = { notFound, errorHandler };
