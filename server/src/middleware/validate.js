'use strict';

const { AppError } = require('../lib/errors');

/**
 * Validate request parts against zod schemas. Parsed (and stripped) values are
 * exposed on `req.valid`, so handlers only ever read input that passed
 * validation; unknown fields are dropped.
 */
function validate(schemas) {
  return (req, res, next) => {
    req.valid = {};
    for (const part of ['params', 'query', 'body']) {
      if (!schemas[part]) continue;
      const result = schemas[part].safeParse(req[part] ?? {});
      if (!result.success) {
        const details = result.error.issues.map((i) => ({
          field: [part, ...i.path].join('.'),
          message: i.message,
        }));
        return next(new AppError(400, 'validation_error', 'Invalid request', details));
      }
      req.valid[part] = result.data;
    }
    next();
  };
}

module.exports = { validate };
