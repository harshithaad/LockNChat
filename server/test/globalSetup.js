'use strict';

module.exports = async () => {
  require('./env');
  const { migrate } = require('../src/db/migrate');
  const { pool } = require('../src/db/pool');
  await migrate({ log: () => {} });
  await pool.end();
};
