'use strict';

/**
 * Token bucket: allows bursts up to `capacity`, refilling `refillPerSecond`
 * tokens per second. `take()` returns false when the caller is over the limit.
 */
function createBucket({ capacity, refillPerSecond, now = Date.now }) {
  let tokens = capacity;
  let last = now();

  return {
    take() {
      const current = now();
      tokens = Math.min(capacity, tokens + ((current - last) / 1000) * refillPerSecond);
      last = current;
      if (tokens < 1) return false;
      tokens -= 1;
      return true;
    },
  };
}

module.exports = { createBucket };
