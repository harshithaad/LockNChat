'use strict';

const { createBucket } = require('../src/lib/rateBucket');

test('allows a burst up to capacity, then refills over time', () => {
  let now = 0;
  const bucket = createBucket({ capacity: 3, refillPerSecond: 2, now: () => now });

  expect([bucket.take(), bucket.take(), bucket.take()]).toEqual([true, true, true]);
  expect(bucket.take()).toBe(false);

  now += 500; // one token refilled
  expect(bucket.take()).toBe(true);
  expect(bucket.take()).toBe(false);

  now += 10_000; // never exceeds capacity
  expect([bucket.take(), bucket.take(), bucket.take(), bucket.take()]).toEqual([true, true, true, false]);
});
