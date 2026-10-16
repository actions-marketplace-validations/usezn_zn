'use strict';
// A database URL whose password is only a reference is not a secret; a literal password still is.
const test = require('node:test');
const assert = require('node:assert/strict');
const { redactSecrets } = require('../lib/rules');

test('db_url_password skips references and keeps literals', () => {
  for (const t of ['postgres://app:${PGPASSWORD}@db.example.com/app', 'mysql://app:$DB_PASS@db.example.com', 'redis://app:%REDIS_PASSWORD%@cache.example.com',
    'amqp://app:<password>@mq.example.com', 'mongodb://app:{{ password }}@db.example.com', 'postgres://app:{{password}}@db.example.com']) {
    assert.equal(redactSecrets(t).sanitized, t, t);
  }
  for (const t of ['postgres://app:ZnTestFakePw42x@db.example.com/app', 'mysql://app:$literal$pw9@db.example.com', 'redis://app:pw%20x@cache.example.com',
    'postgres://app:$kR7vQ2mZx9LpW4@db.example.com', 'mysql://app:%Passw0rd%@db.example.com', 'postgres://app:<R3al!Pw>@db.example.com', 'postgres://app:{{Tr0ub4dor&3}}@db.example.com']) {
    assert.match(redactSecrets(t).sanitized, /\[REDACTED_DB_PASSWORD\]/, t);
  }
});
