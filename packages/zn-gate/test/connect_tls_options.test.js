'use strict';

// NODE_OPTIONS is read the way Node reads it (spaces outside quotes, quotes removed), and
// every option that loads code or changes the TLS settings holds back a saved key.

const test = require('node:test');
const assert = require('node:assert/strict');
const cloudKey = require('../lib/cloud-key');

const why = (o) => cloudKey.tlsRefusal({ NODE_OPTIONS: o });

test('loader, require and import options are refused in every form Node accepts', () => {
  for (const o of [
    '--require ./x.js', '--require=./x.js', '-r ./x.js', '--import ./x.mjs', '--import=./x.mjs',
    '--loader ./l.mjs', '--loader=./l.mjs', '--experimental-loader ./l.mjs', '--experimental-loader=./l.mjs',
    '"--require" ./x.js', "'--import=./x.mjs'", '"--loader=./l.mjs"', "'-r' ./x.js", '"--experimental-loader" ./l.mjs',
    '--max-old-space-size=512 "--require" ./x.js', '--use-openssl-ca', '"--use-openssl-ca"',
    '--openssl-config=/tmp/o.cnf', '--openssl-config /tmp/o.cnf', "'--openssl-config=/tmp/o.cnf'",
  ]) {
    assert.match(why(o), /NODE_OPTIONS/, o);
  }
});

test('harmless options are not refused, and a quoted value is not read as an option', () => {
  for (const o of ['', '--max-old-space-size=512', '--enable-source-maps', '--stack-trace-limit=50 --no-warnings', '--title "my --require app"', "--title='-r x'"]) {
    assert.equal(why(o), null, o);
  }
});

test('OPENSSL_CONF holds back a saved key', () => {
  assert.match(cloudKey.tlsRefusal({ OPENSSL_CONF: '/tmp/o.cnf' }), /OPENSSL_CONF is set/);
  assert.equal(cloudKey.tlsRefusal({ OPENSSL_CONF: '' }), null);
});
