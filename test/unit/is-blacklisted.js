const getPort = require('get-port');
const test = require('ava');

const ForwardEmail = require('../..');

test.before(async (t) => {
  t.context.forwardEmail = new ForwardEmail({
    port: await getPort(),
    blacklist: ['bad.com']
  });
});

test('will return true if domain is blacklisted', (t) => {
  const { forwardEmail } = t.context;

  const res = forwardEmail.isBlacklisted('bad.com');

  t.true(res);
});

test('will return true if domain ends with blacklisted', (t) => {
  const { forwardEmail } = t.context;

  const res = forwardEmail.isBlacklisted('test-bad.com');

  t.true(res);
});

test('will return false if domain is not blacklisted', (t) => {
  const { forwardEmail } = t.context;

  const res = forwardEmail.isBlacklisted('test.com');

  t.false(res);
});
