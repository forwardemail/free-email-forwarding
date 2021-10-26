const getPort = require('get-port');
const test = require('ava');

const ForwardEmail = require('../..');

test.before(async (t) => {
  t.context.forwardEmail = new ForwardEmail({
    port: await getPort()
  });
});

test('will return address with filer', (t) => {
  const { forwardEmail } = t.context;

  const res = forwardEmail.parseFilter('Paul+paul@example.com');

  t.is(res, 'paul');
});

test('will return blank string when no filter', (t) => {
  const { forwardEmail } = t.context;

  const res = forwardEmail.parseFilter('paul@example.com');

  t.is(res, '');
});
