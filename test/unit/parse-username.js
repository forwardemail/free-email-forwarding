const getPort = require('get-port');
const test = require('ava');

const ForwardEmail = require('../..');

test.before(async (t) => {
  t.context.forwardEmail = new ForwardEmail({
    port: await getPort()
  });
});

test('will return username from Name@example.com', (t) => {
  const { forwardEmail } = t.context;

  const res = forwardEmail.parseUsername('Name@example.com');

  t.is(res, 'name');
});

test('will return username from Paul+paul@example.com', (t) => {
  const { forwardEmail } = t.context;

  const res = forwardEmail.parseUsername('Paul+paul@example.com');

  t.is(res, 'paul');
});
