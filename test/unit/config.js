const test = require('ava');
const getPort = require('get-port');

const ForwardEmail = require('../..');

test('can be constructed', async (t) => {
  const forwardEmail = new ForwardEmail({ port: await getPort() });

  t.true(forwardEmail instanceof ForwardEmail);
});
