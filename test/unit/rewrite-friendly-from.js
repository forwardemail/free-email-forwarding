const getPort = require('get-port');
const test = require('ava');

const ForwardEmail = require('../..');

test.before(async (t) => {
  t.context.forwardEmail = new ForwardEmail({
    port: await getPort()
  });
});

test('will parse "from" field when given name', (t) => {
  const { forwardEmail } = t.context;

  const res = forwardEmail.rewriteFriendlyFrom('Paul <theprophet@dune.com>');

  t.is(res, '"Paul" <no-reply@forwardemail.net>');
});

test('will parse "from" field when not given a name', (t) => {
  const { forwardEmail } = t.context;

  const res = forwardEmail.rewriteFriendlyFrom('<theprophet@dune.com>');

  t.is(res, '"theprophet@dune.com" <no-reply@forwardemail.net>');
});
