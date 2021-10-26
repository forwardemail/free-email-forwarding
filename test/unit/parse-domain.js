const getPort = require('get-port');
const test = require('ava');

const ForwardEmail = require('../..');

test.before(async (t) => {
  t.context.forwardEmail = new ForwardEmail({
    port: await getPort(),
    blacklist: ['bad.com']
  });
});

test('will return domain from name@example.com', (t) => {
  const { forwardEmail } = t.context;

  const res = forwardEmail.parseDomain('name@example.com');

  t.is(res, 'example.com');
});

function fqdnError(t, input) {
  const { forwardEmail } = t.context;

  t.throws(
    () => {
      forwardEmail.parseDomain(input);
    },
    {
      message:
        /does not contain a fully qualified domain name \("FQDN"\) nor IP address\./
    }
  );
}

for (const input of ['', 'name@ex', 'name@10.3']) {
  test(`will throw error when given ${input}`, fqdnError, input);
}

test('will throw error when given a blacklist address', (t) => {
  const { forwardEmail } = t.context;

  t.throws(
    () => {
      forwardEmail.parseDomain('name@bad.com');
    },
    {
      message: /The domain .* is blacklisted by <.*>\./
    }
  );
});
