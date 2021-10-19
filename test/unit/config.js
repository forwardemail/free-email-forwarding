/* eslint-disable no-new */
const test = require('ava');
const getPort = require('get-port');

const ForwardEmail = require('../..');

test('can be constructed without passed config', (t) => {
  const forwardEmail = new ForwardEmail();

  t.true(forwardEmail instanceof ForwardEmail);
});

test('can be constructed with passed config', async (t) => {
  const forwardEmail = new ForwardEmail({ port: await getPort() });

  t.true(forwardEmail instanceof ForwardEmail);
});

test('throws if dnsbl domains/removals is not the same length', async (t) => {
  await t.throwsAsync(
    async () => {
      new ForwardEmail({
        port: await getPort(),
        dnsbl: {
          domains: ['arrakis'],
          removals: ['harkonnen', 'bene gesserit']
        }
      });
    },
    { message: 'DNSBL_DOMAINS length must be equal to DNSBL_REMOVALS.' }
  );
});

test('can set ssl and configure properly', async (t) => {
  const forwardEmail = new ForwardEmail({ port: await getPort(), ssl: {} });

  const { ssl } = forwardEmail.config;
  t.is(ssl.minVersion, 'TLSv1.2');
  t.is(typeof ssl.ciphers, 'string');
  t.is(ssl.honorCipherOrder, true);
});

test('will log SMTPServer errors', async (t) => {
  t.plan(1);

  const forwardEmail = new ForwardEmail({
    port: await getPort(),
    logger: {
      error: () => {
        t.pass();
      },
      debug: () => {}
    }
  });

  forwardEmail.server.emit('error');
});
