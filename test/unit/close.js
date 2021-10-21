const { once } = require('events');

const Client = require('nodemailer/lib/smtp-connection');
const getPort = require('get-port');
const pify = require('pify');
const test = require('ava');

const ForwardEmail = require('../..');

test.before(async (t) => {
  t.context.forwardEmail = new ForwardEmail({
    port: await getPort()
  });
});

test.afterEach(async (t) => {
  const { forwardEmail } = t.context;

  if (forwardEmail.server.listening) {
    await forwardEmail.stop();
  }
});

test('will close', async (t) => {
  await t.notThrowsAsync(async () => {
    const { forwardEmail } = t.context;

    await forwardEmail.listen();

    const connection = pify(
      new Client({
        port: forwardEmail.config.port,
        host: '127.0.0.1',
        ignoreTLS: true,
        connectionTimeout: 100
      })
    );

    const err = await connection.connect();
    t.is(err, undefined);
    connection.quit();
    await once(connection, 'end');

    await forwardEmail.close();
  });
});
