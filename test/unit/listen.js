const { once } = require('events');

const getPort = require('get-port');
const test = require('ava');
const Client = require('nodemailer/lib/smtp-connection');

const ForwardEmail = require('../..');

test.before(async (t) => {
  t.context.forwardEmail = new ForwardEmail({
    port: await getPort()
  });
});

test.afterEach(async (t) => {
  await t.context.forwardEmail.close();
});

test('will listen using config settings', async (t) => {
  t.plan(1);

  const { forwardEmail } = t.context;

  await forwardEmail.listen();

  const connection = new Client({
    port: forwardEmail.config.port,
    host: '127.0.0.1',
    ignoreTLS: true
  });

  connection.connect(() => {
    t.pass();
    connection.quit();
  });

  await once(connection, 'end');
});

test('will listen using given port', async (t) => {
  t.plan(1);

  const { forwardEmail } = t.context;
  const port = await getPort();

  await forwardEmail.listen(port);

  const connection = new Client({
    port,
    host: '127.0.0.1',
    ignoreTLS: true
  });

  connection.connect(() => {
    t.pass();
    connection.quit();
  });

  await once(connection, 'end');
});
