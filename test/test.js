const fs = require('fs');
const os = require('os');
const path = require('path');
const uuid = require('uuid');
const shell = require('shelljs');
const bytes = require('bytes');
const test = require('ava');
const nodemailer = require('nodemailer');
const Client = require('nodemailer/lib/smtp-connection');
const domains = require('disposable-email-domains');

const ForwardEmail = require('../');
const { beforeEach, afterEach } = require('./helpers');

const tls = { rejectUnauthorized: false };

test.beforeEach(beforeEach);
test.afterEach(afterEach);

test('returns itself', t => {
  t.true(new ForwardEmail() instanceof ForwardEmail);
});

test('binds context', t => {
  t.true(t.context.forwardEmail instanceof ForwardEmail);
});

test.cb('rejects auth connections', t => {
  const port = t.context.forwardEmail.server.address().port;
  const connection = new Client({ port, tls });
  connection.on('end', t.end);
  connection.connect(() => {
    connection.login({ user: 'user', pass: 'pass' }, err => {
      t.is(err.responseCode, 500);
      connection.quit();
    });
  });
});

test('verifies connection', async t => {
  const port = t.context.forwardEmail.server.address().port;
  const transporter = nodemailer.createTransport({ port, tls });
  await transporter.verify();
  t.pass();
});

test('rejects forwarding a non-FQDN email', async t => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const port = t.context.forwardEmail.server.address().port;
  const connection = new Client({ port, tls });
  const info = await transporter.sendMail({
    from: 'from@forwardemail.net',
    to: 'Niftylettuce <hello@127.0.0.1>',
    subject: 'test',
    text: 'test text',
    html: '<strong>test html</strong>',
    attachments: []
  });
  return new Promise(resolve => {
    connection.on('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, err => {
        t.is(err.responseCode, 550);
        t.regex(err.message, /is not a FQDN/);
        connection.quit();
      });
    });
  });
});

// test('rejects forwarding a non-registered email domain', async t => {
//   t.regex(err.message, /does not have a valid forwardemail TXT record/);
// });

test('rejects forwarding a non-registered email address', async t => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const port = t.context.forwardEmail.server.address().port;
  const connection = new Client({ port, tls });
  const info = await transporter.sendMail({
    from: 'from@forwardemail.net',
    to: 'Niftylettuce <fail@test.niftylettuce.com>', // "pass" works
    subject: 'test',
    text: 'test text',
    html: '<strong>test html</strong>',
    attachments: []
  });
  return new Promise(resolve => {
    connection.on('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, err => {
        t.is(err.responseCode, 550);
        t.regex(err.message, /Invalid forward-email TXT record/);
        connection.quit();
      });
    });
  });
});

test('rejects forwarding an email without dkim and spf', async t => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const port = t.context.forwardEmail.server.address().port;
  const connection = new Client({ port, tls });
  const info = await transporter.sendMail({
    from: 'from@forwardemail.net',
    to: 'Niftylettuce <hello@niftylettuce.com>',
    cc: 'cc@niftylettuce.com',
    subject: 'test',
    text: 'test text',
    html: '<strong>test html</strong>',
    attachments: []
  });
  return new Promise(resolve => {
    connection.on('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, err => {
        t.is(err.responseCode, 550);
        t.regex(err.message, /No passing DKIM signature found/);
        connection.quit();
      });
    });
  });
});

test('forwards an email with dkim', async t => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const port = t.context.forwardEmail.server.address().port;
  const connection = new Client({ port, tls });
  const info = await transporter.sendMail({
    from: 'from@forwardemail.net',
    to: 'Niftylettuce <hello@niftylettuce.com>',
    cc: 'cc@niftylettuce.com',
    subject: 'test',
    text: 'test text',
    html: '<strong>test html</strong>',
    attachments: [],
    dkim: {
      domainName: 'forwardemail.net',
      keySelector: 'default',
      privateKey: fs.readFileSync(
        path.join(__dirname, '..', 'dkim-private.key'),
        'utf8'
      )
    }
  });
  return new Promise(resolve => {
    connection.on('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, err => {
        t.is(err, null);
        connection.quit();
      });
    });
  });
});

test('rejects a spam file', async t => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const port = t.context.forwardEmail.server.address().port;
  const connection = new Client({ port, tls });
  const info = await transporter.sendMail({
    from: 'foo@forwardemail.net',
    to: 'Baz <baz@forwardemail.net>',
    // taken from:
    // <https://github.com/humantech/node-spamd/blob/master/test/spamd-tests.js#L13-L14>
    subject: 'Viagra, Cialis, Vicodin: buy medicines without prescription!',
    html: 'Cheap prices on viagra, cialis, vicodin! FPA approved!',
    dkim: {
      domainName: 'forwardemail.net',
      keySelector: 'default',
      privateKey: fs.readFileSync(
        path.join(__dirname, '..', 'dkim-private.key'),
        'utf8'
      )
    }
  });
  return new Promise(resolve => {
    connection.on('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, err => {
        if (!shell.which('spamassassin') || !shell.which('spamc')) {
          t.is(err, null);
        } else {
          t.is(err.responseCode, 551);
          t.regex(err.message, /Message detected as spam/);
        }
        connection.quit();
      });
    });
  });
});

test('rejects a file over the limit', async t => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const filePath = path.join(os.tmpdir(), uuid());
  const size = bytes('25mb');
  const port = t.context.forwardEmail.server.address().port;
  const connection = new Client({ port, tls });
  fs.writeFileSync(filePath, Buffer.from(new Array(size).fill('0')));
  const info = await transporter.sendMail({
    from: 'foo@forwardemail.net',
    to: 'Baz <baz@forwardemail.net>',
    subject: 'test',
    text: 'test text',
    html: '<strong>test text</strong>',
    attachments: [{ path: filePath }]
  });
  return new Promise(resolve => {
    connection.on('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, err => {
        t.is(err.responseCode, 450);
        t.regex(err.message, /Message size exceeds maximum/);
        fs.unlinkSync(filePath);
        connection.quit();
      });
    });
  });
});

/*
test('prevents spam through rate limiting', async t => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const port = t.context.forwardEmail.server.address().port;

  let failed = 0;

  await Promise.all(
    Array.from(Array(200).keys()).map(() => {
      return new Promise(async (resolve, reject) => {
        try {
          const info = await transporter.sendMail({
            from: 'foo@forwardemail.net',
            to: 'Baz <baz@forwardemail.net>',
            subject: 'test',
            text: 'test text',
            html: '<strong>test html</strong>',
            dkim: {
              domainName: 'forwardemail.net',
              keySelector: 'default',
              privateKey: fs.readFileSync(
                path.join(__dirname, '..', 'dkim-private.key'),
                'utf8'
              )
            }
          });
          const connection = new Client({ port, tls });
          connection.on('end', resolve);
          connection.connect(() => {
            connection.send(info.envelope, info.message, err => {
              if (err && err.responseCode === 451) failed++;
              connection.quit();
            });
          });
        } catch (err) {
          reject(err);
        }
      });
    })
  );

  t.is(failed, 100);
});
*/

test('rejects a disposable email sender', async t => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const port = t.context.forwardEmail.server.address().port;
  const connection = new Client({ port, tls });
  const info = await transporter.sendMail({
    from: `disposable@${domains[0]}`,
    to: 'Niftylettuce <hello@niftylettuce.com>',
    subject: 'test',
    text: 'test text',
    html: '<strong>test html</strong>'
  });
  return new Promise(resolve => {
    connection.on('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, err => {
        t.is(err.responseCode, 550);
        t.regex(err.message, /Disposable email addresses are not permitted/);
        connection.quit();
      });
    });
  });
});

test.todo('rejects invalid dkim signature');
test.todo('accepts valid dkim signature');
test.todo('rejects invalid spf');
test.todo('accepts valid spf');
test.todo('supports + symbol aliased onRcptTo');
