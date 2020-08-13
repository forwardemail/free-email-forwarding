const dns = require('dns');
const fs = require('fs');
const os = require('os');
const path = require('path');

const Client = require('nodemailer/lib/smtp-connection');
const IORedis = require('ioredis');
const _ = require('lodash');
const bytes = require('bytes');
const getPort = require('get-port');
const isCI = require('is-ci');
const nodemailer = require('nodemailer');
const pify = require('pify');
const test = require('ava');
const { v4 } = require('uuid');

const lookupAsync = pify(dns.lookup);

const ForwardEmail = require('..');

const tls = { rejectUnauthorized: false };

const client = new IORedis();

test.beforeEach(async (t) => {
  const keys = await client.keys('limit:*');
  if (keys.length > 0) await Promise.all(keys.map((key) => client.del(key)));
  const port = await getPort();
  const forwardEmail = new ForwardEmail({ port });
  await forwardEmail.listen();
  t.context.forwardEmail = forwardEmail;
});

test.afterEach(async (t) => {
  await t.context.forwardEmail.close();
});

test('returns itself', (t) => {
  t.true(new ForwardEmail() instanceof ForwardEmail);
});

test('binds context', (t) => {
  t.true(t.context.forwardEmail instanceof ForwardEmail);
});

test.cb('rejects auth connections', (t) => {
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });
  connection.once('end', t.end);
  connection.connect(() => {
    connection.login({ user: 'user', pass: 'pass' }, (err) => {
      // TODO: t.regex(err.message, /someregex/)
      t.is(err.responseCode, 500);
      connection.close();
    });
  });
});

test('verifies connection', async (t) => {
  const { port } = t.context.forwardEmail.server.address();
  const transporter = nodemailer.createTransport({ port, tls });
  await transporter.verify();
  t.pass();
});

/*
test('rejects forwarding a non-FQDN email', async t => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({  port, tls });
  const info = await transporter.sendMail({
    from: 'ForwardEmail <from@forwardemail.net>',
    to: 'Niftylettuce <hello@127.0.0.1>',
    subject: 'test',
    text: 'test text',
    html: '<strong>test html</strong>',
    attachments: []
  });
  return new Promise(resolve => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, err => {
        // TODO: t.regex(err.message, /someregex/)
        t.is(err.responseCode, 550);
        t.regex(err.message, /is not a fully qualified domain name/);
        connection.close();
      });
    });
  });
});
*/

// test('rejects forwarding a non-registered email domain', async t => {
//   t.regex(err.message, /does not have a valid forwardemail TXT record/);
// });

test('rejects forwarding a non-registered email address', async (t) => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });
  const info = await transporter.sendMail({
    from: 'ForwardEmail <from@forwardemail.net>',
    to: 'Niftylettuce <fail@test.niftylettuce.com>', // "pass" works
    subject: 'test',
    text: 'test text',
    html: '<strong>test html</strong>',
    attachments: []
  });
  return new Promise((resolve) => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, (err) => {
        t.regex(
          err.message,
          /is not configured properly and does not contain any valid/
        );
        t.is(err.responseCode, 550);
        connection.close();
      });
    });
  });
});

if (!isCI)
  test('rejects an email with failing SPF', async (t) => {
    const transporter = nodemailer.createTransport({
      streamTransport: true
    });
    const { port } = t.context.forwardEmail.server.address();
    const connection = new Client({ port, tls });
    const info = await transporter.sendMail({
      from: 'ForwardEmail <from@forwardemail.net>',
      to: 'Niftylettuce <hello@niftylettuce.com>',
      cc: 'cc@niftylettuce.com',
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>',
      attachments: [],
      dkim: t.context.forwardEmail.config.dkim
    });
    return new Promise((resolve) => {
      connection.once('end', resolve);
      connection.connect(() => {
        connection.send(info.envelope, info.message, (err) => {
          t.regex(
            err.message,
            /The email you sent has failed SPF validation with a result of "fail"/
          );
          t.is(err.responseCode, 550);
          connection.close();
        });
      });
    });
  });

if (!isCI)
  test('forwards an email with DKIM and without SPF (no DMARC)', async (t) => {
    const transporter = nodemailer.createTransport({
      streamTransport: true
    });
    const { port } = t.context.forwardEmail.server.address();
    const connection = new Client({ port, tls });
    const info = await transporter.sendMail({
      // NOTE: this is forwardMAIL.net not forwardEMAIL.net (I have registered both)
      from: 'Example <from@forwardmail.net>',
      to: 'Niftylettuce <hello@niftylettuce.com>',
      subject: 'forwards an email with DKIM and without SPF (no DMARC)',
      text: 'test text',
      html: '<strong>test html</strong>',
      attachments: [],
      dkim: t.context.forwardEmail.config.dkim
    });
    return new Promise((resolve) => {
      connection.once('end', resolve);
      connection.connect(() => {
        connection.send(info.envelope, info.message, (err) => {
          t.is(err, null);
          connection.close();
        });
      });
    });
  });

if (!isCI)
  test('forwards an email without DKIM nor SPF (no DMARC)', async (t) => {
    const transporter = nodemailer.createTransport({
      streamTransport: true
    });
    const { port } = t.context.forwardEmail.server.address();
    const connection = new Client({ port, tls });
    const info = await transporter.sendMail({
      // NOTE: this is forwardMAIL.net not forwardEMAIL.net (I have registered both)
      from: 'Example <from@forwardmail.net>',
      to: 'Niftylettuce <hello@niftylettuce.com>',
      subject: 'forwards an email without DKIM nor SPF (no DMARC)',
      text: 'test text',
      html: '<strong>test html</strong>',
      attachments: []
    });
    return new Promise((resolve) => {
      connection.once('end', resolve);
      connection.connect(() => {
        connection.send(info.envelope, info.message, (err) => {
          t.is(err, null);
          connection.close();
        });
      });
    });
  });

if (!isCI)
  test('rejects forwarding an email with max forwarding addresses exceeded', async (t) => {
    const transporter = nodemailer.createTransport({
      streamTransport: true
    });
    const { port } = t.context.forwardEmail.server.address();
    const connection = new Client({ port, tls });
    const info = await transporter.sendMail({
      from: 'ForwardEmail <from@forwardemail.net>',
      to: '1@niftylettuce.com',
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>',
      attachments: [],
      dkim: t.context.forwardEmail.config.dkim
    });
    return new Promise((resolve) => {
      connection.once('end', resolve);
      connection.connect(() => {
        connection.send(info.envelope, info.message, (err) => {
          t.regex(err.message, /addresses which exceeds the maximum/);
          t.is(err.responseCode, 550);
          connection.close();
        });
      });
    });
  });

if (!isCI)
  test('rejects forwarding an email with recursive max forwarding addresses exceeded', async (t) => {
    const transporter = nodemailer.createTransport({
      streamTransport: true
    });
    const { port } = t.context.forwardEmail.server.address();
    const connection = new Client({ port, tls });
    const info = await transporter.sendMail({
      from: 'ForwardEmail <from@forwardemail.net>',
      to: '2@niftylettuce.com',
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>',
      attachments: [],
      dkim: t.context.forwardEmail.config.dkim
    });
    return new Promise((resolve) => {
      connection.once('end', resolve);
      connection.connect(() => {
        connection.send(info.envelope, info.message, (err) => {
          t.regex(err.message, /addresses which exceeds the maximum/);
          t.is(err.responseCode, 550);
          connection.close();
        });
      });
    });
  });

if (!isCI)
  test('forwards an email with DKIM and SPF without recursive loop', async (t) => {
    const transporter = nodemailer.createTransport({
      streamTransport: true
    });
    const { port } = t.context.forwardEmail.server.address();
    const connection = new Client({ port, tls });
    const info = await transporter.sendMail({
      from: 'from@forwardemail.net',
      to: [
        'test@niftylettuce.com',
        'admin@niftylettuce.com',
        'hello@niftylettuce.com',
        'hello+test@niftylettuce.com',
        'test+hello@niftylettuce.com'
      ],
      subject: 'forwards an email without recursive loop',
      text: 'test text',
      html: '<strong>test html</strong>',
      attachments: [],
      dkim: t.context.forwardEmail.config.dkim
    });
    return new Promise((resolve) => {
      connection.once('end', resolve);
      connection.connect(() => {
        connection.send(info.envelope, info.message, (err) => {
          t.is(err, null);
          connection.close();
        });
      });
    });
  });

if (!isCI)
  test('rejects sending to one invalid recipient', async (t) => {
    const transporter = nodemailer.createTransport({
      streamTransport: true
    });
    const { port } = t.context.forwardEmail.server.address();
    const connection = new Client({ port, tls });
    const info = await transporter.sendMail({
      from: 'ForwardEmail <from@forwardemail.net>',
      to: 'Niftylettuce <admin@niftylettuce.com>, oops@localhost',
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>',
      attachments: [],
      dkim: t.context.forwardEmail.config.dkim
    });
    return new Promise((resolve) => {
      connection.once('end', resolve);
      connection.connect(() => {
        connection.send(info.envelope, info.message, (err, response) => {
          t.is(err, null);
          t.is(response.accepted.length, 1);
          t.is(response.rejected.length, 1);
          connection.close();
        });
      });
    });
  });

if (!isCI)
  test('forwards an email with DKIM and SPF to domain aliased recipients', async (t) => {
    const transporter = nodemailer.createTransport({
      streamTransport: true
    });
    const { port } = t.context.forwardEmail.server.address();
    const connection = new Client({ port, tls });
    const info = await transporter.sendMail({
      from: 'ForwardEmail <from@forwardemail.net>',
      // a@cabinjs.com -> a@lipo.io -> niftylettuce+a@gmail.com
      to: 'Alias <a@cabinjs.com>',
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>',
      attachments: [],
      dkim: t.context.forwardEmail.config.dkim
    });
    /*
    t.deepEqual(info.envelope, ['niftylettuce@gmail.com']);
    */
    return new Promise((resolve) => {
      connection.once('end', resolve);
      connection.connect(() => {
        connection.send(info.envelope, info.message, (err) => {
          t.is(err, null);
          connection.close();
        });
      });
    });
  });

if (!isCI)
  test('forwards an email with DKIM and SPF to global recipients', async (t) => {
    const transporter = nodemailer.createTransport({
      streamTransport: true
    });
    const { port } = t.context.forwardEmail.server.address();
    const connection = new Client({ port, tls });
    const info = await transporter.sendMail({
      from: 'ForwardEmail <from@forwardemail.net>',
      to: 'Niftylettuce <admin@niftylettuce.com>',
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>',
      attachments: [],
      dkim: t.context.forwardEmail.config.dkim
    });
    /*
    t.deepEqual(info.envelope, ['niftylettuce@gmail.com']);
    */
    return new Promise((resolve) => {
      connection.once('end', resolve);
      connection.connect(() => {
        connection.send(info.envelope, info.message, (err) => {
          t.is(err, null);
          connection.close();
        });
      });
    });
  });

if (!isCI)
  test('forwards an email with DKIM and SPF to multiple recipients', async (t) => {
    const transporter = nodemailer.createTransport({
      streamTransport: true
    });
    const { port } = t.context.forwardEmail.server.address();
    const connection = new Client({ port, tls });
    const info = await transporter.sendMail({
      from: 'niftylettuce@gmail.com',
      to: 'test@lad.sh',
      cc: 'cc@niftylettuce.com',
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>'
    });
    /*
    t.deepEqual(info.envelope, [
      'nicholasbaugh@gmail.com',
      'niftylettuce+a@gmail.com',
      'niftylettuce+b@gmail.com',
      'niftylettuce@gmail.com'
    ]);
    */
    return new Promise((resolve) => {
      connection.once('end', resolve);
      connection.connect(() => {
        connection.send(info.envelope, info.message, (err) => {
          t.is(err, null);
          connection.close();
        });
      });
    });
  });

if (!isCI)
  test('forwards an email with DKIM and SPF and a comma in the FROM', async (t) => {
    const transporter = nodemailer.createTransport({
      streamTransport: true
    });
    const { port } = t.context.forwardEmail.server.address();
    const connection = new Client({ port, tls });
    const info = await transporter.sendMail({
      from: '"Doe, John" <john.doe@lipo.io>',
      to: 'Niftylettuce <hello@niftylettuce.com>',
      cc: 'cc@niftylettuce.com',
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>',
      attachments: [],
      dkim: t.context.forwardEmail.config.dkim
    });
    return new Promise((resolve) => {
      connection.once('end', resolve);
      connection.connect(() => {
        connection.send(info.envelope, info.message, (err) => {
          t.is(err, null);
          connection.close();
        });
      });
    });
  });

test('rejects a spam file', async (t) => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });

  const info = await transporter.sendMail({
    from: 'foo@forwardemail.net',
    to: 'Baz <baz@forwardemail.net>',
    // taken from:
    // <https://github.com/humantech/node-spamd/blob/master/test/spamd-tests.js#L13-L14>
    subject: 'Viagra, Cialis, Vicodin: buy medicines without prescription!',
    html: 'Cheap prices on viagra, cialis, vicodin! FPA approved!',
    dkim: t.context.forwardEmail.config.dkim
  });
  return new Promise((resolve) => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, (err) => {
        t.regex(err.message, /Message detected as spam/);
        t.is(err.responseCode, 554);
        connection.close();
      });
    });
  });
});

test('creates 100 simultaneous connections (w/o rate limiting)', async (t) => {
  const forwardEmail = new ForwardEmail({ limiter: false });
  const port = await getPort();
  forwardEmail.server.listen(port);
  await Promise.all(
    _.range(100).map(async () => {
      const connection = new Client({ port, tls });
      const transporter = nodemailer.createTransport({
        streamTransport: true
      });
      const info = await transporter.sendMail({
        from: 'foo@forwardemail.net',
        to: 'Baz <no-reply@forwardemail.net>',
        subject: 'test',
        text: 'test text',
        html: '<strong>test text</strong>'
      });
      return new Promise((resolve, reject) => {
        connection.once('error', reject);
        connection.once('end', resolve);
        connection.connect(() => {
          connection.send(info.envelope, info.message, (err) => {
            t.regex(err.message, /You need to reply/);
            t.is(err.responseCode, 550);
            connection.close();
          });
        });
      });
    })
  );
  t.pass();
});

test('rejects a file over the limit', async (t) => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const filePath = path.join(os.tmpdir(), v4());
  const size = t.context.forwardEmail.config.smtp.size + 1;
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });
  const fh = fs.openSync(filePath, 'w');
  fs.writeSync(fh, 'ok', size);
  const info = await transporter.sendMail({
    from: 'foo@forwardemail.net',
    to: 'Baz <baz@forwardemail.net>',
    subject: 'test',
    text: 'test text',
    html: '<strong>test text</strong>',
    attachments: [{ path: filePath }]
  });
  return new Promise((resolve) => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, (err) => {
        t.regex(
          err.message,
          new RegExp(
            `Maximum allowed message size ${bytes(
              t.context.forwardEmail.config.smtp.size
            )} exceeded`,
            'g'
          )
        );
        t.is(err.responseCode, 552);
        fs.unlinkSync(filePath);
        connection.close();
      });
    });
  });
});

if (!isCI)
  test('rejects and accepts at same time', async (t) => {
    const transporter = nodemailer.createTransport({
      streamTransport: true
    });
    const { port } = t.context.forwardEmail.server.address();
    const connection = new Client({ port, tls });
    const info = await transporter.sendMail({
      from: 'foo@forwardemail.net',
      to: 'Niftylettuce <hello@niftylettuce.com>, no-reply@forwardemail.net',
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>',
      dkim: t.context.forwardEmail.config.dkim
    });
    return new Promise((resolve) => {
      connection.once('end', resolve);
      connection.connect(() => {
        connection.send(info.envelope, info.message, (err) => {
          // TODO: t.regex(err.message, /someregex/)
          t.is(err.responseCode, 550);
          connection.close();
        });
      });
    });
  });

test('requires at least one valid email in To header if it was set', async (t) => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });
  const info = await transporter.sendMail({
    envelope: {
      from: 'foo@spamchecker.net',
      to: 'baz@spamchecker.net'
    },
    raw: `
Message-ID: <123.abc@test>
Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
From: foo@spamchecker.net
To:
Subject: requires at least one valid email in To header if it was set
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`.trim()
  });
  return new Promise((resolve) => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, (err) => {
        t.regex(err.message, /please include at least one/);
        t.is(err.responseCode, 550);
        connection.close();
      });
    });
  });
});

test('allows empty Bcc header', async (t) => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });
  const info = await transporter.sendMail({
    envelope: {
      from: 'foo@spamchecker.net',
      to: 'baz@spamchecker.net'
    },
    raw: `
Message-ID: <123.abc@test>
Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
From: foo@spamchecker.net
Bcc:
Subject: allows empty Bcc header
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`.trim()
  });
  return new Promise((resolve) => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, (err) => {
        t.is(err, null);
        connection.close();
      });
    });
  });
});

test('to parsing should not throw error', async (t) => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });
  const info = await transporter.sendMail({
    envelope: {
      from: 'test@niftylettuce.com',
      to: 'notthrow@forwardemail.net'
    },
    raw: `
Message-ID: <123.abc@test>
Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
From: Test <test@niftylettuce.com>
To: undisclosed-recipients:;
Cc:
Bcc: bcc@niftylettuce.com
Date: Sun, 17 May 2020 18:21:15 -0500
Subject: testing parser
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`.trim()
  });
  return new Promise((resolve) => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, (err) => {
        t.is(err, null);
        connection.close();
      });
    });
  });
});

test('nobody', async (t) => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });
  const info = await transporter.sendMail({
    envelope: {
      from: 'test@niftylettuce.com',
      to: 'nobody@forwardemail.net'
    },
    raw: `
Message-ID: <123.abc@test>
Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
To: nobody@forwardemail.net
From: Test <test@niftylettuce.com>
Subject: testing custom port forwarding
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`.trim()
  });
  return new Promise((resolve) => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, (err) => {
        t.is(err, null);
        connection.close();
      });
    });
  });
});

test('webhooks', async (t) => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });
  const info = await transporter.sendMail({
    envelope: {
      from: 'test@niftylettuce.com',
      to: 'webhook@spamapi.net'
    },
    raw: `
Message-ID: <123.abc@test>
Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
To: webhook@spamapi.net
From: Test <test@niftylettuce.com>
Subject: testing webhooks
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`.trim()
  });
  return new Promise((resolve) => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, (err) => {
        t.is(err, null);
        connection.close();
      });
    });
  });
});

test('port forwarding', async (t) => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });
  const info = await transporter.sendMail({
    envelope: {
      from: 'test@niftylettuce.com',
      to: ['test@spamapi.net', 'john@spamapi.net']
    },
    raw: `
Message-ID: <123.abc@test>
Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
To: test@spamapi.net
From: Test <test@niftylettuce.com>
Subject: testing custom port forwarding
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`.trim()
  });
  return new Promise((resolve) => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, (err) => {
        t.is(err, null);
        connection.close();
      });
    });
  });
});

test('tests SRS auto-reply', async (t) => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });
  const info = await transporter.sendMail({
    envelope: {
      from: 'foo@wakeup.io',
      to: [
        t.context.forwardEmail.srs.forward(
          'nicholasbaugh@gmail.com',
          t.context.forwardEmail.config.srsDomain
        ),
        'srs@spamchecker.net'
      ]
    },
    raw: `
Message-ID: <123.abc@test>
Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
To: nicholasbaugh@gmail.com
From: startupsupper@gmail.com
Subject: tests SRS auto-reply
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`.trim()
  });
  return new Promise((resolve) => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, (err) => {
        t.is(err, null);
        connection.close();
      });
    });
  });
});

test('tests verification record', async (t) => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });
  const info = await transporter.sendMail({
    from: 'foo@forwardemail.net',
    to: 'test@spamchecker.net',
    subject: 'test',
    text: 'test text',
    html: '<strong>test html</strong>'
  });
  return new Promise((resolve) => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, (err) => {
        // TODO: t.regex(err.message, /someregex/)
        t.is(err.responseCode, 550);
        connection.close();
      });
    });
  });
});

test('rejects an email to no-reply@forwardemail.net', async (t) => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });
  const info = await transporter.sendMail({
    from: 'foo@forwardemail.net',
    to: 'Niftylettuce <no-reply@forwardemail.net>',
    subject: 'test',
    text: 'test text',
    html: '<strong>test html</strong>'
  });
  return new Promise((resolve) => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, (err) => {
        t.regex(
          err.message,
          /You need to reply to the "Reply-To" email address on the email; do not send messages to <no-reply@forwardemail.net>/
        );
        t.is(err.responseCode, 550);
        connection.close();
      });
    });
  });
});

test('ForwardEmail is not in DNS blacklists', async (t) => {
  const ips = await Promise.all([
    lookupAsync('forwardemail.net'),
    lookupAsync('mx1.forwardemail.net'),
    lookupAsync('mx2.forwardemail.net')
  ]);
  const [domain, mx1, mx2] = await Promise.all(
    ips.map((ip) => t.context.forwardEmail.checkBlacklists(ip.address))
  );
  t.is(domain, false);
  t.is(mx1, false);
  t.is(mx2, false);
});

if (!isCI)
  test('disabled emails are delivered to blackhole', async (t) => {
    const transporter = nodemailer.createTransport({
      streamTransport: true
    });
    const { port } = t.context.forwardEmail.server.address();
    const connection = new Client({ port, tls });
    const info = await transporter.sendMail({
      from: 'test@spamchecker.net',
      to: 'disabled@niftylettuce.com',
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>'
    });
    return new Promise((resolve) => {
      connection.once('end', resolve);
      connection.connect(() => {
        connection.send(info.envelope, info.message, (err) => {
          t.is(err, null);
          connection.close();
        });
      });
    });
  });

//
// NOTE: redis could test this by sending same message twice
// and then checking redis.get key/hash value if it was set in between
//
test('greylisting with redis', async (t) => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });

  const { port } = t.context.forwardEmail.server.address();

  const connection = new Client({ port, tls });

  const envelope = {
    from: 'test@spamapi.net',
    to: 'test@forwardemail.net'
  };

  const raw = `
Message-ID: <123.abc@test>
Date: ${new Date().toString()}
To: nobody@forwardemail.net
From: Test <test@niftylettuce.com>
Subject: testing custom port forwarding
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`.trim();

  const connect = pify(connection.connect).bind(connection);
  const send = pify(connection.send).bind(connection);
  const key = t.context.forwardEmail.getSentKey('niftylettuce@gmail.com', raw);

  const info = await transporter.sendMail({
    envelope,
    raw
  });

  let value = await t.context.forwardEmail.client.get(key);

  t.is(value, null);

  await connect();

  await send(info.envelope, info.message);

  // note the envelope.to hash is for niftylettuce@gmail.com
  // since that is where it actually forwards to (that's where test@niftylettuce.com goes to)
  value = await t.context.forwardEmail.client.get(key);

  t.is(value, '1');
});

/*
test.todo('rejects invalid DKIM signature');
test.todo('accepts valid DKIM signature');
test.todo('rejects invalid SPF');
test.todo('accepts valid SPF');
test.todo('supports + symbol aliased onRcptTo');
test.todo('preserves charset');
test.tood('graceful shutdown');

if (!isCI)
  test('prevents spam through rate limiting', async t => {
    const transporter = nodemailer.createTransport({
      streamTransport: true
    });
    const { port } = t.context.forwardEmail.server.address();

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
              dkim: t.context.forwardEmail.config.dkim
            });
            const connection = new Client({  port, tls });
            connection.once('end', resolve);
            connection.connect(() => {
              connection.send(info.envelope, info.message, err => {
                if (err && err.responseCode === 451) failed++;
                connection.close();
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

//
// these tests are sourced from Spam Scanner
//

//
// TODO: re-enable these three tests once classifier is fixed
//
/*
test('should detect spam', async (t) => {
  const scan = await scanner.scan(fixtures('spam.eml'));
  t.true(scan.is_spam);
  t.true(typeof scan.results.classification === 'object');
  t.is(scan.results.classification.category, 'spam');
});

test('should detect spam fuzzy', async (t) => {
  const scan = await scanner.scan(fixtures('spam-fuzzy.eml'));
  t.true(scan.is_spam);
  t.true(typeof scan.results.classification === 'object');
  t.is(scan.results.classification.category, 'spam');
});

test('should detect ham', async (t) => {
  const scan = await scanner.scan(fixtures('ham.eml'));
  t.false(scan.is_spam);
  t.true(typeof scan.results.classification === 'object');
  t.is(scan.results.classification.category, 'ham');
});
*/

test('should detect not phishing with different org domains (temporary)', async (t) => {
  const scan = await t.context.forwardEmail.scanner.scan(
    path.join(__dirname, 'fixtures', 'phishing.eml')
  );
  t.false(scan.is_spam);
  t.true(scan.results.phishing.length === 0);
});

test('should detect idn masquerading', async (t) => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });

  const raw = await fs.promises.readFile(
    path.join(__dirname, 'fixtures', 'idn.eml')
  );
  const info = await transporter.sendMail({
    envelope: {
      to: 'beep@lad.sh',
      from: 'niftylettuce@gmail.com'
    },
    raw
  });
  return new Promise((resolve) => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, (err) => {
        t.regex(err.message, /Possible IDN homograph attack/);
        t.is(err.responseCode, 554);
        connection.close();
      });
    });
  });
});

test('should detect executable files', async (t) => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });

  const raw = await fs.promises.readFile(
    path.join(__dirname, 'fixtures', 'executable.eml')
  );
  const info = await transporter.sendMail({
    envelope: {
      to: 'foo@example.com',
      from: 'beep@niftylettuce.com'
    },
    raw
  });
  return new Promise((resolve) => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, (err) => {
        t.regex(
          err.message,
          /file name indicated it was a dangerous executable/
        );
        t.is(err.responseCode, 554);
        connection.close();
      });
    });
  });
});

test('should check against Cloudflare', async (t) => {
  const link = Buffer.from('eHZpZGVvcy5jb20=', 'base64').toString();
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });

  const info = await transporter.sendMail({
    html: `<a href="${link}">test</a>`,
    text: link,
    from: 'foo@bar.com',
    envelope: {
      to: 'foo@example.com',
      from: 'beep@niftylettuce.com'
    }
  });
  return new Promise((resolve) => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, (err) => {
        t.regex(
          err.message,
          new RegExp(
            `Link hostname of "${link}" was detected by Cloudflare to contain malware, phishing, and/or adult content.`
          )
        );
        t.is(err.responseCode, 554);
        connection.close();
      });
    });
  });
});

test('GTUBE test', async (t) => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });
  const info = await transporter.sendMail({
    raw: `
Subject: Test spam mail (GTUBE)
Message-ID: <GTUBE1.1010101@example.net>
Date: Wed, 23 Jul 2003 23:30:00 +0200
From: Sender <sender@example.net>
To: Recipient <recipient@example.net>
Precedence: junk
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

This is the GTUBE, the
  Generic
  Test for
  Unsolicited
  Bulk
  Email

If your spam filter supports it, the GTUBE provides a test by which you
can verify that the filter is installed correctly and is detecting incoming
spam. You can send yourself a test mail containing the following string of
characters (in upper case and with no white spaces and line breaks):

XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X

You should send this test mail from an account outside of your network.
    `.trim(),
    envelope: {
      to: 'foo@example.com',
      from: 'beep@niftylettuce.com'
    }
  });
  return new Promise((resolve) => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, (err) => {
        t.regex(
          err.message,
          /Message detected to contain the GTUBE test from <https:\/\/spamassassin.apache.org\/gtube\/>/
        );
        t.is(err.responseCode, 554);
        connection.close();
      });
    });
  });
});

test('EICAR test', async (t) => {
  const transporter = nodemailer.createTransport({
    streamTransport: true
  });
  const { port } = t.context.forwardEmail.server.address();
  const connection = new Client({ port, tls });

  const info = await transporter.sendMail({
    html: 'test',
    text: 'test',
    attachments: [{ path: path.join(__dirname, 'fixtures', 'eicar.com.txt') }],
    from: 'foo@bar.com',
    envelope: {
      to: 'foo@lad.sh',
      from: 'beep@niftylettuce.com'
    }
  });
  return new Promise((resolve) => {
    connection.once('end', resolve);
    connection.connect(() => {
      connection.send(info.envelope, info.message, (err) => {
        t.true(
          err.message.includes(
            'Attachment "eicar.com.txt" was infected with "Eicar-Test-Signature".'
          ) ||
            err.message.includes(
              'Attachment "eicar.com.txt" was infected with "Win.Test.EICAR_HDB-1".'
            )
        );
        t.is(err.responseCode, 554);
        connection.close();
      });
    });
  });
});
