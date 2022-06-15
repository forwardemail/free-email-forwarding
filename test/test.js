const dns = require('dns');
const fs = require('fs');
const os = require('os');
const path = require('path');
const process = require('process');
const { Buffer } = require('buffer');

const Client = require('nodemailer/lib/smtp-connection');
const Koa = require('koa');
const Redis = require('ioredis-mock');
const bodyParser = require('koa-bodyparser');
const bytes = require('bytes');
const getPort = require('get-port');
const ip = require('ip');
const ms = require('ms');
const mxConnect = require('mx-connect');
const nodemailer = require('nodemailer');
const pify = require('pify');
const randomString = require('randomstring');
const revHash = require('rev-hash');
const safeStringify = require('fast-safe-stringify');
const test = require('ava');
const { Headers } = require('mailsplit');
const { SRS } = require('sender-rewriting-scheme');
const { stripIndents } = require('common-tags');
const { v4 } = require('uuid');

const { env } = require('../helpers');
const ForwardEmail = require('..');

const IP_ADDRESS = ip.address();
const asyncMxConnect = pify(mxConnect);
const tls = { rejectUnauthorized: false };

//
// TODO: all tests that simply `await` sendMail should check `info` object
//       to ensure accepted, rejected, and rejectedErrors are what they need to be
//
// TODO: we should rewrite all the recipients TO below so that they are accurate
//       (e.g. the blackhole one is not configured against something !is_enabled for alias
//

test.beforeEach(async (t) => {
  const port = await getPort();
  t.context.client = new Redis({
    maxRetriesPerRequest: 1,
    maxLoadingRetryTime: ms('5s')
  });
  t.context.fe = new ForwardEmail({
    redis: t.context.client,
    port,
    rateLimit: false,
    greylistTimeout: false
  });
  const keys = await t.context.client.keys('ratelimit:*');
  if (keys.length > 0)
    await Promise.all(keys.map((key) => t.context.client.del(key)));
  await t.context.fe.listen();
  const address = t.context.fe.server.address();
  const mx = await asyncMxConnect({
    target: IP_ADDRESS,
    port: address.port
  });
  t.context.transporter = nodemailer.createTransport({
    logger: t.context.fe.config.logger,
    debug: true,
    direct: true,
    host: mx.host,
    port: mx.port,
    connection: mx.socket,
    ignoreTLS: true,
    secure: false,
    tls: {
      rejectUnauthorized: false
    }
  });
});

test.afterEach(async (t) => {
  t.context.transporter.close();
  await t.context.fe.close();
});

test.afterEach.always(async (t) => {
  await t.context.client.flushall();
});

if (process.env.BENCHMARK === 'true') {
  const dkim = {
    domainName: env.DKIM_DOMAIN_NAME,
    keySelector: env.DKIM_KEY_SELECTOR,
    privateKey: env.DKIM_PRIVATE_KEY_PATH
      ? fs.readFileSync(env.DKIM_PRIVATE_KEY_PATH, 'utf8')
      : undefined
  };
  for (let i = 0; i < 100; i++) {
    test(`benchmark #${i + 1}`, async (t) => {
      await t.context.transporter.sendMail({
        from: 'foo@forwardemail.net',
        to: 'Baz <disabled@niftylettuce.com>',
        subject: 'test',
        text: 'test text',
        html: randomString.generate(Math.round(Math.random() * 100)),
        dkim
      });
    });
  }
}

test('returns itself', (t) => {
  t.true(new ForwardEmail() instanceof ForwardEmail);
});

test('binds context', (t) => {
  t.true(t.context.fe instanceof ForwardEmail);
});

test('rejects auth connections', async (t) => {
  const { port } = t.context.fe.server.address();
  const connection = new Client({ port, tls });
  await new Promise((resolve) => {
    connection.connect(() => {
      connection.login({ user: 'user', pass: 'pass' }, (err) => {
        t.regex(err.message, /command not recognized/);
        t.is(err.responseCode, 500);
        connection.close();
      });
    });
    connection.once('end', () => resolve());
  });
});

test('verifies connection', async (t) => {
  await t.context.transporter.verify();
  t.pass();
});

test('rejects forwarding to local address', async (t) => {
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      envelope: {
        from: '',
        to: 'foo@127.0.0.1'
      },
      raw: `
  Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
  From: foo@forwardmail.net
  Bcc:
  Subject: local address
  Mime-Version: 1.0
  Content-Type: text/plain; charset=us-ascii
  Content-Transfer-Encoding: 7bit

  Test`
    })
  );
  t.regex(err.message, /is not a valid RFC 5322 email address/);
  t.is(err.responseCode, 553);
});

test('rejects forwarding to localhost', async (t) => {
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      envelope: {
        from: '',
        to: 'foo@localhost'
      },
      raw: `
  Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
  From: foo@forwardmail.net
  Bcc:
  Subject: local address
  Mime-Version: 1.0
  Content-Type: text/plain; charset=us-ascii
  Content-Transfer-Encoding: 7bit

  Test`
    })
  );
  t.regex(err.message, /is not a valid RFC 5322 email address/);
  t.is(err.responseCode, 553);
});

test('rejects forwarding a non-registered email address', async (t) => {
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      from: 'from@forwardemail.net',
      to: 'Niftylettuce <fail@test.niftylettuce.com>', // "pass" works
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>',
      attachments: [],
      dkim: t.context.fe.config.dkim
    })
  );
  t.regex(err.message, /Invalid recipients/);
  t.is(err.responseCode, 421);
});

test('socket timeout', async (t) => {
  const port = await getPort();
  const fe = new ForwardEmail({
    redis: t.context.client,
    port,
    rateLimit: false,
    greylistTimeout: false,
    smtp: {
      socketTimeout: ms('10ms')
    }
  });
  await fe.listen();
  const address = fe.server.address();
  const mx = await asyncMxConnect({
    target: IP_ADDRESS,
    port: address.port
  });
  const transporter = nodemailer.createTransport({
    logger: fe.config.logger,
    debug: true,
    direct: true,
    host: mx.host,
    port: mx.port,
    connection: mx.socket,
    ignoreTLS: true,
    secure: false,
    tls: {
      rejectUnauthorized: false
    }
  });
  const mail = {
    envelope: {
      from: '',
      to: 'foo@forwardmail.net'
    },
    raw: `
Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
From: foo@forwardmail.net
Bcc:
Subject: recipient overflow
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`
  };
  const err = await t.throwsAsync(transporter.sendMail(mail));
  t.regex(err.message, /Timeout - closing connection/);
  t.is(err.responseCode, 421);
});

// <https://github.com/nodemailer/smtp-server/issues/179>
test('recipient overflow', async (t) => {
  // fake dns cache here
  const emails = Array.from({
    length: t.context.fe.config.maxRecipients + 1
  }).map((e, i) => `${i}@test-${i}.com`);
  const obj = {};
  for (let i = 0; i < emails.length; i++) {
    obj[`dns:txt:test-${i}.com`] = safeStringify([
      [`forward-email=${i}:${i}@gmail.com`]
    ]);
    obj[`dns:mx:test-${i}.com`] = safeStringify([
      { exchange: 'mx1.forwardemail.net', priority: 10 },
      { exchange: 'mx2.forwardemail.net', priority: 10 }
    ]);
  }

  await t.context.client.mset(obj);

  const info = await t.context.transporter.sendMail({
    envelope: {
      from: 'from@forwardmail.net',
      to: emails
    },
    raw: `
Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
From: foo@forwardmail.net
Bcc:
Subject: recipient overflow
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`
  });
  t.deepEqual(info.accepted, emails.slice(0, -1));
  t.deepEqual(info.rejected, emails.slice(-1));
  t.true(info.rejectedErrors.length === 1);
  t.regex(info.rejectedErrors[0].message, /Too many recipients/);
  t.is(info.rejectedErrors[0].responseCode, 452);
});

test('spf hard fail', async (t) => {
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      envelope: {
        from: 'foo@forwardemail.net',
        to: 'baz@spamchecker.net'
      },
      raw: stripIndents`
Message-ID: <123.${Date.now()}@test>
Date: ${new Date().toISOString()}
From: foo@spamchecker.net
To:
Subject: requires at least one valid email in To header if it was set
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Test`
    })
  );
  t.regex(
    err.message,
    /The email sent has failed SPF validation and is rejected due to the domain's SPF hard fail policy/
  );
  t.is(err.responseCode, 550);
});

test('rejects an email with failing DMARC', async (t) => {
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      from: 'ForwardEmail <from@forwardemail.net>',
      to: 'Niftylettuce <hello@niftylettuce.com>',
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>',
      attachments: []
    })
  );
  t.regex(
    err.message,
    /The email sent has failed DMARC validation and is rejected/
  );
  t.is(err.responseCode, 550);
});

test('forwards an email with DKIM and without SPF (passes DMARC)', async (t) => {
  const info = await t.context.transporter.sendMail({
    from: 'Example <from@forwardemail.net>',
    to: 'Niftylettuce <hello@niftylettuce.com>',
    subject: 'forwards an email with DKIM and without SPF (passes DMARC)',
    text: 'test text',
    html: '<strong>test html</strong>',
    attachments: [],
    dkim: t.context.fe.config.dkim
  });
  t.deepEqual(info.accepted, ['hello@niftylettuce.com']);
});

test('forwards an email without DKIM nor SPF (no DMARC)', async (t) => {
  const info = await t.context.transporter.sendMail({
    // NOTE: this is forwardMAIL.net not forwardEMAIL.net (I have registered both)
    from: 'Example <from@forwardmail.net>',
    to: 'Niftylettuce <hello@niftylettuce.com>',
    subject: 'forwards an email without DKIM nor SPF (no DMARC)',
    text: 'test text',
    html: '<strong>test html</strong>',
    attachments: []
  });
  t.deepEqual(info.accepted, ['hello@niftylettuce.com']);
});

/*
test('rejects forwarding an email with max forwarding addresses exceeded', async (t) => {
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      from: 'ForwardEmail <from@forwardemail.net>',
      to: '1@niftylettuce.com',
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>',
      attachments: [],
      dkim: t.context.fe.config.dkim
    })
  );
  t.regex(err.message, /addresses which exceeds the maximum/);
  t.is(err.responseCode, 550);
});

test('rejects forwarding an email with recursive max forwarding addresses exceeded', async (t) => {
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      from: 'ForwardEmail <from@forwardemail.net>',
      to: '2@niftylettuce.com',
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>',
      attachments: [],
      dkim: t.context.fe.config.dkim
    })
  );
  t.regex(err.message, /addresses which exceeds the maximum/);
  t.is(err.responseCode, 550);
});

test('forwards an email with DKIM and SPF without recursive loop', async (t) => {
  const info = await t.context.transporter.sendMail({
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
    dkim: t.context.fe.config.dkim
  });
  t.deepEqual(info.accepted, [
    'test@niftylettuce.com',
    'admin@niftylettuce.com',
    'hello@niftylettuce.com',
    'hello+test@niftylettuce.com',
    'test+hello@niftylettuce.com'
  ]);
});
*/

test('rejects sending to one invalid recipient', async (t) => {
  const info = await t.context.transporter.sendMail({
    from: 'ForwardEmail <from@forwardemail.net>',
    to: 'Niftylettuce <admin@niftylettuce.com>, oops@localhost',
    subject: 'test',
    text: 'test text',
    html: '<strong>test html</strong>',
    attachments: [],
    dkim: t.context.fe.config.dkim
  });
  t.deepEqual(info.accepted, ['admin@niftylettuce.com']);
  t.deepEqual(info.rejected, ['oops@localhost']);
  t.regex(
    info.rejectedErrors[0].message,
    /The recipient address of oops@localhost is not a valid RFC 5322 email address/
  );
  t.is(info.rejectedErrors[0].responseCode, 553);
});

test('forwards an email with DKIM and SPF to domain aliased recipients', async (t) => {
  const info = await t.context.transporter.sendMail({
    from: 'ForwardEmail <from@forwardemail.net>',
    // a@cabinjs.com -> a@lipo.io -> niftylettuce+a@gmail.com
    to: 'Alias <a@cabinjs.com>',
    subject: 'test',
    text: 'test text',
    html: '<strong>test html</strong>',
    attachments: [],
    dkim: t.context.fe.config.dkim
  });
  t.deepEqual(info.accepted, ['a@cabinjs.com']);
});

test('forwards an email with DKIM and SPF to global recipients', async (t) => {
  const info = await t.context.transporter.sendMail({
    from: 'ForwardEmail <from@forwardemail.net>',
    to: 'Niftylettuce <admin@niftylettuce.com>',
    subject: 'test',
    text: 'test text',
    html: '<strong>test html</strong>',
    attachments: [],
    dkim: t.context.fe.config.dkim
  });
  t.deepEqual(info.accepted, ['admin@niftylettuce.com']);
});

test('forwards an email with DKIM and SPF to multiple recipients', async (t) => {
  const info = await t.context.transporter.sendMail({
    from: 'niftylettuce@gmail.com',
    to: 'test@lad.sh',
    cc: 'cc@niftylettuce.com',
    subject: 'test',
    text: 'test text',
    html: '<strong>test html</strong>'
  });
  t.deepEqual(info.accepted, ['test@lad.sh', 'cc@niftylettuce.com']);
});

test('forwards an email with DKIM and SPF and a comma in the FROM', async (t) => {
  const info = await t.context.transporter.sendMail({
    from: '"Doe, John" <john.doe@lipo.io>',
    to: 'Niftylettuce <hello@niftylettuce.com>',
    cc: 'cc@niftylettuce.com',
    subject: 'test',
    text: 'test text',
    html: '<strong>test html</strong>',
    attachments: [],
    dkim: t.context.fe.config.dkim
  });
  t.deepEqual(info.accepted, ['hello@niftylettuce.com', 'cc@niftylettuce.com']);
});

/*
test('rejects a spam file', async (t) => {
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      from: 'foo@forwardemail.net',
      to: 'Baz <baz@forwardemail.net>',
      // taken from:
      // <https://github.com/humantech/node-spamd/blob/master/test/spamd-tests.js#L13-L14>
      subject: 'Viagra, Cialis, Vicodin: buy medicines without prescription!',
      html: 'Cheap prices on viagra, cialis, vicodin! FPA approved!',
      dkim: t.context.fe.config.dkim
    })
  );
  t.regex(err.message, /Message detected as spam/);
  t.is(err.responseCode, 554);
});
*/

test('attempts to overload and run out of memory', async (t) => {
  const messages = [];
  for (let i = 0; i < 50; i++) {
    messages.push(randomString.generate(Math.round(Math.random() * 100)));
  }

  async function mapper(text) {
    const address = t.context.fe.server.address();
    const mx = await asyncMxConnect({
      target: IP_ADDRESS,
      port: address.port
    });
    const transporter = nodemailer.createTransport({
      logger: t.context.fe.config.logger,
      debug: true,
      direct: true,
      host: mx.host,
      port: mx.port,
      connection: mx.socket,
      ignoreTLS: true,
      secure: false,
      tls: {
        rejectUnauthorized: false
      }
    });
    const err = await t.throwsAsync(
      transporter.sendMail({
        envelope: {
          from: 'test@test.com',
          to: ['no-reply@forwardemail.net']
        },
        from: 'foo@forwardemail.net',
        to: 'Baz <no-reply@forwardemail.net>',
        subject: 'test',
        text
      })
    );
    t.regex(err.message, /You need to reply to the "Reply-To"/);
    t.is(err.responseCode, 553);
  }

  for (const message of messages) {
    // eslint-disable-next-line no-await-in-loop
    await mapper(message);
  }
});

test('rejects a file over the limit', async (t) => {
  const filePath = path.join(os.tmpdir(), v4());
  const size = t.context.fe.config.smtp.size + 1;
  const fh = await fs.promises.open(filePath, 'w');
  await fh.write('ok', size);
  await fh.close();
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      from: 'foo@forwardemail.net',
      to: 'Baz <baz@forwardemail.net>',
      subject: 'test',
      text: 'test text',
      html: '<strong>test text</strong>',
      attachments: [{ path: filePath }]
    })
  );
  await fs.promises.unlink(filePath);
  t.regex(
    err.message,
    new RegExp(
      `Maximum allowed message size ${bytes(
        t.context.fe.config.smtp.size
      )} exceeded`,
      'g'
    )
  );
  t.is(err.responseCode, 552);
});

test('rejects everyone in envelope as no-reply', async (t) => {
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      from: 'foo@forwardemail.net',
      to: 'no-reply@forwardemail.net, no-reply@forwardemail.net, no-reply@forwardemail.net',
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>',
      dkim: t.context.fe.config.dkim
    })
  );
  t.is(err.responseCode, 553);
  t.regex(err.message, /You need to reply to the "Reply-To"/);
});

test('rejects invalid SRS in RCPT TO envelope', async (t) => {
  const srs = new SRS({
    separator: '=',
    secret: 'faketest',
    maxAge: 30
  });
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      from: 'foo@forwardemail.net',
      to: srs.forward('fake@srs.com', t.context.fe.config.srsDomain),
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>',
      dkim: t.context.fe.config.dkim
    })
  );
  t.is(err.responseCode, 553);
  t.regex(err.message, /Invalid SRS address/);
});

test('rejects and accepts at same time', async (t) => {
  const info = await t.context.transporter.sendMail({
    from: 'foo@forwardemail.net',
    to: 'Niftylettuce <hello@niftylettuce.com>, no-reply@forwardemail.net',
    subject: 'test',
    text: 'test text',
    html: '<strong>test html</strong>',
    dkim: t.context.fe.config.dkim
  });
  t.deepEqual(info.accepted, ['hello@niftylettuce.com']);
  t.deepEqual(info.rejected, ['no-reply@forwardemail.net']);
  t.regex(
    info.rejectedErrors[0].message,
    /You need to reply to the "Reply-To"/
  );
  t.is(info.rejectedErrors[0].responseCode, 553);
  // wait a few seconds for bounce to go out
  await new Promise((resolve) => {
    setTimeout(resolve, 500);
  });
});

test('allows empty Bcc header', async (t) => {
  const info = await t.context.transporter.sendMail({
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

Test`
  });
  t.deepEqual(info.accepted, ['baz@spamchecker.net']);
});

test('to parsing should not throw error', async (t) => {
  const info = await t.context.transporter.sendMail({
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

Test`
  });
  t.deepEqual(info.accepted, ['notthrow@forwardemail.net']);
});

test('nobody', async (t) => {
  const info = await t.context.transporter.sendMail({
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

Test`
  });
  t.deepEqual(info.accepted, ['nobody@forwardemail.net']);
});

test('regex with global flag', async (t) => {
  const info = await t.context.transporter.sendMail({
    envelope: {
      from: 'test@spamapi.net',
      to: 'match@spamapi.net'
    },
    raw: `
Message-ID: <123.abc@test>
Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
To: match@spamapi.net
From: test@spamapi.net
Subject: testing regex with global flag
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`
  });
  t.deepEqual(info.accepted, ['match@spamapi.net']);
});

test('regex with replacement', async (t) => {
  const info = await t.context.transporter.sendMail({
    envelope: {
      from: 'test@spamapi.net',
      to: 'support@spamapi.net'
    },
    raw: `
Message-ID: <123.abc@test>
Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
To: support@spamapi.net
From: test@spamapi.net
Subject: testing regex with global flag
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`
  });
  t.deepEqual(info.accepted, ['support@spamapi.net']);
});

test('webhooks', async (t) => {
  //
  // NOTE: in the future we should do complete dns mocking
  //
  const port = await getPort();
  const app = new Koa();
  app.use(bodyParser());
  app.use((ctx) => {
    // ctx.request.body.recipients
    if (ctx.request.body.recipients.includes('webhook4@webhooks.net')) {
      ctx.status = 408;
      ctx.body = 'Timeout';
      return;
    }

    // respond with an error for one and success for the other
    if (ctx.path === '/fail') {
      ctx.status = 500;
      ctx.body = 'Bad webhook';
    }

    ctx.body = ctx.request.body;
  });
  app.listen(port);

  // set dns cache for the bounce test
  await t.context.client.set(
    'dns:txt:foo.com',
    safeStringify([[`forward-email=foo:foo@gmail.com`]])
  );
  await t.context.client.set(
    'dns:mx:foo.com',
    safeStringify([
      { exchange: 'mx1.forwardemail.net', priority: 10 },
      { exchange: 'mx2.forwardemail.net', priority: 10 }
    ])
  );

  // set dns cache for the webhook test
  await t.context.client.set(
    'dns:txt:webhooks.net',
    safeStringify([
      [`forward-email=webhook1:http://${IP_ADDRESS}:${port}`], // grouped
      [`forward-email=webhook2:http://${IP_ADDRESS}:${port}`], // grouped
      [`forward-email=webhook3:HTTP://${IP_ADDRESS}:${port}`], // separate (due to case)
      [`forward-email=webhook4:http://${IP_ADDRESS}:${port}/timeout`], // separate (fail)
      [`forward-email=webhook5:http://${IP_ADDRESS}:${port}/fail`], // separate (fail)
      [`forward-email=webhook6:http://${IP_ADDRESS}:${port}/fail`] // separate (fail)
    ])
  );

  const address = t.context.fe.server.address();

  {
    const mx = await asyncMxConnect({
      target: IP_ADDRESS,
      port: address.port
    });

    const transporter = nodemailer.createTransport({
      logger: t.context.fe.config.logger,
      debug: true,
      direct: true,
      host: mx.host,
      port: mx.port,
      connection: mx.socket,
      ignoreTLS: true,
      secure: false,
      tls: {
        rejectUnauthorized: false
      }
    });

    const err = await t.throwsAsync(
      transporter.sendMail({
        envelope: {
          from: 'foo@foo.com',
          to: [
            'webhook1@webhooks.net',
            'webhook2@webhooks.net',
            'webhook3@webhooks.net',
            'webhook4@webhooks.net',
            'webhook5@webhooks.net',
            'some@randomemail.com',
            'some@undefined',
            'localhost',
            'some@localhost',
            t.context.fe.srs.forward('srs@undefined.com'),
            t.context.fe.srs.forward('srs@undefined'),
            t.context.fe.srs.forward(
              'some@niftylettuce.com',
              t.context.fe.config.srsDomain
            ),
            t.context.fe.srs.forward(
              'webhook6@webhooks.net',
              t.context.fe.config.srsDomain
            ),
            'match@spamapi.net'
          ]
        },
        html: '<strong>some random text</strong>',
        text: 'some random text',
        from: 'foo <foo@foo.com>',
        attachments: [
          {
            // utf-8 string as an attachment
            filename: 'text1.txt',
            content: 'hello world!'
          }
        ]
      })
    );
    t.regex(
      err.message,
      /Message was sent successfully to some@niftylettuce.com, webhook6@webhooks.net, match@spamapi.net, webhook1@webhooks.net, webhook2@webhooks.net, and webhook3@webhooks.net; some@randomemail.com is not configured to use https:\/\/forwardemail.net; 408 Request Timeout Error for webhook4@webhooks.net; 500 Internal Server Error for webhook5@webhooks.net; If you need help, forward this email to support@forwardemail.net or visit https:\/\/forwardemail.net. Please note we are an email service provider and most likely not your intended recipient./
    );

    // wait a few seconds for bounce to go out
    await new Promise((resolve) => {
      setTimeout(resolve, 500);
    });
  }
});

test('port forwarding', async (t) => {
  const info = await t.context.transporter.sendMail({
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

Test`
  });
  t.deepEqual(info.accepted, ['test@spamapi.net', 'john@spamapi.net']);
});

test('vacation auto-responder', async (t) => {
  await t.context.client.set(
    'dns:txt:foo.com',
    safeStringify([[`forward-email=foo:foo@gmail.com`]])
  );
  await t.context.client.set(
    'dns:txt:_dmarc.foo.com',
    safeStringify([[`v=DMARC1; p=reject; pct=100; rua=mailto:re+jtcoaomz3e7@dmarc.postmarkapp.com; sp=none; aspf=r;`]])
  );
  await t.context.client.set(
    'dns:mx:foo.com',
    safeStringify([
      { exchange: 'mx1.forwardemail.net', priority: 10 },
      { exchange: 'mx2.forwardemail.net', priority: 10 }
    ])
  );
  const info = await t.context.transporter.sendMail({
    envelope: {
      from: '',
      to: [
        t.context.fe.srs.forward('foo@foo.com', t.context.fe.config.srsDomain)
      ]
    },
    raw: `
Message-ID: <123.abc@test>
Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
To: foo@foo.com
From: foo@foo.com
Subject: tests SRS auto-reply
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`
  });
  t.deepEqual(info.accepted, [
    t.context.fe.srs.forward('foo@foo.com', t.context.fe.config.srsDomain)
  ]);
});

test('tests SRS auto-reply', async (t) => {
  const info = await t.context.transporter.sendMail({
    envelope: {
      from: 'foo@wakeup.io',
      to: [
        t.context.fe.srs.forward(
          'foobar@gmail.com',
          t.context.fe.config.srsDomain
        ),
        'srs@spamchecker.net'
      ]
    },
    raw: `
Message-ID: <123.abc@test>
Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
To: foobar@gmail.com
From: startupsupper@gmail.com
Subject: tests SRS auto-reply
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`
  });
  t.deepEqual(info.accepted, [
    t.context.fe.srs.forward('foobar@gmail.com', t.context.fe.config.srsDomain),
    'srs@spamchecker.net'
  ]);
});

test('tests verification record', async (t) => {
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      from: 'foo@spamchecker.net',
      to: 'test@example.com',
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>'
    })
  );
  t.is(err.responseCode, 421);
  t.regex(
    err.message,
    /Error for test@example.com of "test@example.com is not configured to use/
  );
});

test('rejects an email to no-reply@forwardemail.net', async (t) => {
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      from: 'foo@forwardemail.net',
      to: 'Niftylettuce <no-reply@forwardemail.net>',
      subject: 'test',
      text: 'test text',
      html: '<strong>test html</strong>'
    })
  );
  t.regex(err.message, /You need to reply to the "Reply-To"/);
  t.is(err.responseCode, 553);
});

// NOTE: we have schedule in our GitHub Action workflow to run the tests hourly
test('not in dnsbl', async (t) => {
  const ips = await Promise.all([
    dns.promises.lookup('forwardemail.net'),
    dns.promises.lookup('mx1.forwardemail.net'),
    dns.promises.lookup('mx2.forwardemail.net')
  ]);
  const [domain, mx1, mx2] = await Promise.all(
    ips.map((ip) => t.context.fe.checkBlacklists(ip.address))
  );
  t.is(domain, false);
  t.is(mx1, false);
  t.is(mx2, false);
});

test('disabled emails are delivered to blackhole', async (t) => {
  const info = await t.context.transporter.sendMail({
    from: 'test@spamchecker.net',
    to: 'disabled@niftylettuce.com',
    subject: 'test',
    text: 'test text',
    html: '<strong>test html</strong>'
  });
  t.deepEqual(info.accepted, ['disabled@niftylettuce.com']);
});

test('sends max retry error if count is exceeded', async (t) => {
  const envelope = {
    from: 'test@spamapi.net',
    to: 'test@forwardemail.net'
  };

  const messageId = `<123.abc.${Date.now()}@test>`;

  const raw = stripIndents`
Message-ID: ${messageId}
Date: ${new Date().toString()}
To: nobody@forwardemail.net
From: Test <test@niftylettuce.com>
Subject: testing custom port forwarding
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`;

  const [headers, chunks] = raw.split('\n\n');
  t.is(chunks, 'Test');

  const fingerprint = t.context.fe.getFingerprint(
    {
      isWhitelisted: false,
      remoteAddress: IP_ADDRESS
    },
    new Headers(headers),
    [Buffer.from(chunks)]
  );

  t.log('fingerprint', fingerprint);
  t.is(fingerprint, `${revHash(IP_ADDRESS)}:${revHash(messageId)}`);

  const key = `${t.context.fe.config.fingerprintPrefix}:${fingerprint}:count`;

  t.is(await t.context.client.get(key), null);
  t.is(
    await t.context.client.incrby(key, t.context.fe.config.maxRetry),
    t.context.fe.config.maxRetry
  );

  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      envelope,
      raw
    })
  );

  t.is(err.responseCode, 550);
  t.regex(err.message, /This message has been retried the maximum/);
  t.is(await t.context.client.incrby(key, 0), t.context.fe.config.maxRetry + 1);
});

// TODO: test greylisting with multiple recipients and combinations
// TODO: test greylisting with invalid greylist key value data (not an int)
// TODO: note the value is "true" and not 1
// TODO: for greylisting, check isWhitelisted first
// TODO: check regex message for greylist 1, 2 times
// TODO: then on the third final attempt, value should be "true" and not a counter
test('greylisting', async (t) => {
  const port = await getPort();

  const fe = new ForwardEmail({
    redis: t.context.client,
    port,
    greylistTimeout: ms('5s')
  });
  await fe.listen();

  const address = fe.server.address();

  //
  // NOTE: in future we will mock/spoof DNS requests (which will be more reliable)
  //
  // set dns cache for the test
  await t.context.client.set(
    'dns:txt:foo.com',
    safeStringify([[`forward-email=foo:foo@gmail.com`]])
  );
  await t.context.client.set(
    'dns:mx:foo.com',
    safeStringify([
      { exchange: 'mx1.forwardemail.net', priority: 10 },
      { exchange: 'mx2.forwardemail.net', priority: 10 }
    ])
  );

  // greylist key is null
  const key = fe.getGreylistKey(IP_ADDRESS, '', 'foo@foo.com');
  t.is(key, `greylist:${revHash([IP_ADDRESS, '', 'foo@foo.com'].join(':'))}`);

  {
    const value = await t.context.client.get(key);
    t.is(value, null);
  }

  const mail = {
    envelope: {
      from: '',
      to: 'foo@foo.com'
    },
    raw: stripIndents`
From: foo@foo.com
Date: ${new Date().toISOString()}

Message`
  };

  // ensure greylisted
  {
    const mx = await asyncMxConnect({
      target: IP_ADDRESS,
      port: address.port
    });
    const transporter = nodemailer.createTransport({
      logger: fe.config.logger,
      debug: true,
      direct: true,
      host: mx.host,
      port: mx.port,
      connection: mx.socket,
      ignoreTLS: true,
      secure: false,
      tls: {
        rejectUnauthorized: false
      }
    });
    const err = await t.throwsAsync(transporter.sendMail(mail));
    t.regex(err.message, /Greylisted for 5 seconds/);
    t.is(err.responseCode, 450);
  }

  // greylist key was set properly
  {
    const value = await t.context.client.get(key);
    const time = Number.parseInt(value, 10);
    t.is(value, time.toString());
    t.true(Number.isFinite(time));
    t.true(time > 0);
    t.true(Date.now() > time);
  }

  // wait 1 second
  await new Promise((resolve) => {
    setTimeout(resolve, 1000);
  });

  // try greylisting again
  {
    const mx = await asyncMxConnect({
      target: IP_ADDRESS,
      port: address.port
    });
    const transporter = nodemailer.createTransport({
      logger: fe.config.logger,
      debug: true,
      direct: true,
      host: mx.host,
      port: mx.port,
      connection: mx.socket,
      ignoreTLS: true,
      secure: false,
      tls: {
        rejectUnauthorized: false
      }
    });
    const err = await t.throwsAsync(transporter.sendMail(mail));
    t.regex(err.message, /Greylisted for \d seconds/);
    t.is(err.responseCode, 450);
  }

  // wait 4 seconds
  await new Promise((resolve) => {
    setTimeout(resolve, 4000);
  });

  // should be successful now
  {
    const mx = await asyncMxConnect({
      target: IP_ADDRESS,
      port: address.port
    });
    const transporter = nodemailer.createTransport({
      logger: fe.config.logger,
      debug: true,
      direct: true,
      host: mx.host,
      port: mx.port,
      connection: mx.socket,
      ignoreTLS: true,
      secure: false,
      tls: {
        rejectUnauthorized: false
      }
    });
    const info = await transporter.sendMail(mail);
    t.deepEqual(info.accepted, ['foo@foo.com']);
  }
});

test('greylisted and then hits rate limit', async (t) => {
  const port = await getPort();

  const fe = new ForwardEmail({
    redis: t.context.client,
    port,
    greylistTimeout: ms('10m'),
    rateLimit: {
      duration: ms('10m'),
      max: 25
    }
  });
  await fe.listen();

  const address = fe.server.address();

  const raw = stripIndents`
From: foo@foo.com
Date: ${new Date().toISOString()}

Message`;

  for (let i = 1; i <= 50; i++) {
    // eslint-disable-next-line no-await-in-loop
    const mx = await asyncMxConnect({
      target: IP_ADDRESS,
      port: address.port
    });
    const transporter = nodemailer.createTransport({
      logger: fe.config.logger,
      debug: true,
      direct: true,
      host: mx.host,
      port: mx.port,
      connection: mx.socket,
      ignoreTLS: true,
      secure: false,
      tls: {
        rejectUnauthorized: false
      }
    });
    // eslint-disable-next-line no-await-in-loop
    const err = await t.throwsAsync(
      transporter.sendMail({
        raw,
        envelope: { from: '', to: `foo+${i}@foo.com` }
      })
    );
    if (i <= 25) {
      t.regex(err.message, /Greylisted for \d* minutes/);
      t.is(err.responseCode, 450);
    } else {
      t.regex(
        err.message,
        new RegExp(`Rate limit exceeded for ${IP_ADDRESS}, retry in`)
      );
      t.is(err.responseCode, 421);
    }
  }
});

//
// TODO: we can assign `t.context.something += 1` in webhook for testing
// TODO: should we use "NX" as last argument after ttl for PX
//
// 10+ undeliverable in X period
// (reduced by Y every Z period)
// assumed to be a spammer spamming undeliverable mail
//

test('backscatter without mail from', async (t) => {
  await t.context.client.set(
    'dns:txt:foo.com',
    safeStringify([[`forward-email=foo:foo@gmail.com`]])
  );
  await t.context.client.set(
    'dns:mx:foo.com',
    safeStringify([
      { exchange: 'mx1.forwardemail.net', priority: 10 },
      { exchange: 'mx2.forwardemail.net', priority: 10 }
    ])
  );
  await t.context.client.set(`backscatter:${IP_ADDRESS}`, 'true');
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      envelope: {
        from: '',
        to: 'foo@foo.com'
      },
      raw: `
Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
From: foo@forwardmail.net
Bcc:
Subject: backscatter
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`
    })
  );
  t.regex(err.message, /blacklisted by https:\/\/www.backscatterer.org/);
  t.is(err.responseCode, 554);
});

test('backscatter works with valid username', async (t) => {
  await t.context.client.set(
    'dns:txt:foo.com',
    safeStringify([[`forward-email=foo:foo@gmail.com`]])
  );
  await t.context.client.set(
    'dns:mx:foo.com',
    safeStringify([
      { exchange: 'mx1.forwardemail.net', priority: 10 },
      { exchange: 'mx2.forwardemail.net', priority: 10 }
    ])
  );
  await t.context.client.set(`backscatter:${IP_ADDRESS}`, 'true');
  const info = await t.context.transporter.sendMail({
    envelope: {
      from: 'foo@foo.com',
      to: 'foo@foo.com'
    },
    raw: `
Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
From: foo@forwardmail.net
Bcc:
Subject: backscatter
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`
  });
  t.deepEqual(info.accepted, ['foo@foo.com']);
});

test('backscatter mailer-daemon@', async (t) => {
  await t.context.client.set(
    'dns:txt:foo.com',
    safeStringify([[`forward-email=foo:foo@gmail.com`]])
  );
  await t.context.client.set(
    'dns:mx:foo.com',
    safeStringify([
      { exchange: 'mx1.forwardemail.net', priority: 10 },
      { exchange: 'mx2.forwardemail.net', priority: 10 }
    ])
  );
  await t.context.client.set(`backscatter:${IP_ADDRESS}`, 'true');
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      envelope: {
        from: 'mailer-daemon@foo.com',
        to: 'foo@foo.com'
      },
      raw: `
Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
From: foo@forwardmail.net
Bcc:
Subject: backscatter
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`
    })
  );
  t.regex(err.message, /blacklisted by https:\/\/www.backscatterer.org/);
  t.is(err.responseCode, 554);
});

test('backscatter superseded by whitelist', async (t) => {
  await t.context.client.set(`whitelist:${IP_ADDRESS}`, 'true');
  await t.context.client.set(
    'dns:txt:foo.com',
    safeStringify([[`forward-email=foo:foo@gmail.com`]])
  );
  await t.context.client.set(
    'dns:mx:foo.com',
    safeStringify([
      { exchange: 'mx1.forwardemail.net', priority: 10 },
      { exchange: 'mx2.forwardemail.net', priority: 10 }
    ])
  );
  await t.context.client.set(`backscatter:${IP_ADDRESS}`, 'true');
  const info = await t.context.transporter.sendMail({
    envelope: {
      from: '',
      to: 'foo@foo.com'
    },
    raw: `
Date: Thu, 9 Nov 2000 10:44:00 -0800 (PST)
From: foo@forwardmail.net
Bcc:
Subject: backscatter
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`
  });
  t.deepEqual(info.accepted, ['foo@foo.com']);
});

test('fingerprints body correctly', async (t) => {
  const from = 'test@spamapi.net';
  const envelope = {
    from,
    to: 'test@forwardemail.net'
  };
  const date = new Date().toISOString();
  const raw = stripIndents`
Content-Type: text/plain; charset=utf-8
X-Test-Header: Some-Value
From: ${from}
Date: ${date}
Content-Transfer-Encoding: 7bit
MIME-Version: 1.0

Just
another
test`;

  const [header, body] = raw.replace(/\n/g, '\r\n').split('\r\n\r\n');
  const headers = new Headers(header);
  const chunks = Buffer.concat([Buffer.from(body + '\r\n')]);

  const fingerprint = t.context.fe.getFingerprint(
    {
      isWhitelisted: false,
      remoteAddress: IP_ADDRESS
    },
    headers,
    chunks
  );

  t.log('fingerprint', fingerprint);
  t.is(
    fingerprint,
    `${revHash(IP_ADDRESS)}:${revHash([date, from].join(':'))}:${revHash(
      chunks
    )}`
  );

  const key = `${t.context.fe.config.fingerprintPrefix}:${fingerprint}:count`;

  t.is(await t.context.client.get(key), null);

  await t.context.transporter.sendMail({
    envelope,
    raw
  });

  t.is(await t.context.client.get(key), '1');

  const address = t.context.fe.server.address();
  const mx = await asyncMxConnect({
    target: IP_ADDRESS,
    port: address.port
  });
  const transporter = nodemailer.createTransport({
    logger: t.context.fe.config.logger,
    debug: true,
    direct: true,
    host: mx.host,
    port: mx.port,
    connection: mx.socket,
    ignoreTLS: true,
    secure: false,
    tls: {
      rejectUnauthorized: false
    }
  });

  await transporter.sendMail({
    envelope,
    raw
  });

  t.is(await t.context.client.get(key), '2');
});

test('prevents sending same message twice with fingerprinting', async (t) => {
  const envelope = {
    from: 'test@spamapi.net',
    to: 'test@forwardemail.net'
  };

  const date = new Date().toString();
  const from = 'Test <test@niftylettuce.com>';
  const to = 'nobody@forwardemail.net';
  const subject = 'testing custom port forwarding';

  const raw = stripIndents`
Date: ${date}
To: ${to}
From: ${from}
Subject: ${subject}
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

Test`;

  const [header, body] = raw.replace(/\n/g, '\r\n').split('\r\n\r\n');
  const headers = new Headers(header);
  const chunks = Buffer.concat([Buffer.from(body + '\r\n')]);

  const fingerprint = t.context.fe.getFingerprint(
    {
      isWhitelisted: false,
      remoteAddress: IP_ADDRESS
    },
    headers,
    chunks
  );

  t.log('fingerprint', fingerprint);
  t.is(
    fingerprint,
    `${revHash(IP_ADDRESS)}:${revHash(
      [date, from, to, subject].join(':')
    )}:${revHash(chunks)}`
  );

  const key = `${t.context.fe.config.fingerprintPrefix}:${fingerprint}:count`;

  t.is(await t.context.client.get(key), null);

  await t.context.transporter.sendMail({
    envelope,
    raw
  });

  t.is(
    await t.context.client.get(
      `${t.context.fe.config.fingerprintPrefix}:${fingerprint}:${revHash(
        'niftylettuce@gmail.com'
      )}`
    ),
    '1'
  );

  t.is(await t.context.client.get(key), '1');

  const address = t.context.fe.server.address();
  const mx = await asyncMxConnect({
    target: IP_ADDRESS,
    port: address.port
  });
  const transporter = nodemailer.createTransport({
    logger: t.context.fe.config.logger,
    debug: true,
    direct: true,
    host: mx.host,
    port: mx.port,
    connection: mx.socket,
    ignoreTLS: true,
    secure: false,
    tls: {
      rejectUnauthorized: false
    }
  });

  await transporter.sendMail({
    envelope,
    raw
  });

  t.is(
    await t.context.client.get(
      `${t.context.fe.config.fingerprintPrefix}:${fingerprint}:${revHash(
        'niftylettuce@gmail.com'
      )}`
    ),
    '1'
  );
  t.is(await t.context.client.get(key), '2');
});

test.todo('use a valid SRS address in envelope to (bounce)');
test.todo('all the different fingerprint combinations');

test('rejects invalid DKIM signature', async (t) => {
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      from: 'Example <from@forwardemail.net>',
      to: 'Niftylettuce <hello@niftylettuce.com>',
      subject: 'forwards an email with DKIM and without SPF (passes DMARC)',
      text: 'test text',
      html: '<strong>test html</strong>',
      attachments: [],
      dkim: {
        ...t.context.fe.config.dkim,
        domainName: 'foobar.com'
      }
    })
  );
  t.is(err.responseCode, 550);
  t.regex(
    err.message,
    /The email sent has failed DMARC validation and is rejected due to the domain's DMARC policy./
  );
});

// TODO: add proofpoint dnsbl lookup test
test.todo('proofpoint');

test.todo('rejects invalid SPF');

test.todo('accepts valid SPF');

test.todo('supports + symbol aliased onRcptTo');

test.todo('preserves charset');

test.todo('graceful shutdown');

test.todo('whitelisting root domain');
test.todo('whitelisting subdomain');
test.todo('whitelisting IP address');

test.todo('blacklisting root domain');
test.todo('blacklisting subdomain');
test.todo('blacklisting IP address');

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
  const scan = await t.context.fe.scanner.scan(
    path.join(__dirname, 'fixtures', 'phishing.eml')
  );
  t.false(scan.is_spam);
  t.true(scan.results.phishing.length === 0);
});

// TODO: this needs re-enabled later
/*
test('should detect idn masquerading', async (t) => {
  const raw = await fs.promises.readFile(
    path.join(__dirname, 'fixtures', 'idn.eml')
  );
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      envelope: {
        to: 'beep@lad.sh',
        from: 'niftylettuce@gmail.com'
      },
      raw
    })
  );
  t.regex(err.message, /Possible IDN homograph attack/);
  t.is(err.responseCode, 554);
});
*/

test('should detect executable files', async (t) => {
  const raw = await fs.promises.readFile(
    path.join(__dirname, 'fixtures', 'executable.eml')
  );
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      envelope: {
        to: 'beep@lad.sh',
        from: 'beep@niftylettuce.com'
      },
      raw
    })
  );
  t.regex(err.message, /file name indicated it was a dangerous executable/);
  t.is(err.responseCode, 554);
});

test('should check against Cloudflare', async (t) => {
  const link = Buffer.from('eHZpZGVvcy5jb20=', 'base64').toString();
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      html: `<a href="${link}">test</a>`,
      text: link,
      from: 'foo@bar.com',
      envelope: {
        to: 'beep@lad.sh',
        from: 'beep@niftylettuce.com'
      }
    })
  );
  t.regex(
    err.message,
    /Links were detected that may contain adult-related content. For more information on Spam Scanner visit https:\/\/spamscanner.net./
  );
  t.is(err.responseCode, 554);
});

test('GTUBE test', async (t) => {
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
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

You should send this test mail from an account outside of your network.`,
      envelope: {
        to: 'beep@lad.sh',
        from: 'beep@niftylettuce.com'
      }
    })
  );
  t.regex(
    err.message,
    /Message detected to contain the GTUBE test from https:\/\/spamassassin.apache.org\/gtube\//
  );
  t.is(err.responseCode, 554);
});

test('EICAR test', async (t) => {
  const err = await t.throwsAsync(
    t.context.transporter.sendMail({
      html: 'test',
      text: 'test',
      attachments: [
        { path: path.join(__dirname, 'fixtures', 'eicar.com.txt') }
      ],
      from: 'foo@bar.com',
      envelope: {
        to: 'beep@lad.sh',
        from: 'beep@niftylettuce.com'
      }
    })
  );
  t.true(
    err.message.includes(
      'Attachment "eicar.com.txt" was infected with Eicar-Test-Signature.'
    ) ||
      err.message.includes(
        'Attachment "eicar.com.txt" was infected with Win.Test.EICAR_HDB-1.'
      )
  );
  t.is(err.responseCode, 554);
});
