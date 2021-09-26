const fs = require('fs');
const path = require('path');
const { env } = require('../../helpers');

const Client = require('nodemailer/lib/smtp-connection');
const test = require('ava');
const nodemailer = require('nodemailer');
const randomString = require('randomstring');

const tls = { rejectUnauthorized: false };

const dkim = {
  domainName: env.DKIM_DOMAIN_NAME,
  keySelector: env.DKIM_KEY_SELECTOR,
  privateKey: fs.readFileSync(
    path.resolve('test/fixtures/dkim-test-private.key'),
    'utf8'
  )
};

for (let i = 0; i < 100; i++) {
  test(`benchmark #${i + 1}`, async (t) => {
    const connection = new Client({ port: 25, tls });
    const transporter = nodemailer.createTransport({
      streamTransport: true
    });
    const info = await transporter.sendMail({
      from: 'foo@forwardemail.net',
      to: 'Baz <disabled@niftylettuce.com>',
      subject: 'test',
      text: 'test text',
      html: randomString.generate(2000),
      dkim
    });
    return new Promise((resolve, reject) => {
      connection.once('error', reject);
      connection.once('end', resolve);
      connection.connect(() => {
        connection.send(info.envelope, info.message, (err) => {
          t.is(err, null);
          connection.close();
        });
      });
    });
  });
}
