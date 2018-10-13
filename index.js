const fs = require('fs');
const { promisify } = require('util');
const os = require('os');
const path = require('path');
const dns = require('dns');
const punycode = require('punycode/');
const parseDomain = require('parse-domain');
const autoBind = require('auto-bind');
const { oneLine } = require('common-tags');
const { SMTPServer } = require('smtp-server');
const bytes = require('bytes');
const { MailParser } = require('mailparser');
const nodemailer = require('nodemailer');
const redis = require('redis');
const Limiter = require('ratelimiter');
const ms = require('ms');
const domains = require('disposable-email-domains');
const wildcards = require('disposable-email-domains/wildcard.json');
const validator = require('validator');
const bluebird = require('bluebird');
const isObject = require('lodash/isObject');
const isString = require('lodash/isString');
const uniq = require('lodash/uniq');
const addressParser = require('nodemailer/lib/addressparser');
const common = require('email-providers/common.json');
let mailUtilities = require('mailin/lib/mailUtilities.js');

const blacklist = require('./blacklist');

mailUtilities = bluebird.promisifyAll(mailUtilities);

const invalidTXTError = new Error('Invalid forward-email TXT record');
invalidTXTError.responseCode = 550;

const invalidMXError = new Error('Sender has invalid MX records');
invalidMXError.responseCode = 550;

const headers = [
  'subject',
  'references',
  'date',
  'to',
  'from',
  'to',
  'cc',
  'bcc',
  'message-id',
  'in-reply-to',
  'reply-to'
];

const log = process.env.NODE_ENV !== 'production';

class ForwardEmail {
  constructor(config = {}) {
    config = {
      smtp: {},
      limiter: {},
      exchanges: ['mx1.forwardemail.net', 'mx2.forwardemail.net'],
      ...config
    };

    const ssl = {};
    if (process.env.NODE_ENV === 'production') {
      ssl.secure = process.env.SECURE === 'true';
      // ssl.needsUpgrade = true;
      ssl.key = fs.readFileSync(
        '/home/deploy/mx1.forwardemail.net.key',
        'utf8'
      );
      ssl.cert = fs.readFileSync(
        '/home/deploy/mx1.forwardemail.net.cert',
        'utf8'
      );
      ssl.ca = fs.readFileSync('/home/deploy/mx1.forwardemail.net.ca', 'utf8');
    }
    this.ssl = ssl;

    this.config = {
      smtp: {
        size: bytes('25mb'),
        onConnect: this.onConnect.bind(this),
        onData: this.onData.bind(this),
        onMailFrom: this.onMailFrom.bind(this),
        onRcptTo: this.onRcptTo.bind(this),
        disabledCommands: ['AUTH'],
        ...ssl,
        logInfo: log,
        logger: log,
        ...config.smtp
      },
      limiter: { ...config.limiter },
      exchanges: config.exchanges
    };

    // setup rate limiting with redis
    this.limiter = {
      db: redis.createClient(),
      max: 100, // max requests within duration
      duration: ms('1h'),
      ...this.config.limiter
    };

    // setup our smtp server which listens for incoming email
    this.server = new SMTPServer(this.config.smtp);

    autoBind(this);
  }

  parseUsername(address) {
    ({ address } = addressParser(address)[0]);
    let username =
      address.indexOf('+') === -1
        ? address.split('@')[0]
        : address.split('+')[0];

    username = punycode.toASCII(username);
    return username;
  }

  parseFilter(address) {
    ({ address } = addressParser(address)[0]);
    return address.indexOf('+') === -1
      ? ''
      : address.split('+')[1].split('@')[0];
  }

  parseDomain(address) {
    let domain = addressParser(address)[0].address.split('@')[1];
    domain = punycode.toASCII(domain);

    // check against blacklist
    if (this.isBlacklisted(domain)) {
      const err = new Error('Blacklisted domains are not permitted');
      err.responseCode = 550;
      throw err;
    }

    // ensure fully qualified domain name
    if (!validator.isFQDN(domain)) {
      const err = new Error(`${domain} is not a FQDN`);
      err.responseCode = 550;
      throw err;
    }

    // prevent disposable email addresses from being used
    if (this.isDisposable(domain)) {
      const err = new Error('Disposable email addresses are not permitted');
      err.responseCode = 550;
      throw err;
    }

    return domain;
  }

  onConnect(session, fn) {
    // TODO: this needs tested in production
    // or we need to come up with a better way to do this
    if (process.env.NODE_ENV === 'test') return fn();
    if (validator.isFQDN(session.clientHostname)) return fn();
    const err = new Error(`${session.clientHostname} is not a FQDN`);
    err.responseCode = 550;
    fn(err);
  }

  onData(stream, session, fn) {
    // <https://github.com/nodemailer/mailparser/blob/master/examples/pipe.js>
    const parser = new MailParser();
    const mail = { attachments: [] };
    let rawEmail = '';

    stream.on('error', fn);

    parser.on('error', err => {
      stream.emit('error', err);
      parser.end();
    });

    parser.on('end', async () => {
      try {
        headers.forEach(key => {
          if (mail.headers.has(key)) {
            const formatted = key.replace(/-([a-z])/g, (m, c) =>
              c.toUpperCase()
            );
            mail[formatted] = mail.headers.get(key);
            mail.headers.delete(key);
            if (['to', 'from', 'cc', 'bcc'].includes(key)) {
              mail[formatted] = mail[formatted].text;
            }
          }
        });

        const rcptTo = session.envelope.rcptTo.map(to => {
          return async () => {
            const address = await this.getForwardingAddress(to.address);
            return {
              ...to,
              address
            };
          };
        });

        session.envelope.rcptTo = await Promise.all(rcptTo.map(fn => fn()));

        session.envelope = {
          from: session.envelope.mailFrom.address,
          // make sure it's unique so we don't send dups
          to: uniq(session.envelope.rcptTo.map(to => to.address))
        };

        mail.headers = [...mail.headers].reduce((obj, [key, value]) => {
          if (isObject(value)) {
            if (isString(value.value)) obj[key] = value.value;
            if (isObject(value.params))
              Object.keys(value.params).forEach(k => {
                obj[key] += `; ${k}=${value.params[k]}`;
              });
          } else {
            obj[key] = value;
          }
          return obj;
        }, {});

        const obj = {
          ...mail
          // envelope: session.envelope
        };

        if (['test', 'development'].includes(process.env.NODE_ENV))
          console.dir(obj);

        // TODO: not sure if we need to change this
        // obj.to = await this.getForwardingAddress(obj.to);

        const spf = await this.validateSPF(
          session.remoteAddress,
          mail.from,
          session.clientHostname
        );

        const dkim = await this.validateDKIM(rawEmail);

        // TODO: if we are sending mail as then we must enforce DKIM
        // in order to prevent spoofing of messages

        // basically if there was no valid SPF record found for this sender
        // AND if there was no valid DKIM signature on the message
        // then we must refuse sending this email along because it
        // literally has on validation that it's from who it says its from
        //
        // but also check to see if it's from a well-known provider
        // (e.g. from a top 30000 alexa ranked sites)
        let alexa = false;
        try {
          const domain = this.parseDomain(session.envelope.from);
          const parsedDomain = parseDomain(domain);
          alexa = common.includes(`${parsedDomain.domain}.${parsedDomain.tld}`);
        } catch (err) {}

        if (!alexa && !spf && !dkim) {
          const err = new Error(
            oneLine`Please ensure the email service you are sending from either has SPF, DKIM, or is a top-ranked <30K Alexa.com domain.\n\nYou can most likely resolve this problem by searching on Google for "$serviceName SPF DKIM setup" (be sure to replace $serviceName with your email service provider, e.g. "Zoho").\n\nIf you continue to have issues, please see https://forwardemail.net or file an issue on GitHub at https://github.com/niftylettuce/forward-email. We'd be glad to help out!\n\n--\n@niftylettuce`
          );
          err.responseCode = 550;
          throw err;
        }

        // check against spamd if this message is spam
        // <https://github.com/humantech/node-spamd#usage>
        //
        // note that we wrap with a try/catch due to this error
        /* eslint-disable max-len */
        /*
        0|smtp     | error: TypeError: Cannot read property '2' of null
        0|smtp     |     at processResponse (/var/www/production/source/node_modules/spamc/index.js:381:43)
        0|smtp     |     at /var/www/production/source/node_modules/spamc/index.js:99:28
        0|smtp     |     at Socket.<anonymous> (/var/www/production/source/node_modules/spamc/index.js:327:28)
        0|smtp     |     at Socket.emit (events.js:182:13)
        0|smtp     |     at Socket.EventEmitter.emit (domain.js:442:20)
        0|smtp     |     at TCP._handle.close (net.js:595:12)
        */
        /* eslint-enable max-len */
        let spamScore = 0;
        try {
          spamScore = await mailUtilities.computeSpamScoreAsync(rawEmail);
        } catch (err) {}

        if (spamScore >= 5 && !alexa) {
          // TODO: blacklist IP address
          const err = new Error(
            `Message detected as spam (spam score was ${spamScore})`
          );
          err.responseCode = 554;
          throw err;
        }

        // TODO: implement spamassassin automatic learning
        // through bayes based off response from proxy (e.g. gmail response)
        // (if spam errors occur, we need 550 error code)
        // and we also might want to add clamav
        // for attachment scanning to prevent those from going through as well

        await Promise.all(
          session.envelope.to.map(to => {
            return (async () => {
              // TODO: pick lowest priority address found
              const addresses = await this.validateMX(to);
              const transporter = nodemailer.createTransport({
                debug: log,
                logger: log,
                direct: true,
                // secure: true,
                // requireTLS: true,
                opportunisticTLS: true,
                port: 25,
                host: addresses[0].exchange,
                ...this.ssl,
                name: os.hostname(),
                tls: {
                  rejectUnauthorized: process.env.NODE_ENV !== 'test'
                }
                // <https://github.com/nodemailer/nodemailer/issues/625>
              });

              // verify transport
              // await transporter.verify();

              const dkim = {};
              if (process.env.NODE_ENV === 'production') {
                dkim.domainName = 'forwardemail.net';
                dkim.keySelector = 'default';
                dkim.privateKey = fs.readFileSync(
                  '/home/deploy/dkim-private.key',
                  'utf8'
                );
              } else if (process.env.NODE_ENV === 'test') {
                dkim.domainName = 'forwardemail.net';
                dkim.keySelector = 'default';
                dkim.privateKey = fs.readFileSync(
                  path.join(__dirname, 'dkim-private.key'),
                  'utf8'
                );
              }

              const email = {
                ...obj,
                envelope: session.envelope,
                dkim
              };

              // allow Gmail "Send Mail As" by re-writing the FROM of the email
              // (otherwise we receive the following error when connecting to Gmail)
              //
              // 550-5.7.1 Unauthenticated email from google.com is not accepted due
              // to domain's DMARC policy. Please contact the administrator of
              // google.com domain if this was a legitimate mail. Please visit
              // https://support.google.com/mail/answer/2451690 to learn about the
              // DMARC initiative
              //
              // Note that the email is from "gmail-noreply@google.com" therefore
              // we can rewrite the "from" of the email if it matches this exactly
              if (email.envelope.from === 'gmail-noreply@google.com') {
                // validate clientHostname domain is gmail
                const parsedDomain = parseDomain(session.clientHostname);
                if (
                  `${parsedDomain.domain}.${parsedDomain.tld}` === 'google.com'
                ) {
                  email.from = email.to;
                  session.envelope.from = session.envelope.to;
                }
              }

              delete email.messageId;
              delete email.headers['mime-version'];
              delete email.headers['content-type'];
              delete email.headers['dkim-signature'];
              delete email.headers['x-google-dkim-signature'];
              delete email.headers['x-gm-message-state'];
              delete email.headers['x-google-smtp-source'];
              delete email.headers['x-received'];
              delete email.headers['x-google-address-confirmation'];
              const info = await transporter.sendMail(email);
              return info;
            })();
          })
        );

        fn();
      } catch (err) {
        // parse SMTP code and message
        if (err.message && err.message.startsWith('SMTP code:')) {
          err.responseCode = err.message.split('SMTP code:')[1].split(' ')[0];
          err.message = err.message.split('msg:')[1];
          // TODO: we need to use bayes auto learning here
          // to tell spam assassin that this email in particular failed
          // (IFF as it was sent to a gmail, yahoo, or other major provider)
        }
        // add a note to email me for help
        err.message +=
          '\n\n If you need help with email-forwarding setup or troubleshooting please visit https://forwardemail.net';
        fn(err);
      }
    });

    stream.on('data', chunk => {
      rawEmail += chunk;
    });

    stream.on('end', () => {
      if (stream.sizeExceeded) {
        const err = new Error(
          `Message size exceeds maximum of ${bytes(this.config.smtp.size)}`
        );
        err.responseCode = 450;
        parser.emit('error', err);
      }
    });

    parser.on('headers', headers => {
      mail.headers = headers;
    });

    parser.on('data', data => {
      if (data.type === 'text') {
        Object.keys(data).forEach(key => {
          if (['text', 'html', 'textAsHtml'].includes(key)) {
            mail[key] = data[key];
          }
        });
      }

      if (data.type === 'attachment') {
        const chunks = [];
        let chunklen = 0;

        mail.attachments.push(data);

        data.content.on('readable', () => {
          let chunk;
          while ((chunk = data.content.read()) !== null) {
            chunks.push(chunk);
            chunklen += chunk.length;
          }
        });

        data.content.on('end', () => {
          data.content = Buffer.concat(chunks, chunklen);
          data.release();
        });
      }
    });

    stream.pipe(parser);
  }

  // TODO: eBay/PayPal/Google cannot be forwarded so we need alt. solution
  // or maybe there's a way we can get them to whitelist our server
  //
  // TODO: we need to add Google Structured Data and then submit whitelist req

  //
  // basically we have to check if the domain has an SPF record
  // if it does, then we need to check if the sender's domain is included
  //
  // if any errors occur, we should respond with this:
  // err.message = 'SPF validation error';
  // err.responseCode = 451;
  //
  // however if it's something like a network error
  // we should respond with a `421` code as we do below
  //
  // here's some code for reference, not sure if it's useful
  // <https://github.com/mixmaxhq/spf-validator/blob/master/index.js>
  // <https://github.com/Flolagale/mailin/blob/fac7dcf59404691e551568f987caaaa464303b6b/lib/mailUtilities.js#L49>
  // const { spfSetup, hasSPFSender } = require('email-setup');
  // const isSpfSetup = await spfSetup(domain);
  // const isSpfSender = await hasSPFSender('foo.com', '_spf.google.com');
  // if (!isSetup)
  //
  async validateSPF(remoteAddress, from, clientHostname) {
    // <https://github.com/Flolagale/mailin/blob/master/lib/mailin.js#L265>
    try {
      const pass = await mailUtilities.validateSpfAsync(
        remoteAddress,
        from,
        clientHostname
      );
      return pass;
    } catch (err) {
      err.responseCode = 421;
      throw err;
    }
  }

  async validateMX(address) {
    try {
      const domain = this.parseDomain(address);
      const addresses = await promisify(dns.resolveMx)(domain);
      if (!addresses || addresses.length === 0) throw invalidMXError;
      return addresses;
    } catch (err) {
      if (/queryMx ENODATA/.test(err) || /queryTxt ENOTFOUND/.test(err)) {
        err.message = invalidMXError.message;
        err.responseCode = invalidMXError.responseCode;
      } else if (!err.responseCode) {
        err.responseCode = 421;
      }
      throw err;
    }
  }

  async validateDKIM(rawEmail) {
    try {
      // <https://github.com/jhermsmeier/node-dkim/blob/master/test/verify.js#L35>
      // const records = await promisify(dkim.verify)(Buffer.from(rawEmail));
      // const pass =
      //   records.length > 0 && records.every(record => record.verified);
      // return pass;
      const pass = await mailUtilities.validateDkimAsync(rawEmail);
      return pass;
    } catch (err) {
      err.responseCode = 421;
      throw err;
    }
  }

  validateRateLimit(email) {
    // if SPF TXT record exists for the domain name
    // then ensure that `session.remoteAddress` resolves
    // to either the IP address or the domain name value for the SPF
    return new Promise((resolve, reject) => {
      const id = email;
      const limit = new Limiter({ id, ...this.limiter });
      limit.get((err, limit) => {
        if (err) {
          err.responseCode = 421;
          return reject(err);
        }
        if (limit.remaining) return resolve();
        const delta = (limit.reset * 1000 - Date.now()) | 0;
        err = new Error(
          `Rate limit exceeded, retry in ${ms(delta, { long: true })}`
        );
        err.responseCode = 451;
        reject(err);
      });
    });
  }

  isBlacklisted(domain) {
    return blacklist.includes(domain);
  }

  isDisposable(domain) {
    for (const d of domains) {
      if (d === domain) return true;
    }
    for (const w of wildcards) {
      if (w === domain || domain.endsWith(`.${w}`)) return true;
    }
    return false;
  }

  async onMailFrom(address, session, fn) {
    try {
      await this.validateRateLimit(address.address);
      await this.validateMX(address.address);
      fn();
    } catch (err) {
      fn(err);
    }
  }

  // this returns the forwarding address for a given email address
  async getForwardingAddress(address) {
    const domain = this.parseDomain(address);
    const records = await promisify(dns.resolveTxt)(domain);

    // dns TXT record must contain `forward-email=` prefix
    let record;

    for (let i = 0; i < records.length; i++) {
      records[i] = records[i].join(''); // join chunks together
      if (records[i].startsWith('forward-email=')) {
        record = records[i];
        break;
      }
    }

    if (!record) throw invalidTXTError;

    // e.g. hello@niftylettuce.com => niftylettuce@gmail.com
    // record = "forward-email=hello:niftylettuce@gmail.com"
    // e.g. hello+test@niftylettuce.com => niftylettuce+test@gmail.com
    // record = "forward-email=hello:niftylettuce@gmail.com"
    // e.g. *@niftylettuce.com => niftylettuce@gmail.com
    // record = "forward-email=niftylettuce@gmail.com"
    // e.g. *+test@niftylettuce.com => niftylettuce@gmail.com
    // record = "forward-email=niftylettuce@gmail.com"
    record = record.replace('forward-email=', '');

    // remove trailing whitespaces from each address listed
    const addresses = record.split(',').map(a => a.trim());

    if (addresses.length === 0) throw invalidTXTError;

    // store if we have a forwarding address or not
    let forwardingAddress;

    // store if we have a global redirect or not
    let globalForwardingAddress;

    // check if we have a specific redirect and store global redirects (if any)
    // get username from recipient email address
    // (e.g. hello@niftylettuce.com => hello)
    const username = this.parseUsername(address);

    for (let i = 0; i < addresses.length; i++) {
      if (addresses[i].indexOf(':') === -1) {
        if (
          validator.isFQDN(this.parseDomain(addresses[i])) &&
          validator.isEmail(addresses[i])
        )
          globalForwardingAddress = addresses[i];
      } else {
        const address = addresses[i].split(':');

        if (address.length !== 2) throw invalidTXTError;

        // address[0] = hello (username)
        // address[1] = niftylettuce@gmail.com (forwarding email)

        // check if we have a match
        if (username === address[0]) {
          forwardingAddress = address[1];
          break;
        }
      }
    }

    // if we don't have a specific forwarding address try the global redirect
    if (!forwardingAddress && globalForwardingAddress)
      forwardingAddress = globalForwardingAddress;

    // if we don't have a forwarding address then throw an error
    if (!forwardingAddress) throw invalidTXTError;

    // otherwise transform the + symbol filter if we had it
    // and then resolve with the newly formatted forwarding address
    if (address.indexOf('+') === -1) return forwardingAddress;

    return `${this.parseUsername(forwardingAddress)}+${this.parseFilter(
      address
    )}@${this.parseDomain(forwardingAddress)}`;
  }

  async onRcptTo(address, session, fn) {
    try {
      // validate forwarding address by looking up TXT record `forward-email=`
      await this.getForwardingAddress(address.address);

      // validate MX records exist and contain ours
      const addresses = await this.validateMX(address.address);
      const exchanges = addresses.map(mxAddress => mxAddress.exchange);
      const hasAllExchanges = this.config.exchanges.every(exchange =>
        exchanges.includes(exchange)
      );
      if (hasAllExchanges) return fn();
      const err = new Error(
        `Missing required DNS MX records: ${this.config.exchanges.join(', ')}`
      );
      err.responseCode = 550;
      throw err;
    } catch (err) {
      fn(err);
    }
  }
}

if (!module.parent) {
  const forwardEmail = new ForwardEmail();
  forwardEmail.server.listen(process.env.PORT || 25);
}

module.exports = ForwardEmail;
