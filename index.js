const crypto = require('crypto');
const dns = require('dns');
const fs = require('fs');
const os = require('os');
const path = require('path');
// const { Resolver } = require('dns');
const Limiter = require('ratelimiter');
const Promise = require('bluebird');
const _ = require('lodash');
const addressParser = require('nodemailer/lib/addressparser');
const DKIM = require('nodemailer/lib/dkim');
const autoBind = require('auto-bind');
const bytes = require('bytes');
const dkimVerify = require('python-dkim-verify');
const dmarcParse = require('dmarc-parse');
const dnsbl = require('dnsbl');
const domains = require('disposable-email-domains');
const ip = require('ip');
const isCI = require('is-ci');
const ms = require('ms');
const nodemailer = require('nodemailer');
const parseDomain = require('parse-domain');
const punycode = require('punycode/');
const redis = require('redis');
const s = require('underscore.string');
const spfCheck2 = require('python-spfcheck2');
const validator = require('validator');
const wildcards = require('disposable-email-domains/wildcard.json');
const { SMTPServer } = require('smtp-server');
const { oneLine } = require('common-tags');

let mailUtilities = require('mailin/lib/mailUtilities.js');
const MessageSplitter = require('./message-splitter');

mailUtilities = Promise.promisifyAll(mailUtilities);

// currently running into this error when using this code:
// `Error: Mail command failed: 421 Cannot read property '_handle' of undefined`
// const resolver = new Resolver();
// resolver.setServers(servers);
// const resolveMx = Promise.promisify(resolver.resolveMx);
// const resolveTxt = Promise.promisify(resolver.resolveTxt);

const blacklist = require('./blacklist');

const invalidTXTError = new Error('Invalid forward-email TXT record');
invalidTXTError.responseCode = 550;

const invalidMXError = new Error('Sender has invalid MX records');
invalidMXError.responseCode = 550;

// our server's current IP address
const IP_ADDRESS = ip.address();

const log = process.env.NODE_ENV !== 'production';

if (log) Error.stackTraceLimit = Infinity;

// taken from:
// node_modules/nodemailer/lib/mime-node/index.js
function createMessageID(session) {
  return (
    '<' +
    [2, 2, 2, 6].reduce(
      // crux to generate UUID-like random strings
      (prev, len) => prev + '-' + crypto.randomBytes(len).toString('hex'),
      crypto.randomBytes(4).toString('hex')
    ) +
    '@' +
    // try to use the domain of the FROM address
    session.envelope.mailFrom.address.split('@').pop() +
    '>'
  );
}

class ForwardEmail {
  constructor(config = {}) {
    this.ssl = {
      secure: false,
      ...config.ssl
    };

    if (process.env.NODE_ENV === 'test' && !isCI)
      config.dkim = {
        domainName: 'forwardemail.net',
        keySelector: 'default',
        privateKey: fs.readFileSync(
          path.join(__dirname, 'dkim-private.key'),
          'utf8'
        ),
        cacheDir: os.tmpdir()
      };

    this.config = {
      // TODO: eventually set 127.0.0.1 as DNS server
      // for both `dnsbl` and `dns` usage
      // https://gist.github.com/zhurui1008/48130439a079a3c23920
      //
      // <https://blog.cloudflare.com/announcing-1111/>
      dns: ['1.1.1.1'],
      noReply: 'no-reply@forwardemail.net',
      smtp: {
        size: bytes('25mb'),
        onConnect: this.onConnect.bind(this),
        onData: this.onData.bind(this),
        onMailFrom: this.onMailFrom.bind(this),
        onRcptTo: this.onRcptTo.bind(this),
        disabledCommands: ['AUTH'],
        logInfo: log,
        logger: log,
        ...config.smtp,
        ...this.ssl
      },
      limiter: { ...config.limiter },
      ssl: this.ssl,
      exchanges: ['mx1.forwardemail.net', 'mx2.forwardemail.net'],
      dkim: {},
      ...config
    };

    // set up DKIM instance for signing messages
    this.dkim = new DKIM(this.config.dkim);

    // setup rate limiting with redis
    this.limiter = {
      db: redis.createClient(),
      max: 200, // max requests within duration
      duration: ms('1h'),
      ...this.config.limiter
    };

    // setup our smtp server which listens for incoming email
    this.server = new SMTPServer(this.config.smtp);

    this.dns = Promise.promisifyAll(dns);
    this.dns.setServers(this.config.dns);

    autoBind(this);
  }

  rewriteFriendlyFrom(from) {
    // preserve user's name
    const { name } = addressParser(from)[0];
    return `${name} <${this.config.noReply}>`;
  }

  parseUsername(address) {
    ({ address } = addressParser(address)[0]);
    let username =
      address.indexOf('+') === -1
        ? address.split('@')[0]
        : address.split('+')[0];

    username = punycode.toASCII(username).toLowerCase();
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

  async onConnect(session, fn) {
    // TODO: this needs tested in production
    // or we need to come up with a better way to do this
    if (process.env.NODE_ENV === 'test') return fn();
    // ensure it's a fully qualififed domain name
    if (!validator.isFQDN(session.clientHostname)) {
      const err = new Error(`${session.clientHostname} is not a FQDN`);
      err.responseCode = 550;
      return fn(err);
    }

    // ensure that it's not on the DNS blacklist
    try {
      const result = await dnsbl.lookup(
        session.remoteAddress,
        'zen.spamhaus.org',
        {
          servers: this.config.dns
        }
      );
      if (!result) return fn();
      const error = new Error(
        `Your IP address of ${
          session.remoteAddress
        } is listed on the ZEN Spamhaus DNS Blacklist.  See https://www.spamhaus.org/query/ip/${
          session.remoteAddress
        } for more information.`
      );
      error.responseCode = 554;
      fn(error);
    } catch (err) {
      if (log) console.error(err);
      fn();
    }
  }

  onData(stream, session, fn) {
    const messageSplitter = new MessageSplitter();
    const chunks = [];

    messageSplitter.on('readable', () => {
      let chunk;
      while ((chunk = messageSplitter.read()) !== null) {
        // TODO: it would be nice if we could exit early
        // rather than continuing to read the entire stream
        if (stream.sizeExceeded) return;
        chunks.push(chunk);
      }
    });

    // eslint-disable-next-line complexity
    messageSplitter.once('end', async () => {
      //
      // we need to check the following:
      //
      // 1) X if email file size exceeds the limit (no bottleneck)
      // 2) X prevent replies to no-reply@forwardemail.net (no bottleneck)
      // 3) X ensure all email headers were parsed
      // 4) X check for spam (score must be < 5) (child process spam daemon)
      // 5) X if DKIM signature passed and was valid (child process python)
      // 6) X if SPF is valid (child process python)
      // 7) X check for DMARC compliance (DNS lookup)
      // 8) X reverse SPF check and rewrite with friendly-from (DNS lookup)
      // 9) X rewrite message ID
      // 10) X add our own DKIM signature and remove DKIM header (no bottleneck)
      // 11) X send email
      //
      // future:
      // 10) verify and sign with ARC
      // <https://datatracker.ietf.org/doc/draft-ietf-dmarc-arc-usage/?include_text=1>
      //
      try {
        //
        // 1) if email file size exceeds the limit
        //
        if (stream.sizeExceeded) {
          const err = new Error(
            `Message size exceeds maximum of ${bytes(this.config.smtp.size)}`
          );
          err.responseCode = 450;
          throw err;
        }

        //
        // 2) prevent replies to no-reply@forwardemail.net
        //
        if (
          _.some(
            session.envelope.rcptTo,
            to => to.address === this.config.noReply
          )
        ) {
          const err = new Error(
            oneLine`You need to reply to the "Reply-To" email address on the email; do not send messages to <${
              this.config.noReply
            }>`
          );
          err.responseCode = 550;
          throw err;
        }

        //
        // 3) ensure all email headers were parsed
        //
        if (!messageSplitter.headersParsed) {
          const err = new Error(
            'Headers were unable to be parsed, please try again'
          );
          err.responseCode = 421;
          throw new Error(err);
        }

        //
        // store variables for use later
        //
        let rewriteFriendlyFrom = false;
        // headers object (includes the \r\n\r\n header and body separator)
        const { headers } = messageSplitter;
        const from = headers.getFirst('from');
        // message body as a single Buffer (everything after the \r\n\r\n separator)
        const body = Buffer.concat(chunks);

        const originalRaw = Buffer.concat([headers.build(), body]);

        //
        // 4) check for spam (score must be < 5)
        //
        // TODO: we need to replace the spam block below with implementation
        // // of `pdf-spamc-stream` from https://github.com/streamtOtO/spamc-stream
        // // note that this package name is published with several key updates
        //
        // TODO: we may also want to add clamav for attachment scanning
        let spamScore = 0;
        try {
          spamScore = await mailUtilities.computeSpamScoreAsync(originalRaw);
        } catch (err) {
          if (log) console.error(err);
        }

        if (spamScore >= 5) {
          const err = new Error(
            `Message detected as spam (spam score was ${spamScore})`
          );
          err.responseCode = 554;
          throw err;
        }

        //
        // 5) if DKIM signature passed and was valid
        //
        const dkim =
          headers.getFirst('dkim-signature') === ''
            ? true
            : await this.validateDKIM(originalRaw);
        if (!dkim) {
          const err = new Error(
            oneLine`
              The email you sent has an invalid DKIM signature, please try again or check your email service's DKIM configuration.\n
              If you believe this is an error, please forward this email to: support@forwardemail.net
            `
          );
          err.responseCode = 550;
          throw err;
        }

        //
        // 6) if SPF is valid
        //
        const spf = await this.validateSPF(
          session.remoteAddress,
          session.envelope.mailFrom.address,
          session.clientHostname
        );
        if (!['pass', 'neutral', 'none', 'softfail'].includes(spf)) {
          const err = new Error(
            oneLine`
              The email you sent has failed SPF validation with a result of "${spf}".  Please try again or check your email service's SPF configuration.\n
              If you believe this is an error, please forward this email to: support@forwardemail.net
            `
          );
          err.responseCode = 550;
          throw err;
        }

        //
        // 7) check for DMARC compliance
        //
        const dmarcRecord = await this.getDMARC(
          session.envelope.mailFrom.address.split('@')[1]
        );
        if (dmarcRecord) {
          try {
            const result = dmarcParse(dmarcRecord);
            if (
              !_.isObject(result) ||
              !_.isObject(result.tags) ||
              !_.isObject(result.tags.p) ||
              !_.isString(result.tags.p.value)
            )
              throw new Error('Invalid DMARC parsed result');
            // if quarantine or reject then we need to rewrite w/friendly-from
            if (
              ['quarantine', 'reject'].includes(
                result.tags.p.value.toLowerCase().trim()
              )
            ) {
              rewriteFriendlyFrom = true;
              // eslint-disable-next-line max-depth
              if (headers.getFirst('reply-to') === '')
                headers.update('Reply-To', from);
              headers.update('From', this.rewriteFriendlyFrom(from));
            }
          } catch (err) {
            if (log) console.error(err);
          }
        }

        //
        // 8) reverse SPF check and rewrite with friendly-from (DNS lookup)
        //
        if (!rewriteFriendlyFrom) {
          const reverseSpf = await this.validateSPF(
            IP_ADDRESS,
            session.envelope.mailFrom.address,
            // TODO: eventually we need a way to map which IP
            // is to which exchange/FQDN without assuming it's the first
            this.config.exchanges[0] // our server's FQDN (pick the first)
          );

          if (!['pass', 'neutral', 'none'].includes(reverseSpf)) {
            rewriteFriendlyFrom = true;
            if (headers.getFirst('reply-to') === '')
              headers.update('Reply-To', from);
            headers.update('From', this.rewriteFriendlyFrom(from));
          }
        }

        //
        // 9) rewrite message ID
        //
        let rewritten = false;
        const recipients = await Promise.all(
          session.envelope.rcptTo.map(async to => {
            const address = await this.getForwardingAddress(to.address);
            if (rewritten) return address;
            // Gmail won't show the message in the inbox if it's sending FROM
            // the same address that gets forwarded TO using our service
            // (we can assume that other mail providers do the same)
            const fromAddress = addressParser(from)[0].address;
            if (address === fromAddress) {
              rewritten = true;
              if (headers.getFirst('message-id') !== '')
                headers.update('In-Reply-To', headers.getFirst('message-id'));
              headers.update('Message-ID', createMessageID(session));
            }

            return address;
          })
        );

        //
        // 10) add our own DKIM signature and remove DKIM header (no bottleneck)
        //

        // remove existing signatures
        headers.remove('dkim-signature');
        headers.remove('x-google-dkim-signature');

        // sign new message
        const signedChunks = [];
        const output = this.dkim.sign(
          // join headers object and body into a full rfc822 formatted email
          // headers.build() compiles headers into a Buffer with the \r\n\r\n separator
          Buffer.concat([headers.build(), body])
        );
        output.once('error', err => stream.destroy(err));
        output.on('readable', () => {
          let chunk;
          while ((chunk = output.read()) !== null) {
            signedChunks.push(chunk);
          }
        });
        output.once('end', async () => {
          //
          // 11) send email
          //
          const raw = Buffer.concat(signedChunks);
          try {
            await Promise.each(_.uniq(recipients), async to => {
              const addresses = await this.validateMX(to);
              const transporter = nodemailer.createTransport({
                debug: log,
                logger: log,
                direct: true,
                opportunisticTLS: true,
                port: 25,
                host: addresses[0].exchange,
                ...this.ssl,
                name: os.hostname(),
                tls: {
                  rejectUnauthorized: process.env.NODE_ENV !== 'test'
                }
              });
              await transporter.sendMail({
                envelope: {
                  from: rewriteFriendlyFrom
                    ? this.config.noReply
                    : session.envelope.mailFrom.address,
                  to
                },
                raw
              });
            });
            fn();
          } catch (err) {
            stream.destroy(err);
          }
        });
      } catch (err) {
        stream.destroy(err);
      }
    });

    messageSplitter.once('error', err => {
      // parse SMTP code and message
      if (err.message && err.message.startsWith('SMTP code:')) {
        err.responseCode = err.message.split('SMTP code:')[1].split(' ')[0];
        err.message = err.message.split('msg:')[1];
      }

      err.message +=
        '\n\n If you need help please forward this email to support@forwardemail.net or visit https://forwardemail.net';
      if (log) console.error(err);
      fn(err);
    });

    stream.once('error', err => messageSplitter.destroy(err));

    stream.pipe(messageSplitter);
  }

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
  async validateSPF(remoteAddress, from, clientHostname) {
    if (process.env.NODE_ENV === 'test') {
      remoteAddress = '178.128.149.101';
      clientHostname = 'mx1.forwardemail.net';
    }

    try {
      const [result, explanation] = await spfCheck2(
        remoteAddress,
        from,
        clientHostname
      );
      if (['permerror', 'temperror'].includes(result))
        throw new Error(
          `SPF validation failed with result "${result}" and explanation "${explanation}"`
        );
      return result;
    } catch (err) {
      err.responseCode = 421;
      throw err;
    }
  }

  async getDMARC(hostname) {
    if (process.env.NODE_ENV === 'test') hostname = 'forwardemail.net';
    const parsedDomain = parseDomain(hostname);
    if (!parsedDomain) return false;
    const entry = `_dmarc.${hostname}`;
    try {
      const records = await dns.resolveTxtAsync(entry);
      // note that it's an array of arrays [ [ 'v=DMARC1' ] ]
      if (!_.isArray(records) || _.isEmpty(records)) return false;
      if (!_.isArray(records[0]) || _.isEmpty(records[0])) return false;
      // join together the record by space
      return records[0].join(' ');
    } catch (err) {
      // recursively look up from subdomain to parent domain for record
      if (_.isString(err.code) && err.code === 'ENOTFOUND') {
        // no dmarc record exists so return `false`
        if (!parsedDomain.subdomain) return false;
        // otherwise attempt to lookup the parent domain's DMARC record instead
        return this.getDMARC(`${parsedDomain.domain}.${parsedDomain.tld}`);
      }

      if (log) console.error(err);
      // if there's an error then assume that we need to rewrite
      // with a friendly-from, for whatever reason
      return true;
    }
  }

  async validateDKIM(raw) {
    try {
      const result = await dkimVerify(raw);
      return result;
    } catch (err) {
      if (log) console.error(err);
      err.responseCode = 421;
      throw err;
    }
  }

  async validateMX(address) {
    try {
      const domain = this.parseDomain(address);
      const addresses = await dns.resolveMxAsync(domain);
      if (!addresses || addresses.length === 0) throw invalidMXError;
      return _.sortBy(addresses, 'priority');
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

  validateRateLimit(email) {
    // if SPF TXT record exists for the domain name
    // then ensure that `session.remoteAddress` resolves
    // to either the IP address or the domain name value for the SPF
    return new Promise((resolve, reject) => {
      if (email === this.config.noReply) return resolve();
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
    const records = await dns.resolveTxtAsync(domain);

    // dns TXT record must contain `forward-email=` prefix
    const validRecords = [];

    // add support for multi-line TXT records
    for (let i = 0; i < records.length; i++) {
      records[i] = records[i].join(''); // join chunks together
      if (records[i].startsWith('forward-email='))
        validRecords.push(records[i].replace('forward-email=', ''));
    }

    // join multi-line TXT records together and replace double w/single commas
    const record = validRecords
      .join(',')
      .replace(/,+/g, ',')
      .trim();

    // if the record was blank then throw an error
    if (s.isBlank(record)) throw invalidTXTError;

    // e.g. hello@niftylettuce.com => niftylettuce@gmail.com
    // record = "forward-email=hello:niftylettuce@gmail.com"
    // e.g. hello+test@niftylettuce.com => niftylettuce+test@gmail.com
    // record = "forward-email=hello:niftylettuce@gmail.com"
    // e.g. *@niftylettuce.com => niftylettuce@gmail.com
    // record = "forward-email=niftylettuce@gmail.com"
    // e.g. *+test@niftylettuce.com => niftylettuce@gmail.com
    // record = "forward-email=niftylettuce@gmail.com"

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
      // convert addresses to lowercase
      addresses[i] = addresses[i].toLowerCase();
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
  const config = {
    noReply: 'no-reply@forwardemail.net',
    exchanges: ['mx1.forwardemail.net', 'mx2.forwardemail.net'],
    ssl: {},
    dkim: {}
  };

  if (process.env.NODE_ENV === 'production') {
    // needsUpgrade = true;
    config.ssl = {
      secure: process.env.SECURE === 'true',
      key: fs.readFileSync('/home/deploy/mx1.forwardemail.net.key', 'utf8'),
      cert: fs.readFileSync('/home/deploy/mx1.forwardemail.net.cert', 'utf8'),
      ca: fs.readFileSync('/home/deploy/mx1.forwardemail.net.ca', 'utf8')
    };
    config.dkim = {
      domainName: 'forwardemail.net',
      keySelector: 'default',
      privateKey: fs.readFileSync('/home/deploy/dkim-private.key', 'utf8'),
      cacheDir: os.tmpdir()
    };
  }

  const forwardEmail = new ForwardEmail(config);
  forwardEmail.server.listen(process.env.PORT || 25);
}

module.exports = ForwardEmail;
