const dns = require('dns');
const fs = require('fs');
const os = require('os');
const util = require('util');

const DKIM = require('nodemailer/lib/dkim');
const Limiter = require('ratelimiter');
const NodeDKIM = require('dkim');
const Promise = require('bluebird');
const Redis = require('@ladjs/redis');
const _ = require('lodash');
const addressParser = require('nodemailer/lib/addressparser');
const arrayJoinConjunction = require('array-join-conjunction');
const bytes = require('bytes');
const dmarcParse = require('dmarc-parse');
const dnsbl = require('dnsbl');
const domains = require('disposable-email-domains');
const getFQDN = require('get-fqdn');
const ip = require('ip');
const isSANB = require('is-string-and-not-blank');
const ms = require('ms');
const nodemailer = require('nodemailer');
const parseDomain = require('parse-domain');
const punycode = require('punycode/');
const sharedConfig = require('@ladjs/shared-config');
const spfCheck2 = require('python-spfcheck2');
const validator = require('validator');
const wildcards = require('disposable-email-domains/wildcard.json');
const { SMTPServer } = require('smtp-server');
const { boolean } = require('boolean');
const { oneLine } = require('common-tags');

let mailUtilities = require('mailin/lib/mailUtilities.js');

const verifyDKIM = util.promisify(NodeDKIM.verify).bind(NodeDKIM);

const {
  CustomError,
  MessageSplitter,
  createMessageID,
  env,
  logger
} = require('./helpers');

mailUtilities = Promise.promisifyAll(mailUtilities);

const CODES_TO_RESPONSE_CODES = {
  ETIMEDOUT: 420,
  ECONNRESET: 442,
  EADDRINUSE: 421,
  ECONNREFUSED: 421,
  EPIPE: 421,
  ENOTFOUND: 421,
  ENETUNREACH: 421,
  EAI_AGAIN: 421
};

const RETRY_CODES = _.keys(CODES_TO_RESPONSE_CODES);
const transporterConfig = {
  debug: !env.IS_SILENT,
  logger,
  direct: true,
  opportunisticTLS: true,
  port: 25,
  tls: {
    rejectUnauthorized: env.NODE_ENV !== 'test'
  },
  connectionTimeout: ms('5s'),
  greetingTimeout: ms('5s'),
  socketTimeout: 0
};

class ForwardEmail {
  constructor(config = {}) {
    this.config = {
      ...sharedConfig('SMTP'),
      // TODO: eventually set 127.0.0.1 as DNS server
      // for both `dnsbl` and `dns` usage
      // https://gist.github.com/zhurui1008/48130439a079a3c23920
      //
      // <https://blog.cloudflare.com/announcing-1111/>
      // TODO: <https://github.com/niftylettuce/forward-email/issues/131#issuecomment-490484052>
      dns: env.DNS_PROVIDERS,
      noReply: env.EMAIL_NOREPLY,
      logger,
      smtp: {
        size: bytes(env.SMTP_MESSAGE_MAX_SIZE),
        onConnect: this.onConnect.bind(this),
        onData: this.onData.bind(this),
        onMailFrom: this.onMailFrom.bind(this),
        onRcptTo: this.onRcptTo.bind(this),
        disabledCommands: ['AUTH'],
        logInfo: !env.IS_SILENT,
        logger,
        ...config.smtp
      },
      blacklistedStr:
        "Your mail server's IP address of %s is listed on the %s DNS blacklist (visit %s to submit a removal request and try again).",
      dnsbl: {
        domains: env.DNSBL_DOMAINS,
        removals: env.DNSBL_REMOVALS
      },
      exchanges: env.SMTP_EXCHANGE_DOMAINS,
      dkim: {
        domainName: env.DKIM_DOMAIN_NAME,
        keySelector: env.DKIM_KEY_SELECTOR,
        privateKey: fs.readFileSync(env.DKIM_PRIVATE_KEY_PATH, 'utf8'),
        cacheDir: os.tmpdir()
      },
      maxForwardedAddresses: env.MAX_FORWARDED_ADDRESSES,
      email: env.EMAIL_SUPPORT,
      website: env.WEBSITE_URL,
      recordPrefix: env.TXT_RECORD_PREFIX,
      ...config
    };

    if (
      this.dnsbl &&
      Array.isArray(this.dnsbl.domains) &&
      Array.isArray(this.dnsbl.removals) &&
      this.dnsbl.domains.length !== this.dnsbl.removals.length
    )
      throw new Error('DNSBL_DOMAINS length must be equal to DNSBL_REMOVALS');

    if (this.config.ssl) {
      if (boolean(process.env.IS_NOT_SECURE)) this.config.ssl.secure = false;
      else this.config.ssl.secure = true;
    }

    this.config.smtp = {
      ...this.config.smtp,
      ...this.config.ssl
    };

    // set up DKIM instance for signing messages
    this.dkim = new DKIM(this.config.dkim);

    // initialize redis
    const client = new Redis(
      this.config.redis,
      logger,
      this.config.redisMonitor
    );

    // setup rate limiting with redis
    /*
    if (this.config.rateLimit) {
      this.limiter = {
        db: client,
        ...this.config.rateLimit
      };
    }
    */

    // expose client
    this.client = client;
    // setup our smtp server which listens for incoming email
    this.server = new SMTPServer(this.config.smtp);
    // kind of hacky but I filed a GH issue
    // <https://github.com/nodemailer/smtp-server/issues/135>
    this.server.address = this.server.server.address.bind(this.server.server);
    this.server.on('error', err => {
      logger.error(err);
    });

    this.dns = Promise.promisifyAll(dns);
    this.dns.setServers(this.config.dns);

    this.listen = this.listen.bind(this);
    this.close = this.close.bind(this);
    this.processRecipient = this.processRecipient.bind(this);
    this.processAddress = this.processAddress.bind(this);
    this.sendEmail = this.sendEmail.bind(this);
    this.rewriteFriendlyFrom = this.rewriteFriendlyFrom.bind(this);
    this.parseUsername = this.parseUsername.bind(this);
    this.parseFilter = this.parseFilter.bind(this);
    this.parseDomain = this.parseDomain.bind(this);
    this.onConnect = this.onConnect.bind(this);
    this.checkBlacklists = this.checkBlacklists.bind(this);
    this.onData = this.onData.bind(this);
    this.validateSPF = this.validateSPF.bind(this);
    this.getDMARC = this.getDMARC.bind(this);
    this.validateDKIM = this.validateDKIM.bind(this);
    this.validateMX = this.validateMX.bind(this);
    this.validateRateLimit = this.validateRateLimit.bind(this);
    this.isBlacklisted = this.isBlacklisted.bind(this);
    this.isDisposable = this.isDisposable.bind(this);
    this.onMailFrom = this.onMailFrom.bind(this);
    this.getForwardingAddresses = this.getForwardingAddresses.bind(this);
    this.onRcptTo = this.onRcptTo.bind(this);
  }

  async listen(port) {
    await util.promisify(this.server.listen).bind(this.server)(
      port || this.config.port
    );
  }

  async close() {
    await util.promisify(this.server.close).bind(this.server);
  }

  processRecipient(options) {
    const { recipient, name, from, raw } = options;
    const { address, addresses } = recipient;
    return Promise.all(
      addresses.map(({ to, host }) => {
        return this.processAddress(address, {
          to,
          host,
          name,
          from,
          raw: this.dkim.sign(raw)
        });
      })
    );
  }

  async processAddress(address, options) {
    try {
      const info = await this.sendEmail(options);
      logger.log(info);
      return info;
    } catch (err) {
      // here we do some magic so that we push an error message
      // that has the end-recipient's email masked with the
      // original to address that we were trying to send to
      err.message = err.message.replace(new RegExp(options.to, 'gi'), address);
      logger.error(err);
      return {
        accepted: [],
        rejected: [address],
        rejectedErrors: [err]
      };
    }
  }

  // TODO: eventually we can combine multiple recipients
  // that have the same MX records in the same envelope `to`
  sendEmail(options) {
    const { to, host, name, from, raw } = options;
    const transporter = nodemailer.createTransport({
      ...transporterConfig,
      ...this.config.ssl,
      host,
      name
    });
    return transporter.sendMail({ envelope: { from, to }, raw });
  }

  rewriteFriendlyFrom(from) {
    // preserve user's name
    const { address, name } = addressParser(from)[0];
    if (!name || name.trim() === '')
      return `"${address}" <${this.config.noReply}>`;
    return `"${name}" <${this.config.noReply}>`;
  }

  parseUsername(address) {
    ({ address } = addressParser(address)[0]);
    let username = address.includes('+')
      ? address.split('+')[0]
      : address.split('@')[0];

    username = punycode.toASCII(username).toLowerCase();
    return username;
  }

  parseFilter(address) {
    ({ address } = addressParser(address)[0]);
    return address.includes('+') ? address.split('+')[1].split('@')[0] : '';
  }

  parseDomain(address, isSender = true) {
    let domain = addressParser(address)[0].address.split('@')[1];
    domain = punycode.toASCII(domain);

    // check against blacklist
    if (this.isBlacklisted(domain))
      throw new CustomError('Blacklisted domains are not permitted');

    // ensure fully qualified domain name
    /*
    if (!validator.isFQDN(domain))
      throw new CustomError(
        `${domain} is not a fully qualified domain name ("FQDN")`
      );
    */

    // prevent disposable email addresses from being used
    if (isSender && this.isDisposable(domain))
      throw new CustomError(
        `Disposable email address domain of ${domain} is not permitted`
      );

    return domain;
  }

  async checkBlacklists(ip) {
    // if no blacklists are provided then return early
    if (
      !this.config.dnsbl ||
      !this.config.dnsbl.domains ||
      (Array.isArray(this.config.dnsbl.domains) &&
        this.config.dnsbl.domains.length === 0)
    ) {
      logger.warn('No DNS blacklists were provided');
      return false;
    }

    if (Array.isArray(this.config.dnsbl.domains)) {
      const results = await dnsbl.batch(ip, this.config.dnsbl.domains, {
        servers: this.config.dns
      });
      if (!Array.isArray(results) || results.length === 0) return false;
      const blacklistedResults = results.filter(result => result.listed);
      if (blacklistedResults.length === 0) return false;
      return blacklistedResults
        .map(result =>
          util.format(
            this.config.blacklistedStr,
            ip,
            result.blacklist,
            this.config.dnsbl.removals[
              this.config.dnsbl.domains.indexOf(result.blacklist)
            ]
          )
        )
        .join(' ');
    }

    const result = await dnsbl.lookup(ip, this.config.dnsbl.domains, {
      servers: this.config.dns
    });
    if (!result) return false;
    return util.format(
      this.config.blacklistedStr,
      ip,
      this.config.dnsbl.domains,
      this.config.dnsbl.removals
    );
  }

  async onConnect(session, fn) {
    if (env.NODE_ENV === 'test') return fn();

    // TODO: implement stricter spam checking to alleviate this
    // ensure it's a fully qualififed domain name
    /*
    if (!validator.isFQDN(session.clientHostname))
      return fn(
        new CustomError(
          `${session.clientHostname} is not a fully qualified domain name ("FQDN")`
        )
      );
    */

    // ensure that it's not on the DNS blacklist
    // Spamhaus = zen.spamhaus.org
    // SpamCop = bl.spamcop.net
    // Barracuda = b.barracudacentral.org
    // Lashback = ubl.unsubscore.com
    // PSBL = psbl.surriel.com
    try {
      const message = await this.checkBlacklists(session.remoteAddress);
      if (!message) return fn();
      const err = new CustomError(message, 554);
      logger.error(err);
      fn(err);
    } catch (err) {
      logger.error(err);
      fn();
    }
  }

  async onData(stream, session, fn) {
    //
    // store an object of email addresses that bounced
    // with their associated error that occurred
    //
    const bounces = [];

    //
    // store an array of chunks of the message
    //
    const chunks = [];

    //
    // read the message headers and message itself
    //
    const messageSplitter = new MessageSplitter({
      size: this.config.smtp.size
    });

    messageSplitter.on('readable', () => {
      let chunk;
      while ((chunk = messageSplitter.read()) !== null) {
        chunks.push(chunk);
      }
    });

    //
    // if an error occurs we have to continue reading the stream
    //
    messageSplitter.once('error', err => {
      stream.unpipe(messageSplitter);
      stream.on('readable', () => {
        stream.read();
      });
      stream.once('end', () => fn(err));
    });

    // eslint-disable-next-line complexity
    messageSplitter.once('end', async () => {
      //
      // we need to check the following:
      //
      // 1) X if email file size exceeds the limit (no bottleneck)
      // 2) X ensure all email headers were parsed
      // 3) X prevent replies to no-reply@forwardemail.net (no bottleneck)
      // 4) X check for spam (score must be < 5) (child process spam daemon)
      // 5) X if DKIM signature passed and was valid (child process python)
      // 6) X if SPF is valid (child process python)
      // 7) X check for DMARC compliance (DNS lookup)
      // 8) X reverse SPF check and rewrite with friendly-from (DNS lookup)
      // 9) X rewrite message ID and lookup multiple recipients
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
        if (stream.sizeExceeded)
          throw new CustomError(
            `Maximum allowed message size ${bytes(
              this.config.smtp.size
            )} exceeded`,
            552
          );

        //
        // 2) ensure all email headers were parsed
        //
        if (!messageSplitter.headersParsed)
          throw new CustomError(
            'Headers were unable to be parsed, please try again',
            421
          );

        //
        // 3) prevent replies to no-reply@forwardemail.net
        //
        if (
          _.every(
            session.envelope.rcptTo,
            to => to.address === this.config.noReply
          )
        )
          throw new CustomError(
            oneLine`You need to reply to the "Reply-To" email address on the email; do not send messages to <${this.config.noReply}>`
          );

        //
        // store variables for use later
        //
        let rewriteFriendlyFrom = false;
        // headers object (includes the \r\n\r\n header and body separator)
        const { headers } = messageSplitter;
        const originalFrom = headers.getFirst('from');

        // parse the from address and set a parsed reply-to if necessary
        const fromAddress = addressParser(originalFrom)[0];
        const replyTo =
          fromAddress.name && fromAddress.name.trim() !== ''
            ? `"${fromAddress.name}" <${fromAddress.address}>`
            : fromAddress.address;

        // message body as a single Buffer (everything after the \r\n\r\n separator)
        const originalRaw = Buffer.concat([headers.build(), ...chunks]);

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
          logger.error(err);
        }

        if (spamScore >= env.SPAM_SCORE_THRESHOLD)
          throw new CustomError(
            `Message detected as spam (spam score of ${spamScore} exceeds threshold of ${env.SPAM_SCORE_THRESHOLD})`,
            554
          );

        //
        // 5) if DKIM signature passed and was valid
        //
        //
        // if and only if there was a `dkim-signature` or `x-google-dkim-signature` header
        //
        if (
          headers.getFirst('dkim-signature') !== '' ||
          headers.getFirst('x-google-dkim-signature') !== ''
        )
          await this.validateDKIM(originalRaw);

        // get the fully qualified domain name ("FQDN") of this server
        const ipAddress =
          env.NODE_ENV === 'test'
            ? await this.dns.lookupAsync(this.config.exchanges[0])
            : ip.address();
        const name = await getFQDN(ipAddress);

        //
        // 6) if SPF is valid
        //
        const spf = await this.validateSPF(
          env.NODE_ENV === 'test' ? ipAddress : session.remoteAddress,
          session.envelope.mailFrom.address,
          env.NODE_ENV === 'test' ? name : session.clientHostname
        );
        if (!['pass', 'neutral', 'none', 'softfail'].includes(spf))
          throw new CustomError(
            `The email you sent has failed SPF validation with a result of "${spf}"`
          );

        //
        // 7) check for DMARC compliance
        //
        const fromDomain = session.envelope.mailFrom.address.split('@')[1];
        const dmarcRecord = await this.getDMARC(fromDomain);
        if (dmarcRecord) {
          try {
            const result = dmarcParse(dmarcRecord);
            if (
              !_.isObject(result) ||
              !_.isObject(result.tags) ||
              !_.isObject(result.tags.p) ||
              !_.isString(result.tags.p.value)
            )
              throw new CustomError(
                `Invalid DMARC parsed result for ${fromDomain}`
              );
            // if quarantine or reject then we need to rewrite w/friendly-from
            if (
              ['quarantine', 'reject'].includes(
                result.tags.p.value.toLowerCase().trim()
              )
            ) {
              rewriteFriendlyFrom = true;
              // eslint-disable-next-line max-depth
              if (headers.getFirst('reply-to') === '')
                headers.update('Reply-To', replyTo);
              headers.update('From', this.rewriteFriendlyFrom(originalFrom));
            }
          } catch (err) {
            logger.error(err);
          }
        }

        //
        // 8) reverse SPF check and rewrite with friendly-from (DNS lookup)
        //
        if (!rewriteFriendlyFrom) {
          const reverseSpf = await this.validateSPF(
            // our server's current IP address
            ipAddress,
            // original from address
            session.envelope.mailFrom.address,
            // is to which exchange/FQDN without assuming it's the first
            name
          );

          if (!['pass', 'neutral', 'none'].includes(reverseSpf)) {
            rewriteFriendlyFrom = true;
            if (headers.getFirst('reply-to') === '')
              headers.update('Reply-To', originalFrom);
            headers.update('From', this.rewriteFriendlyFrom(originalFrom));
          }
        }

        //
        // 9) rewrite message ID and lookup multiple recipients
        //
        let rewritten = false;

        // TODO: message-id should be the same if the message gets retried
        // that way duplicate messages sent in part due to failure will have
        // the same re-created message id
        const messageId = createMessageID(session);

        let recipients = await Promise.all(
          session.envelope.rcptTo.map(async to => {
            try {
              // bounce message if it was sent to no-reply@
              if (to.address === this.config.noReply)
                throw new CustomError(
                  oneLine`You need to reply to the "Reply-To" email address on the email; do not send messages to <${this.config.noReply}>`
                );

              // get all forwarding addresses for this individual address
              const addresses = await this.getForwardingAddresses(to.address);

              // if we already rewrote headers no need to continue
              if (rewritten) return { address: to.address, addresses };

              // Gmail won't show the message in the inbox if it's sending FROM
              // the same address that gets forwarded TO using our service
              // (we can assume that other mail providers do the same)
              for (const address of addresses) {
                if (rewritten) break;
                const fromAddress = addressParser(originalFrom)[0].address;
                if (address !== fromAddress) continue;
                rewritten = true;
                if (headers.getFirst('message-id') !== '')
                  headers.update('In-Reply-To', headers.getFirst('message-id'));
                headers.update('Message-ID', messageId);
              }

              return { address: to.address, addresses };
            } catch (err) {
              logger.error(err);
              bounces.push({
                address: to.address,
                err
              });
            }
          })
        );

        // flatten the recipients and make them unique
        recipients = _.uniqBy(_.compact(_.flatten(recipients)), 'address');

        // go through recipients and if we have a user+xyz@domain
        // AND we also have user@domain then honor the user@domain only
        // (helps to alleviate bulk spam with services like Gmail)
        recipients = recipients.map(recipient => {
          recipient.addresses = recipient.addresses.filter(address => {
            if (!address.includes('+')) return true;
            return !recipient.addresses.includes(
              `${this.parseUsername(address)}@${this.parseDomain(
                address,
                false
              )}`
            );
          });
          return recipient;
        });

        recipients = await Promise.all(
          recipients.map(async recipient => {
            try {
              const errors = [];
              const { addresses } = recipient;
              recipient.addresses = await Promise.all(
                addresses.map(async address => {
                  try {
                    const addresses = await this.validateMX(address);
                    // `addresses` are already pre-sorted by lowest priority
                    return { to: address, host: addresses[0].exchange };
                  } catch (err) {
                    logger.error(err);
                    errors.push({
                      address,
                      err
                    });
                  }
                })
              );
              recipient.addresses = _.compact(recipient.addresses);
              if (!_.isEmpty(recipient.addresses)) return recipient;
              throw new Error(
                errors.map(error => `${error.address}: ${error.err.message}`)
              );
            } catch (err) {
              logger.error(err);
              bounces.push({
                address: recipient.address,
                err
              });
            }
          })
        );

        recipients = _.compact(recipients);

        // if no recipients return early with bounces joined together
        if (_.isEmpty(recipients)) {
          if (_.isEmpty(bounces)) throw new CustomError('Invalid recipients');
          throw new CustomError(
            bounces
              .map(
                bounce =>
                  `Error for ${bounce.address} of "${bounce.err.message}"`
              )
              .join(', ')
          );
        }

        //
        // 10) add our own DKIM signature and remove DKIM header (no bottleneck)
        //

        // remove existing signatures
        headers.remove('dkim-signature');
        headers.remove('x-google-dkim-signature');

        // join headers object and body into a full rfc822 formatted email
        // headers.build() compiles headers into a Buffer with the \r\n\r\n separator
        // (eventually we call `dkim.sign(raw)` and pass it to nodemailer's `raw` option)
        const raw = Buffer.concat([headers.build(), ...chunks]);

        // set from address based if we had to do a friendly-from rewrite
        const from = rewriteFriendlyFrom
          ? this.config.noReply
          : session.envelope.mailFrom.address;

        //
        // 11) send email
        //
        try {
          const accepted = [];
          await Promise.all(
            recipients.map(async recipient => {
              const results = await this.processRecipient({
                recipient,
                name,
                from,
                raw
              });
              for (const element of results) {
                // TODO: a@a.com -> b@b.com + c@c.com when c@c.com fails
                // it will still say a@a.com is successful
                // but it will be confusing because the b@b.com will be
                // masked to a@a.com and the end user will see that there
                // was both a success and a failure for the same address
                // (perhaps we indicate this user has email forwarded?)
                if (element.accepted.length > 0)
                  accepted.push(recipient.address);
                if (element.rejected.length === 0) continue;
                for (let x = 0; x < element.rejected.length; x++) {
                  const err = element.rejectedErrors[x];
                  bounces.push({
                    address: recipient.address,
                    err
                  });
                }
              }
            })
          );

          if (bounces.length === 0) return fn();

          const codes = bounces.map(bounce => {
            if (_.isNumber(bounce.err.responseCode))
              return bounce.err.responseCode;
            if (
              _.isString(bounce.err.code) &&
              RETRY_CODES.includes(bounce.err.code)
            )
              return CODES_TO_RESPONSE_CODES[bounce.err.code];
            return 550;
          });

          // sort the codes and get the lowest one
          // (that way 4xx retries are attempted)
          const [code] = codes.sort();

          const messages = [];

          if (accepted.length > 0)
            messages.push(
              `Message was sent successfully to ${arrayJoinConjunction(
                accepted
              )}`
            );

          for (const element of bounces) {
            messages.push(
              `Error for ${element.address} of "${element.err.message}"`
            );
          }

          // join the messages together and make them unique
          const err = new CustomError(_.uniq(messages).join(', '), code);

          logger.error(err);

          fn(err);
        } catch (err) {
          stream.destroy(err);
        }
      } catch (err) {
        stream.destroy(err);
      }
    });

    stream.once('error', err => {
      // parse SMTP code and message
      if (err.message && err.message.startsWith('SMTP code:')) {
        err.responseCode = err.message.split('SMTP code:')[1].split(' ')[0];
        err.message = err.message.split('msg:')[1];
      }

      err.message += ` - if you need help please forward this email to ${this.config.email} or visit ${this.config.website}`;
      logger.error(err);
      fn(err);
    });

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
    try {
      const [result, explanation] = await spfCheck2(
        remoteAddress,
        from,
        clientHostname
      );
      if (['permerror', 'temperror'].includes(result))
        throw new CustomError(
          `SPF validation failed with result "${result}" and explanation "${explanation}"`
        );
      return result;
    } catch (err) {
      err.responseCode = 421;
      throw err;
    }
  }

  async getDMARC(hostname) {
    if (env.NODE_ENV === 'test') hostname = 'forwardemail.net';
    const parsedDomain = parseDomain(hostname);
    if (!parsedDomain) return false;
    const entry = `_dmarc.${hostname}`;
    try {
      const records = await this.dns.resolveTxtAsync(entry);
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

      logger.error(err);
      // if there's an error then assume that we need to rewrite
      // with a friendly-from, for whatever reason
      return true;
    }
  }

  async validateDKIM(raw) {
    let results = [];
    try {
      results = await verifyDKIM(raw);
    } catch (err) {
      logger.error(err);
      err.responseCode = 421;
      throw err;
    }

    if (
      !Array.isArray(results) ||
      (Array.isArray(results) && results.length === 0) ||
      (Array.isArray(results) &&
        results.length > 0 &&
        results.every(
          result =>
            result.verified ||
            [NodeDKIM.NONE, NodeDKIM.OK].includes(result.status)
        ))
    )
      return true;

    const messages = results
      .filter(result => _.isError(result.error))
      .map(result => result.error.message);

    if (messages.length === 0)
      throw new CustomError('The email you sent has an invalid DKIM signature');

    // join the messages together and make them unique
    throw new CustomError(_.uniq(messages).join(', '));
  }

  async validateMX(address) {
    try {
      const domain = this.parseDomain(address);
      const addresses = await this.dns.resolveMxAsync(domain);
      if (!addresses || addresses.length === 0)
        throw new CustomError(
          `DNS lookup for ${domain} did not return any valid MX records`
        );
      return _.sortBy(addresses, 'priority');
    } catch (err) {
      if (/queryMx ENODATA/.test(err)) {
        err.message = `DNS lookup for ${address} did not return a valid MX record`;
        err.responseCode = 550;
      } else if (/queryTxt ENOTFOUND/.test(err)) {
        err.message = `DNS lookup for ${address} did not return a valid TXT record`;
        err.responseCode = 550;
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
      if (email === this.config.noReply || !this.limiter) return resolve();
      const id = email;
      const limit = new Limiter({ id, ...this.limiter });
      limit.get((err, limit) => {
        if (err) {
          err.responseCode = 421;
          return reject(err);
        }

        if (limit.remaining) return resolve();
        const delta = (limit.reset * 1000 - Date.now()) | 0;
        reject(
          new CustomError(
            `Rate limit exceeded, retry in ${ms(delta, { long: true })}`,
            451
          )
        );
      });
    });
  }

  isBlacklisted(domain) {
    return Array.isArray(env.BLACKLIST)
      ? env.BLACKLIST.includes(domain)
      : false;
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
      await Promise.all([
        this.validateRateLimit(address.address),
        this.validateMX(address.address)
      ]);
      fn();
    } catch (err) {
      fn(err);
    }
  }

  // TODO: we should cache this recursive lookup for 2m or something
  // this returns the forwarding address for a given email address
  async getForwardingAddresses(address, recursive = []) {
    const domain = this.parseDomain(address, false);
    const records = await this.dns.resolveTxtAsync(domain);

    // dns TXT record must contain `forward-email=` prefix
    const validRecords = [];

    // add support for multi-line TXT records
    for (let i = 0; i < records.length; i++) {
      records[i] = records[i].join(''); // join chunks together
      if (records[i].startsWith(`${this.config.recordPrefix}=`))
        validRecords.push(
          records[i].replace(`${this.config.recordPrefix}=`, '')
        );
    }

    // join multi-line TXT records together and replace double w/single commas
    const record = validRecords
      .join(',')
      .replace(/,+/g, ',')
      .trim();

    // if the record was blank then throw an error
    if (!isSANB(record))
      throw new CustomError(
        `${address} domain of ${domain} has a blank "${this.config.recordPrefix}" TXT record`
      );

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

    if (addresses.length === 0)
      throw new CustomError(
        `${address} domain of ${domain} has zero forwarded addresses configured in the TXT record with "${this.config.recordPrefix}"`
      );

    // store if we have a forwarding address or not
    let forwardingAddresses = [];

    // store if we have a global redirect or not
    const globalForwardingAddresses = [];

    // check if we have a specific redirect and store global redirects (if any)
    // get username from recipient email address
    // (e.g. hello@niftylettuce.com => hello)
    const username = this.parseUsername(address);

    for (let i = 0; i < addresses.length; i++) {
      // convert addresses to lowercase
      addresses[i] = addresses[i].toLowerCase();
      if (addresses[i].includes(':')) {
        const addr = addresses[i].split(':');

        if (addr.length !== 2 || !validator.isEmail(addr[1]))
          throw new CustomError(
            `${address} domain of ${domain} has an invalid "${this.config.recordPrefix}" TXT record due to an invalid email address of "${addresses[i]}"`
          );

        // addr[0] = hello (username)
        // addr[1] = niftylettuce@gmail.com (forwarding email)

        // check if we have a match
        if (username === addr[0]) forwardingAddresses.push(addr[1]);
      } else if (validator.isFQDN(addresses[i])) {
        // allow domain alias forwarding
        // (e.. the record is just "b.com" if it's not a valid email)
        globalForwardingAddresses.push(`${username}@${addresses[i]}`);
      } else {
        const domain = this.parseDomain(addresses[i], false);
        if (validator.isFQDN(domain) && validator.isEmail(addresses[i])) {
          globalForwardingAddresses.push(addresses[i]);
        }
      }
    }

    // if we don't have a specific forwarding address try the global redirect
    if (
      forwardingAddresses.length === 0 &&
      globalForwardingAddresses.length > 0
    ) {
      globalForwardingAddresses.forEach(address => {
        forwardingAddresses.push(address);
      });
    }

    // if we don't have a forwarding address then throw an error
    if (forwardingAddresses.length === 0)
      throw new CustomError(
        `${address} domain of ${domain} is not configured properly and does not contain any valid "${this.config.recordPrefix}" TXT records`
      );

    // allow one recursive lookup on forwarding addresses
    const recursivelyForwardedAddresses = [];
    await Promise.each(forwardingAddresses, async forwardingAddress => {
      try {
        if (recursive.includes(forwardingAddress)) return;

        const newRecursive = forwardingAddresses.concat(recursive);
        // prevent a double-lookup if user is using + symbols
        if (forwardingAddress.includes('+'))
          newRecursive.push(
            `${this.parseUsername(address)}@${this.parseDomain(address, false)}`
          );

        const addresses = await this.getForwardingAddresses(
          forwardingAddress,
          newRecursive
        );
        // if it was recursive then remove the original
        if (addresses.length > 0)
          recursivelyForwardedAddresses.push(forwardingAddress);
        // add the recursively forwarded addresses
        addresses.forEach(address => {
          forwardingAddresses.push(address);
        });
      } catch (err) {
        logger.error(err);
      }
    });

    // make the forwarding addresses unique
    // and omit the addresses recursively forwarded
    forwardingAddresses = _.uniq(forwardingAddresses);
    _.pullAll(forwardingAddresses, recursivelyForwardedAddresses);

    // NOTE:
    // issue is that people could work around the limit
    // for example:
    //
    // a:a.com
    // a:b.com
    // a:c.com
    // a:d.com
    // a:e.com
    // a:f.com <--- cut off after here
    //
    // a:test@domain.com
    // test:f.com <-- here is workaround
    // test:g.com
    // test:h.com
    // ...

    // if max number of forwarding addresses exceeded
    if (forwardingAddresses.length > this.config.maxForwardedAddresses)
      throw new CustomError(
        `The address ${address} is attempted to be forwarded to (${forwardingAddresses.length}) addresses which exceeds the maximum of (${this.config.maxForwardedAddresses})`
      );

    // otherwise transform the + symbol filter if we had it
    // and then resolve with the newly formatted forwarding address
    // (we can return early here if there was no + symbol)
    if (!address.includes('+')) return forwardingAddresses;

    return forwardingAddresses.map(forwardingAddress => {
      return `${this.parseUsername(forwardingAddress)}+${this.parseFilter(
        address
      )}@${this.parseDomain(forwardingAddress, false)}`;
    });
  }

  async onRcptTo(address, session, fn) {
    try {
      // validate forwarding address by looking up TXT record `forward-email=`
      await this.getForwardingAddresses(address.address);

      // validate MX records exist and contain ours
      const addresses = await this.validateMX(address.address);
      const exchanges = addresses.map(mxAddress => mxAddress.exchange);
      const hasAllExchanges = this.config.exchanges.every(exchange =>
        exchanges.includes(exchange)
      );
      if (hasAllExchanges) return fn();
      throw new CustomError(
        `${
          address.address
        } is missing required DNS MX records of ${this.config.exchanges.join(
          ', '
        )}`
      );
    } catch (err) {
      fn(err);
    }
  }
}

module.exports = ForwardEmail;
