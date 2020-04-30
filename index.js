const crypto = require('crypto');
const dns = require('dns');
const fs = require('fs');
// const tls = require('tls');
const util = require('util');

const DKIM = require('nodemailer/lib/dkim');
const Limiter = require('ratelimiter');
const Redis = require('@ladjs/redis');
const _ = require('lodash');
const addressParser = require('nodemailer/lib/addressparser');
const arrayJoinConjunction = require('array-join-conjunction');
const bytes = require('bytes');
const dkimVerify = require('python-dkim-verify');
const dmarcParse = require('dmarc-parse');
const dnsbl = require('dnsbl');
const domains = require('disposable-email-domains');
const getFQDN = require('get-fqdn');
const got = require('got');
const ip = require('ip');
const isSANB = require('is-string-and-not-blank');
// const mailUtilities = require('mailin/lib/mailUtilities.js');
const ms = require('ms');
const nodemailer = require('nodemailer');
const parseDomain = require('parse-domain');
const punycode = require('punycode/');
const sharedConfig = require('@ladjs/shared-config');
const spfCheck2 = require('python-spfcheck2');
const validator = require('validator');
const wildcards = require('disposable-email-domains/wildcard.json');
const { SMTPServer } = require('smtp-server');
const { SRS } = require('sender-rewriting-scheme');
const { boolean } = require('boolean');
const { oneLine } = require('common-tags');

const {
  CustomError,
  MessageSplitter,
  createMessageID,
  env,
  logger
} = require('./helpers');

const lookupAsync = util.promisify(dns.lookup);
const resolveTxtAsync = util.promisify(dns.resolveTxt);
const resolveMxAsync = util.promisify(dns.resolveMx);
// const computeSpamScoreAsync = util.promisify(mailUtilities.computeSpamScore);

/*
//
// omit ciphers according to hardenize
// <https://www.hardenize.com/report/forwardemail.net/1585706984#email_tls>
//
// Special thanks to Fedor Indutny <https://github.com/indutny> for their help with TLS configuration
//
// The mapping to Node.js cipher names is slightly different so this list is manually curated
//
const OMITTED_CIPHERS = [
  // TLS_RSA_WITH_AES_128_CBC_SHA
  'aes128-sha',
  // TLS_RSA_WITH_AES_128_CBC_SHA256
  'aes128-sha256',
  // TLS_RSA_WITH_AES_128_GCM_SHA256
  'aes128-gcm-sha256',
  // TLS_RSA_WITH_AES_256_CBC_SHA
  'aes256-sha',
  // TLS_RSA_WITH_AES_256_CBC_SHA256
  'aes256-sha256',
  // TLS_RSA_WITH_AES_256_GCM_SHA384
  'aes128-gcm-sha384'
];

const CIPHERS = `${tls.DEFAULT_CIPHERS}:${OMITTED_CIPHERS.map(
  cipher => `!${cipher.toUpperCase()}`
).join(':')}`;
*/

// From Fedor:
const CIPHERS = [
  'ECDHE-RSA-CHACHA20-POLY1305',
  'ECDHE-RSA-AES256-GCM-SHA384',
  'DHE-RSA-AES256-GCM-SHA384',
  'ECDHE-RSA-AES128-GCM-SHA256',
  'DHE-RSA-AES128-GCM-SHA256',
  'ECDHE-RSA-AES256-SHA384',
  'ECDHE-RSA-AES128-SHA256',
  'DHE-RSA-AES256-SHA256',
  'DHE-RSA-AES128-SHA256',
  'DHE-RSA-CHACHA20-POLY1305',
  'AES256-GCM-SHA384',
  'AES128-GCM-SHA256',
  'AES256-SHA256',
  'AES128-SHA256',

  // SHA128 is lame
  'ECDHE-RSA-AES256-SHA',
  'ECDHE-RSA-AES128-SHA',
  'DHE-RSA-AES256-SHA',
  'DHE-RSA-AES128-SHA',
  'AES256-SHA',
  'AES128-SHA'
].join(':');

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
      // BUT we would need to set up an API endpoint/functionality
      // on our service at https://forwardemail.net that would clear
      // the local dns cache at 127.0.0.1 after purging Cloudflare/Google
      // for both `dnsbl` and `dns` usage
      // <https://gist.github.com/zhurui1008/48130439a079a3c23920>
      // <https://github.com/niftylettuce/forward-email/issues/131#issuecomment-490484052>
      //
      // <https://blog.cloudflare.com/announcing-1111/>
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
        logger: !env.IS_SILENT, // doesn't seem to be bunyan compatible
        ...config.smtp
      },
      spamScoreThreshold: env.SPAM_SCORE_THRESHOLD,
      blacklist: env.BLACKLIST,
      blacklistedStr:
        "Your mail server's IP address of %s is listed on the %s DNS blacklist (visit %s to submit a removal request and try again).",
      dnsbl: {
        domains: env.DNSBL_DOMAINS,
        removals: env.DNSBL_REMOVALS,
        ...config.dnsbl
      },
      rateLimit: {
        duration: env.RATELIMIT_DURATION
          ? parseInt(env.RATELIMIT_DURATION, 10)
          : 60000,
        max: env.RATELIMIT_MAX ? parseInt(env.RATELIMIT_MAX, 10) : 100,
        prefix: env.RATELIMIT_PREFIX
          ? env.RATELIMIT_PREFIX
          : `limit_${env.NODE_ENV.toLowerCase()}`
      },
      exchanges: env.SMTP_EXCHANGE_DOMAINS,
      dkim: {
        domainName: env.DKIM_DOMAIN_NAME,
        keySelector: env.DKIM_KEY_SELECTOR,
        privateKey: isSANB(env.DKIM_PRIVATE_KEY_PATH)
          ? fs.readFileSync(env.DKIM_PRIVATE_KEY_PATH, 'utf8')
          : undefined,
        //
        // TODO: Add Feedback-ID for Google (?)
        //
        // Feedback-ID added before signed (assuming they want it signed?)
        // (5-15 characters, unique across mail stream for each SenderId)
        // Feedback-ID: a:b:c:SenderId (a,b,c are optional)
        // <https://support.google.com/mail/answer/6254652?hl=en>
        //
        // This header must also be stripped from the email (replaced)
        //
        // <https://github.com/nodemailer/nodemailer/blob/11121b88c58259a0374d8b22ec6509c43d1656cb/lib/dkim/sign.js#L22
        /*
        headerFieldNames: [
          'From',
          'Sender',
          'Reply-To',
          'Subject',
          'Date',
          'Message-ID',
          'To',
          'Cc',
          'MIME-Version',
          'Content-Type',
          'Content-Transfer-Encoding',
          'Content-ID',
          'Content-Description',
          'Resent-Date',
          'Resent-From',
          'Resent-Sender',
          'Resent-To',
          'Resent-Cc',
          'Resent-Message-ID',
          'In-Reply-To',
          'References',
          'List-Id',
          'List-Help',
          'List-Unsubscribe',
          'List-Subscribe',
          'List-Post',
          'List-Owner',
          'List-Archive'
        ].join(':'),
        */
        ...config.dkim
      },
      maxForwardedAddresses: env.MAX_FORWARDED_ADDRESSES,
      email: env.EMAIL_SUPPORT,
      website: env.WEBSITE_URL,
      recordPrefix: env.TXT_RECORD_PREFIX,
      whitelistedDisposableDomains: env.VANITY_DOMAINS,
      lookupEndpoint: env.LOOKUP_ENDPOINT,
      lookupSecrets: env.LOOKUP_SECRETS,
      srs: {
        separator: '=',
        secret: env.SRS_SECRET,
        maxAge: 30
      },
      srsDomain: env.SRS_DOMAIN,
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
      this.config.ssl.minVersion = 'TLSv1.2';
      this.config.ssl.ciphers = CIPHERS;
      //
      // should be automatic per `tls.createServer()` but just in case
      // <https://expeditedsecurity.com/blog/a-plus-node-js-ssl/>
      //
      this.config.ssl.honorCipherOrder = true;

      //
      // perfect forward secrecy with tls requires `dhparam`
      // https://nodejs.org/api/tls.html#tls_perfect_forward_secrecy
      // `openssl dhparam -outform PEM -out dhparam.pem 2048`
      //
      if (isSANB(env.DHPARAM_KEY_PATH))
        this.config.ssl.dhparam = fs.readFileSync(env.DHPARAM_KEY_PATH, 'utf8');

      // <https://tools.ietf.org/html/draft-ietf-tls-oldversions-deprecate-00#section-8>
      this.config.ssl.secureOptions =
        crypto.constants.SSL_OP_NO_SSLv2 |
        crypto.constants.SSL_OP_NO_SSLv3 |
        crypto.constants.SSL_OP_NO_TLSv1 |
        crypto.constants.SSL_OP_NO_TLSv11;
      delete this.config.ssl.allowHTTP1;
      if (boolean(process.env.IS_NOT_SECURE)) this.config.ssl.secure = false;
      else this.config.ssl.secure = true;
    }

    // Sender Rewriting Schema ("SRS")
    this.srs = new SRS(this.config.srs);

    // SMTP Server
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
    if (this.config.rateLimit) {
      this.limiter = {
        db: client,
        ...this.config.rateLimit
      };
    }

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

    dns.setServers(this.config.dns);

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
    this.checkSRS = this.checkSRS.bind(this);
    this.onMailFrom = this.onMailFrom.bind(this);
    this.getForwardingAddresses = this.getForwardingAddresses.bind(this);
    this.onRcptTo = this.onRcptTo.bind(this);
    this.conditionallyRemoveSignatures = this.conditionallyRemoveSignatures.bind(
      this
    );
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
          host,
          name,
          envelope: {
            from,
            to
          },
          raw
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
      err.message = err.message.replace(
        new RegExp(options.envelope.to, 'gi'),
        address
      );
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
    const { host, name, envelope, raw } = options;
    const transporter = nodemailer.createTransport({
      ...transporterConfig,
      ...this.config.ssl,
      host,
      name
    });
    return transporter.sendMail({ envelope, raw });
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
      throw new CustomError(
        `The domain ${domain} is blacklisted by ${this.config.website}`
      );

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
    /*
    // ensure it's a fully qualififed domain name
    if (!validator.isFQDN(session.clientHostname))
      return fn(
        new CustomError(
          `${session.clientHostname} is not a fully qualified domain name ("FQDN")`
        )
      );
    */

    try {
      // check against blacklist
      if (
        validator.isFQDN(session.clientHostname) &&
        this.isBlacklisted(session.clientHostname)
      )
        throw new CustomError(
          `The domain ${session.clientHostname} is blacklisted by ${this.config.website}`
        );

      if (this.isBlacklisted(session.remoteAddress))
        throw new CustomError(
          `The IP address ${session.remoteAddress} is blacklisted by ${this.config.website}`
        );

      // ensure that it's not on the DNS blacklist
      // Spamhaus = zen.spamhaus.org
      // SpamCop = bl.spamcop.net
      // Barracuda = b.barracudacentral.org
      // Lashback = ubl.unsubscore.com
      // PSBL = psbl.surriel.com
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
    // debugging
    //
    let originalRaw;

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
      // 3) X reverse SRS bounces
      // 4) X prevent replies to no-reply@forwardemail.net (no bottleneck)
      // 5) O check for spam (score must be < 5) (child process spam daemon)
      // 6) X if SPF is valid (child process python)
      // 7) X check for DMARC compliance
      // 8) X conditionally rewrite with friendly from if DMARC were to fail
      // 9) X rewrite message ID and lookup multiple recipients
      // 10) X add our own DKIM signature
      // 11) X set from address using SRS
      // 12) X send email
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
        // store variables for use later
        //
        // headers object (includes the \r\n\r\n header and body separator)
        const { headers } = messageSplitter;
        const messageId = headers.getFirst('message-id');
        const replyTo = headers.getFirst('reply-to');
        const inReplyTo = headers.getFirst('in-reply-to');

        //
        // 3) reverse SRS bounces
        //

        // <https://www.oreilly.com/library/view/programming-internet-email/9780596802585/ch02s04.html>
        // <https://tools.ietf.org/html/rfc822
        // TODO: either To, BCC are required on the message
        /*
        A.3.1.  Minimum required

          Date:     26 Aug 76 1429 EDT        Date:     26 Aug 76 1429 EDT
          From:     Jones@Registry.Org   or   From:     Jones@Registry.Org
          Bcc:                                To:       Smith@Registry.Org

             Note that the "Bcc" field may be empty, while the  "To"  field
             is required to have at least one address.
        */

        // check "To:" header
        const originalTo = headers.getFirst('to');
        if (!originalTo)
          throw new CustomError(
            'Your message is not RFC 5322 compliant, please include a valid "To" header.'
          );
        headers.update('to', this.checkSRS(originalTo));

        //
        // rewrite envelope rcpt to
        //
        session.envelope.rcptTo = session.envelope.rcptTo.map(to => ({
          ...to,
          address: this.checkSRS(to.address)
        }));

        //
        // 4) prevent replies to no-reply@forwardemail.net
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
        const originalFrom = headers.getFirst('from');

        if (!originalFrom)
          throw new CustomError(
            'Your message is not RFC 5322 compliant, please include a valid "From" header.'
          );

        // parse the domain of the RFC5322.From address
        const fromDomain = this.parseDomain(originalFrom);
        const parsedFromDomain = parseDomain(fromDomain);

        // message body as a single Buffer (everything after the \r\n\r\n separator)
        originalRaw = Buffer.concat([headers.build(), ...chunks]);

        //
        // 5) check for spam (score must be < 5)
        //
        // TODO: we need to replace the spam block below with implementation
        // // of `pdf-spamc-stream` from https://github.com/streamtOtO/spamc-stream
        // // note that this package name is published with several key updates
        //
        // TODO: we may also want to add clamav for attachment scanning
        /*
        let spamScore = 0;
        try {
          spamScore = await computeSpamScoreAsync(originalRaw);
        } catch (err) {
          logger.error(err);
        }

        if (spamScore >= this.config.spamScoreThreshold)
          throw new CustomError(
            `Message detected as spam (spam score of ${spamScore} exceeds threshold of ${this.config.spamScoreThreshold})`,
            554
          );
        */

        // get the fully qualified domain name ("FQDN") of this server
        let ipAddress;
        if (env.NODE_ENV === 'test') {
          const obj = await lookupAsync(this.config.exchanges[0]);
          ipAddress = obj.address;
        } else {
          ipAddress = ip.address();
        }

        const name = await getFQDN(ipAddress);

        //
        // 6) if SPF is valid
        //
        const spf = await this.validateSPF(
          session.remoteAddress,
          session.envelope.mailFrom.address,
          session.clientHostname
        );
        if (!['pass', 'neutral', 'none', 'softfail'].includes(spf))
          throw new CustomError(
            `The email you sent has failed SPF validation with a result of "${spf}"`
          );

        //
        // 7) check for DMARC compliance
        //
        // this section was written in accordance with "11.3.  Determine Handling Policy"
        // <https://dmarc.org/draft-dmarc-base-00-01.html#receiver_policy>
        //
        // DMARC authentication pass =
        // (SPF authentication pass AND SPF identifier alignment)
        // OR (DKIM authentication pass AND DKIM identifier alignment)
        //
        // Note that our implementation doesn't abide by any percentage thresholds
        // or send a DMARC report email to anyone at the moment
        // (since we don't store logs we can't implement a threshold to begin with)
        //
        const dmarcRecord = await this.getDMARC(fromDomain);
        let dmarcPass = true;
        let reject = false;
        if (dmarcRecord) {
          try {
            const result = dmarcParse(dmarcRecord.record);
            if (
              !_.isObject(result) ||
              !_.isObject(result.tags) ||
              !_.isObject(result.tags.p) ||
              !_.isString(result.tags.p.value)
            )
              throw new CustomError(
                `Invalid DMARC parsed result for ${fromDomain}`
              );

            // we shouldn't completely reject if it was quarantine
            // instead we should just add a spam header or something
            reject = result.tags.p.value === 'reject';

            // if the sp value indicates that subdomains should not be quarantined or rejected then set to false
            // dmarcRecord.hostname indicates the DMARC TXT hostname record found
            // handle result.tags.sp IF it exists and if domain doesn't match
            if (
              dmarcRecord.hostname !== fromDomain &&
              _.isObject(result.tags.sp) &&
              _.isString(result.tags.sp.value) &&
              result.tags.sp.value === 'none'
            )
              reject = false;

            /*
              // <https://dmarc.org/draft-dmarc-base-00-01.html#dmarc_format>
              adkim:
              (plain-text; OPTIONAL, default is "r".) Indicates whether or not strict DKIM identifier alignment is required by the Domain Owner.
              If and only if the value of the string is "s", strict mode is in use. See Section 4.2.1 for details.
              aspf:
              (plain-text; OPTIONAL, default is "r".) Indicates whether or not strict SPF identifier alignment is required by the Domain Owner.
              If and only if the value of the string is "s", strict mode is in use. See Section 4.2.2 for details.

              // <https://dmarc.org/draft-dmarc-base-00-01.html#id_alignment_element>
              4.2.1.  DKIM-authenticated Identifiers
              DMARC provides the option of applying DKIM in a strict mode or a relaxed mode {R2}.

              In relaxed mode, the Organizational Domain of the [DKIM]-authenticated signing domain (taken from the value of the "d=" tag in the signature)
              and that of the RFC5322.From domain must be equal. In strict mode, only an exact match is considered to produce identifier alignment.

              To illustrate, in relaxed mode, if a validated DKIM signature successfully verifies with a "d=" domain of "example.com", and the RFC5322.From
              domain is "alerts@news.example.com", the DKIM "d=" domain and the RFC5322.From domain are considered to be "in alignment". In strict mode, this test would fail.

              However, a DKIM signature bearing a value of "d=com" would never allow an "in alignment" result as "com" should appear on all public suffix lists, and therefore cannot be an Organizational Domain.

              Identifier alignment is required to prevent abuse by phishers that send DKIM-signed email using an arbitrary "d=" domain (such as a Cousin Domain) to pass authentication checks.

              4.2.2.  SPF-authenticated Identifiers
              DMARC provides the option of applying SPF in a strict mode or a relaxed mode {R2}.

              In relaxed mode, the [SPF]-authenticated RFC5321.MailFrom (commonly called the "envelope sender") domain and RFC5322.From domain must match or share the same Organizational Domain.
              The SPF-authenticated RFC5321.MailFrom domain may be a parent domain or child domain of the RFC5322.From domain. In strict mode, only an exact DNS domain match is considered to produce identifier alignment.

              For example, if a message passes an SPF check with an RFC5321.MailFrom domain of "cbg.bounces.example.com", and the address portion of the RFC5322.From field
              contains "payments@example.com", the Authenticated RFC5321.MailFrom domain identifier and the RFC5322.From domain are considered to be "in alignment" in relaxed mode, but not in strict mode.

              For purposes of identifier alignment, in relaxed mode, Organizational Domains of RFC5321.MailFrom domains that are a parent domain of the RFC5322.From domain
              are acceptable as many large organizations perform more efficient bounce processing by mapping the RFC5321.MailFrom domain to specific mailstreams.
              */
            let aspf = 'r';
            /* eslint-disable max-depth */
            if (
              _.isObject(result.tags.aspf) &&
              _.isString(result.tags.aspf.value)
            )
              aspf = result.tags.aspf.value;

            // ensure SPF matches s or r
            let hasPassingSPF = false;

            // only test if SPF passed to begin with
            if (spf === 'pass') {
              const envelopeFromDomain = this.parseDomain(
                session.envelope.mailFrom.address
              );
              const parsedEnvelopeFromDomain = parseDomain(envelopeFromDomain);

              // MAIL FROM envelope organization domain must match FROM organization domain in relaxed mode
              if (
                aspf === 'r' &&
                parsedEnvelopeFromDomain.domain === parsedFromDomain.domain
              ) {
                hasPassingSPF = true;
              } else if (aspf === 's' && envelopeFromDomain === fromDomain) {
                // MAIL FROM envelope domain must match exactly FROM domain in strict mode
                hasPassingSPF = true;
              }
            }

            //
            // inspired by dmarc-parse
            // <https://github.com/softvu/dmarc-parse/blob/master/index.js>
            //
            /*
              What is the difference between the "Mail From" and "From Header", aren't they the same?
              In email, like in real mail, there is the concept of an envelope containing the message.

              The envelope will have three pieces of identification information, the host greeting, the "MAIL FROM:" return address and the "RCPT TO:" list of recipient addresses.
              The message content comprises a set of header fields and a body. The body, in turn can be simple text or can be a structured, multi-media "MIME" object of attachments. The set of header fields can be quite extensive, but typically at least include: "Subject:" "Date:" the "To:" and "From:".
              The "MAIL FROM" command specifies the address of the recipient for return notices if any problems occur with the delivery of the message, such as non-delivery notices.

              The "From:" header field indicates who is the author of the message.

              The technical notation for referring to components of email information is: RFC5321.MailFrom and RFC5322.
              From according to the IETF RFCs where the field is defined and the specific field being referenced.

              All this information can be spoofed. DMARC protects the domain name of the RFC5322:From field against spoofing.
              */

            // ensure DKIM matches s or r
            /*
              DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=news;
              c=relaxed/relaxed; q=dns/txt; t=1126524832; x=1149015927;
              h=from:to:subject:date:keywords:keywords;
              bh=MHIzKDU2Nzf3MDEyNzR1Njc5OTAyMjM0MUY3ODlqBLP=;
              b=hyjCnOfAKDdLZdKIc9G1q7LoDWlEniSbzc+yuU2zGrtruF00ldcF
              VoG4WTHNiYwG
              */
            /*
              > parseDomain('foobaz.beep.com')
              { tld: 'com', domain: 'beep', subdomain: 'foobaz' }
              > parseDomain('beep.com')
              { tld: 'com', domain: 'beep', subdomain: '' }
              */

            // note that the dkim verify python function only verifies first
            // dkim-signature header found, not all headers found
            // (which will conflict with DMARC since DMARC can pass alignment for any DKIM signature)
            // so we have to pass an index for each
            //
            // Note that a single email can contain multiple DKIM signatures, and it
            // is considered to be a DMARC "pass" if any DKIM signature is aligned
            // and verifies.
            //
            let hasPassingDKIM = false;

            if (!hasPassingSPF) {
              let adkim = 'r';
              if (
                _.isObject(result.tags.adkim) &&
                _.isString(result.tags.adkim.value)
              )
                adkim = result.tags.adkim.value;
              const signatures = headers.get('dkim-signature');
              // const updatedTo = headers.getFirst('to') !== originalTo;
              for (const [i, signature] of signatures.entries()) {
                // eslint-disable-next-line no-await-in-loop
                const isValidDKIM = await this.validateDKIM(originalRaw, i);
                if (!isValidDKIM) continue;
                const terms = signature
                  .split(/;/)
                  .map(t => t.trim())
                  .filter(t => t !== '');
                const rules = terms.map(t => t.split(/[=]/).map(r => r.trim()));
                for (const rule of rules) {
                  // term = d
                  // value = example.com
                  const [term, value] = rule;

                  if (term !== 'd') continue;
                  const dkimParsedDomain = parseDomain(value);

                  // relaxed mode means the domain can be a subdomain
                  // strict mode means the domain must be exact match
                  if (
                    (adkim === 'r' &&
                      dkimParsedDomain.domain === parsedFromDomain.domain) ||
                    (adkim === 's' && value === fromDomain)
                  ) {
                    hasPassingDKIM = true;
                    break;
                  }
                }

                // if at least one signature passes DKIM then it
                // is to be considered passing DKIM check for DMARC
                if (hasPassingDKIM) break;
              }
            }

            // if both DKIM and SPF fails then fail DMARC policy
            if (!hasPassingDKIM && !hasPassingSPF) dmarcPass = false;

            //
            // 8) conditionally rewrite with friendly from if DMARC were to fail
            //
            // we have to do this because if DKIM fails BUT SPF passes
            // then when we forward the message along, the DMARC SPF check
            // would fail on the FROM (e.g. message@netflix.com)
            // and the new SPF check would be against @forwardemail.net due to SRS
            // which would fail DMARC since the SPF check would be netflix.com versus forwardemail.net
            //
            if (reject && !hasPassingDKIM && hasPassingSPF) {
              //
              // if the DKIM signature signs the Reply-To and the From
              // then we will probably want to remove it since it won't be valid anymore
              //
              const changes = ['from', 'x-original-from'];
              headers.update('From', this.rewriteFriendlyFrom(originalFrom));
              headers.update('X-Original-From', originalFrom);
              //
              // if there was an original reply-to on the email
              // then we don't want to modify it of course
              //
              if (!replyTo) {
                changes.push('reply-to');
                headers.update('Reply-To', originalFrom);
              }

              // conditionally remove signatures necessary
              this.conditionallyRemoveSignatures(headers, changes);
            }

            /* eslint-enable max-depth */
          } catch (err) {
            logger.error(err);
          }
        }

        // throw an error if dmarc did not pass
        // and we it was a reject policy
        if (!dmarcPass && reject)
          throw new CustomError(
            `Unauthenticated email from ${fromDomain} is not accepted due to domain's DMARC policy. See https://dmarc.org to learn more about the DMARC initiative.`
          );

        //
        // 9) rewrite message ID and lookup multiple recipients
        //
        let rewritten = false;
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

              if (addresses === false)
                return { address: to.address, addresses: [], ignored: true };

              // if we already rewrote headers no need to continue
              if (rewritten) return { address: to.address, addresses };

              // the same address that gets forwarded TO using our service
              // (we can assume that other mail providers do the same)
              for (const address of addresses) {
                if (rewritten) break;
                const fromAddress = addressParser(originalFrom)[0].address;
                if (address !== fromAddress) continue;
                rewritten = true;

                //
                // if there was no message id then we don't need to add one
                // otherwise if there was one, then we need to consider dkim
                // and any passing signatures had had a changed header
                // need removed (we keep track of changed headers below)
                //
                if (messageId) {
                  const changes = ['message-id', 'x-original-message-id'];
                  headers.update('Message-ID', createMessageID(session));
                  headers.update('X-Original-Message-ID', messageId);
                  // don't modify the reply-to if it was already set
                  if (!inReplyTo) {
                    changes.push('in-reply-to');
                    headers.update('In-Reply-To', messageId);
                  }

                  // conditionally remove signatures necessary
                  this.conditionallyRemoveSignatures(headers, changes);
                }
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
                    // e.g. if the MX servers don't exist for recipient
                    // then obviously there should be an error
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
              if (errors.length === 0) return recipient;
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
        // 10) add our own DKIM signature
        //

        // join headers object and body into a full rfc822 formatted email
        // headers.build() compiles headers into a Buffer with the \r\n\r\n separator
        // (eventually we call `dkim.sign(raw)` and pass it to nodemailer's `raw` option)
        const raw = this.dkim.sign(Buffer.concat([headers.build(), ...chunks]));

        // 11) set from address using SRS
        const from = this.srs.forward(
          session.envelope.mailFrom.address,
          this.config.srsDomain
        );

        //
        // 12) send email
        //
        try {
          const accepted = [];
          await Promise.all(
            recipients.map(async recipient => {
              // return early if recipient is ignored
              if (recipient.ignored) return;
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
      const log = { session };
      if (originalRaw) log.email = originalRaw.toString();
      logger.error(err, log);
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
    // if (env.NODE_ENV === 'test') hostname = 'forwardemail.net';
    const parsedDomain = parseDomain(hostname);
    if (!parsedDomain) return false;
    const entry = `_dmarc.${hostname}`;
    try {
      const records = await resolveTxtAsync(entry);
      // note that it's an array of arrays [ [ 'v=DMARC1' ] ]
      if (!_.isArray(records) || _.isEmpty(records)) return false;
      if (!_.isArray(records[0]) || _.isEmpty(records[0])) return false;
      // join together the record by space
      return { hostname, record: records[0].join(' ') };
    } catch (err) {
      // recursively look up from subdomain to parent domain for record
      if (_.isString(err.code) && err.code === 'ENOTFOUND') {
        // no dmarc record exists so return `false`
        if (!parsedDomain.subdomain) return false;
        // otherwise attempt to lookup the parent domain's DMARC record instead
        return this.getDMARC(`${parsedDomain.domain}.${parsedDomain.tld}`);
      }

      logger.error(err);
      return false;
    }
  }

  async validateDKIM(raw, index) {
    try {
      const pass = await dkimVerify(raw, index);
      return pass;
    } catch (err) {
      logger.error(err);
      err.message = `Your email contained an invalid DKIM signature. For more information visit https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail. You can also reach out to us for help analyzing this issue.  Original error message: ${err.message}`;
      err.responseCode = 421;
      throw err;
    }
  }

  async validateMX(address) {
    try {
      const domain = this.parseDomain(address);
      const addresses = await resolveMxAsync(domain);
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
      const limit = new Limiter({ ...this.limiter, id });
      limit.get((err, limit) => {
        if (err) {
          err.responseCode = 421;
          return reject(err);
        }

        if (limit.remaining) {
          logger.info(
            `Rate limit for ${email} is now ${limit.remaining - 1}/${
              limit.total
            }`
          );
          return resolve();
        }

        const delta = (limit.reset * 1000 - Date.now()) | 0;
        reject(
          new CustomError(
            `Rate limit exceeded for ${id}, retry in ${ms(delta, {
              long: true
            })}`,
            451
          )
        );
      });
    });
  }

  isBlacklisted(domain) {
    return Array.isArray(this.config.blacklist)
      ? this.config.blacklist.includes(domain)
      : false;
  }

  isDisposable(domain) {
    if (this.config.whitelistedDisposableDomains.includes(domain)) return false;

    for (const d of domains) {
      if (d === domain) return true;
    }

    for (const w of wildcards) {
      if (w === domain || domain.endsWith(`.${w}`)) return true;
    }

    return false;
  }

  // this returns either the reversed SRS address
  // or the address that was passed to this function
  checkSRS(address) {
    if (!/^SRS/i.test(address)) return address;
    try {
      const reversed = this.srs.reverse(address);
      if (_.isNull(reversed))
        throw new Error(`Invalid SRS reversed address for ${address}`);
      return reversed;
    } catch (err) {
      logger.error(err);
      return address;
    }
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

  // this returns the forwarding address for a given email address
  // eslint-disable-next-line complexity
  async getForwardingAddresses(address, recursive = []) {
    const domain = this.parseDomain(address, false);
    const records = await resolveTxtAsync(domain);

    // dns TXT record must contain `forward-email=` prefix
    const validRecords = [];

    // verifications must start with `forward-email-site-verification=` prefix
    const verifications = [];

    // add support for multi-line TXT records
    for (let i = 0; i < records.length; i++) {
      records[i] = records[i].join(''); // join chunks together
      if (records[i].startsWith(`${this.config.recordPrefix}=`))
        validRecords.push(
          records[i].replace(`${this.config.recordPrefix}=`, '')
        );
      if (
        records[i].startsWith(`${this.config.recordPrefix}-site-verification=`)
      )
        verifications.push(
          records[i].replace(
            `${this.config.recordPrefix}-site-verification=`,
            ''
          )
        );
    }

    if (verifications.length > 0) {
      if (verifications.length > 1)
        throw new CustomError(
          `Domain ${domain} has multiple verification TXT records of "${this.config.recordPrefix}-site-verification" and should only have one`
        );
      // if there was a verification record then perform lookup
      try {
        const { body } = await got.get(
          `${this.config.lookupEndpoint}?verification_record=${verifications[0]}`,
          {
            responseType: 'json',
            username: this.config.lookupSecrets[0]
          }
        );
        // body is an Array of records that are formatted like TXT records
        if (Array.isArray(body)) {
          // combine with any existing TXT records (ensures graceful DNS propagation)
          for (const element of body) {
            validRecords.push(element);
          }
        }
      } catch (err) {
        logger.error(err);
      }
    }

    // join multi-line TXT records together and replace double w/single commas
    const record = validRecords
      .join(',')
      .replace(/,+/g, ',')
      .trim();

    // if the record was blank then throw an error
    if (!isSANB(record))
      throw new CustomError(
        `${address} domain of ${domain} has a blank "${this.config.recordPrefix}" TXT record or has zero aliases configured`
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

    // store if address is ignored or not
    let ignored = false;

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
        // check if we have a match (and if it is ignored)
        if (addr[0].indexOf('!') === 0 && username === addr[0].slice(1)) {
          ignored = true;
          break;
        }

        if (username === addr[0]) forwardingAddresses.push(addr[1]);
      } else if (validator.isFQDN(addresses[i])) {
        // allow domain alias forwarding
        // (e.. the record is just "b.com" if it's not a valid email)
        globalForwardingAddresses.push(`${username}@${addresses[i]}`);
      } else if (validator.isEmail(addresses[i])) {
        const domain = this.parseDomain(addresses[i], false);
        if (validator.isFQDN(domain) && validator.isEmail(addresses[i])) {
          globalForwardingAddresses.push(addresses[i]);
        }
      }
    }

    // if it was ignored then return early with false indicating it's disabled
    if (ignored) return false;

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

    const len = forwardingAddresses.length;
    for (let x = 0; x < len; x++) {
      const forwardingAddress = forwardingAddresses[x];
      try {
        if (recursive.includes(forwardingAddress)) continue;

        const newRecursive = forwardingAddresses.concat(recursive);
        // prevent a double-lookup if user is using + symbols
        if (forwardingAddress.includes('+'))
          newRecursive.push(
            `${this.parseUsername(address)}@${this.parseDomain(address, false)}`
          );

        // eslint-disable-next-line no-await-in-loop
        const addresses = await this.getForwardingAddresses(
          forwardingAddress,
          newRecursive
        );
        // if address was ignored then skip adding it
        if (addresses === false) continue;

        // if it was recursive then remove the original
        if (addresses.length > 0)
          recursivelyForwardedAddresses.push(forwardingAddress);
        // add the recursively forwarded addresses
        for (const element of addresses) {
          forwardingAddresses.push(element);
        }
      } catch (err) {
        logger.error(err);
      }
    }

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
      // attempt reverse SRS here
      address.address = this.checkSRS(address.address);

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

  conditionallyRemoveSignatures(headers, changes) {
    //
    // Note that we always remove the "X-Google-DKIM-Signature" header
    // if there is at least one change passed, as I believe that
    // Google wil flag this as spam and result in a 421 connection timeout
    // if it is not removed otherwise, and there was a rewrite done
    //
    // Return early if no changes
    if (changes.length === 0) return;

    // Always remove X-Google-DKIM-Signature
    headers.remove('x-google-dkim-signature');

    //
    // Right now it's not easy to delete a header by its index
    // therefore I filed a GitHub issue with mailsplit package for this
    //
    // <https://github.com/andris9/mailsplit/issues/8>
    //
    // So our alternative is to just delete all the DKIM signatures
    // and then add them back at the end of the header lines (length + 1)
    // so that the `headers.add` method will call `lines.push`
    // <https://github.com/andris9/mailsplit/blob/master/lib/headers.js#L107>
    //

    // Get all signatures as an Array
    const signatures = headers.get('dkim-signature');

    // Remove all DKIM-Signatures (we add back the ones that are not affected)
    headers.remove('dkim-signature');

    // Note that we don't validate the signature, we just check its headers
    // And we don't specifically because `this.validateDKIM` could throw error
    for (const signature of signatures) {
      const terms = signature
        .split(/;/)
        .map(t => t.trim())
        .filter(t => t !== '');
      const rules = terms.map(t => t.split(/[=]/).map(r => r.trim()));
      for (const rule of rules) {
        // term = d
        // value = example.com
        //
        const [term, value] = rule;
        if (term !== 'h') continue;
        const signedHeaders = value
          .split(':')
          .map(h => h.trim().toLowerCase())
          .filter(h => h !== '');
        if (signedHeaders.length === 0) continue;
        if (signedHeaders.every(h => !changes.includes(h)))
          headers.add('dkim-signature', signature, headers.lines.length + 1);
      }
    }
  }
}

module.exports = ForwardEmail;
