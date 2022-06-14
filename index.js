const crypto = require('crypto');
const dns = require('dns');
const fs = require('fs');
const os = require('os');
const process = require('process');
const util = require('util');
const { Buffer } = require('buffer');

const punycode = require('punycode/');
const DKIM = require('nodemailer/lib/dkim');
const RateLimiter = require('async-ratelimiter');
const MimeNode = require('nodemailer/lib/mime-node');
const RE2 = require('re2');
const Redis = require('@ladjs/redis');
const SpamScanner = require('spamscanner');
const _ = require('lodash');
const addressParser = require('nodemailer/lib/addressparser');
const arrayJoinConjunction = require('array-join-conjunction');
const bytes = require('bytes');
const combineErrors = require('combine-errors');
const dashify = require('dashify');
const dnsbl = require('dnsbl');
const getFQDN = require('get-fqdn');
const getStream = require('get-stream');
const ip = require('ip');
const isFQDN = require('is-fqdn');
const isSANB = require('is-string-and-not-blank');
const ms = require('ms');
const mxConnect = require('mx-connect');
const nodemailer = require('nodemailer');
const pify = require('pify');
const pMap = require('p-map');
const prettyMilliseconds = require('pretty-ms');
const regexParser = require('regex-parser');
const revHash = require('rev-hash');
const clone = require('rfdc/default');
const safeStringify = require('fast-safe-stringify');
const sharedConfig = require('@ladjs/shared-config');
const splitLines = require('split-lines');
const status = require('statuses');
const superagent = require('superagent');
const validator = require('validator');
const zoneMTABounces = require('zone-mta/lib/bounces');
const { Iconv } = require('iconv');
const { SMTPServer } = require('smtp-server');
const { SRS } = require('sender-rewriting-scheme');
const { authenticate, sealMessage } = require('mailauth');
const { boolean } = require('boolean');
const { fromUrl, parseDomain, ParseResultType } = require('parse-domain');
const { simpleParser } = require('mailparser');

const concurrency = os.cpus().length;

//
// TODO: all this hard-coded IP, domains, etc needs to be configurable (including in messages)
//
const IP_ADDRESS = ip.address();
const NAME =
  IP_ADDRESS === '138.197.213.185'
    ? 'mx1.forwardemail.net'
    : 'mx2.forwardemail.net';

function isTLSError(err) {
  return (
    (err.code && TLS_RETRY_CODES.has(err.code)) ||
    (err.message && REGEX_TLS_ERR.test(err.message)) ||
    (err.library && err.library === 'SSL routines') ||
    err.reason ||
    err.host ||
    err.cert
  );
}

const pkg = require('./package');
const { CustomError, MessageSplitter, env, logger } = require('./helpers');

const HTTP_RETRY_ERROR_CODES = new Set([
  'ETIMEDOUT',
  'ECONNRESET',
  'EADDRINUSE',
  'ECONNREFUSED',
  'EPIPE',
  'ENOTFOUND',
  'ENETUNREACH',
  'EAI_AGAIN'
]);

const DEFER_AND_SLOWDOWN = new Set(['defer', 'slowdown']);

const MAIL_RETRY_ERROR_CODES = new Set([
  'ESOCKET',
  'ECONNECTION',
  'ETIMEDOUT',
  'EDNS',
  'EPROTOCOL'
]);

const HTTP_RETRY_STATUS_CODES = new Set([
  408, 413, 429, 500, 502, 503, 504, 521, 522, 524
]);

//
// NOTE: we want to _always_ retry in order to ensure deliverability
//       (e.g. DNS sometimes fails, sometimes people misconfigure records, or transfer domains, etc)
// <https://github.com/nodejs/node/blob/08dd4b1723b20d56fbedf37d52e736fe09715f80/lib/dns.js#L296-L320>
//
const CODES_TO_RESPONSE_CODES = {
  EADDRGETNETWORKPARAMS: 421,
  EADDRINUSE: 421,
  EAI_AGAIN: 421,
  EBADFLAGS: 421,
  EBADHINTS: 421,
  ECANCELLED: 421,
  ECONNREFUSED: 421,
  ECONNRESET: 442,
  EDESTRUCTION: 421,
  EFORMERR: 421,
  ELOADIPHLPAPI: 421,
  ENETUNREACH: 421,
  ENODATA: 421,
  ENOMEM: 421,
  ENOTFOUND: 421,
  ENOTINITIALIZED: 421,
  EPIPE: 421,
  EREFUSED: 421,
  ESERVFAIL: 421,
  ETIMEOUT: 421 // 420
};

const CODES = Object.keys(CODES_TO_RESPONSE_CODES);
const MAP_CODES_TO_RESPONSE_CODES = new Map(
  CODES.map((key) => [key, CODES_TO_RESPONSE_CODES[key]])
);
const RETRY_CODE_NUMBERS = new Set(Object.values(CODES_TO_RESPONSE_CODES));
const RETRY_CODES = new Set(CODES);
const TLS_RETRY_CODES = new Set(['ETLS', 'ECONNRESET']);

const asyncMxConnect = pify(mxConnect);

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

const transporterConfig = {
  debug: !env.IS_SILENT,
  direct: true,
  // this can be overridden now
  // port: 25,
  tls: {
    rejectUnauthorized: env.NODE_ENV !== 'test'
  },
  connectionTimeout: ms('180s'),
  greetingTimeout: ms('180s'),
  socketTimeout: ms('180s')
};

// <https://srs-discuss.v2.listbox.narkive.com/Mh6X2B2w/help-how-to-unwind-an-srs-address#post17>
// note we can't use `/^SRS=/i` because it would match `srs@example.com`
const REGEX_SRS0 = new RE2(/^srs0[-+=]\S+=\S{2}=(\S+)=(.+)@\S+$/i);
const REGEX_SRS1 = new RE2(/^srs1[+-=]\S+=\S+==\S+=\S{2}=\S+@\S+$/i);
const REGEX_DIAGNOSTIC_CODE = new RE2(/^\d{3} /);
const REGEX_BOUNCE_ADDRESS = new RE2(/BOUNCE_ADDRESS/g);
const REGEX_BOUNCE_ERROR_MESSAGE = new RE2(/BOUNCE_ERROR_MESSAGE/g);
const REGEX_TLS_ERR = new RE2(
  /ssl routines|ssl23_get_server_hello|\/deps\/openssl|ssl3_check/gim
);

// <https://unix.stackexchange.com/q/65013>
const MAILER_DAEMON_USERNAMES = new Set([
  'abuse',
  'ftp',
  'hostmaster',
  'mailer-daemon',
  'mailer_daemon',
  'mailerdaemon',
  'news',
  'nobody',
  'noc',
  'postmaster',
  'root',
  'security',
  'usenet',
  'webmaster',
  'www'
]);

class ForwardEmail {
  constructor(config = {}) {
    this.config = _.merge(
      {},
      sharedConfig('SMTP'),
      {
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
          onData: this.onData.bind(this),
          onConnect: this.onConnect.bind(this),
          onMailFrom: this.onMailFrom.bind(this),
          onRcptTo: this.onRcptTo.bind(this),
          disabledCommands: ['AUTH'],
          // NOTE: we don't need to set a value for maxClients
          //       since we have rate limiting enabled by IP
          // maxClients: Infinity, // default is Infinity
          // allow 10m to process bulk RCPT TO
          socketTimeout: ms('10m'),
          // default closeTimeout is 30s
          closeTimeout: ms('30s'),
          logInfo: true,
          // <https://github.com/nodemailer/smtp-server/issues/177>
          disableReverseLookup: true,
          logger
        },
        spamScoreThreshold: env.SPAM_SCORE_THRESHOLD,
        whitelist: new Set(
          _.isArray(env.WHITELIST)
            ? env.WHITELIST.map((key) => key.toLowerCase())
            : []
        ),
        blacklistedStr:
          'The IP %s is listed on the %s DNS blacklist; Visit %s to submit a removal request.',
        dnsbl: {
          domains: env.DNSBL_DOMAINS,
          removals: env.DNSBL_REMOVALS
        },
        exchanges: env.SMTP_EXCHANGE_DOMAINS,
        dkim: {
          domainName: env.DKIM_DOMAIN_NAME,
          keySelector: env.DKIM_KEY_SELECTOR,
          privateKey: isSANB(env.DKIM_PRIVATE_KEY_PATH)
            ? fs.readFileSync(env.DKIM_PRIVATE_KEY_PATH, 'utf8')
            : undefined
        },
        maxRecipients: env.MAX_RECIPIENTS,
        maxForwardedAddresses: env.MAX_FORWARDED_ADDRESSES,
        email: env.EMAIL_SUPPORT,
        website: env.WEBSITE_URL,
        recordPrefix: env.TXT_RECORD_PREFIX,
        apiEndpoint: env.API_ENDPOINT,
        apiSecrets: env.API_SECRETS,
        srs: {
          separator: '=',
          secret: env.SRS_SECRET,
          maxAge: 30
        },
        srsDomain: env.SRS_DOMAIN,
        timeout: ms('180s'),
        greylistTimeout: ms('5m'),
        greylistTtlMs: ms('30d'),
        retry: 3,
        simpleParser: { Iconv },
        isURLOptions: {
          protocols: ['http', 'https'],
          require_protocol: true
        },
        mailerDaemon: {
          name: 'Mail Delivery Subsystem',
          address: 'mailer-daemon@[HOSTNAME]'
        },
        sendingZone: 'bounces',
        userAgent: `${pkg.name}/${pkg.version}`,
        spamScanner: {
          logger,
          memoize: {
            // since memoizee doesn't support supplying mb or gb of cache size
            // we can calculate how much the maximum could potentially be
            // the max length of a domain name is 253 characters (bytes)
            // and if we want to store up to 1 GB in memory, that's
            // `Math.floor(bytes('1GB') / 253)` = 4244038 (domains)
            // note that this is per thread, so if you have 4 core server
            // you will have 4 threads, and therefore need 4 GB of free memory
            size: Math.floor(bytes('0.5GB') / 253)
          }
          // clamscan: false
        },
        ttlMs: ms('7d'),
        maxRetry: 500,
        messageIdDomain: env.MESSAGE_ID_DOMAIN,
        dnsCachePrefix: 'dns',
        fingerprintPrefix: 'f',
        dnsCacheMs: ms('1m'),
        dnsReverseCacheMs: ms('10m'),
        dnsBlacklistCacheMs: ms('30m'),
        //
        // we want low limits here in case redis has issues
        // (otherwise emails might now flow through due to SPOF)
        //
        redis: {
          maxRetriesPerRequest: 1,
          maxLoadingRetryTime: ms('5s')
        }
      },
      config
    );

    if (
      this.dnsbl &&
      _.isArray(this.dnsbl.domains) &&
      _.isArray(this.dnsbl.removals) &&
      this.dnsbl.domains.length !== this.dnsbl.removals.length
    )
      throw new Error('DNSBL_DOMAINS length must be equal to DNSBL_REMOVALS.');

    if (this.config.ssl) {
      // set minimum tls version allowed
      this.config.ssl.minVersion = 'TLSv1.2';

      // set tls ciphers allowed (in order of preference)
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
        crypto.constants.SSL_OP_NO_SSLv2 | // eslint-disable-line no-bitwise
        crypto.constants.SSL_OP_NO_SSLv3 |
        crypto.constants.SSL_OP_NO_TLSv1 |
        crypto.constants.SSL_OP_NO_TLSv11;
      delete this.config.ssl.allowHTTP1;

      // TODO: this can most likely be moved down to only be a property in smtp config below
      this.config.ssl.secure = !boolean(process.env.IS_NOT_SECURE);

      // Add TLS options to SMTP Server
      for (const key of Object.keys(this.config.ssl)) {
        this.config.smtp[key] = this.config.ssl[key];
      }
    }

    // Sender Rewriting Schema ("SRS")
    this.srs = new SRS(this.config.srs);

    // set up DKIM instance for signing messages
    this.dkim = new DKIM(this.config.dkim);

    // initialize redis
    this.client =
      this.config.redis === false
        ? false
        : _.isPlainObject(this.config.redis)
        ? new Redis(this.config.redis, this.logger, this.config.redisMonitor)
        : this.config.redis;

    // setup rate limiting with redis
    if (this.client && this.config.rateLimit) {
      this.rateLimiter = new RateLimiter({
        db: this.client,
        max: this.config.rateLimit.max,
        duration: this.config.rateLimit.duration,
        namespace: this.config.rateLimit.prefix
      });
    }

    // setup our smtp server which listens for incoming email
    this.server = new SMTPServer(this.config.smtp);

    // kind of hacky but I filed a GH issue
    // <https://github.com/nodemailer/smtp-server/issues/135>
    this.server.address = this.server.server.address.bind(this.server.server);

    this.server.on('error', (err) => {
      this.config.logger.error(err);
    });

    // TODO: investigate why cabin transforms like that

    // expose spamscanner
    if (this.client) this.config.spamScanner.client = this.client;
    this.scanner = new SpamScanner(this.config.spamScanner);

    this.listen = this.listen.bind(this);
    this.close = this.close.bind(this);
    this.sendEmail = this.sendEmail.bind(this);
    this.rewriteFriendlyFrom = this.rewriteFriendlyFrom.bind(this);
    this.parseUsername = this.parseUsername.bind(this);
    this.parseFilter = this.parseFilter.bind(this);
    this.parseHostFromDomainOrAddress =
      this.parseHostFromDomainOrAddress.bind(this);
    this.parseRootDomain = this.parseRootDomain.bind(this);
    this.onConnect = this.onConnect.bind(this);
    this.checkBlacklists = this.checkBlacklists.bind(this);
    this.onData = this.onData.bind(this);
    this.validateMX = this.validateMX.bind(this);
    this.validateRateLimit = this.validateRateLimit.bind(this);
    this.isBlacklisted = this.isBlacklisted.bind(this);
    this.isWhitelisted = this.isWhitelisted.bind(this);
    this.isBackscatter = this.isBackscatter.bind(this);
    this.checkSRS = this.checkSRS.bind(this);
    this.onMailFrom = this.onMailFrom.bind(this);
    this.getForwardingAddresses = this.getForwardingAddresses.bind(this);
    this.onRcptTo = this.onRcptTo.bind(this);
    this.getBounceStream = this.getBounceStream.bind(this);
    this.getDiagnosticCode = this.getDiagnosticCode.bind(this);
    this.getFingerprint = this.getFingerprint.bind(this);
    this.getGreylistKey = this.getGreylistKey.bind(this);
    this.resolver = this.resolver.bind(this);
    // <https://github.com/nodemailer/smtp-server/issues/177>
    this.reverser = this.reverser.bind(this);
    this.refineAndLogError = this.refineAndLogError.bind(this);
    this.getErrorCode = this.getErrorCode.bind(this);
    this.parseSendErrorAndConditionallyThrow =
      this.parseSendErrorAndConditionallyThrow.bind(this);
  }

  // eslint-disable-next-line complexity
  parseSendErrorAndConditionallyThrow(
    err,
    session,
    transporter,
    envelope
    // raw
  ) {
    // log the error
    this.config.logger.warn(err, { session, envelope });

    // store a counter for the day of how many emails had errors
    if (this.client)
      this.client
        .incr(`mail_error:${session.arrivalDateFormatted}`)
        .then()
        .catch((err) => this.config.logger.fatal(err));

    //
    // Gmail relies on Spamhaus and this error message indicates it is blocked by Gmail
    // Therefore we should send an email to administrators alerting them
    // (this is often faster than alerts from routine blacklist monitoring services
    //
    if (
      transporter &&
      transporter.options &&
      transporter.options.host === 'gmail.com' &&
      err.message.indexOf(
        "The IP you're using to send mail is not authorized"
      ) !== -1
    ) {
      this.config.logger.fatal(err, { session, envelope });
      err.responseCode = 421;
      throw err;
    }

    /*
        if (
          this.client &&
          host === 'gmail.com' &&
          (
            err.message.startsWith('Please try again in 1 hour') ||
            err.message.includes(
            'The email account that you tried to reach is over quota'
          ) ||
            err.message.includes(
              'The email account that you tried to reach is disabled'
            ) ||
            err.message.includes(
              'The email account that you tried to reach does not exist'
            ) ||
            err.message.includes('is receiving mail too quickly') ||
            err.message.includes(
              'trying to contact is receiving mail at a rate'
            )) &&
          _.isArray(err.rejected)
        ) {
          //
          // greylist for 1 hour
          //
          for (const address of err.rejected) {
            // eslint-disable-next-line max-depth
            this.client
              .set(`greylist:${address}`, Date.now() + 3600000)
              .then()
              .catch((err) => this.config.logger.fatal(err));
          }
        }
        */

    if (
      transporter &&
      transporter.options &&
      transporter.options.host === 'gmail.com' &&
      err.response &&
      (err.response.indexOf('suspicious due to the very low reputation') !==
        -1 ||
        err.response.indexOf('one or more suspicious entries') !== -1)
    ) {
      //
      // TODO: train spamscanner here based off the content and links
      //
      if (session.isWhitelisted) {
        this.config.logger.fatal(new Error('Whitelist spam detected'), {
          value: session.whitelistValue,
          err,
          session,
          envelope
        });
      } else {
        this.config.logger.fatal(new Error('Blacklisted spam'), {
          value: session.isValidClientHostname
            ? session.clientHostname
            : session.remoteAddress,
          err,
          session,
          envelope
        });
        if (this.client)
          this.client
            .set(
              `blacklist:${
                session.isValidClientHostname
                  ? session.clientHostname
                  : session.remoteAddress
              }`,
              'true'
            )
            .then()
            .catch((err) => this.config.logger.fatal(err));
      }

      throw err;
    }

    if (
      transporter &&
      transporter.options &&
      transporter.options.host === 'gmail.com' &&
      // (err.message.includes(
      //   'unsolicited mail originating from your IP address'
      // ) ||
      // err.message.includes(
      //   'To best protect our users from spam, the message has been blocked'
      // ) ||
      // err.message.includes(
      //   'likely unsolicited mail. To reduce the amount of spam sent to Gmail'
      // ) ||
      err.response &&
      (err.response.indexOf('its content presents a potential') !== -1 ||
        err.response.indexOf('suspicious due to the nature of the content') !==
          -1)
      // || (err.response &&
      //   err.response.includes('To protect our users from spam')))
    ) {
      //
      // TODO: train spamscanner here based off the content and links
      //
      if (session.isWhitelisted) {
        this.config.logger.fatal(
          new Error('Whitelist suspicious content detected'),
          {
            value: session.whitelistValue,
            err,
            session,
            envelope
          }
        );
      } else {
        this.config.logger.fatal(new Error('Suspicious content detected'), {
          value: session.isValidClientHostname
            ? session.clientHostname
            : session.remoteAddress,
          session,
          envelope,
          err
        });
      }

      throw err;
    }

    //
    // if there was `err.response` and it had a bounce reason
    // and if the bounce action was defer, slowdown, or it has a category
    // of blacklist, then we should retry sending it later and send a 421 code
    // and alert our team in Slack so they can investigate if IP mitigation needed
    //
    if (isSANB(err.response)) {
      const bounceInfo = zoneMTABounces.check(err.response);
      if (
        ['defer', 'slowdown'].includes(bounceInfo.action) ||
        bounceInfo.category === 'blacklist'
      ) {
        this.config.logger[
          bounceInfo.category === 'blacklist' ? 'fatal' : 'error'
        ](err, {
          bounce_info: bounceInfo,
          session,
          envelope
        });
        err.responseCode = 421;
        throw err;
      }
    }

    // TODO: this should be more full proof
    if (
      err.command === 'CONN' &&
      MAIL_RETRY_ERROR_CODES.has(err.code) &&
      !isTLSError(err)
    ) {
      err.responseCode = 421;
      throw err;
    }
  }

  getErrorCode(err) {
    if (!_.isError(err)) return 550;
    if (_.isNumber(err.responseCode)) return err.responseCode;
    if (_.isString(err.code) && RETRY_CODES.has(err.code))
      return MAP_CODES_TO_RESPONSE_CODES.get(err.code);
    if (
      (err.code && HTTP_RETRY_ERROR_CODES.has(err.code)) ||
      (_.isNumber(err.status) && HTTP_RETRY_STATUS_CODES.has(err.status))
    )
      return 421;
    return 550;
  }

  // eslint-disable-next-line complexity
  refineAndLogError(err, session) {
    // parse SMTP code and message
    if (err.message && err.message.startsWith('SMTP code:')) {
      if (!err.responseCode)
        err.responseCode = err.message.split('SMTP code:')[1].split(' ')[0];
      err.message = err.message.split('msg:')[1];
    }

    // if it was HTTP error and no `responseCode` set then try to parse it
    // into a SMTP-friendly format for error handling
    if (!err.responseCode) {
      if (
        (err.code && HTTP_RETRY_ERROR_CODES.has(err.code)) ||
        (_.isNumber(err.status) && HTTP_RETRY_STATUS_CODES.has(err.status))
      )
        err.responseCode = 421;
      // TODO: map HTTP to SMTP codes appropriately
      else err.responseCode = 550;
    }

    this.config.logger[
      (err &&
        err.message &&
        err.message.indexOf('Invalid recipients') !== -1) ||
      (err &&
        err.message &&
        err.message.indexOf('DNS blacklist') !== -1 &&
        err.responseCode &&
        err.responseCode === 554) ||
      (err &&
        err.responseCode &&
        (err.responseCode < 500 || err.responseCode === 452))
        ? 'warn'
        : 'error'
    ](err, { session });

    // preserve original message
    err._message = err.message;

    //
    // replace linebreaks
    //
    // (otherwise you will get DATA command failed if this is RCPT TO command if you have multiple linebreaks)
    //
    const lines = splitLines(err.message);
    lines.push(
      `If you need help, forward this email to ${this.config.email} or visit ${this.config.website}. Please note we are an email service provider and most likely not your intended recipient.`
    );

    // set the new message
    err.message = lines.join('; ');

    // add a helpful error message for users
    return err;
  }

  async listen(port, ...args) {
    await pify(this.server.listen).bind(this.server)(
      port || this.config.port,
      ...args
    );
  }

  async close() {
    await pify(this.server.close).bind(this.server);
  }

  getDiagnosticCode(err) {
    if (isSANB(err.response) && REGEX_DIAGNOSTIC_CODE.test(err.response))
      return err.response;
    return `${
      err.responseCode || err.code || err.statusCode || err.status || 500
    } ${err.message}`;
  }

  getBounceStream(options) {
    // options.headers
    // options.from (MAIL FROM)
    // options.name (FQDN of our MX server)
    // options.bounce = {
    //   address: recipient address that failed,
    //   host: recipient host name that failed,
    //   err: error and error message,
    // }
    //
    // Mail Delivery Subsystem <mailer-daemon@mx1.forwardemail.net>
    //
    const rootNode = new MimeNode(
      'multipart/report; report-type=delivery-status'
    );

    const from = this.config.mailerDaemon;
    const to = options.from;
    const { sendingZone } = this.config;

    // format Mailer Daemon address
    const fromAddress = rootNode
      ._convertAddresses(rootNode._parseAddresses(from))
      .replace(/\[hostname]/gi, options.name);

    rootNode.setHeader('From', fromAddress);
    rootNode.setHeader('To', to);
    rootNode.setHeader('X-Sending-Zone', sendingZone);
    rootNode.setHeader('X-Failed-Recipients', options.bounce.address);
    rootNode.setHeader('Auto-Submitted', 'auto-replied');
    rootNode.setHeader('Subject', 'Delivery Status Notification (Failure)');

    if (options.messageId) {
      rootNode.setHeader('In-Reply-To', options.messageId);
      rootNode.setHeader('References', options.messageId);
    }

    rootNode
      .createChild('text/plain; charset=utf-8')
      .setHeader('Content-Description', 'Notification')
      .setContent(
        options.template && options.template.text
          ? options.template.text
              .replace(REGEX_BOUNCE_ADDRESS, options.bounce.address)
              .replace(
                REGEX_BOUNCE_ERROR_MESSAGE,
                options.bounce.err.message
                // isSANB(options.bounce.err.response) ? options.bounce.err.response : options.bounce.err.message
              )
          : [
              `Your message wasn't delivered to ${options.bounce.address} due to an error.`,
              '',
              'The response was:',
              '',
              options.bounce.err.message,
              // options.bounce.err.response || options.bounce.err.message,
              '',
              `If you need help, forward this email to ${this.config.email} or visit ${this.config.website}.`,
              '',
              `Please note we are an email service provider and most likely not your intended recipient.`
            ].join('\n')
      );

    if (options.template && options.template.html)
      rootNode
        .createChild('text/html; charset=utf-8')
        .setHeader('Content-Description', 'Notification')
        .setContent(
          options.template.html
            .replace(REGEX_BOUNCE_ADDRESS, options.bounce.address)
            .replace(
              REGEX_BOUNCE_ERROR_MESSAGE,
              options.bounce.err.message
              // options.bounce.err.response || options.bounce.err.message
            )
        );

    rootNode
      .createChild('message/delivery-status')
      .setHeader('Content-Description', 'Delivery report')
      .setContent(
        [
          `Reporting-MTA: dns; ${options.name}`,
          `X-ForwardEmail-Version: ${pkg.version}`,
          `X-ForwardEmail-Session-ID: ${options.id}`,
          `X-ForwardEmail-Sender: rfc822; ${options.from}`,
          `Arrival-Date: ${new Date(options.arrivalTime)
            .toUTCString()
            .replace(/GMT/, '+0000')}`,
          `Final-Recipient: rfc822; ${options.bounce.address}`,
          `Action: failed`,
          `Status: 5.0.0`,
          `Remote-MTA: dns; ${options.bounce.host || 'webhook'}`,
          `Diagnostic-Code: smtp; ${this.getDiagnosticCode(options.bounce.err)}`
        ].join('\n')
      );

    rootNode.createChild('message/rfc822').setContent(options.originalRaw);

    return rootNode.createReadStream();
  }

  // triplet CLIENT_IP / SENDER / RECIPIENT
  // default delay from postfix is 5mins (300s) so we will respect that
  // <https://postgrey.schweikert.ch/>
  getGreylistKey(clientIP, sender, recipient) {
    return `greylist:${revHash([clientIP, sender, recipient].join(':'))}`;
  }

  //
  // generate a fingerprint for the email (returns a short md5 hash)
  //
  // <https://metacpan.org/pod/Email::Fingerprint>
  // <https://dl.acm.org/doi/fullHtml/10.1145/1105664.1105677>
  //
  getFingerprint(session, headers, body) {
    const prefix = [];

    // use either the whitelisted value or the client hostname or the remote address
    prefix.push(
      revHash(
        session.isWhitelisted
          ? session.whitelistValue
          : session.isValidClientHostname
          ? session.clientHostname
          : session.remoteAddress
      )
    );

    const messageId = headers.getFirst('Message-ID');
    if (messageId) {
      prefix.push(revHash(messageId));
      return prefix.join(':');
    }

    const sentKeyHeaders = [];
    for (const key of ['Date', 'From', 'To', 'Cc', 'Subject']) {
      const value = headers.getFirst(key);
      if (isSANB(value)) sentKeyHeaders.push(value);
    }

    if (sentKeyHeaders.length > 0)
      prefix.push(revHash(sentKeyHeaders.join(':')));

    //
    // TODO: we need to use indexOf everywhere because it is 20x+ faster than regex and startsWith
    // <https://www.measurethat.net/Benchmarks/Show/4797/1/js-regex-vs-startswith-vs-indexof>
    //

    // otherwise hash the body
    prefix.push(revHash(body));
    return prefix.join(':');
  }

  // TODO: implement ARF parser
  //       POST /abuse
  //       GET /abuse?email=mailfrom&ip=
  //       sends 4xx retry later if it found in this list
  //       which gives us time to manually curate the list of false positives

  // eslint-disable-next-line complexity
  async sendEmail(options, session) {
    this.config.logger.info('attempting to send email', { options, session });
    const { host, name, envelope, raw, port } = options;

    //
    // TODO: two good resources for testing greylisting:
    // <https://test.meinmail.info/greylisting-test.html> (translate to en)
    // <http://www.allaboutspam.com/email-server-test/>
    //

    //
    // we need to do a lookup for each address in the `envelope.to` Array
    // to determine which addresses for this host were already successful
    //
    const alreadyAccepted = [];
    const to = [];
    if (_.isString(envelope.to)) envelope.to = [envelope.to];
    if (this.client) {
      try {
        const values = await this.client.mget(
          envelope.to.map(
            (t) =>
              `${this.config.fingerprintPrefix}:${
                session.fingerprint
              }:${revHash(t)}`
          )
        );
        // reset the filtered envelope since we were able to obtain values
        for (const [i, value] of values.entries()) {
          // if the value was corrupt and it gets sent successfully it will get corrected
          if (value) {
            const int = Number.parseInt(value, 10);
            // eslint-disable-next-line max-depth
            if (Number.isFinite(int) && int > 0)
              alreadyAccepted.push(envelope.to[i]);
            else to.push(envelope.to[i]);
          } else {
            to.push(envelope.to[i]);
          }
        }
      } catch (err) {
        this.config.logger.fatal(err);
        for (const t of envelope.to) {
          to.push(t);
        }
      }
    } else {
      for (const t of envelope.to) {
        to.push(t);
      }
    }

    if (to.length === 0) {
      return {
        accepted: [],
        alreadyAccepted,
        rejected: [],
        rejectedErrors: []
      };
    }

    // TODO: we should parse minutes and seconds, and if it's less than 2 minutes, then use `delay`
    // TODO: we should retry on defer's, and not just fallback to plaintext without TLS if that fails

    // try it once with opportunisticTLS otherwise ignoreTLS
    // (e.g. in case of a bad altname on a certificate)
    let info;
    let transporter;
    let mx = {
      host,
      port: Number.parseInt(port, 10)
    };

    if (env.NODE_ENV === 'test') {
      info = {
        accepted: to,
        alreadyAccepted,
        rejected: [],
        rejectedErrors: []
      };

      return info;
    }

    try {
      if (mx.port === 25) {
        // TODO: pass custom DNS resolver here
        // <https://github.com/zone-eu/mx-connect/issues/3>
        mx = await asyncMxConnect({
          // mx.host can be an email address
          // <https://github.com/zone-eu/mx-connect#configuration-options>
          target: mx.host,
          port: mx.port,
          localHostname: name
        });
      }

      transporter = nodemailer.createTransport(
        _.merge(transporterConfig, this.config.ssl, {
          opportunisticTLS: true,
          logger: this.config.logger,
          host: mx.host,
          port: mx.port,
          ...(mx.socket ? { connection: mx.socket } : {}),
          name,
          tls: {
            ...(mx.hostname ? { servername: mx.hostname } : {}),
            rejectUnauthorized: false
          }
        })
      );

      info = await transporter.sendMail({
        envelope: { from: envelope.from, to },
        raw
      });

      return info;
    } catch (err) {
      this.parseSendErrorAndConditionallyThrow(
        err,
        session,
        transporter,
        envelope
        // raw
      );

      // this error will indicate it is a TLS issue, so we should retry as plain
      // if it doesn't have all these properties per this link then its not TLS
      //
      // ✖  error     Error [ERR_TLS_CERT_ALTNAME_INVALID]: Hostname/IP does not match certificate's altnames: Host: mx.example.com. is not in the cert's altnames: DNS:test1.example.com, DNS:test2.example.com
      //     at Object.checkServerIdentity (tls.js:288:12)
      //     at TLSSocket.onConnectSecure (_tls_wrap.js:1483:27)
      //     at TLSSocket.emit (events.js:311:20)
      //     at TLSSocket._finishInit (_tls_wrap.js:916:8)
      //     at TLSWrap.ssl.onhandshakedone (_tls_wrap.js:686:12)
      //   reason: "Host: mx.example.com. is not in the cert's altnames: DNS:test1.example.com, DNS:test2.example.com",
      //   host: 'mx.example.com',
      //   cert: ...,
      //   ...
      //
      // <https://github.com/nodejs/node/blob/1f9761f4cc027315376cd669ceed2eeaca865d76/lib/tls.js#L287>
      //
      // we should only retry on cert/connection error
      // <https://gist.github.com/andris9/2e28727c4fd905ccbfe74fb348d27cc1>
      //
      // NOTE: we may want to uncomment the line below, otherwise all emails that fail will be retried
      // if (!err.reason || !err.host || !err.cert) throw err;
      //

      if (
        (err.code &&
          Number.parseInt(err.code, 10) >= 400 &&
          Number.parseInt(err.code, 10) < 500) ||
        isTLSError(err)
      ) {
        mx = {
          host,
          port: Number.parseInt(port, 10)
        };
        if (mx.port === 25)
          // TODO: pass custom DNS resolver here
          // <https://github.com/zone-eu/mx-connect/issues/3>
          mx = await asyncMxConnect({
            target: host,
            port: mx.port,
            localHostname: name
          });
        // try sending the message again without TLS enabled
        transporter = nodemailer.createTransport(
          _.merge(transporterConfig, this.config.ssl, {
            ignoreTLS: true,
            secure: false,
            logger: this.config.logger,
            host: mx.host,
            port: mx.port,
            ...(mx.socket ? { connection: mx.socket } : {}),
            name
          })
        );
        try {
          info = await transporter.sendMail({
            envelope: { from: envelope.from, to },
            raw
          });
          return info;
        } catch (err) {
          this.parseSendErrorAndConditionallyThrow(
            err,
            session,
            transporter,
            envelope
            // raw
          );
          throw err;
        }
      }

      throw err;
    }
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

  parseRootDomain(domain) {
    const parseResult = parseDomain(fromUrl(domain));
    return parseResult.type === ParseResultType.Listed &&
      _.isObject(parseResult.icann) &&
      isSANB(parseResult.icann.domain)
      ? `${parseResult.icann.domain}.${parseResult.icann.topLevelDomains.join(
          '.'
        )}`
      : domain;
  }

  parseHostFromDomainOrAddress(address) {
    const parsedAddress = addressParser(address);
    let domain = address;

    if (
      _.isArray(parsedAddress) &&
      _.isObject(parsedAddress[0]) &&
      isSANB(parsedAddress[0].address)
    ) {
      domain = parsedAddress[0].address;
    }

    const atPos = domain.indexOf('@');
    if (atPos !== -1) domain = domain.slice(atPos + 1);

    domain = domain.toLowerCase().trim();

    try {
      domain = punycode.toASCII(domain);
    } catch {
      // ignore punycode conversion errors
    }

    // ensure fully qualified domain name or IP address
    if (!domain || (!isFQDN(domain) && !validator.isIP(domain)))
      throw new CustomError(
        `${
          domain || address
        } does not contain a fully qualified domain name ("FQDN") nor IP address.`
      );

    return domain;
  }

  async reverser(ip) {
    if (!validator.isIP(ip)) {
      this.config.logger.fatal(new Error('IP address was invalid'), { ip });
      return false;
    }

    const key = `${this.config.dnsCachePrefix}:reverse:${ip}`
      .toLowerCase()
      .trim();

    // attempt to fetch from cache and return early
    if (this.client) {
      try {
        const value = await this.client.get(key);
        if (value) {
          this.config.logger.debug('cache hit', { key, value });
          if (isFQDN(value)) return value;
          this.config.logger.debug('cache invalid', { key, value });
          this.client.del(key).then().catch(this.config.logger.error);
        } else {
          this.config.logger.debug('cache miss', { key, value });
        }
      } catch (err) {
        this.config.logger.error(err);
      }
    }

    // perform reverse dns lookup
    try {
      const values = await dns.promises.reverse(ip);
      if (!_.isArray(values) || values.length === 0 || !isFQDN(values[0]))
        throw new Error('Reverse lookup returned invalid FQDN', { ip, values });
      if (this.client) {
        this.client
          .set(key, values[0], 'PX', this.config.reverseCacheMs)
          .then()
          .catch(this.config.logger.error);
      }

      return values[0];
    } catch (err) {
      // <https://github.com/nodejs/node/issues/3112>
      if (err.code === 'EINVAL') return false;
      // no hostnames found
      throw err;
    }
  }

  async resolver(name, rr, reset = false, client = this.client) {
    const key = `${this.config.dnsCachePrefix}:${rr}:${name}`
      .toLowerCase()
      .trim();

    //
    // attempt to fetch from cache and return early
    //
    if (client && !reset) {
      try {
        let value = await client.get(key);
        if (value) {
          this.config.logger.debug('cache hit', { key, value });
          try {
            value = JSON.parse(value);
            //
            // validate that it is an Array of Arrays
            // (TXT values need to be Array of Arrays)
            // this ensures that the cache is not corrupt
            // for critical forwarding configuration
            //
            // eslint-disable-next-line max-depth
            if (rr.toLowerCase() === 'txt') {
              // eslint-disable-next-line max-depth
              if (
                _.isArray(value) &&
                value.every(
                  (a) => _.isArray(a) && _.every(a, (s) => _.isString(s))
                )
              )
                return value;
              throw new Error('Invalid TXT resolver cache', {
                name,
                rr,
                value
              });
            }

            // MX
            // value = [
            //   { exchange: 'mx2.forwardemail.net', priority: 20 },
            //   { exchange: 'mx1.forwardemail.net', priority: 10 }
            // ]
            // eslint-disable-next-line max-depth
            if (rr.toLowerCase() === 'mx') {
              // eslint-disable-next-line max-depth
              if (
                _.isArray(value) &&
                value.every(
                  (a) =>
                    _.isObject(a) &&
                    isSANB(a.exchange) &&
                    Number.isFinite(a.priority)
                )
              )
                return value;
              throw new Error('Invalid MX resolver cache', {
                name,
                rr,
                key,
                value
              });
            }

            // TODO: validate any other RR here otherwise no validation is done for cache integrity
            return value;
          } catch (err) {
            this.config.logger.fatal(err);
          }
        }

        this.config.logger.debug('cache miss', { key, value });
      } catch (err) {
        this.config.logger.error(err);
      }
    }

    // perform dns or dnsbl lookup
    let value;
    let ttl = this.config.dnsCacheMs;

    if (rr === 'DNSBL_BATCH') {
      // override ttl for dnsbl
      ttl = this.config.dnsBlacklistCacheMs;
      value = await dnsbl.batch(name, this.config.dnsbl.domains, {
        servers: this.config.dns
      });
    } else if (rr === 'DNSBL') {
      // override ttl for dnsbl
      ttl = this.config.dnsBlacklistCacheMs;
      value = await dnsbl.lookup(name, this.config.dnsbl.domains, {
        servers: this.config.dns
      });
    } else {
      value = await dns.promises.resolve(name, rr);
    }

    // store it in the cache in the background
    if (value && client) {
      client
        .set(key, safeStringify(value), 'PX', ttl)
        .then()
        .catch(this.config.logger.error);
    }

    return value;
  }

  async checkBlacklists(ip) {
    // if no blacklists are provided then return early
    if (
      !this.config.dnsbl ||
      !this.config.dnsbl.domains ||
      (_.isArray(this.config.dnsbl.domains) &&
        this.config.dnsbl.domains.length === 0)
    ) {
      this.config.logger.error('No DNS blacklists were provided');
      return false;
    }

    // if it is a FQDN then look it up by IP address
    if (isFQDN(ip)) {
      try {
        const values = await this.resolver(ip, 'A');
        return Promise.all(values.map((value) => this.checkBlacklists(value)));
      } catch (err) {
        // TODO: handle retries here
        this.config.logger.warn(err);
        this.config.logger.warn(
          new Error('DNS lookup failed to get IP', { ip })
        );
        return false;
      }
    }

    if (_.isArray(this.config.dnsbl.domains)) {
      try {
        const results = await this.resolver(ip, 'DNSBL_BATCH');
        if (!_.isArray(results) || results.length === 0) return false;
        const blacklistedResults = results.filter((result) => result.listed);
        if (blacklistedResults.length === 0) return false;
        return blacklistedResults
          .map((result) =>
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
      } catch (err) {
        // TODO: handle retries here (note API 408 client timeout would need rewritten, e.g. if resolver() function has configurable retry count)
        this.config.logger.warn(err);
        this.config.logger.warn(
          new Error('DNS lookup failed to get IP', { ip })
        );
        return false;
      }
    }

    try {
      const result = await this.resolver(ip, 'DNSBL');
      if (!result) return false;
      return util.format(
        this.config.blacklistedStr,
        ip,
        this.config.dnsbl.domains,
        this.config.dnsbl.removals
      );
    } catch (err) {
      // TODO: handle retries here (note API 408 client timeout would need rewritten, e.g. if resolver() function has configurable retry count)
      this.config.logger.warn(err);
      this.config.logger.warn(new Error('DNS lookup failed to get IP', { ip }));
      return false;
    }
  }

  //
  // NOTE: we should prevent the double whitelisting lookup
  //       (once is done for each isBlacklisted call)
  //
  async onConnect(session, fn) {
    if (this.server._closeTimeout)
      return setImmediate(() =>
        fn(new CustomError('Server shutdown in progress', 421))
      );

    // set arrival time for future use by bounce handler
    session.arrivalDate = new Date();
    session.arrivalDateFormatted = session.arrivalDate
      .toISOString()
      .split('T')[0];
    session.arrivalTime = session.arrivalDate.getTime();

    // lookup the client hostname
    try {
      const clientHostname = await this.reverser(session.remoteAddress);
      if (isFQDN(clientHostname)) {
        session.isValidClientHostname = true;
        //
        // NOTE: we parseHostFromDomainOrAddress here in case the clientHostname is encoded
        // (we use punycode() + toLowerCase() in parseHostFromDomainOrAddress to normalize everything)
        //
        session.clientHostname =
          this.parseHostFromDomainOrAddress(clientHostname);
      }
    } catch (err) {
      this.config.logger.fatal(err);
    }

    try {
      //
      // TODO: we should check all links/IP addresses (excluding Received headers)
      //       resolved against Spamhaus ZEN too w/SpamScanner
      //
      // ensure that it's not on the DNS blacklist
      // X Spamhaus = zen.spamhaus.org
      // - SpamCop = bl.spamcop.net
      // - Barracuda = b.barracudacentral.org
      // - Lashback = ubl.unsubscore.com
      // - PSBL = psbl.surriel.com
      //
      // TODO: re-enable this once we figure out why it wasn't working (and move down below)
      // const message = await this.checkBlacklists(session.remoteAddress);
      // if (message) {
      //   throw new CustomError(message, 554);
      // }

      //
      // check if the session is whitelisted (useful for greylisting)
      //
      session.isWhitelisted = false;
      try {
        if (session.isValidClientHostname) {
          // check the root domain
          const domain = this.parseRootDomain(session.clientHostname);
          session.isWhitelisted = await this.isWhitelisted(domain);
          if (session.isWhitelisted) {
            session.whitelistValue = domain;
          } else if (domain !== session.clientHostname) {
            // if differed, check the sub-domain
            session.isWhitelisted = await this.isWhitelisted(
              session.clientHostname
            );
            // eslint-disable-next-line max-depth
            if (session.isWhitelisted)
              session.whitelistValue = session.clientHostname;
          }
        }

        if (!session.isWhitelisted) {
          session.isWhitelisted = await this.isWhitelisted(
            session.remoteAddress
          );
          if (session.isWhitelisted)
            session.whitelistValue = session.remoteAddress;
        }
      } catch (err) {
        this.config.logger.fatal(err);
      }

      //
      // if we're not whitelisted then check against rate limitations
      // (validateRateLimit will only throw an error if rate limit exceeded)
      // (default is 10000 emails per sender hostname or IP every hour)
      //
      // TODO: refactor to support this:
      //       if (!session.isWhitelisted && !noWhitelistLookupErrorsOccurred)
      if (!session.isWhitelisted)
        await this.validateRateLimit(
          session.isValidClientHostname
            ? session.clientHostname
            : session.remoteAddress
        );

      //
      // check against the blacklist
      // (isBlacklisted will never throw an error)
      //
      const [isRemoteAddressBlacklisted, isClientHostnameBlacklisted] =
        await Promise.all([
          this.isBlacklisted(session.remoteAddress),
          session.isValidClientHostname
            ? this.isBlacklisted(session.clientHostname)
            : Promise.resolve(false)
        ]);

      if (isRemoteAddressBlacklisted) {
        if (!session.isWhitelisted)
          throw new CustomError(
            `The IP ${session.remoteAddress} is blacklisted by ${this.config.website}. To request removal, please email whitelist@forwardemail.net.`,
            554
          );
        this.config.logger.fatal(new Error('Whitelisted blacklist detected'), {
          value: session.whitelistValue,
          ip: session.remoteAddress,
          session
        });
      }

      if (isClientHostnameBlacklisted) {
        if (!session.isWhitelisted)
          throw new CustomError(
            `The domain ${session.clientHostname} is blacklisted by ${this.config.website}. To request removal, please email whitelist@forwardemail.net.`,
            554
          );
        this.config.logger.fatal(new Error('Whitelisted blacklist detected'), {
          value: session.whitelistValue,
          domain: session.clientHostname,
          session
        });
      }

      setImmediate(fn);
    } catch (err) {
      setImmediate(() => fn(this.refineAndLogError(err, session)));
    }
  }

  //
  // TODO: the stream stuff below needs rewritten
  //       (we shouldn't need streamEnded stuff)
  //
  async onData(stream, _session, fn) {
    if (this.server._closeTimeout)
      return setImmediate(() =>
        fn(new CustomError('Server shutdown in progress', 421))
      );

    //
    // passthrough streams don't have a `.ended` property
    //
    let streamEnded = false;
    stream.once('end', () => {
      streamEnded = true;
    });

    //
    // store original session since smtp-server calls `_resetSession()` internally
    // which causes values in the `session` object to become reset
    // (e.g. the envelope, clientHostname, remoteAddress, etc)
    //
    // <https://github.com/nodemailer/smtp-server/blob/2bd0975292208f1cf77d7a93cb3d8b3c4d48acb8/lib/smtp-connection.js#L590-L618>
    //
    const session = clone(_session);

    //
    // read the message headers and message itself
    //
    const messageSplitter = new MessageSplitter({
      size: this.config.smtp.size
    });

    const chunks = [];
    messageSplitter.on('readable', () => {
      let chunk;
      while ((chunk = messageSplitter.read()) !== null) {
        chunks.push(chunk);
      }
    });

    //
    // if an error occurs we have to continue reading the stream
    //
    messageSplitter.once('error', (err) => {
      if (streamEnded) {
        setImmediate(() => fn(this.refineAndLogError(err, session)));
      } else {
        stream.once('end', () => {
          setImmediate(() => fn(this.refineAndLogError(err, session)));
        });
      }

      stream.unpipe(messageSplitter);
      stream.on('readable', () => {
        stream.read();
      });
    });

    // eslint-disable-next-line complexity
    messageSplitter.on('end', async () => {
      //
      // we need to check the following:
      //
      // 1) X if email file size exceeds the limit (no bottleneck)
      // 2) X ensure all email headers were parsed
      // 3) X reverse SRS bounces
      // 4) X prevent replies to no-reply@forwardemail.net (no bottleneck)
      // 5) X check for spam
      // 6) X validate SPF, DKIM, DMARC, and ARC
      // 7) X lookup forwarding recipients recursively
      // 8) X normalize recipients by host and without "+" symbols
      // 9) X send email
      //
      try {
        //
        // 1) if email file size exceeds the limit
        //
        if (stream.sizeExceeded)
          throw new CustomError(
            `Maximum allowed message size ${bytes(
              this.config.smtp.size
            )} exceeded.`,
            552
          );

        //
        // 2) ensure all email headers were parsed
        //
        if (!messageSplitter.headersParsed)
          throw new CustomError(
            'Headers were unable to be parsed, please try again.',
            421
          );

        //
        // store variables for use later
        //
        // headers object (includes the \r\n\r\n header and body separator)
        const { headers } = messageSplitter;

        const originalFrom = headers.getFirst('From');

        if (!originalFrom)
          throw new CustomError(
            'Your message is not RFC 5322 compliant, please include a valid "From" header.'
          );

        //
        // parse the original from and ensure that all addresses are valid addresses
        //
        const originalFromAddresses = addressParser(originalFrom);
        if (
          _.isEmpty(originalFromAddresses) ||
          originalFromAddresses.some(
            (addr) =>
              !_.isObject(addr) ||
              !isSANB(addr.address) ||
              !validator.isEmail(addr.address)
          )
        )
          throw new CustomError(
            'Your message must contain valid email addresses in the "From" header.'
          );

        // <https://github.com/zone-eu/zone-mta/blob/2557a975ee35ed86e4d95d6cfe78d1b249dec1a0/plugins/core/email-bounce.js#L97>
        if (headers.get('Received').length > 25)
          throw new CustomError('Message was stuck in a redirect loop.');

        //
        // 3) reverse SRS bounces
        //
        const originalValue = headers.getFirst('To');
        if (originalValue) {
          const reversedValue = this.checkSRS(originalValue);
          if (originalValue !== reversedValue) {
            headers.update('To', reversedValue);
          }
        }

        const body = Buffer.concat(chunks);
        const originalRaw = Buffer.concat([headers.build(), body]);

        //
        // store an object of email addresses that bounced
        // with their associated error that occurred
        //
        const bounces = [];

        //
        // this gets us a prefix we can use for individual recipients
        // to denote whether or not they received their email
        // (so we don't send twice if only 1/3 forwarding failed to the other 2/3)
        //
        session.fingerprint = this.getFingerprint(session, headers, body);

        const messageId = headers.getFirst('Message-ID');
        let needsSealed = false;
        if (!isSANB(messageId)) {
          let domain = this.config.messageIdDomain;
          //
          // use the sender's parsed envelope from address
          //
          if (isSANB(session.envelope.mailFrom.address))
            domain = this.parseHostFromDomainOrAddress(
              this.checkSRS(session.envelope.mailFrom.address)
            );

          const id = `<${dashify(session.fingerprint)}@${domain}>`;
          headers.update('Message-ID', id);
          needsSealed = true;
        }

        //
        // only allow up to X retries for this message in general
        //
        if (this.client) {
          try {
            const key = `${this.config.fingerprintPrefix}:${session.fingerprint}:count`;
            const count = await this.client.incr(key);
            if (Number.isFinite(count)) {
              // set the keys expiry in the background
              this.client
                .pexpire(key, this.config.ttlMs)
                .then()
                .catch((err) => this.config.logger.fatal(err));

              // check if it exceeded the max retry count
              // eslint-disable-next-line max-depth
              if (count > this.config.maxRetry)
                throw new CustomError(
                  `This message has been retried the maximum of (${this.config.maxRetry}) times and has permanently failed.`
                );
            } else {
              //
              // perform background redis operations to keep flow moving
              //
              this.client
                .pipeline()
                .del(key)
                .incr(key)
                .pexpire(key, this.config.ttlMs)
                .exec()
                .then()
                .catch((err) => this.config.logger.fatal(err));
            }
          } catch (err) {
            if (err.responseCode === 550) throw err;
            this.config.logger.fatal(err);
          }
        }

        //
        // 5) check for spam
        //
        let scan;

        //
        // TODO: ignore parsing of URL's/IP's in "Received"-like headers
        //
        // TODO: enable this for non-test environments
        if (env.NODE_ENV === 'test') {
          try {
            scan = await this.scanner.scan(originalRaw);
          } catch (err) {
            this.config.logger.fatal(err, { session });
          }
        }

        // check for arbitrary tests (e.g. EICAR)
        if (
          _.isObject(scan) &&
          _.isObject(scan.results) &&
          _.isArray(scan.results.arbitrary) &&
          !_.isEmpty(scan.results.arbitrary)
        )
          throw new CustomError(scan.results.arbitrary.join(' '), 554);

        //
        // 6) validate SPF, DKIM, DMARC, and ARC
        //

        // get the fully qualified domain name ("FQDN") of this server
        let ipAddress = IP_ADDRESS;
        let name = NAME;
        if (env.NODE_ENV === 'test') {
          const object = await this.resolver(this.config.exchanges[0], 'A');
          ipAddress = object[0];
          name = await getFQDN(ipAddress);
        }

        //
        // TODO: set `Return-Path`, `X-Original-To`, and `X-Delivered-To` (if not set)
        // inspired by Postfix and requested by users
        //
        // <http://www.postfix.org/virtual.8.html>
        // <https://github.com/forwardemail/free-email-forwarding/pull/247>
        // <https://addons.thunderbird.net/en-us/thunderbird/addon/x-original-to-column/>
        //
        // if (!headers.hasHeader('X-Original-To'))
        //   headers.update('X-Original-To', session.envelope.rcptTo);

        // set `X-ForwardEmail-Version`
        headers.update('X-ForwardEmail-Version', pkg.version);
        // and `X-ForwardEmail-Session-ID`
        headers.update('X-ForwardEmail-Session-ID', session.id);
        // and `X-ForwardEmail-Sender`
        headers.update(
          'X-ForwardEmail-Sender',
          `rfc822; ${
            session.envelope.mailFrom.address
              ? this.checkSRS(session.envelope.mailFrom.address)
              : session.remoteAddress
          }`
        );

        let sealHeaders;
        const authOptions = {
          ip: session.remoteAddress,
          helo: session.hostNameAppearsAs,
          sender: session.envelope.mailFrom.address,
          mta: name,
          ...(_.isObject(this.config.dkim) &&
          isSANB(this.config.dkim.domainName) &&
          isSANB(this.config.dkim.keySelector) &&
          isSANB(this.config.dkim.privateKey)
            ? {
                seal: {
                  signingDomain: this.config.dkim.domainName,
                  selector: this.config.dkim.keySelector,
                  privateKey: this.config.dkim.privateKey
                }
              }
            : {}),
          resolver: this.resolver
        };
        const {
          dkim,
          spf,
          arc,
          dmarc,
          headers: arcSealedHeaders,
          bimi
          // no need for this:
          // `receivedChain`
        } = await authenticate(originalRaw, authOptions);

        const hadPassingSPF =
          _.isObject(spf) &&
          _.isObject(spf.status) &&
          spf.status.result === 'pass';

        const hadAlignedAndPassingDKIM =
          _.isObject(dkim) &&
          _.isArray(dkim.results) &&
          !_.isEmpty(dkim.results) &&
          dkim.results.some(
            (result) =>
              _.isObject(result) &&
              _.isObject(result.status) &&
              result.status.result === 'pass' &&
              isSANB(result.status.aligned)
          );

        //
        // only reject if ARC was not passing
        // and DMARC fail with p=reject policy
        //
        if (
          //
          // NOTE: google doesn't respect ARC, it only respects DMARC
          //       and only whitelists certain providers, so we should do the same
          //
          // _.isObject(arc) &&
          // _.isObject(arc.status) &&
          // arc.status.result !== 'pass' &&
          _.isObject(dmarc) &&
          // ['reject', 'quarantine'].includes(dmarc.policy)
          dmarc.policy === 'reject' &&
          _.isObject(dmarc.status) &&
          // ['fail', 'temperror'].includes(dmarc.status.result)
          dmarc.status.result === 'fail'
          // also fail authentication if there was failing DMARC with p=none, no signed dkim, and no spf
          // (_.isObject(dmarc) &&
          //   dmarc.policy === 'none' &&
          //   _.isObject(dmarc.status) &&
          //   dmarc.status.result === 'fail')
          // ['fail', 'temperror'].includes(dmarc.status.result) &&
          //! hadPassingDKIM &&
          // !hadPassingSPF
        )
          throw new CustomError(
            "The email sent has failed DMARC validation and is rejected due to the domain's DMARC policy."
          );

        // if no DMARC and SPF had hardfail then reject
        // NOTE: it'd be nice if we alerted admins of SPF permerror due to SPF misconfiguration
        if (
          (!dmarc ||
            (_.isObject(dmarc) &&
              _.isObject(dmarc.status) &&
              dmarc.status.result === 'none')) && // ['none', 'fail'].includes(dmarc.status.result) && // temperror
          _.isObject(spf) &&
          _.isObject(spf.status) &&
          spf.status.result === 'fail' &&
          !hadAlignedAndPassingDKIM
        )
          throw new CustomError(
            "The email sent has failed SPF validation and is rejected due to the domain's SPF hard fail policy."
          );

        //
        // 7) lookup forwarding recipients recursively
        //
        let recipients = await Promise.all(
          // eslint-disable-next-line complexity
          session.envelope.rcptTo.map(async (to) => {
            try {
              let port = '25';
              let hasAdultContentProtection = true;
              let hasPhishingProtection = true;
              let hasExecutableProtection = true;
              let hasVirusProtection = true;

              // if it was a bounce then return early
              const address = this.checkSRS(to.address);
              if (address !== to.address)
                return { address, addresses: [address], port };

              // get all forwarding addresses for this individual address
              const addresses = await this.getForwardingAddresses(to.address);

              if (addresses === false)
                return { address: to.address, addresses: [], ignored: true };

              // lookup the port (e.g. if `forward-email-port=` or custom set on the domain)
              const domain = this.parseHostFromDomainOrAddress(to.address);

              try {
                const req = await superagent
                  .get(`${this.config.apiEndpoint}/v1/settings`)
                  .query({ domain })
                  .set('Accept', 'application/json')
                  .set('User-Agent', this.config.userAgent)
                  .auth(this.config.apiSecrets[0])
                  .timeout(this.config.timeout)
                  .retry(this.config.retry);

                // body is an Object
                if (_.isObject(req.body)) {
                  // `port` (String) - a valid port number, defaults to 25
                  if (
                    isSANB(req.body.port) &&
                    validator.isPort(req.body.port) &&
                    req.body.port !== '25'
                  ) {
                    port = req.body.port;
                    this.config.logger.debug(
                      new Error(`Custom port for ${to.address} detected`),
                      {
                        port,
                        session
                      }
                    );
                  }

                  // Spam Scanner boolean values adjusted by user in Advanced Settings page
                  if (_.isBoolean(req.body.has_adult_content_protection))
                    hasAdultContentProtection =
                      req.body.has_adult_content_protection;
                  if (_.isBoolean(req.body.has_phishing_protection))
                    hasPhishingProtection = req.body.has_phishing_protection;
                  if (_.isBoolean(req.body.has_executable_protection))
                    hasExecutableProtection =
                      req.body.has_executable_protection;
                  if (_.isBoolean(req.body.has_virus_protection))
                    hasVirusProtection = req.body.has_virus_protection;
                }
              } catch (err) {
                //
                // 400 bad request error will occur if the endpoint
                // calls `app.resolver` (which is this resolver)
                // which can throw an error if dns resolver errors
                // (e.g. Error: getHostByAddr ENOTFOUND)
                //
                this.config.logger.warn(err, {
                  endpoint: `${this.config.apiEndpoint}/v1/settings`,
                  domain
                });
              }

              //
              // NOTE: here is where we check if Spam Scanner settings
              // were either enabled or disabled, and if they were enabled
              // and the respective policy did not pass, then throw that error as a bounce
              //
              if (_.isObject(scan) && _.isObject(scan.results)) {
                //
                // NOTE: until we are confident with the accuracy
                // we are not utilizing classification right now
                // however we still want to use other detections
                //
                const messages = [];

                if (
                  hasPhishingProtection &&
                  _.isArray(scan.results.phishing) &&
                  !_.isEmpty(scan.results.phishing)
                ) {
                  for (const message of scan.results.phishing) {
                    // if we're not filtering for adult-related content then continue early
                    // eslint-disable-next-line max-depth
                    if (
                      !hasAdultContentProtection &&
                      message.indexOf('adult-related content') !== -1
                    )
                      continue;
                    // eslint-disable-next-line max-depth
                    if (message.indexOf('adult-related content') === -1)
                      messages.push(
                        'Links were detected that may contain phishing and/or malware.'
                      );
                    else
                      messages.push(
                        'Links were detected that may contain adult-related content.'
                      );
                    //
                    // NOTE: we do not want to push the link in the response
                    //       (otherwise bounce emails may never arrive to sender)
                    //
                    // messages.push(message);
                  }
                }

                if (
                  hasExecutableProtection &&
                  _.isArray(scan.results.executables) &&
                  !_.isEmpty(scan.results.executables)
                ) {
                  for (const message of scan.results.executables.slice(0, 2)) {
                    messages.push(message);
                  }

                  messages.push(
                    `You may want to re-send your attachment in a compressed archive format (e.g. a ZIP file).`
                  );
                }

                if (
                  hasVirusProtection &&
                  _.isArray(scan.results.viruses) &&
                  !_.isEmpty(scan.results.viruses)
                ) {
                  for (const message of scan.results.viruses.slice(0, 2)) {
                    messages.push(message);
                  }
                }

                if (messages.length > 0) {
                  messages.push(
                    'For more information on Spam Scanner visit https://spamscanner.net.'
                  );
                  throw new CustomError(_.uniq(messages).join(' '), 554);
                }
              }

              return {
                address: to.address,
                addresses,
                port
              };
            } catch (err) {
              this.config.logger.warn(err, { session });
              bounces.push({
                address: to.address,
                err
              });
            }
          })
        );

        // flatten the recipients and make them unique
        recipients = _.uniqBy(_.compact(recipients.flat()), 'address');

        // TODO: we can probably remove this now
        // go through recipients and if we have a user+xyz@domain
        // AND we also have user@domain then honor the user@domain only
        // (helps to alleviate bulk spam with services like Gmail)
        for (const recipient of recipients) {
          const filtered = [];
          for (const address of recipient.addresses) {
            if (address.indexOf('+') === -1) {
              filtered.push(address);
              continue;
            }

            if (
              recipient.addresses.indexOf(
                `${this.parseUsername(
                  address
                )}@${this.parseHostFromDomainOrAddress(address)}`
              ) === -1
            )
              filtered.push(address);
          }

          recipient.addresses = filtered;
        }

        recipients = await Promise.all(
          recipients.map(async (recipient) => {
            const errors = [];
            const addresses = [];
            await Promise.all(
              recipient.addresses.map(async (address) => {
                try {
                  // TODO: add punycode support
                  // check if the address was blacklisted
                  const isBlacklisted = await this.isBlacklisted(address);
                  if (isBlacklisted) {
                    const err = new CustomError(
                      // NOTE: we suppress the actual address here that is blacklisted (to protect privacy of email forwarding)
                      `The address ${recipient.address} is blacklisted by ${this.config.website}. To request removal, please email whitelist@forwardemail.net.`,
                      554
                    );
                    err.address = address;
                    throw err;
                  }

                  // if it was a URL webhook then return early
                  if (validator.isURL(address, this.config.isURLOptions)) {
                    addresses.push({ to: address, is_webhook: true });
                    return;
                  }

                  addresses.push({
                    to: address,
                    host: this.parseHostFromDomainOrAddress(address)
                  });
                  return;
                } catch (err) {
                  // e.g. if the MX servers don't exist for recipient
                  // then obviously there should be an error
                  this.config.logger.error(err, { session });
                  errors.push(err);
                }
              })
            );

            // map it back
            recipient.addresses = addresses;

            // custom port support
            if (recipient.addresses.length === 0 && recipient.port !== '25')
              recipient.addresses.push({
                to: recipient.address,
                host: this.parseHostFromDomainOrAddress(recipient.address)
              });

            if (recipient.addresses.length > 0) return recipient;
            if (errors.length === 0) return;
            for (const err of errors) {
              this.config.logger.error(err, { session });
            }

            const err = combineErrors(errors);
            err.code = errors.map((err) => this.getErrorCode(err)).sort()[0];
            err.responseCode = err.code;
            bounces.push({
              address: recipient.address,
              err
            });
          })
        );

        recipients = _.compact(recipients);

        // if no recipients return early with bounces joined together
        if (_.isEmpty(recipients)) {
          if (_.isEmpty(bounces)) throw new CustomError('Invalid recipients');
          // go by lowest code (e.g. 421 retry instead of 5xx if one still hasn't sent yet)
          const [code] = bounces
            .map((bounce) => this.getErrorCode(bounce.err))
            .sort();
          throw new CustomError(
            bounces
              .map(
                (bounce) =>
                  `Error for ${bounce.address} of "${bounce.err.message}"`
              )
              .join(', '),
            code
          );
        }

        //
        // 8) normalize recipients by host and without "+" symbols
        //
        const normalized = [];

        for (const recipient of recipients) {
          // if it's ignored then don't bother
          if (recipient.ignored) continue;
          for (const address of recipient.addresses) {
            // if it's a webhook then return early
            if (address.is_webhook) {
              //
              // NOTE: we group webhooks based off their endpoint
              //       to reduce the number of requests sent across
              //
              const match = normalized.find((r) => r.webhook === address.to);
              // eslint-disable-next-line max-depth
              if (match) {
                // eslint-disable-next-line max-depth
                if (match.to.indexOf(address.to) === -1)
                  match.to.push(address.to);
                // eslint-disable-next-line max-depth
                if (!match.replacements[recipient.address])
                  match.replacements[recipient.address] = address.to; // normal;
              } else {
                const replacements = {};
                replacements[recipient.address] = address.to; // normal;
                normalized.push({
                  webhook: address.to,
                  to: [address.to],
                  recipient: recipient.address,
                  replacements
                });
              }

              continue;
            }

            // get normalized form without `+` symbol
            // const normal = `${this.parseUsername(
            //   address.to
            // )}@${this.parseHostFromDomainOrAddress(address.to)}`;
            const match = normalized.find(
              (r) => r.host === address.host && r.port === recipient.port
            );
            if (match) {
              // if (!match.to.includes(normal)) match.to.push(normal);
              // eslint-disable-next-line max-depth
              if (match.to.indexOf(address.to) === -1)
                match.to.push(address.to);
              // eslint-disable-next-line max-depth
              if (!match.replacements[recipient.address])
                match.replacements[recipient.address] = address.to; // normal;
            } else {
              const replacements = {};
              replacements[recipient.address] = address.to; // normal;
              normalized.push({
                host: address.host,
                port: recipient.port,
                recipient: recipient.address,
                to: [address.to], // [ normal ],
                replacements
              });
            }
          }
        }

        if (normalized.length === 0) {
          if (streamEnded) return setImmediate(fn);
          stream.once('end', () => setImmediate(fn));
          return;
        }

        //
        // 9) send email
        //
        const accepted = [];
        const selfTestEmails = [];

        //
        // TODO: better abuse prevention around this
        //
        // only use SRS if:
        // - ARC none
        // - SPF pass
        // - DMARC none OR p=reject and pass
        // - no passing DKIM
        //
        const from = isSANB(session.envelope.mailFrom.address)
          ? this.srs.forward(
              this.checkSRS(session.envelope.mailFrom.address),
              this.config.srsDomain
            )
          : session.envelope.mailFrom.address;

        if (
          _.isObject(dmarc) &&
          dmarc.policy === 'reject' &&
          _.isObject(dmarc.status) &&
          dmarc.status.result === 'pass' &&
          hadPassingSPF &&
          _.isObject(dmarc.alignment) &&
          _.isObject(dmarc.alignment.dkim) &&
          dmarc.alignment.dkim.result === false
        ) {
          //
          // rewrite with friendly from here
          //
          const replyTo = headers.getFirst('Reply-To');
          //
          // if the DKIM signature signs the Reply-To and the From
          // then we will probably want to remove it since it won't be valid anymore
          //
          headers.update('From', this.rewriteFriendlyFrom(originalFrom));
          headers.update('X-Original-From', originalFrom);
          //
          // if there was an original reply-to on the email
          // then we don't want to modify it of course
          //
          if (!replyTo) headers.update('Reply-To', originalFrom);

          // seal the modified mesasge using initial authentication results
          if (
            _.isObject(this.config.dkim) &&
            isSANB(this.config.dkim.domainName) &&
            isSANB(this.config.dkim.keySelector) &&
            isSANB(this.config.dkim.privateKey)
          ) {
            try {
              sealHeaders = await sealMessage(
                Buffer.concat([headers.build(), body]),
                {
                  signingDomain: this.config.dkim.domainName,
                  selector: this.config.dkim.keySelector,
                  privateKey: this.config.dkim.privateKey,
                  // values from the authentication step
                  authResults: arc.authResults,
                  cv: arc.status.result
                }
              );
            } catch (err) {
              this.config.logger.fatal(err, { session });
            }
          }
        } else if (
          // seal the modified mesasge using initial authentication results
          needsSealed &&
          _.isObject(this.config.dkim) &&
          isSANB(this.config.dkim.domainName) &&
          isSANB(this.config.dkim.keySelector) &&
          isSANB(this.config.dkim.privateKey)
        ) {
          try {
            sealHeaders = await sealMessage(
              Buffer.concat([headers.build(), body]),
              {
                signingDomain: this.config.dkim.domainName,
                selector: this.config.dkim.keySelector,
                privateKey: this.config.dkim.privateKey,
                // values from the authentication step
                authResults: arc.authResults,
                cv: arc.status.result
              }
            );
          } catch (err) {
            this.config.logger.fatal(err, { session });
          }
        }

        const raw = Buffer.concat([
          Buffer.from(sealHeaders ? sealHeaders : arcSealedHeaders),
          headers.build(),
          body
        ]);

        //
        // this is the core function that sends the email
        //
        // eslint-disable-next-line complexity
        const mapper = async (recipient) => {
          if (recipient.webhook) {
            try {
              const key = `${this.config.fingerprintPrefix}:${
                session.fingerprint
              }:${revHash(safeStringify(Object.keys(recipient.replacements)))}`;

              if (this.client) {
                try {
                  const value = await this.client.get(key);
                  // if the value was corrupt and it gets sent successfully it will get corrected
                  // eslint-disable-next-line max-depth
                  if (value) {
                    const int = Number.parseInt(value, 10);
                    // eslint-disable-next-line max-depth
                    if (Number.isFinite(int) && int > 0) {
                      // NOTE: we group together recipients based off endpoint
                      // eslint-disable-next-line max-depth
                      for (const replacement of Object.keys(
                        recipient.replacements
                      )) {
                        // eslint-disable-next-line max-depth
                        if (accepted.indexOf(replacement) === -1)
                          accepted.push(replacement);
                      }

                      return;
                    }
                  }
                } catch (err) {
                  this.config.logger.fatal(err);
                }
              }

              const mail = await simpleParser(raw, this.config.simpleParser);

              const res = await superagent
                .post(
                  // dummyproofing
                  recipient.webhook
                    .replace('HTTP://', 'http://')
                    .replace('HTTPS://', 'https://')
                )
                .set('User-Agent', this.config.userAgent)
                .timeout(this.config.timeout)
                .send({
                  ...mail,
                  raw: _.isBuffer(raw) ? raw.toString('binary') : raw,
                  dkim,
                  spf,
                  arc,
                  dmarc,
                  headers: arcSealedHeaders,
                  bimi,
                  recipients: Object.keys(recipient.replacements),
                  session: {
                    remoteAddress: session.remoteAddress,
                    remotePort: session.remotePort,
                    clientHostname: session.clientHostname,
                    hostNameAppearsAs: session.hostNameAppearsAs,
                    sender: session.envelope.mailFrom.address,
                    mta: name,
                    arrivalDate: session.arrivalDate,
                    arrivalTime: session.arrivalTime
                  }
                });

              // TODO: smart alerts here for webhooks misconfigured (e.g. HTTP -> HTTPS redirect)
              if (
                !_.isObject(res) ||
                !_.isObject(res.req) ||
                res.req.method !== 'POST'
              ) {
                if (_.isArray(res.redirects) && !_.isEmpty(res.redirects))
                  throw new CustomError(
                    `Webhook endpoint redirects occurred which prevented a POST request`
                  );
                throw new CustomError(
                  'Webhook endpoint did not perform a POST request'
                );
              }

              if (this.client)
                this.client
                  .pipeline()
                  .incr(key)
                  .pexpire(key, this.config.ttlMs)
                  .exec()
                  .then()
                  .catch((err) => this.config.logger.fatal(err));

              // NOTE: we group together recipients based off endpoint
              for (const replacement of Object.keys(recipient.replacements)) {
                if (accepted.indexOf(replacement) === -1)
                  accepted.push(replacement);
              }

              return;
            } catch (err_) {
              this.config.logger.warn(err_, {
                session,
                webhook: recipient.webhook
              });

              // determine if code or status is retryable here and set it as `err._responseCode`
              if (
                (isSANB(err_.code) && HTTP_RETRY_ERROR_CODES.has(err_.code)) ||
                (_.isNumber(err_.status) &&
                  HTTP_RETRY_STATUS_CODES.has(err_.status))
              ) {
                err_.responseCode = 421;
              } else {
                // alias `responseCode` for consistency with SMTP responseCode
                // TODO: map HTTP to SMTP codes appropriately
                // if (_.isNumber(err_.status))
                //   err_.responseCode = err_.status;
                // else
                err_.responseCode = 550;
              }

              // hide the webhook endpoint
              err_.message = err_.message.replace(
                new RE2(recipient.webhook, 'gi'),
                'a webhook endpoint'
              );

              // in case the response had sensitive email user information hide it too
              for (const address of Object.keys(recipient.replacements)) {
                err_.message = err_.message.replace(
                  new RE2(address, 'gi'),
                  recipient.replacements[address]
                );
              }

              for (const address of Object.keys(recipient.replacements)) {
                const err = new Error(err_);
                err.message = `${err_.status} ${status(err_.status)}${
                  err_.status === 500 ? '' : ' Error'
                } for ${address}`;
                bounces.push({
                  address,
                  err
                });
              }
            }

            return;
          }

          const options = {
            host: recipient.host,
            port: recipient.port,
            name,
            envelope: {
              from,
              to: recipient.to
            },
            raw
          };

          // TODO: accepted needs to be a Set

          try {
            const info = await this.sendEmail(options, session);
            this.config.logger.info('sent email', {
              info,
              options: _.omit(options, 'raw'),
              session
            });

            if (info.accepted && info.accepted.length > 0) {
              // add the masked recipient to the final accepted array
              // (we don't want to reveal forwarding config to client SMTP servers)
              if (accepted.indexOf(recipient.recipient) === -1)
                accepted.push(recipient.recipient);

              let pipeline;

              if (this.client) pipeline = this.client.pipeline();

              //
              // consolidated logic for redis pipeline
              // and checking for self-test emails sent
              // into one loop for performance
              //
              for (const a of info.accepted) {
                // add to mset operation
                if (this.client) {
                  const key = `${this.config.fingerprintPrefix}:${
                    session.fingerprint
                  }:${revHash(a)}`;
                  pipeline.incr(key);
                  pipeline.pexpire(key, this.config.ttlMs);
                }

                //
                // check to see if we sent an email to the same address it was coming from
                // (and if so, then send a self test email to notify sender it won't show up twice)
                //

                //
                // get normalized form without `+` symbol (in case someone tries test+something@gmail.com)
                //
                const normal = `${this.parseUsername(
                  a
                )}@${this.parseHostFromDomainOrAddress(a)}`;
                if (
                  normal === this.checkSRS(session.envelope.mailFrom.address) &&
                  selfTestEmails.indexOf(normal) === -1
                )
                  selfTestEmails.push(normal);
              }

              // store in the background the successful recipients it was sent to
              if (this.client) {
                // store a counter for the day of how many emails were accepted
                this.client
                  .incrby(
                    `mail_accepted:${session.arrivalDateFormatted}`,
                    info.accepted.length
                  )
                  .then()
                  .catch((err) => this.config.logger.fatal(err));

                if (pipeline)
                  pipeline
                    .exec()
                    .then()
                    .catch((err) => this.config.logger.fatal(err));
              }
            }

            if (info.rejectedErrors && info.rejectedErrors.length > 0) {
              for (const err of info.rejectedErrors) {
                this.config.logger.error(err, {
                  options: _.omit(options, 'raw'),
                  session
                });

                // here we do some magic so that we push an error message
                // that has the end-recipient's email masked with the
                // original to address that we were trying to send to
                for (const address of Object.keys(recipient.replacements)) {
                  err.message = err.message.replace(
                    new RE2(address, 'gi'),
                    recipient.replacements[address]
                  );
                }

                // TODO: in future handle this `options.port`
                // and also handle it in `12) send email`
                bounces.push({
                  address: recipient.recipient,
                  host: recipient.host,
                  err
                });
              }

              if (this.client) {
                // store a counter for the day of how many emails were accepted
                this.client
                  .incrby(
                    `mail_rejected:${session.arrivalDateFormatted}`,
                    info.rejectedErrors.length
                  )
                  .then()
                  .catch((err) => this.config.logger.fatal(err));
              }
            }
          } catch (err) {
            this.config.logger.error(err, {
              omit: _.omit(options, 'raw'),
              session
            });

            // here we do some magic so that we push an error message
            // that has the end-recipient's email masked with the
            // original to address that we were trying to send to
            for (const address of Object.keys(recipient.replacements)) {
              err.message = err.message.replace(
                new RE2(address, 'gi'),
                recipient.replacements[address]
              );
            }

            bounces.push({
              address: recipient.recipient,
              host: recipient.host,
              err
            });
          }
        };

        //
        // since we can have up to 100 recipients, we probably don't want to do them all at once
        // so we utilize pMap here to add additional concurrency for sending
        // (so one sender doesn't utilize the entire CPU for the queue)
        //
        await pMap(normalized, mapper, { concurrency });

        //
        // if there were any where the MAIL FROM was equivalent to the recipient
        // then we'll send them a one-time email to let them know it was successful
        // and also that they made need to check their "Sent" folder since many email
        // hosts like Gmail will not show a message you send from yourself to yourself
        // unless we rewrite the Message-Id header, which was previously did, but even
        // then it causes problems, as it prepends "This email looks suspicious" warning
        //
        // <https://support.google.com/a/answer/1703601?hl=en>
        // <https://stackoverflow.com/a/52534520>
        //
        if (selfTestEmails.length > 0)
          superagent
            .post(`${this.config.apiEndpoint}/v1/self-test`)
            .set('User-Agent', this.config.userAgent)
            .set('Accept', 'application/json')
            .auth(this.config.apiSecrets[0])
            .timeout(this.config.timeout)
            .retry(this.config.retry)
            .send({
              emails: selfTestEmails
            })
            .then(() => {})
            .catch((err) => {
              this.config.logger.error(err, {
                session,
                endpoint: `${this.config.apiEndpoint}/v1/self-test`,
                emails: selfTestEmails
              });
            });

        // if there weren't any bounces then return early
        if (bounces.length === 0) {
          if (streamEnded) return setImmediate(fn);
          stream.once('end', () => setImmediate(fn));
        }

        const errors = [];
        const codes = [];

        if (accepted.length > 0)
          errors.push(
            new Error(
              `Message was sent successfully to ${arrayJoinConjunction(
                accepted
              )}`
            )
          );

        for (const bounce of bounces) {
          //
          // NOTE: we also have `bounce.host` and `bounce.address` to use if needed for more verbosity
          //
          errors.push(bounce.err);
          codes.push(this.getErrorCode(bounce.err));
        }

        // join the messages together and make them unique
        const err = combineErrors(_.uniqBy(errors, 'message'));
        err.code = codes.sort()[0];
        err.responseCode = err.code;

        // send error to user
        if (streamEnded) {
          setImmediate(() => fn(this.refineAndLogError(err, session)));
        } else {
          stream.once('end', () => {
            setImmediate(() => fn(this.refineAndLogError(err, session)));
          });
        }

        //
        // you can't send a bounce email to someone that doesn't exist
        //
        if (!session.envelope.mailFrom.address) return;

        //
        // if the message had any of these headers then don't send bounce
        // <https://www.jitbit.com/maxblog/18-detecting-outlook-autoreplyout-of-office-emails-and-x-auto-response-suppress-header/>
        // <https://github.com/nodemailer/smtp-server/issues/129>
        //
        if (
          headers.hasHeader('X-Autoreply') ||
          headers.hasHeader('X-Autorespond') ||
          (headers.hasHeader('Auto-Submitted') &&
            headers.getFirst('Auto-Submitted') === 'auto-replied')
        )
          return;

        //
        // instead of returning an error if it bounced
        // which would in turn cause the message to get retried
        // we should instead send a bounce email to the user
        //
        // <https://github.com/nodemailer/smtp-server/issues/129>
        //
        // and we also need to make bounces unique by address here
        // (will basically pick the first that was pushed to the list)
        //
        const uniqueBounces = _.uniqBy(bounces, 'address').filter((bounce) => {
          // extra safeguards to prevent exception and let us know of any weirdness
          if (!_.isObject(bounce)) {
            this.config.logger.fatal(
              new Error('Bounce was not an object', { bounce, session })
            );
            return false;
          }

          if (!_.isError(bounce.err)) {
            this.config.logger.fatal(
              new Error('Bounce was missing error object', { bounce, session })
            );
            return false;
          }

          if (isSANB(bounce.err.code) && RETRY_CODES.has(bounce.err.code))
            return false;

          if (
            _.isNumber(bounce.err.responseCode) &&
            RETRY_CODE_NUMBERS.has(bounce.err.responseCode)
          )
            return false;

          if (
            _.isNumber(bounce.err.status) &&
            RETRY_CODE_NUMBERS.has(bounce.err.status)
          )
            return false;

          if (isSANB(bounce.err.response)) {
            // NOTE: what if this throws an error? need to check the source
            const bounceInfo = zoneMTABounces.check(bounce.err.response);
            if (DEFER_AND_SLOWDOWN.has(bounceInfo.action)) return false;
          }

          return true;
        });

        // if all of the bounces were defer/slowdown then return early
        if (uniqueBounces.length === 0) return;

        //
        // TODO: get the latest bounce template rendered for the user from our API
        // (which we'll then replace with the recipient's address and message)
        //
        const template = false;
        /*
          try {
            const req = await superagent
              .get(`${this.config.apiEndpoint}/v1/bounce`)
              .set('Accept', 'application/json')
              .set('User-Agent', `forward-email/${pkg.version}`)
              .auth(this.config.apiSecrets[0])
              .timeout(this.config.timeout)
              .retry(this.config.retry);

            if (_.isObject(req.body) && isSANB(req.body.html) && isSANB(req.body.text))
              template = req.body;
          } catch (err) {
            this.config.logger.error(err, { session });
          }
          */

        Promise.all(
          uniqueBounces.map(async (bounce) => {
            try {
              // TODO: we may want to make this more unique based off `bounce.err.message`
              const key = `${this.config.fingerprintPrefix}:${
                session.fingerprint
              }:bounce:${revHash(bounce.address)}:${this.getErrorCode(
                bounce.err
              )}`;

              if (this.client) {
                const value = await this.client.get(key);
                if (value) {
                  const int = Number.parseInt(value, 10);
                  if (Number.isFinite(int) && int > 0) return;
                }
              }

              const raw = await getStream(
                this.dkim.sign(
                  this.getBounceStream({
                    headers,
                    from,
                    name,
                    bounce,
                    id: session.id,
                    arrivalTime: session.arrivalTime,
                    originalRaw,
                    messageId: headers.getFirst('Message-ID'),
                    template
                  })
                )
              );

              const options = {
                host: this.checkSRS(session.envelope.mailFrom.address),
                port: '25',
                name,
                envelope: {
                  from: this.config.mailerDaemon.address.replace(
                    /\[hostname]/gi,
                    name
                  ),
                  to: this.checkSRS(session.envelope.mailFrom.address)
                },
                raw
              };

              const info = await this.sendEmail(options, session);
              this.config.logger.info('sent email', {
                info,
                options: _.omit(options, 'raw'),
                session
              });

              //
              // TODO: this should iterate over `info.accepted` and `info.rejected`
              //
              if (this.client) {
                this.client
                  .pipeline()
                  .incr(key)
                  .pexpire(key, this.config.ttlMs)
                  .exec()
                  .then()
                  .catch((err) => this.config.logger.fatal(err));
                // store a counter for the day of how many bounces were sent
                this.client
                  .incr(`bounce_sent:${session.arrivalDateFormatted}`)
                  .then()
                  .catch((err) => this.config.logger.fatal(err));
              }
            } catch (err_) {
              this.config.logger.fatal(err_, { session });
            }
          })
        )
          .then()
          .catch((err) => this.config.logger.fatal(err));
      } catch (err) {
        if (streamEnded) {
          setImmediate(() => fn(this.refineAndLogError(err, session)));
        } else {
          stream.once('end', () => {
            setImmediate(() => fn(this.refineAndLogError(err, session)));
          });
        }
      }
    });

    stream.pipe(messageSplitter);
  }

  async validateMX(address) {
    try {
      const domain = this.parseHostFromDomainOrAddress(address);
      const addresses = await this.resolver(domain, 'MX');
      if (!addresses || addresses.length === 0)
        throw new CustomError(
          `DNS lookup for ${domain} did not return any valid MX records.`,
          421
        );
      return _.sortBy(addresses, 'priority');
    } catch (err) {
      this.config.logger.warn(err, { address });
      // support retries
      err.responseCode =
        _.isString(err.code) && RETRY_CODES.has(err.code)
          ? MAP_CODES_TO_RESPONSE_CODES.get(err.code)
          : 421;

      throw err;
    }
  }

  async validateRateLimit(id) {
    if (!this.rateLimiter) return;

    try {
      const limit = await this.rateLimiter.get({ id });

      if (limit.remaining) {
        this.config.logger.debug(
          `Rate limit for ${id} is now ${limit.remaining - 1}/${limit.total}.`
        );
        return;
      }

      const delta = Math.trunc(limit.reset * 1000 - Date.now());
      throw new CustomError(
        `Rate limit exceeded for ${id}, retry in ${prettyMilliseconds(delta, {
          verbose: true,
          secondsDecimalDigits: 0
        })}.`,
        // NOTE: this used to be 451, which is not consistent
        // <https://smtpfieldmanual.com/code/421>
        // <https://smtpfieldmanual.com/code/451>
        // 451
        421
      );
    } catch (err) {
      if (err.responseCode === 421) throw err;
      this.config.logger.fatal(err);
    }
  }

  // TODO: make sure we routinely add all our paying customers
  //       to the DNS whitelist we store in redis

  //
  // NOTE: this assumes that the `domain` passed was already
  //       ran through `parseHostFromDomainOrAddress` function for normalization
  //
  async isWhitelisted(val) {
    try {
      // check hard-coded whitelist
      if (this.config.whitelist.has(val)) return true;

      const result = this.client
        ? await this.client.get(`whitelist:${val}`)
        : false;

      // was not whitelisted
      return result === 'true';
    } catch (err) {
      this.config.logger.fatal(err);
    }

    // return true as a safeguard in case there was an error
    return true;
  }

  // TODO: all calls to isBlacklisted or isWhitelisted
  //       need to use punycode.toASCII
  //
  // NOTE: this assumes that the `domain` passed was already
  //       ran through `parseHostFromDomainOrAddress` function for normalization
  //
  // TODO: this needs to support an address or domain
  //
  async isBlacklisted(value) {
    try {
      //
      // check if it was whitelisted
      //
      // NOTE: if this is any error while performing whitelist lookup
      //       the function will return `true` as safe-guard against false-positive
      //
      const isWhitelisted = await this.isWhitelisted(value);
      if (isWhitelisted) return false;

      // check redis blacklist on root domain
      const rootDomain = this.parseRootDomain(value);
      const isRootDomainBlacklisted = this.client
        ? await this.client.get(`blacklist:${rootDomain}`)
        : false;
      if (boolean(isRootDomainBlacklisted)) return true;

      // check redis blacklist on generic domain (if it differs)
      if (rootDomain !== value) {
        const result = this.client
          ? await this.client.get(`blacklist:${value}`)
          : false;
        if (boolean(result)) return true;
      }
    } catch (err) {
      this.config.logger.fatal(err, { value });
    }

    // was not blacklisted
    return false;
  }

  // this returns either the reversed SRS address
  // or the address that was passed to this function
  checkSRS(address) {
    if (!REGEX_SRS0.test(address) && !REGEX_SRS1.test(address)) return address;

    try {
      const reversed = this.srs.reverse(address);
      if (_.isNull(reversed)) throw new Error('Invalid SRS reversed address');
      return reversed;
    } catch (err) {
      this.config.logger.error(err, { address });
      return address;
    }
  }

  async isBackscatter(session) {
    if (!this.client) return false;

    // check against backscatter
    let value = false;
    try {
      value = await this.client.get(`backscatter:${session.remoteAddress}`);
    } catch (err) {
      this.config.logger.fatal(err);
    }

    // if it was not listed then return false
    if (!boolean(value)) return false;

    // if the host is whitelisted then ignore it
    // but still log that it was found on backscatter list
    // (most likely a false positive)
    if (session.isWhitelisted) {
      this.config.logger.fatal(new Error('Whitelist backscatter detected'), {
        value: session.whitelistValue,
        ip: session.remoteAddress,
        session
      });
      return false;
    }

    return true;
  }

  async onMailFrom(address, session, fn) {
    if (this.server._closeTimeout)
      return setImmediate(() =>
        fn(new CustomError('Server shutdown in progress', 421))
      );

    if (!_.isObject(address) || !isSANB(address.address)) {
      //
      // we need to check against backscatter if blank mail from
      // http://www.backscatterer.org/?target=usage
      //
      const isBackscatter = await this.isBackscatter(session);
      if (isBackscatter)
        return setImmediate(() =>
          fn(
            new CustomError(
              `The IP ${session.remoteAddress} is blacklisted by https://www.backscatterer.org/index.php?target=test&ip=${session.remoteAddress}`,
              554
            )
          )
        );
      return setImmediate(fn);
    }

    try {
      // this will throw an error if it was blacklisted
      const isBlacklisted = await this.isBlacklisted(
        this.checkSRS(address.address)
      );
      if (isBlacklisted)
        throw new CustomError(
          `The address ${this.checkSRS(address.address)} is blacklisted by ${
            this.config.website
          }. To request removal, please email whitelist@forwardemail.net.`,
          554
        );
    } catch (err) {
      if (err.responseCode === 554)
        return setImmediate(() => fn(this.refineAndLogError(err, session)));
      this.config.logger.fatal(err);
    }

    //
    // check if it was in backscatter
    // (only if mailer-daemon@, postmaster@, or another standard)
    // <https://unix.stackexchange.com/q/65013>
    //
    const username = this.parseUsername(this.checkSRS(address.address));

    // return early if it did not contain it
    if (!MAILER_DAEMON_USERNAMES.has(username)) return setImmediate(fn);

    //
    // otherwise check backscatterer if it was mailer-daemon@, postmaster@, etc.
    // http://www.backscatterer.org/?target=usage
    //
    const isBackscatter = await this.isBackscatter(session);
    if (isBackscatter)
      return setImmediate(() =>
        fn(
          new CustomError(
            `The IP ${session.remoteAddress} is blacklisted by https://www.backscatterer.org/index.php?target=test&ip=${session.remoteAddress}`,
            554
          )
        )
      );

    setImmediate(fn);
  }

  // this returns the forwarding address for a given email address
  // eslint-disable-next-line complexity
  async getForwardingAddresses(address, recursive = []) {
    const domain = this.parseHostFromDomainOrAddress(address);

    let records;
    try {
      records = await this.resolver(domain, 'TXT');
      // if records is not an Array
      // or if records is not an Array of Arrays
    } catch (err) {
      this.config.logger.warn(err, { address });
      // support retries
      err.responseCode =
        _.isString(err.code) && RETRY_CODES.has(err.code)
          ? MAP_CODES_TO_RESPONSE_CODES.get(err.code)
          : 421;

      throw err;
    }

    // dns TXT record must contain `forward-email=` prefix
    const validRecords = [];

    // verifications must start with `forward-email-site-verification=` prefix
    const verifications = [];

    // add support for multi-line TXT records
    for (let i = 0; i < records.length; i++) {
      records[i] = records[i].join('').trim(); // join and trim chunks together
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

    // check if we have a specific redirect and store global redirects (if any)
    // get username from recipient email address
    // (e.g. hello@niftylettuce.com => hello)
    const username = this.parseUsername(address);

    if (verifications.length > 0) {
      if (verifications.length > 1)
        throw new CustomError(
          // TODO: we may want to replace this with "Invalid Recipients"
          `Domain ${domain} has multiple verification TXT records of "${this.config.recordPrefix}-site-verification" and should only have one`
        );
      // if there was a verification record then perform lookup
      const req = await superagent
        .get(`${this.config.apiEndpoint}/v1/lookup`)
        .query({ domain, username, verification_record: verifications[0] })
        .set('Accept', 'application/json')
        .set('User-Agent', this.config.userAgent)
        .auth(this.config.apiSecrets[0])
        .timeout(this.config.timeout)
        .retry(this.config.retry);

      // body is an Array of records that are formatted like TXT records
      if (_.isArray(req.body) && req.body.length > 0) {
        // combine with any existing TXT records (ensures graceful DNS propagation)
        for (const element of req.body) {
          validRecords.push(element);
        }
      }
    }

    // join multi-line TXT records together and replace double w/single commas
    const record = validRecords.join(',').replace(/,+/g, ',').trim();

    // if the record was blank then throw an error
    if (!isSANB(record))
      throw new CustomError(
        // TODO: we may want to replace this with "Invalid Recipients"
        `${address} is not configured to use https://forwardemail.net`,
        421
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
    const addresses = record.split(',').map((a) => a.trim());

    if (addresses.length === 0)
      throw new CustomError(
        // TODO: we may want to replace this with "Invalid Recipients"
        `${address} domain of ${domain} has zero forwarded addresses configured in the TXT record with "${this.config.recordPrefix}"`,
        421
      );

    // store if address is ignored or not
    let ignored = false;

    // store if we have a forwarding address or not
    let forwardingAddresses = [];

    // store if we have a global redirect or not
    const globalForwardingAddresses = [];

    for (const element of addresses) {
      // convert addresses to lowercase
      const lowerCaseAddress = element.toLowerCase();

      // must start with / and end with /: and not have the same index for the last index
      // forward-email=/^(support|info)$/:niftylettuce+$1@gmail.com
      // -> this would forward to niftylettuce+support@gmail.com if email sent to support@

      // it either ends with:
      // "/gi:"
      // "/ig:"
      // "/g:"
      // "/i:"
      // "/:"
      //
      let lastIndex;
      const REGEX_FLAG_ENDINGS = ['/gi:', '/ig:', '/g:', '/i:', '/:'];
      const hasTwoSlashes = element.lastIndexOf('/') !== 0;
      const startsWithSlash = element.indexOf('/') === 0;
      if (startsWithSlash && hasTwoSlashes) {
        for (const ending of REGEX_FLAG_ENDINGS) {
          if (
            element.lastIndexOf(ending) !== -1 &&
            element.lastIndexOf(ending) !== 0
          ) {
            lastIndex = ending;
            break;
          }
        }
      }

      //
      // regular expression support
      // <https://github.com/forwardemail/free-email-forwarding/pull/245/commits/e04ea02d700b51771bf61ed512d1763bbf80784b>
      // (with added support for regex gi flags)
      //
      if (startsWithSlash && hasTwoSlashes && lastIndex) {
        const elementWithoutRegex = element.slice(
          Math.max(0, element.lastIndexOf(lastIndex) + lastIndex.length)
        );
        let parsedRegex = element.slice(
          0,
          Math.max(0, element.lastIndexOf(lastIndex) + 1)
        );

        // add case insensitive flag since email addresses are case insensitive
        if (lastIndex === '/g:' || lastIndex === '/:') parsedRegex += 'i';
        //
        // `forward-email=/^(support|info)$/:niftylettuce+$1@gmail.com`
        // support@mydomain.com -> niftylettuce+support@gmail.com
        //
        // `forward-email=/^(support|info)$/:niftylettuce.com/$1`
        // info@mydomain.com -> POST to niftylettuce.com/info
        //
        // `forward-email=/Support/g:niftylettuce.com`
        //
        // `forward-email=/SUPPORT/gi:niftylettuce.com`
        const regex = new RE2(regexParser(parsedRegex));
        if (regex.test(username.toLowerCase())) {
          const substitutedAlias = username
            .toLowerCase()
            .replace(regex, elementWithoutRegex);
          if (substitutedAlias.startsWith('!')) {
            ignored = true;
            break;
          }

          if (
            !isFQDN(substitutedAlias) &&
            !validator.isIP(substitutedAlias) &&
            !validator.isEmail(substitutedAlias) &&
            !validator.isURL(substitutedAlias, this.config.isURLOptions)
          )
            throw new CustomError(
              // TODO: we may want to replace this with "Invalid Recipients"
              `Domain of ${domain} has an invalid "${this.config.recordPrefix}" TXT record due to an invalid regular expression email address match`
            );

          if (validator.isURL(substitutedAlias, this.config.isURLOptions))
            forwardingAddresses.push(substitutedAlias);
          else forwardingAddresses.push(substitutedAlias.toLowerCase());
        }
      } else if (
        (element.indexOf(':') !== -1 || element.indexOf('!') === 0) &&
        !validator.isURL(element, this.config.isURLOptions)
      ) {
        // > const str = 'foo:https://foo.com'
        // > str.slice(0, str.indexOf(':'))
        // 'foo'
        // > str.slice(str.indexOf(':') + 1)
        // 'https://foo.com'
        const index = element.indexOf(':');
        const addr =
          index === -1
            ? [element]
            : [element.slice(0, index), element.slice(index + 1)];

        // addr[0] = hello (username)
        // addr[1] = niftylettuce@gmail.com (forwarding email)
        // check if we have a match (and if it is ignored)
        if (_.isString(addr[0]) && addr[0].indexOf('!') === 0) {
          if (username === addr[0].toLowerCase().slice(1)) {
            ignored = true;
            break;
          }

          continue;
        }

        if (
          addr.length !== 2 ||
          !_.isString(addr[1]) ||
          (!isFQDN(addr[1]) &&
            !validator.isIP(addr[1]) &&
            !validator.isEmail(addr[1]) &&
            !validator.isURL(addr[1], this.config.isURLOptions))
        )
          throw new CustomError(
            // TODO: we may want to replace this with "Invalid Recipients"
            `${lowerCaseAddress} domain of ${domain} has an invalid "${this.config.recordPrefix}" TXT record due to an invalid email address of "${element}"`
          );

        if (_.isString(addr[0]) && username === addr[0].toLowerCase()) {
          if (validator.isURL(addr[1], this.config.isURLOptions))
            forwardingAddresses.push(addr[1]);
          else forwardingAddresses.push(addr[1].toLowerCase());
        }
      } else if (isFQDN(lowerCaseAddress) || validator.isIP(lowerCaseAddress)) {
        // allow domain alias forwarding
        // (e.. the record is just "b.com" if it's not a valid email)
        globalForwardingAddresses.push(`${username}@${lowerCaseAddress}`);
      } else if (validator.isEmail(lowerCaseAddress)) {
        globalForwardingAddresses.push(lowerCaseAddress);
      } else if (validator.isURL(element, this.config.isURLOptions)) {
        globalForwardingAddresses.push(element);
      }
    }

    // if it was ignored then return early with false indicating it's disabled
    if (ignored) return false;

    // if we don't have a specific forwarding address try the global redirect
    if (
      forwardingAddresses.length === 0 &&
      globalForwardingAddresses.length > 0
    ) {
      for (const address of globalForwardingAddresses) {
        forwardingAddresses.push(address);
      }
    }

    // if we don't have a forwarding address then throw an error
    if (forwardingAddresses.length === 0)
      throw new CustomError('Invalid recipients', 421);

    // allow one recursive lookup on forwarding addresses
    const recursivelyForwardedAddresses = [];

    const { length } = forwardingAddresses;
    for (let x = 0; x < length; x++) {
      const forwardingAddress = forwardingAddresses[x];
      try {
        if (recursive.indexOf(forwardingAddress) !== -1) continue;
        if (validator.isURL(forwardingAddress, this.config.isURLOptions))
          continue;

        const newRecursive = [...forwardingAddresses, ...recursive];

        // prevent a double-lookup if user is using + symbols
        if (forwardingAddress.indexOf('+') !== -1)
          newRecursive.push(
            `${this.parseUsername(address)}@${this.parseHostFromDomainOrAddress(
              address
            )}`
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
        this.config.logger.warn(err);
      }
    }

    // make the forwarding addresses unique
    // TODO: omit the addresses recursively forwarded
    forwardingAddresses = _.uniq(forwardingAddresses);

    // lookup here to determine max forwarded addresses on the domain
    // if max number of forwarding addresses exceeded
    let { maxForwardedAddresses } = this.config;
    try {
      const req = await superagent
        .get(
          `${this.config.apiEndpoint}/v1/max-forwarded-addresses?domain=${domain}`
        )
        .set('Accept', 'application/json')
        .set('User-Agent', `forward-email/${pkg.version}`)
        .auth(this.config.apiSecrets[0])
        .timeout(this.config.timeout)
        .retry(this.config.retry);

      // body is an Object with `max_forwarded_addresses` Number
      if (
        _.isObject(req.body) &&
        _.isNumber(req.body.max_forwarded_addresses) &&
        req.body.max_forwarded_addresses > 0
      )
        maxForwardedAddresses = req.body.max_forwarded_addresses;
    } catch (err) {
      this.config.logger.warn(err, {
        endpoint: `${this.config.apiEndpoint}/v1/max-forwarded-addresses?domain=${domain}`,
        domain
      });
    }

    if (forwardingAddresses.length > maxForwardedAddresses)
      throw new CustomError(
        `The address ${address} is attempted to be forwarded to (${forwardingAddresses.length}) addresses which exceeds the maximum of (${maxForwardedAddresses})`
      );

    // otherwise transform the + symbol filter if we had it
    // and then resolve with the newly formatted forwarding address
    // (we can return early here if there was no + symbol)
    if (address.indexOf('+') === -1) return forwardingAddresses;

    return forwardingAddresses.map((forwardingAddress) => {
      if (
        isFQDN(forwardingAddress) ||
        validator.isIP(forwardingAddress) ||
        validator.isURL(forwardingAddress, this.config.isURLOptions)
      )
        return forwardingAddress;

      return `${this.parseUsername(forwardingAddress)}+${this.parseFilter(
        address
      )}@${this.parseHostFromDomainOrAddress(forwardingAddress)}`;
    });
  }

  // eslint-disable-next-line complexity
  async onRcptTo(address, session, fn) {
    if (this.server._closeTimeout)
      return setImmediate(() =>
        fn(new CustomError('Server shutdown in progress', 421))
      );

    // <https://github.com/nodemailer/smtp-server/issues/179>
    if (
      session.envelope.rcptTo &&
      session.envelope.rcptTo.length >= this.config.maxRecipients
    )
      return setImmediate(() =>
        fn(new CustomError('Too many recipients', 452))
      );

    try {
      // validate it is a valid email address
      if (!validator.isEmail(address.address))
        throw new CustomError(
          `The recipient address of ${address.address} is not a valid RFC 5322 email address`,
          553
        );

      // check if attempted spoofed or invalid SRS (e.g. fake bounces)
      if (
        (REGEX_SRS0.test(address.address) ||
          REGEX_SRS1.test(address.address)) &&
        this.parseHostFromDomainOrAddress(address.address) ===
          this.config.srsDomain
      ) {
        try {
          this.srs.reverse(address.address);
        } catch (err) {
          this.config.logger.debug(err, { address, session });
          throw new CustomError(
            `Invalid SRS address of ${address.address}`,
            553
          );
        }
      }

      // validate it is not to no-reply
      if (this.checkSRS(address.address) === this.config.noReply)
        throw new CustomError(
          `You need to reply to the "Reply-To" email address on the email, do not send messages to ${this.config.noReply}`,
          553
        );

      // check against blacklist
      const isBlacklisted = await this.isBlacklisted(
        this.checkSRS(address.address)
      );
      if (isBlacklisted)
        throw new CustomError(
          `The address ${this.checkSRS(address.address)} is blacklisted by ${
            this.config.website
          }. To request removal, please email whitelist@forwardemail.net.`,
          554
        );
    } catch (err) {
      if ([550, 553, 554].indexOf(err.responseCode) !== -1)
        return setImmediate(() => fn(this.refineAndLogError(err, session)));
      this.config.logger.fatal(err);
    }

    // if the connection determined that the client's hostname
    // or the remote address of the client is greylisted then
    // we need to lookup the triplet key
    if (session.isWhitelisted || !this.client) return setImmediate(fn);

    // return early if greylisting was disabled (useful for tests)
    if (!this.config.greylistTimeout || !this.config.greylistTtlMs)
      return setImmediate(fn);

    try {
      const key = this.getGreylistKey(
        session.remoteAddress,
        session.envelope.mailFrom.address,
        address.address
      );
      let value = await this.client.get(key);
      //
      // use `session.arrivalTime` as the value for the triplet
      // and if when parsed it is less than 5m (300s) then error
      // (note that the TTL is 30d)
      //
      if (value) {
        // parse the value from a string to an integer (date)
        const time = new Date(Number.parseInt(value, 10)).getTime();
        // validate date stored is not NaN and is numeric positive time
        if (Number.isFinite(time) && time > 0) {
          // successfully retried past the greylist timeout period
          // time = 4:00pm
          // greylist timeout = 5m
          // value is 4:05pm
          // currently it's 4:03pm (arrivalTime)
          // so we subtract value from arrivalTime and we get 2m
          // which is a positive number
          // if this value is greater than greylist timeout then we know its invalid and to reset it
          const msToGo =
            time + this.config.greylistTimeout - session.arrivalTime;

          if (msToGo > 0 && msToGo <= this.config.greylistTimeout)
            throw new CustomError(
              `Greylisted for ${prettyMilliseconds(msToGo, {
                verbose: true,
                secondsDecimalDigits: 0
              })}`,
              450
            );

          //
          // successful greylisting
          //
          // TODO: add X-Greylist header when it finally goes through
          //
          if (Math.abs(msToGo) <= this.config.greylistTtlMs)
            return setImmediate(fn);

          //
          // safety check to ensure that msToGo is not negative past the greylist period
          // (its key should have expired via TTL and so we need to validate that as well)
          //
          this.config.logger.fatal(new Error('Greylist key did not expire'), {
            key
          });

          // attempt to expire/delete the key to resolve moving forwards
          this.client
            .del(key)
            .then()
            .catch((err) => this.config.logger.fatal(err));

          // value stored was invalid so we need to reset it
          value = null;
        } else {
          // value stored was invalid so we need to reset it
          value = null;
        }
      }

      // if there was no value stored then set one and throw an error
      if (!value) {
        await this.client.set(
          key,
          session.arrivalTime,
          'PX',
          this.config.greylistTtlMs
        );
        throw new CustomError(
          `Greylisted for ${prettyMilliseconds(this.config.greylistTimeout, {
            verbose: true,
            secondsDecimalDigits: 0
          })}`,
          450
        );
      }
    } catch (err) {
      if (err.responseCode === 450)
        return setImmediate(() => fn(this.refineAndLogError(err, session)));
      this.config.logger.fatal(err);
    }

    setImmediate(fn);
  }
}

module.exports = ForwardEmail;
