const crypto = require('crypto');
const dns = require('dns');
const fs = require('fs');
const util = require('util');

const DKIM = require('nodemailer/lib/dkim');
const Limiter = require('ratelimiter');
const MimeNode = require('nodemailer/lib/mime-node');
const RE2 = require('re2');
const Redis = require('@ladjs/redis');
const SpamScanner = require('spamscanner');
const _ = require('lodash');
const addressParser = require('nodemailer/lib/addressparser');
const arrayJoinConjunction = require('array-join-conjunction');
const bytes = require('bytes');
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
const punycode = require('punycode/');
const revHash = require('rev-hash');
const safeStringify = require('fast-safe-stringify');
const sharedConfig = require('@ladjs/shared-config');
const splitLines = require('split-lines');
const superagent = require('superagent');
const validator = require('validator');
const zoneMTABounces = require('zone-mta/lib/bounces');
const { Iconv } = require('iconv');
const { SMTPServer } = require('smtp-server');
const { SRS } = require('sender-rewriting-scheme');
const { authenticate } = require('mailauth');
const { boolean } = require('boolean');
const { oneLine } = require('common-tags');
const { simpleParser } = require('mailparser');

const pkg = require('./package');
const {
  CustomError,
  MessageSplitter,
  // createMessageID,
  env,
  logger
} = require('./helpers');

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

const HTTP_RETRY_STATUS_CODES = new Set([
  408,
  413,
  429,
  500,
  502,
  503,
  504,
  521,
  522,
  524
]);

// NOTE: if you change this, be sure to sync in `koa-better-error-handler`
// <https://github.com/nodejs/node/blob/08dd4b1723b20d56fbedf37d52e736fe09715f80/lib/dns.js#L296-L320>
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
  ETIMEOUT: 420
};

const RETRY_CODE_NUMBERS = _.values(CODES_TO_RESPONSE_CODES);
const RETRY_CODES = _.keys(CODES_TO_RESPONSE_CODES);

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
  connectionTimeout: ms('30s'),
  greetingTimeout: ms('30s'),
  socketTimeout: ms('30s')
};

// <https://srs-discuss.v2.listbox.narkive.com/Mh6X2B2w/help-how-to-unwind-an-srs-address#post17>
// note we can't use `/^SRS=/i` because it would match `srs@example.com`
const REGEX_SRS0 = new RE2(/^srs0[-+=]\S+=\S{2}=(\S+)=(.+)@\S+$/i);
const REGEX_SRS1 = new RE2(/^srs1[+-=]\S+=\S+==\S+=\S{2}=\S+@\S+$/i);
const REGEX_DIAGNOSTIC_CODE = new RE2(/^\d{3} /);
const REGEX_BOUNCE_ADDRESS = new RE2(/BOUNCE_ADDRESS/g);
const REGEX_BOUNCE_ERROR_MESSAGE = new RE2(/BOUNCE_ERROR_MESSAGE/g);
const REGEX_TLS_ERR = new RE2(
  /ssl23_get_server_hello|\/deps\/openssl|ssl3_check|ssl routines/gim
);

const MESSAGE_ID_LENGTH = 'Message-ID: '.length;
const REGEX_MESSAGE_ID = new RE2('^Message-ID: ', 'i');

const SENT_KEY_HEADERS = [
  'Bcc',
  'Cc',
  // 'Content-Description',
  // 'Content-ID',
  // 'Content-Transfer-Encoding',
  // 'Content-Type',
  // 'Date',
  'From',
  'In-Reply-To',
  // 'List-Archive',
  // 'List-Help',
  // 'List-Id',
  // 'List-Owner',
  // 'List-Post',
  // 'List-Subscribe',
  // 'List-Unsubscribe',
  // 'MIME-Version',
  // 'Message-ID',
  'References',
  'Reply-To',
  // 'Resent-Cc',
  // 'Resent-Date',
  // 'Resent-From',
  // 'Resent-Message-ID',
  // 'Resent-Sender',
  // 'Resent-To',
  'Sender',
  'Subject',
  'To'
].map((string) => string + ': ');

const REGEX_SENT_KEY_HEADERS = new RE2(`^(${SENT_KEY_HEADERS.join('|')})`, 'i');

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
        onData: this.onData.bind(this),
        onConnect: this.onConnect.bind(this),
        // onMailFrom: this.onMailFrom.bind(this),
        // onRcptTo: this.onRcptTo.bind(this),
        disabledCommands: ['AUTH'],
        logInfo: true,
        logger,
        ...config.smtp
      },
      spamScoreThreshold: env.SPAM_SCORE_THRESHOLD,
      blacklist: env.BLACKLIST,
      blacklistedStr:
        "Your mail server's IP address of %s is listed on the %s DNS blacklist (visit <%s> to submit a removal request and try again).",
      dnsbl: {
        domains: env.DNSBL_DOMAINS,
        removals: env.DNSBL_REMOVALS,
        ...config.dnsbl
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
        // https://github.com/nodemailer/nodemailer/blob/11121b88c58259a0374d8b22ec6509c43d1656cb/lib/dkim/sign.js#L22
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
      apiEndpoint: env.API_ENDPOINT,
      apiSecrets: env.API_SECRETS,
      srs: {
        separator: '=',
        secret: env.SRS_SECRET,
        maxAge: 30
      },
      srsDomain: env.SRS_DOMAIN,
      timeout: ms('20s'),
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
      },
      ttlMs: ms('7d'),
      maxRetry: 50,
      messageIdDomain: env.MESSAGE_ID_DOMAIN,
      dnsCachePrefix: 'dns',
      dnsCacheMs: ms('10m'),
      dnsBlacklistCacheMs: ms('1d'),
      ...config
    };

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

    // initialize and expose redis
    if (this.config.redis)
      this.client = new Redis(
        this.config.redis,
        this.config.logger,
        this.config.redisMonitor
      );

    // setup rate limiting with redis
    if (this.client && this.config.rateLimit) {
      this.limiter = {
        db: this.client,
        ...this.config.rateLimit
      };
    }

    // setup our smtp server which listens for incoming email
    this.server = new SMTPServer(this.config.smtp);
    // kind of hacky but I filed a GH issue
    // <https://github.com/nodemailer/smtp-server/issues/135>
    this.server.address = this.server.server.address.bind(this.server.server);
    this.server.on('error', (err) => {
      this.config.logger.error(err);
    });

    // expose spamscanner
    this.scanner = new SpamScanner({
      ...this.config.spamScanner,
      ...(this.client ? { client: this.client } : {})
    });

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
    this.validateMX = this.validateMX.bind(this);
    this.validateRateLimit = this.validateRateLimit.bind(this);
    this.isBlacklisted = this.isBlacklisted.bind(this);
    this.checkSRS = this.checkSRS.bind(this);
    // this.onMailFrom = this.onMailFrom.bind(this);
    this.getForwardingAddresses = this.getForwardingAddresses.bind(this);
    // this.onRcptTo = this.onRcptTo.bind(this);
    this.conditionallyRemoveSignatures = this.conditionallyRemoveSignatures.bind(
      this
    );
    this.getBounceStream = this.getBounceStream.bind(this);
    this.getDiagnosticCode = this.getDiagnosticCode.bind(this);
    this.getSentKey = this.getSentKey.bind(this);
    this.resolver = this.resolver.bind(this);
    this.refineError = this.refineError.bind(this);
  }

  // eslint-disable-next-line complexity
  refineError(err, session) {
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
      (err && err.message && err.message.includes('Invalid recipients')) ||
      (err &&
        err.message &&
        err.message.includes('DNS blacklist') &&
        err.responseCode &&
        err.responseCode === 554) ||
      (err &&
        err.responseCode &&
        (err.responseCode < 500 || err.responseCode === 452))
        ? 'warn'
        : 'error'
    ](err, { session });

    err.message += ` If you need help please forward this email to ${this.config.email} or visit <${this.config.website}>.`;
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

  processRecipient(options) {
    const { recipient, name, from, raw } = options;
    return this.processAddress(recipient.replacements, {
      host: recipient.host,
      name,
      envelope: {
        from,
        to: recipient.to
      },
      raw,
      port: recipient.port
    });
  }

  async processAddress(replacements, options) {
    try {
      const info = await this.sendEmail(options);
      this.config.logger.log(info);
      return info;
    } catch (err) {
      this.config.logger.error(err);
      // here we do some magic so that we push an error message
      // that has the end-recipient's email masked with the
      // original to address that we were trying to send to
      for (const address of Object.keys(replacements)) {
        err.message = err.message.replace(
          new RE2(address, 'gi'),
          replacements[address]
        );
      }

      return {
        accepted: [],
        // TODO: in future handle this `options.port`
        // and also handle it in `12) send email`
        rejected: [options.host],
        rejectedErrors: [err]
      };
    }
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
              `If you need help, forward this to ${this.config.email} or visit <${this.config.website}>.`
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
          `Arrival-Date: ${new Date(options.arrivalDate)
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

  getSentKey(to, originalRaw) {
    // safeguards for development
    if (_.isString(to)) to = [to];
    if (!_.isArray(to)) throw new Error('to must be an Array.');

    const raw = _.isBuffer(originalRaw)
      ? originalRaw.toString('binary')
      : originalRaw;
    if (!_.isString(raw)) throw new Error('raw must be String.');

    // `raw` seems to have trailing line break
    // so normalizing it is a safeguard
    const lines = splitLines(raw.trim());

    let headers = '';

    // first line break indicate body split
    let body;
    for (const [l, line] of lines.entries()) {
      if (line === '' && typeof lines[l + 1] === 'string') {
        body = l + 1;
        break;
      }

      // if it starts with "Message-ID" then we can just use that as the key
      if (REGEX_MESSAGE_ID.test(line))
        return `sent:${revHash(safeStringify(to))}:${revHash(
          line.slice(MESSAGE_ID_LENGTH)
        )}`;

      // only build a key based off specific common headers
      // (e.g. we ignore "Received-By")
      if (REGEX_SENT_KEY_HEADERS.test(line)) headers += line;
    }

    // since we don't want to spam our end-users due to senders not
    // setting a proper Message-ID header value, we will use
    // a combination of the headers with the body number of lines affixed
    if (body) headers += (lines.length - body).toString();

    return `sent:${revHash(safeStringify(to))}:${revHash(headers)}`;
  }

  // TODO: implement ARF parser
  //       POST /abuse
  //       GET /abuse?email=mailfrom&ip=
  //       sends 4xx retry later if it found in this list
  //       which gives us time to manually curate the list of false positives

  // we have already combined multiple recipients with same host+port mx combo
  // eslint-disable-next-line complexity
  async sendEmail(options) {
    const { host, name, envelope, raw, port } = options;

    //
    // two good resources for testing greylisting:
    // <https://test.meinmail.info/greylisting-test.html> (translate to en)
    // <http://www.allaboutspam.com/email-server-test/>
    //
    const key = this.getSentKey(envelope.to, raw);

    // this has support for greylisting, where we check for a cached key already sent for envelope to
    // and if so, then we will return early and not send the message twice
    // and so in this case, we can send a retry to the end user, but it won't actually retry
    // TTL should be 7 days with rev-hashed body
    const value = this.client ? await this.client.get(key) : null;

    // if there was a value (non-null) then that means it was already sent
    // so we can return early here and not re-send the message twice
    if (value && value === 'true')
      return {
        accepted: [envelope.to],
        rejected: [],
        rejectedErrors: []
      };

    //
    // only allow up to X retries (greylist attempts) for this message
    //
    const count =
      _.isString(value) && _.isFinite(Number.parseInt(value, 10))
        ? Number.parseInt(value, 10) + 1
        : 1;

    if (count > this.config.maxRetry)
      throw new CustomError(
        `This message has been retried the maximum of (${this.config.maxRetry}) times and has permanently failed.`
      );

    if (this.client)
      await this.client.set(key, count.toString(), 'PX', this.config.ttlMs);

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
    try {
      if (mx.port === 25)
        mx = await asyncMxConnect({
          target: mx.host,
          port: mx.port,
          localHostname: name
        });

      transporter = nodemailer.createTransport({
        ...transporterConfig,
        ...this.config.ssl,
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
      });

      info = await transporter.sendMail({ envelope, raw });

      if (this.client)
        await this.client.set(key, 'true', 'PX', this.config.ttlMs);
    } catch (err) {
      this.config.logger.warn(err, { options, envelope });

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
            envelope
          });
          err.responseCode = 421;
          throw err;
        }
      }

      // this error will indicate it is a TLS issue, so we should retry as plain
      // if it doesn't have all these properties per this link then its not TLS
      //
      // ✖  error     Error [ERR_TLS_CERT_ALTNAME_INVALID]: Hostname/IP does not match certificate's altnames: Host: mx.example.com. is not in the cert's altnames: DNS:test1.example.com, DNS:test2.example.com
      //     at Object.checkServerIdentity (tls.js:288:12)
      //     at TLSSocket.onConnectSecure (_tls_wrap.js:1483:27)
      //     at TLSSocket.emit (events.js:311:20)
      //     at TLSSocket._finishInit (_tls_wrap.js:916:8)
      //     at TLSWrap.ssl.onhandshakedone (_tls_wrap.js:686:12) {
      //   reason: "Host: mx.example.com. is not in the cert's altnames: DNS:test1.example.com, DNS:test2.example.com",
      //   host: 'mx.example.com',
      //   cert: { ... },
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
        (err.code && TLS_RETRY_CODES.has(err.code)) ||
        (err.code && REGEX_TLS_ERR.test(err.message)) ||
        err.reason ||
        err.host ||
        err.cert
      ) {
        mx = {
          host,
          port: Number.parseInt(port, 10)
        };
        if (mx.port === 25)
          mx = await asyncMxConnect({
            target: host,
            port: mx.port,
            localHostname: name
          });
        // try sending the message again without TLS enabled
        transporter = nodemailer.createTransport({
          ...transporterConfig,
          ...this.config.ssl,
          ignoreTLS: true,
          secure: false,
          logger: this.config.logger,
          host: mx.host,
          port: mx.port,
          ...(mx.socket ? { connection: mx.socket } : {}),
          name
        });
        try {
          info = await transporter.sendMail({ envelope, raw });

          if (this.client)
            await this.client.set(key, 'true', 'PX', this.config.ttlMs);
        } catch (err) {
          //
          // if there was `err.response` and it had a bounce reason
          // and if the bounce action was defer, slowdown, or it has a category
          // of blacklist, then we should retry sending it later and send a 421 code
          // and alert our team in Slack so they can investigate if IP mitigation needed
          //
          if (isSANB(err.response)) {
            const bounceInfo = zoneMTABounces.check(err.response);
            // eslint-disable-next-line max-depth
            if (
              ['defer', 'slowdown'].includes(bounceInfo.action) ||
              bounceInfo.category === 'blacklist'
            ) {
              this.config.logger[
                bounceInfo.category === 'blacklist' ? 'fatal' : 'error'
              ](err, {
                bounce_info: bounceInfo,
                envelope
              });
              err.responseCode = 421;
            }
          }

          throw err;
        }
      } else {
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
              envelope
            });
            err.responseCode = 421;
          }
        }

        throw err;
      }
    }

    return info;
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

  // parseDomain(address, isSender = true) {
  parseDomain(address) {
    const parsedAddress = addressParser(address);
    let domain;

    if (
      _.isArray(parsedAddress) &&
      _.isObject(parsedAddress[0]) &&
      isSANB(parsedAddress[0].address) &&
      parsedAddress[0].address.includes('@')
    )
      domain = punycode.toASCII(parsedAddress[0].address.split('@')[1]);

    // ensure fully qualified domain name or IP address
    if (!domain || (!isFQDN(domain) && !validator.isIP(domain)))
      throw new CustomError(
        `${
          domain || address
        } does not contain a fully qualified domain name ("FQDN") nor IP address.`
      );

    // check against blacklist
    if (this.isBlacklisted(domain))
      throw new CustomError(
        `The domain ${domain} is blacklisted by <${this.config.website}>.`,
        554
      );

    return domain;
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
        const value = await client.get(key);
        if (value) {
          this.config.logger.debug('cache hit', { key, value });
          return JSON.parse(value);
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
    if (client) {
      client
        .set(key, safeStringify(value), 'PX', ttl)
        // eslint-disable-next-line promise/prefer-await-to-then
        .then(this.config.logger.info)
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
        this.config.logger.warn(err);
        this.config.logger.warn(
          new Error('DNS lookup failed to get IP', { ip })
        );
        return false;
      }
    }

    if (_.isArray(this.config.dnsbl.domains)) {
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
    }

    const result = await this.resolver(ip, 'DNSBL');
    if (!result) return false;
    return util.format(
      this.config.blacklistedStr,
      ip,
      this.config.dnsbl.domains,
      this.config.dnsbl.removals
    );
  }

  async onConnect(session, fn) {
    // set arrival date for future use by bounce handler
    session.arrivalDate = Date.now();

    try {
      // check against blacklist
      if (
        isFQDN(session.clientHostname) &&
        this.isBlacklisted(session.clientHostname)
      )
        throw new CustomError(
          `The domain ${session.clientHostname} is blacklisted by <${this.config.website}>.`,
          554
        );
      if (this.isBlacklisted(session.remoteAddress))
        throw new CustomError(
          `The IP address ${session.remoteAddress} is blacklisted by <${this.config.website}>.`,
          554
        );

      //
      // TODO: check blacklist against MAIL FROM
      //
      // ensure that it's not on the DNS blacklist
      // X Spamhaus = zen.spamhaus.org
      // - SpamCop = bl.spamcop.net
      // - Barracuda = b.barracudacentral.org
      // - Lashback = ubl.unsubscore.com
      // - PSBL = psbl.surriel.com
      //
      // TODO: if someone hits the blacklist we should ratelimit them too
      //
      const message = await this.checkBlacklists(session.remoteAddress);
      if (message) {
        // this.config.blacklist.push(session.remoteAddress);
        throw new CustomError(message, 554);
      }

      fn();
    } catch (err) {
      fn(this.refineError(err, session));
    }
  }

  async onData(stream, session, fn) {
    //
    // passthrough streams don't have a `.ended` property
    //
    let streamEnded = false;
    stream.once('end', () => {
      streamEnded = true;
    });

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
    // store original session.envelope.mailFrom
    // since smtp-server calls `_resetSession()` internally
    // which causes `session.envelope.mailFrom` to be set to `false
    //
    const { mailFrom } = session.envelope;

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
    messageSplitter.on('error', (err) => {
      if (streamEnded) {
        fn(this.refineError(err, session));
      } else {
        stream.once('end', () => {
          fn(this.refineError(err, session));
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
        let { headers } = messageSplitter;
        const messageId = headers.getFirst('Message-ID');

        // <https://github.com/zone-eu/zone-mta/blob/2557a975ee35ed86e4d95d6cfe78d1b249dec1a0/plugins/core/email-bounce.js#L97>
        if (headers.get('Received').length > 25)
          throw new CustomError('Message was stuck in a redirect loop.');

        // NOTE: we can't have this in onConnect because otherwise it would not retry properly
        // validate against rate limiting
        // await this.validateRateLimit(session.remoteAddress);

        //
        // 3) reverse SRS bounces
        //
        const originalValue = headers.getFirst('To');
        const reversedValue = this.checkSRS(originalValue);
        if (originalValue !== reversedValue) {
          headers.update('To', reversedValue);
          // conditionally remove signatures necessary
          headers = this.conditionallyRemoveSignatures(headers, ['To']);
        }

        // clean up the rcptTo list of recipients
        session.envelope.rcptTo = session.envelope.rcptTo.map((to) => {
          // if it was a bounce and not valid, then return early
          if (
            (REGEX_SRS0.test(to.address) || REGEX_SRS1.test(to.address)) &&
            _.isNull(this.srs.reverse(to.address))
          ) {
            this.config.logger.warn(
              new Error(`SRS address of ${to.address} was invalid`),
              { session }
            );
            return;
          }

          const address = this.checkSRS(to.address);
          return {
            ...to,
            address,
            isBounce: address !== to.address
          };
        });

        // remove null entries and clean up the Array
        session.envelope.rcptTo = _.compact(session.envelope.rcptTo);

        //
        // 4) prevent replies to no-reply@forwardemail.net
        //
        if (
          _.every(
            session.envelope.rcptTo,
            (to) => to.address === this.config.noReply
          )
        )
          throw new CustomError(
            oneLine`You need to reply to the "Reply-To" email address on the email; do not send messages to <${this.config.noReply}>.`
          );

        const originalFrom = headers.getFirst('From');
        if (!originalFrom)
          throw new CustomError(
            'Your message is not RFC 5322 compliant, please include a valid "From" header.'
          );

        // message body as a single Buffer (everything after the \r\n\r\n separator)
        originalRaw = Buffer.concat([headers.build(), ...chunks]);

        //
        // 5) check for spam
        //
        let scan;

        try {
          scan = await this.scanner.scan(originalRaw);
        } catch (err) {
          this.config.logger.fatal(err, { session });
        }

        //
        // 6) validate SPF, DKIM, DMARC, and ARC
        //

        // get the fully qualified domain name ("FQDN") of this server
        let ipAddress;
        if (env.NODE_ENV === 'test') {
          const object = await this.resolver(this.config.exchanges[0], 'A');
          ipAddress = object[0];
        } else {
          ipAddress = ip.address();
        }

        const name = await getFQDN(ipAddress);

        // set `X-ForwardEmail-Version`
        headers.update('X-ForwardEmail-Version', pkg.version);
        // and `X-ForwardEmail-Session-ID`
        headers.update('X-ForwardEmail-Session-ID', session.id);
        // and `X-ForwardEmail-Sender`
        headers.update(
          'X-ForwardEmail-Sender',
          `rfc822; ${
            mailFrom.address
              ? this.checkSRS(mailFrom.address)
              : session.remoteAddress
          }`
        );

        const {
          dkim,
          spf,
          arc,
          dmarc,
          headers: arcSealedHeaders
        } = await authenticate(originalRaw, {
          ip: session.remoteAddress,
          helo: session.hostNameAppearsAs,
          sender: mailFrom.address,
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
        });

        const raw = Buffer.concat([
          Buffer.from(arcSealedHeaders),
          headers.build(),
          ...chunks
        ]);

        //
        // TODO: we may want to re-enable this in the future but we have this currently disabled
        //       since there was a high bounce rate of 10%+ in Postmark and we want to reduce this
        //
        // email the person once as a courtesy of their invalid SPF setup
        /*
        if (authResults && authResults.spf && ['fail', 'softfail', 'permerror', 'temperror'].includes(authResults.spf.result))
          superagent
            .post(`${this.config.apiEndpoint}/v1/spf-error`)
            .set('User-Agent', this.config.userAgent)
            .set('Accept', 'application/json')
            .auth(this.config.apiSecrets[0])
            .timeout(this.config.timeout)
            .retry(this.config.retry)
            .send({
              // name
              remote_address: session.remoteAddress,
              from: mailFrom.address,
              client_hostname: session.hostNameAppearsAs,
              result: authResults.spf.result,
              explanation: authResults.spf.reason
            })
            // eslint-disable-next-line promise/prefer-await-to-then
            .then(() => {})
            .catch((err) => {
              this.config.logger.fatal(err, { session });
            });
        */

        //
        // only reject if ARC was not passing
        // and DMARC fail with p=reject policy
        //
        if (
          _.isObject(arc) &&
          _.isObject(arc.status) &&
          arc.status.result !== 'pass' &&
          _.isObject(dmarc) &&
          _.isObject(dmarc.status) &&
          dmarc.status.result === 'fail' &&
          dmarc.policy === 'reject'
        )
          throw new CustomError(
            "The email sent has failed DMARC validation and is rejected due to the domain's DMARC policy."
          );

        //
        // TODO: better abuse prevention around this
        //
        // only use SRS if:
        // - ARC none
        // - SPF pass
        // - DMARC none OR p=reject and pass
        // - no passing DKIM
        //
        let from = mailFrom.address;

        if (
          // - ARC none
          _.isObject(arc) &&
          _.isObject(arc.status) &&
          arc.status.result === 'none' &&
          // - SPF pass
          _.isObject(spf) &&
          _.isObject(spf.status) &&
          spf.status.result === 'pass' &&
          // NOTE: some email scanners still do not respect ARC
          //       and only respect DMARC/SPF/DKIM so until they
          //       are supported we unfortunately have to do SRS rewrite
          // - DMARC none OR p=reject and pass
          _.isObject(dmarc) &&
          _.isObject(dmarc.status) &&
          dmarc.status.result !== 'fail' &&
          // (dmarc.policy === 'reject' && dmarc.status.result === 'pass')) &&
          // - no passing DKIM
          _.isObject(dkim) &&
          _.isObject(dkim.results) &&
          dkim.results.every(
            (result) =>
              !_.isObject(result) ||
              !_.isObject(result.status) ||
              result.status.result !== 'pass'
          )
        ) {
          from = this.srs.forward(
            this.checkSRS(mailFrom.address),
            this.config.srsDomain
          );
        }

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
              if (to.isBounce)
                return { address: to.address, addresses: [to.address], port };

              // bounce message if it was sent to no-reply@
              if (to.address === this.config.noReply)
                throw new CustomError(
                  oneLine`You need to reply to the "Reply-To" email address on the email; do not send messages to <${this.config.noReply}>`
                );

              // get all forwarding addresses for this individual address
              const addresses = await this.getForwardingAddresses(to.address);

              if (addresses === false)
                return { address: to.address, addresses: [], ignored: true };

              // lookup the port (e.g. if `forward-email-port=` or custom set on the domain)
              const domain = this.parseDomain(to.address, false);

              const { body } = await superagent
                .get(`${this.config.apiEndpoint}/v1/settings`)
                .query({ domain })
                .set('Accept', 'application/json')
                .set('User-Agent', this.config.userAgent)
                .auth(this.config.apiSecrets[0])
                .timeout(this.config.timeout)
                .retry(this.config.retry);

              // body is an Object
              if (_.isObject(body)) {
                // `port` (String) - a valid port number, defaults to 25
                if (
                  isSANB(body.port) &&
                  validator.isPort(body.port) &&
                  body.port !== '25'
                ) {
                  port = body.port;
                  this.config.logger.debug(
                    new Error(`Custom port for ${to.address} detected`),
                    {
                      port,
                      session
                    }
                  );
                }

                // Spam Scanner boolean values adjusted by user in Advanced Settings page
                if (_.isBoolean(body.has_adult_content_protection))
                  hasAdultContentProtection = body.has_adult_content_protection;
                if (_.isBoolean(body.has_phishing_protection))
                  hasPhishingProtection = body.has_phishing_protection;
                if (_.isBoolean(body.has_executable_protection))
                  hasExecutableProtection = body.has_executable_protection;
                if (_.isBoolean(body.has_virus_protection))
                  hasVirusProtection = body.has_virus_protection;
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
                  let hasPhishingErrors = false;
                  for (const message of scan.results.phishing.slice(0, 2)) {
                    // if we're not filtering for adult-related content then continue early
                    // eslint-disable-next-line max-depth
                    if (
                      !hasAdultContentProtection &&
                      message.includes('adult-related content')
                    )
                      continue;
                    hasPhishingErrors = true;
                    messages.push(message);
                  }

                  if (hasPhishingErrors)
                    messages.push(
                      `Adult/malware false positives can be corrected at <https://report.teams.cloudflare.com>.`
                    );
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

                // TODO: this could probably be moved outside of the loop
                if (
                  _.isArray(scan.results.arbitrary) &&
                  !_.isEmpty(scan.results.arbitrary)
                ) {
                  for (const message of scan.results.arbitrary.slice(0, 2)) {
                    messages.push(message);
                  }
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
                    'For more information on Spam Scanner visit <https://spamscanner.net>.'
                  );
                  throw new CustomError(messages.join(' '), 554);
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
        recipients = _.uniqBy(_.compact(_.flatten(recipients)), 'address');

        // TODO: we can probably remove this now
        // go through recipients and if we have a user+xyz@domain
        // AND we also have user@domain then honor the user@domain only
        // (helps to alleviate bulk spam with services like Gmail)
        recipients = recipients.map((recipient) => {
          recipient.addresses = recipient.addresses.filter((address) => {
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
          recipients.map(async (recipient) => {
            try {
              const errors = [];
              const { addresses } = recipient;
              recipient.addresses = await Promise.all(
                addresses.map(async (address) => {
                  try {
                    // if it was a URL webhook then return early
                    if (validator.isURL(address, this.config.isURLOptions))
                      return { to: address, is_webhook: true };
                    return {
                      to: address,
                      host: this.parseDomain(address, false)
                    };
                  } catch (err) {
                    // e.g. if the MX servers don't exist for recipient
                    // then obviously there should be an error
                    this.config.logger.error(err, { session });
                    errors.push({
                      address,
                      err
                    });
                  }
                })
              );
              if (recipient.addresses.length === 0 && recipient.port !== '25') {
                recipient.addresses = [
                  {
                    to: recipient.address,
                    host: this.parseDomain(recipient.address, false)
                  }
                ];
              }

              recipient.addresses = _.compact(recipient.addresses);
              if (!_.isEmpty(recipient.addresses)) return recipient;
              if (errors.length === 0) return;
              throw new Error(
                errors.map((error) => `${error.address}: ${error.err.message}`)
              );
            } catch (err) {
              this.config.logger.error(err, { session });
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
          const codes = bounces.map((bounce) => {
            if (_.isNumber(bounce.err.responseCode))
              return bounce.err.responseCode;
            if (
              _.isString(bounce.err.code) &&
              RETRY_CODES.includes(bounce.err.code)
            )
              return CODES_TO_RESPONSE_CODES[bounce.err.code];
            if (
              (bounce.err.code &&
                HTTP_RETRY_ERROR_CODES.has(bounce.err.code)) ||
              (_.isNumber(bounce.err.status) &&
                HTTP_RETRY_STATUS_CODES.has(bounce.err.status))
            )
              return 421;
            return 550;
          });
          const [code] = codes.sort();
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
              // get normalized form without `+` symbol
              // const normal = `${this.parseUsername(
              //   address.to
              // )}@${this.parseDomain(address.to, false)}`;
              const match = normalized.find((r) => r.webhook === address.to);
              // eslint-disable-next-line max-depth
              if (match) {
                // if (!match.to.includes(normal)) match.to.push(normal);
                // eslint-disable-next-line max-depth
                if (!match.to.includes(address.to)) match.to.push(address.to);
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
            // )}@${this.parseDomain(address.to, false)}`;
            const match = normalized.find(
              (r) => r.host === address.host && r.port === recipient.port
            );
            if (match) {
              // if (!match.to.includes(normal)) match.to.push(normal);
              // eslint-disable-next-line max-depth
              if (!match.to.includes(address.to)) match.to.push(address.to);
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
          if (streamEnded) return fn();
          stream.once('end', () => fn());
          return;
        }

        //
        // 9) send email
        //
        const accepted = [];
        const selfTestEmails = [];

        //
        // this is the core function that sends the email
        //
        // eslint-disable-next-line complexity
        const mapper = async (recipient) => {
          if (recipient.webhook) {
            try {
              const key = this.getSentKey(recipient.to, originalRaw);
              const value = this.client ? await this.client.get(key) : null;

              // if there was a value set to true then it means it was sent
              // so we can return early here and not re-send the message twice
              if (value && value === 'true') {
                accepted.push(recipient.recipient);
                return;
              }

              //
              // only allow up to X retries (greylist attempts) for this message
              //
              const count =
                _.isString(value) && _.isFinite(Number.parseInt(value, 10))
                  ? Number.parseInt(value, 10) + 1
                  : 1;

              if (count > this.config.maxRetry)
                throw new CustomError(
                  `This message has been retried the maximum of (${this.config.maxRetry}) times and has permanently failed.`
                );

              const mail = await simpleParser(
                originalRaw,
                this.config.simpleParser
              );

              // Set header describing original address
              mail.headers.set("X-ForwardEmail-User", to.address)

              if (this.client)
                await this.client.set(
                  key,
                  count.toString(),
                  'PX',
                  this.config.ttlMs
                );

              await superagent
                .post(recipient.webhook)
                // .type('message/rfc822')
                .set('User-Agent', this.config.userAgent)
                .timeout(this.config.timeout)
                // .retry(this.config.retry)
                .send({
                  ...mail,
                  raw
                });

              if (this.client)
                await this.client.set(key, 'true', 'PX', this.config.ttlMs);

              accepted.push(recipient.recipient);
              return;
            } catch (err_) {
              this.config.logger.warn(err_, { session });

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

              bounces.push({
                address: recipient.recipient,
                err: err_
              });
            }

            return;
          }

          const result = await this.processRecipient({
            recipient,
            name,
            raw,
            from
          });

          if (result.accepted.length > 0) {
            // add to the
            for (const a of result.accepted) {
              // get normalized form without `+` symbol
              const normal = `${this.parseUsername(a)}@${this.parseDomain(
                a,
                false
              )}`;
              if (
                !selfTestEmails.includes(normal) &&
                normal === this.checkSRS(mailFrom.address)
              )
                selfTestEmails.push(normal);
            }

            accepted.push(recipient.recipient);
          }

          if (result.rejected.length === 0) return;
          for (let x = 0; x < result.rejected.length; x++) {
            const err = result.rejectedErrors[x];
            bounces.push({
              // TODO: in future handle this port: recipient.port
              // and also handle it in `async processAddress(replacements, opts)`
              address: recipient.recipient,
              host: recipient.host,
              err
            });
          }
        };

        await Promise.all(normalized.map((recipient) => mapper(recipient)));

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
            // eslint-disable-next-line promise/prefer-await-to-then
            .then(() => {})
            .catch((err) => {
              this.config.logger.error(err, { session });
            });

        // if there weren't any bounces then return early
        if (bounces.length === 0) {
          if (streamEnded) return fn();
          stream.once('end', () => fn());
        }

        const codes = bounces.map((bounce) => {
          if (_.isNumber(bounce.err.responseCode))
            return bounce.err.responseCode;
          if (
            _.isString(bounce.err.code) &&
            RETRY_CODES.includes(bounce.err.code)
          )
            return CODES_TO_RESPONSE_CODES[bounce.err.code];
          if (
            (bounce.err.code && HTTP_RETRY_ERROR_CODES.has(bounce.err.code)) ||
            (_.isNumber(bounce.err.status) &&
              HTTP_RETRY_STATUS_CODES.has(bounce.err.status))
          )
            return 421;
          return 550;
        });

        // sort the codes and get the lowest one
        // (that way 4xx retries are attempted)
        const [code] = codes.sort();

        const messages = [];

        if (accepted.length > 0)
          messages.push(
            `Message was sent successfully to ${arrayJoinConjunction(
              _.uniq(accepted)
            )}`
          );

        for (const element of bounces) {
          messages.push(
            `Error for ${element.host || element.address} of "${
              element.err.message
            }"`
          );
        }

        // join the messages together and make them unique
        const err = new CustomError(_.uniq(messages).join(', '), code);

        // send error to user
        if (streamEnded) {
          fn(this.refineError(err, session));
        } else {
          stream.once('end', () => {
            fn(this.refineError(err, session));
          });
        }

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
            this.config.logger.error(
              new Error('Bounce was not an object', { bounce, session })
            );
            return false;
          }

          if (!_.isError(bounce.err)) {
            this.config.logger.error(
              new Error('Bounce was missing error object', { bounce, session })
            );
            return false;
          }

          if (isSANB(bounce.err.code) && RETRY_CODES.includes(bounce.err.code))
            return false;

          if (
            _.isNumber(bounce.err.responseCode) &&
            RETRY_CODE_NUMBERS.includes(bounce.err.responseCode)
          )
            return false;

          if (
            _.isNumber(bounce.err.status) &&
            RETRY_CODE_NUMBERS.includes(bounce.err.status)
          )
            return false;

          if (isSANB(bounce.err.response)) {
            const bounceInfo = zoneMTABounces.check(bounce.err.response);
            if (['defer', 'slowdown'].includes(bounceInfo.action)) return false;
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
            const { body } = await superagent
              .get(`${this.config.apiEndpoint}/v1/bounce`)
              .set('Accept', 'application/json')
              .set('User-Agent', `forward-email/${pkg.version}`)
              .auth(this.config.apiSecrets[0])
              .timeout(this.config.timeout)
              .retry(this.config.retry);

            if (_.isObject(body) && isSANB(body.html) && isSANB(body.text))
              template = body;
          } catch (err) {
            this.config.logger.error(err, { session });
          }
          */

        await Promise.all(
          uniqueBounces.map(async (bounce) => {
            const raw = await getStream(
              this.dkim.sign(
                this.getBounceStream({
                  headers,
                  from: mailFrom.address
                    ? this.checkSRS(mailFrom.address)
                    : mailFrom.address,
                  name,
                  bounce,
                  id: session.id,
                  arrivalDate: session.arrivalDate,
                  originalRaw,
                  messageId,
                  template
                })
              )
            );
            const options = {
              host: mailFrom.address
                ? this.checkSRS(mailFrom.address)
                : mailFrom.address,
              //
              // NOTE: bounces to custom ports won't work
              //       we would require custom logic here
              //       to lookup forward-email-port config
              //
              port: '25',
              name,
              envelope: {
                from: '',
                to: mailFrom.address
                  ? this.checkSRS(mailFrom.address)
                  : mailFrom.address
              },
              raw
            };
            try {
              await this.sendEmail(options);
            } catch (err_) {
              this.config.logger.fatal(err_, { session });
            }
          })
        );
      } catch (err) {
        if (streamEnded) {
          fn(this.refineError(err, session));
        } else {
          stream.once('end', () => {
            fn(this.refineError(err, session));
          });
        }
      }
    });

    stream.pipe(messageSplitter);
  }

  async validateMX(address) {
    try {
      const domain = this.parseDomain(address);
      const addresses = await this.resolver(domain, 'MX');
      if (!addresses || addresses.length === 0)
        throw new CustomError(
          `DNS lookup for ${domain} did not return any valid MX records.`,
          420
        );
      return _.sortBy(addresses, 'priority');
    } catch (err) {
      this.config.logger.warn(err, { address });
      // support retries
      if (_.isString(err.code) && RETRY_CODES.includes(err.code)) {
        err.responseCode = CODES_TO_RESPONSE_CODES[err.code];
      } else {
        // all other lookup errors should retry 420
        // https://github.com/nodejs/node/blob/f1ae7ea343020f608fdc1ca77d9cdfe2c093ac72/src/cares_wrap.cc#L95
        err.responseCode = 420;
      }

      throw err;
    }
  }

  validateRateLimit(id) {
    // if SPF TXT record exists for the domain name
    // then ensure that `session.remoteAddress` resolves
    // to either the IP address or the domain name value for the SPF
    return new Promise((resolve, reject) => {
      if (!this.limiter) {
        resolve();
        return;
      }

      const limit = new Limiter({ ...this.limiter, id });
      limit.get((err, limit) => {
        if (err) {
          // if an error occurs we don't want to limit it
          this.config.logger.fatal(err);
          resolve();
          return;
        }

        if (limit.remaining) {
          this.config.logger.info(
            `Rate limit for ${id} is now ${limit.remaining - 1}/${
              limit.total
            }.`
          );
          resolve();
          return;
        }

        const delta = Math.trunc(limit.reset * 1000 - Date.now());
        reject(
          new CustomError(
            `Rate limit exceeded for ${id}, retry in ${ms(delta, {
              long: true
            })}.`,
            // NOTE: this used to be 451, which is not consistent
            // <https://smtpfieldmanual.com/code/421>
            // <https://smtpfieldmanual.com/code/451>
            // 451
            421
          )
        );
      });
    });
  }

  isBlacklisted(domain) {
    return _.isArray(this.config.blacklist)
      ? this.config.blacklist.includes(domain) ||
          this.config.blacklist.some((blacklist) => domain.endsWith(blacklist))
      : false;
  }

  // this returns either the reversed SRS address
  // or the address that was passed to this function
  checkSRS(address) {
    if (!REGEX_SRS0.test(address) && !REGEX_SRS1.test(address)) return address;

    try {
      const reversed = this.srs.reverse(address);
      if (_.isNull(reversed))
        throw new Error(`Invalid SRS reversed address for ${address}`);
      return reversed;
    } catch (err) {
      this.config.logger.error(err);
      return address;
    }
  }

  /*
  async onMailFrom(address, session, fn) {
    try {
      // if (!address.address)
      //   throw new Error('Envelope MAIL FROM is missing on your message');
      // if (address && address.address)
      //   await this.validateRateLimit(address.address);
      // else throw new Error('Missing MAIL FROM');
      // await Promise.all([
      //   this.validateRateLimit(address.address),
      //   (async () => {
      //     // ensure that it's not on the DNS blacklist
      //     // X Spamhaus = zen.spamhaus.org
      //     // - SpamCop = bl.spamcop.net
      //     // - Barracuda = b.barracudacentral.org
      //     // - Lashback = ubl.unsubscore.com
      //     // - PSBL = psbl.surriel.com
      //     const domain = this.parseDomain(address.address);
      //     const message = await this.checkBlacklists(domain);
      //     if (!message) return;
      //     throw new CustomError(message, 554);
      //   })()
      // ]);
      fn();
    } catch (err) {
      this.config.logger.fatal(err, { address, session });
      fn(this.refineError(err, session));
    }
  }
  */

  // this returns the forwarding address for a given email address
  // eslint-disable-next-line complexity
  async getForwardingAddresses(address, recursive = []) {
    const domain = this.parseDomain(address, false);
    let records;
    try {
      records = await this.resolver(domain, 'TXT');
    } catch (err) {
      this.config.logger.warn(err);
      // support retries
      if (_.isString(err.code) && RETRY_CODES.includes(err.code)) {
        err.responseCode = CODES_TO_RESPONSE_CODES[err.code];
      } else {
        // all other lookup errors should retry 420
        // https://github.com/nodejs/node/blob/f1ae7ea343020f608fdc1ca77d9cdfe2c093ac72/src/cares_wrap.cc#L95
        err.responseCode = 420;
      }

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
      const { body } = await superagent
        .get(`${this.config.apiEndpoint}/v1/lookup`)
        .query({ domain, username, verification_record: verifications[0] })
        .set('Accept', 'application/json')
        .set('User-Agent', this.config.userAgent)
        .auth(this.config.apiSecrets[0])
        .timeout(this.config.timeout)
        .retry(this.config.retry);

      // body is an Array of records that are formatted like TXT records
      if (_.isArray(body) && body.length > 0) {
        // combine with any existing TXT records (ensures graceful DNS propagation)
        for (const element of body) {
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
        `${address} domain of ${domain} has a blank "${this.config.recordPrefix}" TXT record or has zero aliases configured`,
        420
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
        420
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
      if (
        (lowerCaseAddress.includes(':') ||
          lowerCaseAddress.indexOf('!') === 0) &&
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
      globalForwardingAddresses.forEach((address) => {
        forwardingAddresses.push(address);
      });
    }

    // if we don't have a forwarding address then throw an error
    if (forwardingAddresses.length === 0)
      throw new CustomError(
        // `${address} domain of ${domain} is not configured properly and does not contain any valid "${this.config.recordPrefix}" TXT records`,
        'Invalid recipients',
        420
      );

    // allow one recursive lookup on forwarding addresses
    const recursivelyForwardedAddresses = [];

    const { length } = forwardingAddresses;
    for (let x = 0; x < length; x++) {
      const forwardingAddress = forwardingAddresses[x];
      try {
        if (recursive.includes(forwardingAddress)) continue;
        if (validator.isURL(forwardingAddress, this.config.isURLOptions))
          continue;

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
        this.config.logger.warn(err);
      }
    }

    // make the forwarding addresses unique
    // and omit the addresses recursively forwarded
    forwardingAddresses = _.uniq(forwardingAddresses);

    // NOTE: this causes recursive forwarding to fail
    // _.pullAll(forwardingAddresses, recursivelyForwardedAddresses);

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

    // lookup here to determine max forwarded addresses on the domain
    // if max number of forwarding addresses exceeded
    let { maxForwardedAddresses } = this.config;
    const { body } = await superagent
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
      _.isObject(body) &&
      _.isNumber(body.max_forwarded_addresses) &&
      body.max_forwarded_addresses > 0
    )
      maxForwardedAddresses = body.max_forwarded_addresses;

    if (forwardingAddresses.length > maxForwardedAddresses)
      throw new CustomError(
        `The address ${address} is attempted to be forwarded to (${forwardingAddresses.length}) addresses which exceeds the maximum of (${maxForwardedAddresses})`
      );

    // otherwise transform the + symbol filter if we had it
    // and then resolve with the newly formatted forwarding address
    // (we can return early here if there was no + symbol)
    if (!address.includes('+')) return forwardingAddresses;

    return forwardingAddresses.map((forwardingAddress) => {
      if (
        isFQDN(forwardingAddress) ||
        validator.isIP(forwardingAddress) ||
        validator.isURL(forwardingAddress, this.config.isURLOptions)
      )
        return forwardingAddress;

      return `${this.parseUsername(forwardingAddress)}+${this.parseFilter(
        address
      )}@${this.parseDomain(forwardingAddress, false)}`;
    });
  }

  /*
  async onRcptTo(address, session, fn) {
    try {
      // if it was a bounce and not valid, then throw an error
      if (
        REGEX_SRS0.test(address.address) ||
        REGEX_SRS1.test(address.address)
      ) {
        if (_.isNull(this.srs.reverse(address.address)))
          throw new CustomError(
            `SRS address of ${address.address} was invalid`
          );
        // otherwise return early
        return fn();
      }

      // validate forwarding address by looking up TXT record `forward-email=`
      await this.getForwardingAddresses(address.address);

      // validate MX records exist and contain ours
      const addresses = await this.validateMX(address.address);
      const exchanges = new Set(
        addresses.map((mxAddress) => mxAddress.exchange)
      );
      const hasAllExchanges = this.config.exchanges.every((exchange) =>
        exchanges.has(exchange)
      );
      if (hasAllExchanges) return fn();
      throw new CustomError(
        `${
          address.address
        } is missing required DNS MX records of ${this.config.exchanges.join(
          ', '
        )}`,
        420
      );
    } catch (err) {
      this.config.logger.fatal(err, { session });
      fn(this.refineError(err, session));
    }
  }
  */

  //
  // TODO: investigate if we need to drop ARC seal headers
  //       if they sign specific headers that we are rewriting
  //
  conditionallyRemoveSignatures(headers, changes) {
    //
    // Note that we always remove the "X-Google-DKIM-Signature" header
    // if there is at least one change passed, as I believe that
    // Google wil flag this as spam and result in a 421 connection timeout
    // if it is not removed otherwise, and there was a rewrite done
    //
    // Return early if no changes
    if (changes.length === 0) return headers;

    // TODO: conditionally remove this signature like we do below with others
    // Always remove X-Google-DKIM-Signature
    headers.remove('X-Google-DKIM-Signature');

    // Convert all changes to lowercase for comparison below
    changes = changes.map((change) => change.toLowerCase().trim());

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
    const signatures = headers.get('DKIM-Signature');

    // If there were no signatures then return early
    if (signatures.length === 0) return headers;

    // Remove all DKIM-Signatures (we add back the ones that are not affected)
    headers.remove('DKIM-Signature');

    // Note that we don't validate the signature, we just check its headers
    for (const signature of signatures) {
      const terms = signature
        .split(/;/)
        .map((t) => t.trim())
        .filter((t) => t !== '');
      const rules = terms.map((t) => t.split(/=/).map((r) => r.trim()));
      for (const rule of rules) {
        // term = d
        // value = example.com
        //
        const [term, value] = rule;
        if (term !== 'h') continue;
        const signedHeaders = value
          .split(':')
          .map((h) => h.trim().toLowerCase())
          .filter((h) => h !== '');
        if (signedHeaders.length === 0) continue;
        if (signedHeaders.every((h) => !changes.includes(h)))
          headers.add('DKIM-Signature', signature, headers.lines.length + 1);
      }
    }

    return headers;
  }
}

module.exports = ForwardEmail;
