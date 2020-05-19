const crypto = require('crypto');
const dns = require('dns');
const fs = require('fs');
const util = require('util');

// const mailUtilities = require('mailin/lib/mailUtilities.js');
const DKIM = require('nodemailer/lib/dkim');
const Limiter = require('ratelimiter');
const MimeNode = require('nodemailer/lib/mime-node');
const RE2 = require('re2');
const Redis = require('@ladjs/redis');
const _ = require('lodash');
const addressParser = require('nodemailer/lib/addressparser');
const bytes = require('bytes');
const dkimVerify = require('python-dkim-verify');
const dmarcParse = require('dmarc-parse');
const dnsbl = require('dnsbl');
const domains = require('disposable-email-domains');
const getFQDN = require('get-fqdn');
const getStream = require('get-stream');
const ip = require('ip');
const isSANB = require('is-string-and-not-blank');
const ms = require('ms');
const nodemailer = require('nodemailer');
const parseDomain = require('parse-domain');
const pify = require('pify');
const pkg = require('./package');
const punycode = require('punycode/');
const sharedConfig = require('@ladjs/shared-config');
const spfCheck2 = require('python-spfcheck2');
const superagent = require('superagent');
const validator = require('validator');
const wildcards = require('disposable-email-domains/wildcard.json');
const { Iconv } = require('iconv');
const { SMTPServer } = require('smtp-server');
const { SRS } = require('sender-rewriting-scheme');
const { boolean } = require('boolean');
const { oneLine } = require('common-tags');
const { simpleParser } = require('mailparser');

const {
  CustomError,
  MessageSplitter,
  createMessageID,
  env,
  logger
} = require('./helpers');

// const computeSpamScoreAsync = pify(mailUtilities.computeSpamScore);

const USER_AGENT = `forward-email/${pkg.version}`;

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
const REGEX_SRS0 = new RE2(/^SRS0[-+=]\S+=\S{2}=(\S+)=(.+)@\S+$/i);
const REGEX_SRS1 = new RE2(/^SRS1[+-=]\S+=\S+==\S+=\S{2}=\S+@\S+$/i);
const REGEX_ENOTFOUND = new RE2(/queryTxt ENOTFOUND/);
const REGEX_ENODATA = new RE2(/queryMx ENODATA/);
const REGEX_DIAGNOSTIC_CODE = new RE2(/^\d{3} /);
const REGEX_BOUNCE_ADDRESS = new RE2(/BOUNCE_ADDRESS/g);
const REGEX_BOUNCE_ERROR_MESSAGE = new RE2(/BOUNCE_ERROR_MESSAGE/g);

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
        logger: env.IS_SILENT ? false : logger,
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
      apiEndpoint: env.API_ENDPOINT,
      apiSecrets: env.API_SECRETS,
      srs: {
        separator: '=',
        secret: env.SRS_SECRET,
        maxAge: 30
      },
      srsDomain: env.SRS_DOMAIN,
      timeout: 10000,
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

    // initialize redis
    const client = new Redis(
      this.config.redis,
      this.config.logger,
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
      this.config.logger.error(err);
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
    this.getBounceStream = this.getBounceStream.bind(this);
    this.getDiagnosticCode = this.getDiagnosticCode.bind(this);
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
          new RegExp(address, 'gi'),
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
    if (err.response && REGEX_DIAGNOSTIC_CODE.test(err.response))
      return err.response;
    return `${err.responseCode ||
      err.code ||
      err.statusCode ||
      err.status ||
      500} ${err.message}`;
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
      .replace(/\[HOSTNAME\]/gi, options.name);

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
                options.bounce.err.response || options.bounce.err.message
              )
          : [
              `Your message wasn't delivered to ${options.bounce.address} due to an error.`,
              '',
              'The response was:',
              '',
              options.bounce.err.response || options.bounce.err.message,
              '',
              `If you need help, forward this to ${this.config.email} or visit ${this.config.website}.`
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
              options.bounce.err.response || options.bounce.err.message
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
          `Remote-MTA: dns; ${options.bounce.host}`,
          `Diagnostic-Code: smtp; ${this.getDiagnosticCode(options.bounce.err)}`
        ].join('\n')
      );

    rootNode.createChild('message/rfc822').setContent(options.originalRaw);

    return rootNode.createReadStream();
  }

  // we have already combined multiple recipients with same host+port mx combo
  async sendEmail(options) {
    const { host, name, envelope, raw, port } = options;
    // try it once with opportunisticTLS otherwise ignoreTLS
    // (e.g. in case of a bad altname on a certificate)
    let info;
    let transporter;
    try {
      transporter = nodemailer.createTransport({
        ...transporterConfig,
        ...this.config.ssl,
        opportunisticTLS: true,
        port: parseInt(port, 10),
        logger: this.config.logger,
        host,
        name
      });
      info = await transporter.sendMail({ envelope, raw });
    } catch (err) {
      /*
      ✖  error     Error [ERR_TLS_CERT_ALTNAME_INVALID]: Hostname/IP does not match certificate's altnames: Host: mx.example.com. is not in the cert's altnames: DNS:test1.example.com, DNS:test2.example.com
          at Object.checkServerIdentity (tls.js:288:12)
          at TLSSocket.onConnectSecure (_tls_wrap.js:1483:27)
          at TLSSocket.emit (events.js:311:20)
          at TLSSocket._finishInit (_tls_wrap.js:916:8)
          at TLSWrap.ssl.onhandshakedone (_tls_wrap.js:686:12) {
        reason: "Host: mx.example.com. is not in the cert's altnames: DNS:test1.example.com, DNS:test2.example.com",
        host: 'mx.example.com',
        cert: { ... },
        ...
      */
      // this will indicate it is a TLS issue, so we should retry as plain
      // if it doesn't have all these properties per this link then its not TLS
      // <https://github.com/nodejs/node/blob/1f9761f4cc027315376cd669ceed2eeaca865d76/lib/tls.js#L287>
      // TODO: we may want to uncomment the line below, otherwise all emails that fail will be retried
      // if (!err.reason || !err.host || !err.cert) throw err;
      // NOTE: we could do smart alerting for customers recipients here
      // but for now we just retry in plain text mode without SSL/STARTTLS
      this.config.logger.error(err, { options, envelope });
      transporter = nodemailer.createTransport({
        ...transporterConfig,
        ...this.config.ssl,
        ignoreTLS: true,
        secure: false,
        port: parseInt(port, 10),
        logger: this.config.logger,
        host,
        name
      });
      info = await transporter.sendMail({ envelope, raw });
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
      this.config.logger.warn('No DNS blacklists were provided');
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
    // set arrival date for future use by bounce handler
    session.arrivalDate = Date.now();

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
      this.config.logger.error(err);
      fn(err);
    } catch (err) {
      this.config.logger.error(err);
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
      // 10) X normalize recipients by host and without "+" symbols
      // 11) X send email
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
        const messageId = headers.getFirst('Message-ID');
        const replyTo = headers.getFirst('Reply-To');
        const inReplyTo = headers.getFirst('In-Reply-To');

        // <https://github.com/zone-eu/zone-mta/blob/2557a975ee35ed86e4d95d6cfe78d1b249dec1a0/plugins/core/email-bounce.js#L97>
        if (headers.get('Received').length > 25)
          throw new CustomError('Message was stuck in a redirect loop');

        // <https://www.oreilly.com/library/view/programming-internet-email/9780596802585/ch02s04.html>
        // <https://tools.ietf.org/html/rfc822
        /*
        A.3.1.  Minimum required

          Date:     26 Aug 76 1429 EDT        Date:     26 Aug 76 1429 EDT
          From:     Jones@Registry.Org   or   From:     Jones@Registry.Org
          Bcc:                                To:       Smith@Registry.Org

             Note that the "Bcc" field may be empty, while the  "To"  field
             is required to have at least one address.
        */
        const hasHeaderTo = headers.hasHeader('To');
        if (!hasHeaderTo && !headers.hasHeader('Bcc'))
          throw new CustomError(
            'Your message is not RFC 5322 compliant, please include a valid "To" and/or "Bcc" header.'
          );

        // validate that the To field has at least one address if it was set
        if (hasHeaderTo) {
          headers.update('To', this.checkSRS(headers.getFirst('To')));
          const toAddresses = addressParser(headers.getFirst('To'));
          if (
            !headers.hasHeader('Bcc') &&
            toAddresses.every(
              a =>
                !_.isObject(a) ||
                !isSANB(a.address) ||
                !validator.isEmail(a.address)
            )
          )
            throw new CustomError(
              'Your message is not RFC 5322 compliant, please include at least one valid email address in the "To" header, otherwise unset it and and use a "Bcc" header.'
            );
        }

        //
        // 3) reverse SRS bounces
        //
        session.envelope.rcptTo = session.envelope.rcptTo.map(to => {
          const address = this.checkSRS(to.address);
          return {
            ...to,
            address,
            isBounce: address !== to.address
          };
        });

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
        const originalFrom = headers.getFirst('From');

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
          this.config.logger.error(err);
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
          const obj = await dns.promises.lookup(this.config.exchanges[0]);
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
              const signatures = headers.get('DKIM-Signature');
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
                changes.push('Reply-To');
                headers.update('Reply-To', originalFrom);
              }

              // conditionally remove signatures necessary
              this.conditionallyRemoveSignatures(headers, changes);
            }

            /* eslint-enable max-depth */
          } catch (err) {
            this.config.logger.error(err);
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
              let port = '25';

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
              try {
                const domain = this.parseDomain(to.address, false);

                const { body } = await superagent
                  .get(`${this.config.apiEndpoint}/v1/port?domain=${domain}`)
                  .set('Accept', 'json')
                  .set('User-Agent', USER_AGENT)
                  .auth(this.config.apiSecrets[0])
                  .timeout(this.config.timeout)
                  .retry(this.config.retry)
                  .send();

                // body is an Object with `port` Number (a valid port number, defaults to 25)
                if (
                  _.isObject(body) &&
                  isSANB(body.port) &&
                  validator.isPort(body.port) &&
                  body.port !== '25'
                ) {
                  port = body.port;
                  this.config.logger.debug(
                    `Custom port for ${to.address} detected`,
                    {
                      port
                    }
                  );
                }
              } catch (err) {
                this.config.logger.error(err);
              }

              // if we already rewrote headers no need to continue
              if (rewritten) return { address: to.address, addresses, port };

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
                  const changes = ['Message-ID', 'X-Original-Message-ID'];
                  headers.update('Message-ID', createMessageID(session));
                  headers.update('X-Original-Message-ID', messageId);
                  // don't modify the reply-to if it was already set
                  if (!inReplyTo) {
                    changes.push('In-Reply-To');
                    headers.update('In-Reply-To', messageId);
                  }

                  // conditionally remove signatures necessary
                  this.conditionallyRemoveSignatures(headers, changes);
                }
              }

              return { address: to.address, addresses, port };
            } catch (err) {
              this.config.logger.error(err);
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
                    // if it was a URL webhook then return early
                    if (validator.isURL(address, this.config.isURLOptions))
                      return { to: address, is_webhook: true };
                    const addresses = await this.validateMX(address);
                    // TODO: we don't do anything with priority right now
                    // `addresses` are already pre-sorted by lowest priority
                    return { to: address, host: addresses[0].exchange };
                  } catch (err) {
                    // e.g. if the MX servers don't exist for recipient
                    // then obviously there should be an error
                    this.config.logger.error(err);
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
                errors.map(error => `${error.address}: ${error.err.message}`)
              );
            } catch (err) {
              this.config.logger.error(err);
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
        // 10) normalize recipients by host and without "+" symbols
        //
        const normalized = [];

        for (const recipient of recipients) {
          // if it's ignored then don't bother
          if (recipient.ignored) continue;
          for (const address of recipient.addresses) {
            // if it's a webhook then return early
            if (address.is_webhook) {
              normalized.push({
                webhook: address.to,
                recipient: recipient.address
              });
              continue;
            }

            // get normalized form without `+` symbol
            // const normal = `${this.parseUsername(
            //   address.to
            // )}@${this.parseDomain(address.to, false)}`;
            const match = normalized.find(
              r => r.host === address.host && r.port === recipient.port
            );
            if (match) {
              // if (!match.to.includes(normal)) match.to.push(normal);
              if (!match.to.includes(address.to)) match.to.push(address.to);
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

        if (normalized.length === 0) return fn();

        //
        // 11) send email
        //

        // set `X-ForwardEmail-Version`
        headers.update('X-ForwardEmail-Version', pkg.version);
        // and `X-ForwardEmail-Session-ID`
        headers.update('X-ForwardEmail-Session-ID', session.id);
        // and `X-ForwardEmai-Sender`
        headers.update(
          'X-ForwardEmail-Sender',
          `rfc822; ${session.envelope.mailFrom.address}`
        );

        // join headers object and body into a full rfc822 formatted email
        // headers.build() compiles headers into a Buffer with the \r\n\r\n separator
        // (eventually we call `dkim.sign(raw)` and pass it to nodemailer's `raw` option)
        const raw = await getStream(
          this.dkim.sign(Buffer.concat([headers.build(), ...chunks]))
        );

        try {
          // set SRS
          const from = this.srs.forward(
            session.envelope.mailFrom.address,
            this.config.srsDomain
          );
          const mapper = async recipient => {
            if (recipient.webhook) {
              try {
                const mail = await simpleParser(
                  originalRaw,
                  this.config.simpleParser
                );

                await superagent
                  .post(recipient.webhook)
                  // .type('message/rfc822')
                  .set('User-Agent', USER_AGENT)
                  .timeout(this.config.timeout)
                  .retry(this.config.retry)
                  .send({
                    ...mail,
                    raw: originalRaw
                  });
              } catch (err) {
                bounces.push({
                  address: recipient.recipient,
                  err,
                  host: recipient.webhook
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

          await Promise.all(normalized.map(mapper));

          // if there weren't any bounces then return early
          if (bounces.length === 0) return fn();

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
            return fn();

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
          const uniqueBounces = _.uniqBy(bounces, 'address');

          //
          // TODO: get the latest bounce template rendered for the user from our API
          // (which we'll then replace with the recipient's address and message)
          //
          const template = false;
          /*
          try {
            const { body } = await superagent
              .get(`${this.config.apiEndpoint}/v1/bounce`)
              .set('Accept', 'json')
              .set('User-Agent', `forward-email/${pkg.version}`)
              .auth(this.config.apiSecrets[0])
              .timeout(this.config.timeout)
              .retry(this.config.retry)
              .send();

            if (_.isObject(body) && isSANB(body.html) && isSANB(body.text))
              template = body;
          } catch (err) {
            this.config.logger.error(err);
          }
          */

          await Promise.all(
            uniqueBounces.map(async bounce => {
              try {
                const addresses = await this.validateMX(
                  session.envelope.mailFrom.address
                );
                await this.sendEmail({
                  host: addresses[0].exchange,
                  port: '25',
                  name,
                  envelope: {
                    from: '',
                    to: session.envelope.mailFrom.address
                  },
                  raw: this.dkim.sign(
                    this.getBounceStream({
                      headers,
                      from: session.envelope.mailFrom.address,
                      name,
                      bounce,
                      id: session.id,
                      arrivalDate: session.arrivalDate,
                      originalRaw,
                      messageId,
                      template
                    })
                  )
                });
              } catch (err) {
                this.config.logger.error(err);
              }
            })
          );

          fn();

          //
          // TODO: add smart alerting here for all `bounces`
          //
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
        if (!err.responseCode)
          err.responseCode = err.message.split('SMTP code:')[1].split(' ')[0];
        err.message = err.message.split('msg:')[1];
      }

      err.message += ` - if you need help please forward this email to ${this.config.email} or visit ${this.config.website}`;
      // if (originalRaw) meta.email = originalRaw.toString();
      this.config.logger.error(err, { session });
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
      const records = await dns.promises.resolveTxt(entry);
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

      this.config.logger.error(err);
      return false;
    }
  }

  async validateDKIM(raw, index) {
    try {
      const pass = await dkimVerify(raw, index);
      return pass;
    } catch (err) {
      this.config.logger.error(err);
      err.message = `Your email contained an invalid DKIM signature. For more information visit https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail. You can also reach out to us for help analyzing this issue.  Original error message: ${err.message}`;
      err.responseCode = 421;
      throw err;
    }
  }

  async validateMX(address) {
    try {
      const domain = this.parseDomain(address);
      const addresses = await dns.promises.resolveMx(domain);
      if (!addresses || addresses.length === 0)
        throw new CustomError(
          `DNS lookup for ${domain} did not return any valid MX records`
        );
      return _.sortBy(addresses, 'priority');
    } catch (err) {
      if (REGEX_ENODATA.test(err)) {
        err.message = `DNS lookup for ${address} did not return a valid MX record`;
        err.responseCode = 550;
      } else if (REGEX_ENOTFOUND.test(err)) {
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
          this.config.logger.info(
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

  async onMailFrom(address, session, fn) {
    try {
      await Promise.all([
        this.validateRateLimit(
          address.address || session.clientHostname || session.remoteAddress
        ),
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
    const records = await dns.promises.resolveTxt(domain);

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
        const { body } = await superagent
          .get(
            `${this.config.apiEndpoint}/v1/lookup?verification_record=${verifications[0]}`
          )
          .set('Accept', 'json')
          .set('User-Agent', USER_AGENT)
          .auth(this.config.apiSecrets[0])
          .timeout(this.config.timeout)
          .retry(this.config.retry)
          .send();

        // body is an Array of records that are formatted like TXT records
        if (Array.isArray(body)) {
          // combine with any existing TXT records (ensures graceful DNS propagation)
          for (const element of body) {
            validRecords.push(element);
          }
        }
      } catch (err) {
        this.config.logger.error(err);
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
      if (addresses[i].includes(':') || addresses[i].indexOf('!') === 0) {
        // > const str = 'foo:https://foo.com'
        // > str.slice(0, str.indexOf(':'))
        // 'foo'
        // > str.slice(str.indexOf(':') + 1)
        // 'https://foo.com'
        const index = addresses[i].indexOf(':');
        const addr =
          index === -1
            ? [addresses[i]]
            : [addresses[i].slice(0, index), addresses[i].slice(index + 1)];

        // addr[0] = hello (username)
        // addr[1] = niftylettuce@gmail.com (forwarding email)
        // check if we have a match (and if it is ignored)
        if (_.isString(addr[0]) && addr[0].indexOf('!') === 0) {
          if (username === addr[0].slice(1)) {
            ignored = true;
            break;
          }

          continue;
        }

        if (
          addr.length !== 2 ||
          !_.isString(addr[1]) ||
          (!validator.isEmail(addr[1]) &&
            !validator.isURL(addr[1], this.config.isURLOptions))
        )
          throw new CustomError(
            `${address} domain of ${domain} has an invalid "${this.config.recordPrefix}" TXT record due to an invalid email address of "${addresses[i]}"`
          );

        if (_.isString(addr[0]) && username === addr[0])
          forwardingAddresses.push(addr[1]);
      } else if (
        validator.isFQDN(addresses[i]) ||
        validator.isIP(addresses[i])
      ) {
        // allow domain alias forwarding
        // (e.. the record is just "b.com" if it's not a valid email)
        globalForwardingAddresses.push(`${username}@${addresses[i]}`);
      } else if (validator.isEmail(addresses[i])) {
        const domain = this.parseDomain(addresses[i], false);
        if (
          (validator.isFQDN(domain) || validator.isIP(domain)) &&
          validator.isEmail(addresses[i])
        ) {
          globalForwardingAddresses.push(addresses[i]);
        }
      } else if (validator.isURL(addresses[i], this.config.isURLOptions)) {
        globalForwardingAddresses.push(addresses[i]);
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
        this.config.logger.error(err);
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

    // lookup here to determine max forwarded addresses on the domain
    // if max number of forwarding addresses exceeded
    let { maxForwardedAddresses } = this.config;
    try {
      const { body } = await superagent
        .get(
          `${this.config.apiEndpoint}/v1/max-forwarded-addresses?domain=${domain}`
        )
        .set('Accept', 'json')
        .set('User-Agent', `forward-email/${pkg.version}`)
        .auth(this.config.apiSecrets[0])
        .timeout(this.config.timeout)
        .retry(this.config.retry)
        .send();

      // body is an Object with `max_forwarded_addresses` Number
      if (
        _.isObject(body) &&
        _.isNumber(body.max_forwarded_addresses) &&
        body.max_forwarded_addresses > 0
      )
        maxForwardedAddresses = body.max_forwarded_addresses;
    } catch (err) {
      this.config.logger.error(err);
    }

    if (forwardingAddresses.length > maxForwardedAddresses)
      throw new CustomError(
        `The address ${address} is attempted to be forwarded to (${forwardingAddresses.length}) addresses which exceeds the maximum of (${maxForwardedAddresses})`
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
    headers.remove('X-Google-DKIM-Signature');

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

    // Remove all DKIM-Signatures (we add back the ones that are not affected)
    headers.remove('DKIM-Signature');

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
          headers.add('DKIM-Signature', signature, headers.lines.length + 1);
      }
    }
  }
}

module.exports = ForwardEmail;
