const RE2 = require('re2');
const _ = require('lodash');

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
  408, 413, 429, 500, 502, 503, 504, 521, 522, 524
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

module.exports = {
  CIPHERS,
  CODES_TO_RESPONSE_CODES,
  HTTP_RETRY_ERROR_CODES,
  HTTP_RETRY_STATUS_CODES,
  MESSAGE_ID_LENGTH,
  // OMITTED_CIPHERS,
  REGEX_BOUNCE_ADDRESS,
  REGEX_BOUNCE_ERROR_MESSAGE,
  REGEX_DIAGNOSTIC_CODE,
  REGEX_MESSAGE_ID,
  REGEX_SENT_KEY_HEADERS,
  REGEX_SRS0,
  REGEX_SRS1,
  REGEX_TLS_ERR,
  RETRY_CODES,
  RETRY_CODE_NUMBERS,
  SENT_KEY_HEADERS,
  TLS_RETRY_CODES
};
