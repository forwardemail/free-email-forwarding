const revHash = require('rev-hash');
const getUuidByString = require('uuid-by-string');

// use these headers for fingerprinting
const TOKEN_HEADERS = [
  'Date',
  'From',
  'To',
  'Cc',
  'Bcc',
  'Subject',
  'DKIM-Signature',
  'DomainKey-Signature',
  'MIME-Version',
  'Reply-To',
  'In-Reply-To',
  'Content-Type',
  'MIME-Version',
  'References'
];

function getHashFingerprint(headers, body) {
  const tokens = [];
  for (const header of TOKEN_HEADERS) {
    const value = headers.getFirst(header);
    if (value) tokens.push(value);
  }

  if (Array.isArray(body) && body.length > 0)
    tokens.push(Buffer.concat(body).toString());

  return tokens.join('');
}

function createMessageID(messageIdDomain, headers, body) {
  const messageId = headers.getFirst('Message-ID');
  const hash = revHash(messageId || getHashFingerprint(headers, body));
  const uuid = getUuidByString(hash);

  //
  // NOTE: we cannot use the domain of the FROM address
  //       since emails that attempt to be retried could
  //       be retried from different servers and have different MAIL FROM addresses
  //
  //       `<${str}@${session.envelope.mailFrom.address.split('@').pop()}>`;
  return `<${uuid}@${messageIdDomain}>`;
}

module.exports = createMessageID;
module.exports.getHashFingerprint = getHashFingerprint;
