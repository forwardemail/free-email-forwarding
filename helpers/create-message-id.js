const crypto = require('crypto');

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

module.exports = createMessageID;
