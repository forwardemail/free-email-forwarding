const crypto = require('crypto');

// node_modules/nodemailer/lib/mime-node/index.js
function createMessageID(session) {
  // crux to generate UUID-like random strings
  let result = crypto.randomBytes(4).toString('hex');
  for (const length of [2, 2, 2, 6]) {
    result += `-${crypto.randomBytes(length).toString('hex')}`;
  }

  // try to use the domain of the FROM address
  return `<${result}@${session.envelope.mailFrom.address.split('@').pop()}>`;
}

module.exports = createMessageID;
