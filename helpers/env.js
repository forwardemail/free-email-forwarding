const process = require('process');
const path = require('path');

const isSANB = require('is-string-and-not-blank');

const test = isSANB(process.env.NODE_ENV)
  ? process.env.NODE_ENV.toLowerCase() === 'test'
  : false;

// note that we had to specify absolute paths here bc
// otherwise tests run from the root folder wont work
const env = require('@ladjs/env')({
  path: path.join(__dirname, '..', test ? '.env.test' : '.env'),
  defaults: path.join(__dirname, '..', '.env.defaults'),
  schema: path.join(__dirname, '..', '.env.schema'),
  errorOnExtra: false
});

module.exports = env;
