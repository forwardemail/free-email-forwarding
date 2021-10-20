const _ = require('lodash');
const getPort = require('get-port');
const test = require('ava');

const {
  CODES_TO_RESPONSE_CODES,
  HTTP_RETRY_ERROR_CODES,
  HTTP_RETRY_STATUS_CODES,
  RETRY_CODES,
  RETRY_CODE_NUMBERS
} = require('../../helpers/constants');

const ForwardEmail = require('../..');

test.before(async (t) => {
  t.context.forwardEmail = new ForwardEmail({ port: await getPort() });
});

test('will return responseCode when passed', (t) => {
  const { forwardEmail } = t.context;

  const code = forwardEmail.getBounceCode({ err: { responseCode: 1 } });

  t.is(code, 1);
});

function retryCodes(t, input) {
  const { forwardEmail } = t.context;

  const code = forwardEmail.getBounceCode({ err: { code: input } });

  t.is(code, CODES_TO_RESPONSE_CODES[input]);
}

for (const code of RETRY_CODES) {
  test(`will return correct code when given ${code}`, retryCodes, code);
}

function httpErrorCodes(t, input) {
  const { forwardEmail } = t.context;

  const code = forwardEmail.getBounceCode({ err: { code: input } });

  t.is(code, 421);
}

for (const code of _.difference([...HTTP_RETRY_ERROR_CODES], RETRY_CODES)) {
  test(
    `will return 421 when given HTTP error code ${code}`,
    httpErrorCodes,
    code
  );
}

function httpStatusCodes(t, input) {
  const { forwardEmail } = t.context;

  const code = forwardEmail.getBounceCode({ err: { status: input } });

  t.is(code, 421);
}

for (const code of _.difference(
  [...HTTP_RETRY_STATUS_CODES],
  RETRY_CODE_NUMBERS
)) {
  test(
    `will return 421 when given HTTP status code ${code}`,
    httpStatusCodes,
    code
  );
}

test('will return 550 by default', (t) => {
  const { forwardEmail } = t.context;

  const code = forwardEmail.getBounceCode({ err: {} });

  t.is(code, 550);
});
