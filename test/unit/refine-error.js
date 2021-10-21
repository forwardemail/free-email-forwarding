const getPort = require('get-port');
const test = require('ava');

const ForwardEmail = require('../..');
const {
  HTTP_RETRY_ERROR_CODES,
  HTTP_RETRY_STATUS_CODES
} = require('../../helpers/constants');

test.before(async (t) => {
  t.context.forwardEmail = new ForwardEmail({
    port: await getPort()
  });
});

test('will add help text to error', (t) => {
  const { forwardEmail } = t.context;

  const err = forwardEmail.refineError({ message: 'test', responseCode: 554 });

  t.regex(err.message, /If you need help please forward this email/);
});

test('will get message from SMTP error', (t) => {
  const { forwardEmail } = t.context;

  const err = forwardEmail.refineError({
    message: 'SMTP code:9000 msg:test',
    responseCode: 430
  });

  t.is(err.responseCode, 430);
  t.not(err.responseCode, 9000);
  t.regex(err.message, /test/);
});

test('will get code from SMTP error', (t) => {
  const { forwardEmail } = t.context;

  const err = forwardEmail.refineError({
    message: 'SMTP code:9000 msg:test'
  });

  t.is(err.responseCode, 9000);
  t.regex(err.message, /test/);
});

function httpErrorCodes(t, input) {
  const { forwardEmail } = t.context;

  const err = forwardEmail.refineError({
    code: input
  });

  t.is(err.responseCode, 421);
}

for (const code of HTTP_RETRY_ERROR_CODES) {
  test(
    `will set responseCode to 421 when given HTTP error code ${code}`,
    httpErrorCodes,
    code
  );
}

function httpStatusCodes(t, input) {
  const { forwardEmail } = t.context;

  const err = forwardEmail.refineError({
    status: input
  });

  t.is(err.responseCode, 421);
}

for (const code of HTTP_RETRY_STATUS_CODES) {
  test(
    `will set responseCode to 421 when given HTTP status code ${code}`,
    httpStatusCodes,
    code
  );
}

test('will set responseCode to 550 when given a non-retry HTTP error code', (t) => {
  const { forwardEmail } = t.context;
  const err = forwardEmail.refineError({
    code: 'ECONFLICT'
  });

  t.is(err.responseCode, 550);
});

test('will set responseCode to 550 when given a non-retry HTTP status code', (t) => {
  const { forwardEmail } = t.context;
  const err = forwardEmail.refineError({
    status: '409'
  });

  t.is(err.responseCode, 550);
});
