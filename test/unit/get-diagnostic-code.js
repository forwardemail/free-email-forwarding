const getPort = require('get-port');
const test = require('ava');

const ForwardEmail = require('../..');

test.before(async (t) => {
  t.context.forwardEmail = new ForwardEmail({
    port: await getPort()
  });
});

test('will return code when response is correct', (t) => {
  const { forwardEmail } = t.context;

  const code = forwardEmail.getDiagnosticCode({ response: '200 OK' });

  t.is(code, '200 OK');
});

function getCode(t, input, dCode = 200) {
  const { forwardEmail } = t.context;

  const code = forwardEmail.getDiagnosticCode({
    [input]: dCode,
    message: 'OK'
  });

  t.is(code, `${dCode} OK`);
}

for (const field of ['responseCode', 'code', 'statusCode', 'status']) {
  test(`will return code based on '${field}' field`, getCode, field);
}

test('will return 500 code when no field is given', getCode, 'blank', 500);
