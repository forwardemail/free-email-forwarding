const getPort = require('get-port');
const revHash = require('rev-hash');
const safeStringify = require('fast-safe-stringify');
const test = require('ava');

const {
  MESSAGE_ID_LENGTH,
  SENT_KEY_HEADERS
} = require('../../helpers/constants');

const ForwardEmail = require('../..');

test.before(async (t) => {
  t.context.forwardEmail = new ForwardEmail({
    port: await getPort()
  });
});

test('will return Message-ID', (t) => {
  const { forwardEmail } = t.context;

  const to = [];
  const originalRaw = 'Message-ID: test';
  const bounce = null;

  const key = forwardEmail.getSentKey(to, originalRaw, bounce);

  t.is(
    key,
    `sent:${revHash(safeStringify(to))}:${revHash(
      originalRaw.slice(MESSAGE_ID_LENGTH)
    )}`
  );
});

test('will return Message-ID with to as string', (t) => {
  const { forwardEmail } = t.context;

  const to = 'paul.atriedes@fremen.com';
  const originalRaw = 'Message-ID: test';
  const bounce = null;

  const key = forwardEmail.getSentKey(to, originalRaw, bounce);

  t.is(
    key,
    `sent:${revHash(safeStringify([to]))}:${revHash(
      originalRaw.slice(MESSAGE_ID_LENGTH)
    )}`
  );
});

test('will return Message-ID with originalRaw as buffer', (t) => {
  const { forwardEmail } = t.context;

  const to = 'paul.atriedes@fremen.com';
  const originalRaw = 'Message-ID: test';
  const bounce = null;

  const key = forwardEmail.getSentKey(
    to,
    Buffer.from(originalRaw, 'utf-8'),
    bounce
  );

  t.is(
    key,
    `sent:${revHash(safeStringify([to]))}:${revHash(
      originalRaw.slice(MESSAGE_ID_LENGTH)
    )}`
  );
});

function headers(t, input) {
  const { forwardEmail } = t.context;

  const to = [];
  const originalRaw = `${input}test`;
  const bounce = null;

  const key = forwardEmail.getSentKey(to, originalRaw, bounce);

  t.is(key, `sent:${revHash(safeStringify(to))}:${revHash(originalRaw)}`);
}

for (const key of SENT_KEY_HEADERS) {
  test(`will return based on ${key}`, headers, key);
}

test('will return based on multiple headers and ignore certain headers', (t) => {
  const { forwardEmail } = t.context;

  const to = [];
  const bounce = null;

  const originalRaw = [];
  for (const key of SENT_KEY_HEADERS) {
    originalRaw.push(`${key}test`);
  }

  const key = forwardEmail.getSentKey(
    to,
    [...originalRaw, 'Received-By: test'].join('\n'),
    bounce
  );

  t.is(
    key,
    `sent:${revHash(safeStringify(to))}:${revHash(originalRaw.join(''))}`
  );
});

test('will return based on multiple headers with body lines', (t) => {
  const { forwardEmail } = t.context;

  const to = [];
  const bounce = null;

  const originalRaw = [];
  for (const key of SENT_KEY_HEADERS) {
    originalRaw.push(`${key}test`);
  }

  const expected = originalRaw.join('') + '5';

  originalRaw.push('');
  for (let i = 0; i < 5; i++) {
    originalRaw.push('test');
  }

  const key = forwardEmail.getSentKey(to, originalRaw.join('\n'), bounce);

  t.is(key, `sent:${revHash(safeStringify(to))}:${revHash(expected)}`);
});

test('will return based on multiple headers with bounce error/code', (t) => {
  const { forwardEmail } = t.context;

  const to = [];
  const bounce = { err: new Error('test'), address: 'test' };

  const originalRaw = [];
  for (const key of SENT_KEY_HEADERS) {
    originalRaw.push(`${key}test`);
  }

  const key = forwardEmail.getSentKey(to, originalRaw.join('\n'), bounce);

  t.is(
    key,
    `sent:${revHash(safeStringify(to))}:${revHash(
      originalRaw.join('')
    )}:bounce:${revHash(safeStringify(bounce.address))}:${safeStringify(550)}`
  );
});

test('will throw error if to is not a string or array', (t) => {
  t.throws(
    () => {
      const { forwardEmail } = t.context;

      const to = null;
      const originalRaw = 'Message-ID: test';
      const bounce = null;

      forwardEmail.getSentKey(to, originalRaw, bounce);
    },
    { message: /to must be an Array./ }
  );
});

test('will throw error if originalRaw is not a string or buffer', (t) => {
  t.throws(
    () => {
      const { forwardEmail } = t.context;

      const to = [];
      const originalRaw = null;
      const bounce = null;

      forwardEmail.getSentKey(to, originalRaw, bounce);
    },
    { message: /raw must be String./ }
  );
});
