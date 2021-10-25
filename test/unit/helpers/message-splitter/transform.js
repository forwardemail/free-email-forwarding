const pify = require('pify');
const sinon = require('sinon');
const test = require('ava');

const { MessageSplitter } = require('../../../../helpers');

test('will return with no change if chunk is null', async (t) => {
  const messageSplitter = pify(new MessageSplitter());

  const err = await messageSplitter._transform(null, 'utf-8');

  t.is(err, undefined);
  t.is(messageSplitter.headerBytes, 0);
});

test('will return with no change if chunk length is 0', async (t) => {
  const messageSplitter = pify(new MessageSplitter());

  const err = await messageSplitter._transform('', 'utf-8');

  t.is(err, undefined);
  t.is(messageSplitter.headerBytes, 0);
});

test('will return successfully when given buffer', async (t) => {
  const messageSplitter = pify(new MessageSplitter());

  let err = await messageSplitter._transform(Buffer.from('test\n\n'), 'utf-8');

  t.is(err, undefined);

  err = await messageSplitter._transform(Buffer.from('test'), 'utf-8');

  t.is(err, undefined);
  t.is(messageSplitter.headerBytes, 6);
});

test('will return successfully when given string', async (t) => {
  const messageSplitter = pify(new MessageSplitter());

  const err = await messageSplitter._transform('test', 'utf-8');

  t.is(err, undefined);
  t.is(messageSplitter.headerBytes, 4);
});

test('will return error if max size is exceeded', async (t) => {
  const messageSplitter = pify(new MessageSplitter({ maxBytes: 2 }));

  await t.throwsAsync(
    async () => {
      await messageSplitter._transform('test', 'utf-8');
    },
    { message: /Maximum allowed message size/ }
  );

  t.is(messageSplitter.sizeExceeded, true);
});

test('will return error from checkHeaders', async (t) => {
  const messageSplitter = pify(new MessageSplitter());

  // force expception
  sinon.stub(messageSplitter, '_checkHeaders').throws();

  await t.throwsAsync(async () => {
    await messageSplitter._transform('test', 'utf-8');
  });
});
