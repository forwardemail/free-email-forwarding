const _ = require('lodash');
const test = require('ava');

const { MessageSplitter } = require('../../../../helpers');

test('will not set headers if they have already been parsed', async (t) => {
  const messageSplitter = new MessageSplitter();
  // force a closed header
  messageSplitter._checkHeaders(Buffer.from('\n\n'));

  messageSplitter.on('headers', () => {
    t.fail();
  });

  const preFlushHeaders = _.clone(messageSplitter.headers);

  await new Promise((resolve) => {
    messageSplitter._flush(resolve);
  });

  t.is(messageSplitter.headerChunks, null);
  t.deepEqual(messageSplitter.headers, preFlushHeaders);
});

test('will set headers if no body was found', async (t) => {
  const messageSplitter = new MessageSplitter();

  messageSplitter._checkHeaders(Buffer.from('test\n'));

  t.not(messageSplitter.headerChunks, null);

  await new Promise((resolve) => {
    messageSplitter._flush(resolve);
  });

  t.is(messageSplitter.headerChunks, null);
});
