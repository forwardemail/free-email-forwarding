const test = require('ava');

const { MessageSplitter } = require('../../../../helpers');

test('will return true if headers are already parsed', (t) => {
  const messageSplitter = new MessageSplitter();

  messageSplitter.headersParsed = true;
  t.is(messageSplitter._checkHeaders(Buffer.from('test')), true);
});

test('will return false if headers are still being parsed', (t) => {
  const messageSplitter = new MessageSplitter();

  t.is(messageSplitter._checkHeaders(Buffer.from('test\ntest')), false);
  t.is(messageSplitter.headersParsed, false);
  t.is(messageSplitter.headerBytes, 9);
});

test("will complete parsing headers when '\\n\\n' is found", (t) => {
  const messageSplitter = new MessageSplitter();

  messageSplitter._checkHeaders(Buffer.from('\r\n'));
  messageSplitter._checkHeaders(Buffer.from('fo'));

  t.is(messageSplitter._checkHeaders(Buffer.from('test\n\ntest')), false);
  t.is(messageSplitter.headersParsed, true);
  t.is(messageSplitter.headerBytes, 10);
  t.is(messageSplitter.headerChunks, null);
});

test("will complete parsing headers when '\\n\\r\\n' is found", (t) => {
  const messageSplitter = new MessageSplitter();

  t.is(messageSplitter._checkHeaders(Buffer.from('test\n\r\n')), false);
  t.is(messageSplitter.headersParsed, true);
  t.is(messageSplitter.headerBytes, 7);
  t.is(messageSplitter.headerChunks, null);
});

test("will complete parsing headers when '\\n\\n' is found including lastBytes", (t) => {
  const messageSplitter = new MessageSplitter();

  messageSplitter._checkHeaders(Buffer.from('test\ntest\n'));

  t.is(messageSplitter._checkHeaders(Buffer.from('\ntest')), false);
  t.is(messageSplitter.headersParsed, true);
  t.is(messageSplitter.headerBytes, 11);
  t.is(messageSplitter.headerChunks, null);
});

test("will complete parsing headers when '\\n\\r\\n' is found including lastBytes", (t) => {
  const messageSplitter = new MessageSplitter();

  messageSplitter._checkHeaders(Buffer.from('test\ntest\n'));

  t.is(messageSplitter._checkHeaders(Buffer.from('\r\ntest')), false);
  t.is(messageSplitter.headersParsed, true);
  t.is(messageSplitter.headerBytes, 12);
  t.is(messageSplitter.headerChunks, null);
});
