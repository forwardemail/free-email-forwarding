const test = require('ava');

const { MessageSplitter } = require('../../../../helpers');

test('will track last 4 bytes of data', (t) => {
  const messageSplitter = new MessageSplitter();

  t.is(messageSplitter.lastBytes.toString(), Buffer.alloc(4).toString());

  messageSplitter._updateLastBytes(Buffer.from('test data'));
  t.is(messageSplitter.lastBytes.toString(), 'data');

  messageSplitter._updateLastBytes(Buffer.from('me'));
  t.is(messageSplitter.lastBytes.toString(), 'tame');
});
