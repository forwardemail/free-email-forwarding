const test = require('ava');

const { MessageSplitter } = require('../../../../helpers');

test('will be defined', (t) => {
  const messageSplitter = new MessageSplitter();

  t.true(messageSplitter instanceof MessageSplitter);
});

test('will set maxBytes', (t) => {
  const messageSplitter = new MessageSplitter({ maxBytes: 20 });

  t.true(messageSplitter instanceof MessageSplitter);
  t.is(messageSplitter._maxBytes, 20);
});
