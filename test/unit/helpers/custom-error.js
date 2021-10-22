const test = require('ava');

const { CustomError } = require('../../../helpers');

test('will return default message and responseCode', (t) => {
  const err = new CustomError();

  t.true(err instanceof CustomError);
  t.is(err.message, 'An unknown error has occurred');
  t.is(err.responseCode, 550);
});

test('will return assigned message and responseCode', (t) => {
  const err = new CustomError(`I'm not addicted to melange.`, 430);

  t.true(err instanceof CustomError);
  t.is(err.message, `I'm not addicted to melange.`);
  t.is(err.responseCode, 430);
});
