class CustomError extends Error {
  constructor(
    message = 'An unknown error has occurred',
    responseCode = 550,
    ...params
  ) {
    super(...params);
    Error.captureStackTrace(this, CustomError);
    this.message = message;
    this.responseCode = responseCode;
  }
}

module.exports = CustomError;
