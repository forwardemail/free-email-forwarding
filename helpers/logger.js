const Cabin = require('cabin');
const pino = require('pino');
const { Signale } = require('signale');

const env = require('./env');

const logger = new Cabin({
  axe: {
    silent: env.IS_SILENT,
    showStack: env.SHOW_STACK,
    name: env.APP_NAME,
    level: 'debug',
    capture: false,
    logger:
      env.NODE_ENV === 'production'
        ? pino({
            customLevels: {
              log: 30
            },
            hooks: {
              // <https://github.com/pinojs/pino/blob/master/docs/api.md#logmethod>
              logMethod(inputArgs, method) {
                return method.call(this, {
                  // <https://github.com/pinojs/pino/issues/854>
                  // message: inputArgs[0],
                  msg: inputArgs[0],
                  meta: inputArgs[1]
                });
              }
            }
          })
        : new Signale()
  }
});

module.exports = logger;
