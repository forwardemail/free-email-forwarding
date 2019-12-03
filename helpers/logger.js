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
            }
          })
        : new Signale()
  }
});

module.exports = logger;
