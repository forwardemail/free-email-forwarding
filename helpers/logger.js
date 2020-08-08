const Axe = require('axe');
const { WebClient } = require('@slack/web-api');
const signale = require('signale');
const pino = require('pino')({
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
});

const env = require('./env');

const isProduction = env.NODE_ENV === 'production';

const config = {
  silent: env.IS_SILENT,
  logger: isProduction ? pino : signale,
  level: isProduction ? 'warn' : 'debug',
  showStack: env.SHOW_STACK,
  showMeta: env.SHOW_META,
  capture: false,
  name: env.APP_NAME
};

// create our application logger that uses a custom callback function
const axe = new Axe({ ...config });

if (env.SLACK_API_TOKEN) {
  // custom logger for Slack that inherits our Axe config
  // (with the exception of a `callback` function for logging to Slack)
  const slackLogger = new Axe(config);

  // create an instance of the Slack Web Client API for posting messages
  const web = new WebClient(env.SLACK_API_TOKEN, {
    // <https://slack.dev/node-slack-sdk/web-api#logging>
    logger: slackLogger,
    logLevel: config.level
  });

  axe.setCallback(async (level, message, meta) => {
    try {
      // if meta did not have `slack: true` or not a specific level
      if (!meta.slack && !['fatal'].includes(level)) return;

      // otherwise post a message to the slack channel
      const fields = [
        {
          title: 'Level',
          value: meta.level,
          short: true
        },
        {
          title: 'Environment',
          value: meta.app.environment,
          short: true
        },
        {
          title: 'Hostname',
          value: meta.app.hostname,
          short: true
        },
        {
          title: 'Hash',
          value: meta.app.hash,
          short: true
        }
      ];

      if (meta.bounce_info)
        fields.push({
          title: 'Bounce Info',
          value: JSON.stringify(meta.bounce_info),
          short: true
        });

      if (meta.envelope)
        fields.push({
          title: 'Envelope',
          value: JSON.stringify(meta.envelope),
          short: true
        });

      const result = await web.chat.postMessage({
        channel: 'logs',
        username: 'Cabin',
        icon_emoji: ':evergreen_tree:',
        attachments: [
          {
            title: meta.err && meta.err.message ? meta.err.message : message,
            color: 'danger',
            text: meta.err && meta.err.stack ? meta.err.stack : null,
            fields
          }
        ]
      });

      // finally log the result from slack
      axe.debug('web.chat.postMessage', { result, callback: false });
    } catch (err) {
      axe.debug(err, { callback: false });
    }
  });
}

module.exports = axe;
