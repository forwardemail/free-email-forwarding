const process = require('process');

const Graceful = require('@ladjs/graceful');
const ip = require('ip');
const ms = require('ms');

const ForwardEmail = require('.');

const app = new ForwardEmail();
const { logger, port } = app.config;

const graceful = new Graceful({
  servers: [app.server],
  redisClients: [app.client],
  logger,
  // smtp-server connections have 30s timeout
  // this yields a +15s overhead
  timeoutMs: ms('45s')
});

graceful.listen();

(async () => {
  try {
    await app.listen(port);
    if (process.send) process.send('ready');
    logger.info(
      `ForwardEmail server listening on ${
        app.server.address().port
      } (LAN: ${ip.address()}:${app.server.address().port})`
    );
  } catch (err) {
    logger.error(err);
    // eslint-disable-next-line unicorn/no-process-exit
    process.exit(1);
  }
})();
