const Graceful = require('@ladjs/graceful');
const ip = require('ip');
const ForwardEmail = require('.');

const app = new ForwardEmail();
const { logger, port } = app.config;

if (!module.parent) {
  const graceful = new Graceful({
    servers: [app.server],
    redisClients: [app.client],
    logger
  });

  graceful.listen();

  (async () => {
    try {
      await app.spamscanner.load();
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
}

module.exports = app;
