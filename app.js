const dns = require('dns');

const Graceful = require('@ladjs/graceful');
const ip = require('ip');
const ForwardEmail = require('.');

const app = new ForwardEmail();
const { logger, port } = app.config;

dns.setServers(app.config.dns);

if (!module.parent) {
  const graceful = new Graceful({
    servers: [app.server],
    redisClients: [app.client],
    logger
  });

  (async () => {
    try {
      await Promise.all([app.listen(port), graceful.listen()]);
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
