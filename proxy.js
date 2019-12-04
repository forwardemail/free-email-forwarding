const Graceful = require('@ladjs/graceful');
const ProxyServer = require('@ladjs/proxy');
const ip = require('ip');

const logger = require('./helpers/logger');

const proxy = new ProxyServer({ logger, redirect: false });

if (!module.parent) {
  const graceful = new Graceful({ servers: [proxy], logger });
  (async () => {
    try {
      await Promise.all([proxy.listen(proxy.config.port), graceful.listen()]);
      if (process.send) process.send('ready');
      const { port } = proxy.server.address();
      logger.info(
        `Lad proxy server listening on ${port} (LAN: ${ip.address()}:${port})`
      );
    } catch (err) {
      logger.error(err);
      // eslint-disable-next-line unicorn/no-process-exit
      process.exit(1);
    }
  })();
}
