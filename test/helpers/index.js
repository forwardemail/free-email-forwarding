const getPort = require('get-port');
const redis = require('redis');

const ForwardEmail = require('../..');

const client = redis.createClient();

const beforeEach = t => {
  return Promise.all([
    new Promise((resolve, reject) => {
      client.keys('limit:*', (err, keys) => {
        if (err) return reject(err);
        if (keys.length === 0) return resolve();
        const args = keys.concat(resolve);
        client.del(...args);
      });
    }),
    (async () => {
      const forwardEmail = new ForwardEmail();
      const port = await getPort();
      forwardEmail.server = forwardEmail.server.listen(port, () => {
        t.context.forwardEmail = forwardEmail;
      });
    })()
  ]);
};

const afterEach = t => {
  return new Promise(resolve => {
    t.context.forwardEmail.server.close(() => {
      resolve();
    });
  });
};

module.exports = { beforeEach, afterEach };
