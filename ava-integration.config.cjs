const baseConfig = require('./ava.config.cjs');

module.exports = {
  ...baseConfig,
  files: ['test/integration/**/*', ...baseConfig.baseFiles]
};
