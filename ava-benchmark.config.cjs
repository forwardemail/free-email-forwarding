const baseConfig = require('./ava.config.cjs');

baseConfig.files[0] = 'test/benchmark/**/*';

module.exports = baseConfig;
