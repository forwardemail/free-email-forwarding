const baseFiles = ['!test/helpers'];

module.exports = {
  baseFiles,
  serial: true,
  failFast: true,
  verbose: true,
  files: ['test/unit/**/*', 'test/integration/**/*', ...baseFiles],
  timeout: '10s'
};
