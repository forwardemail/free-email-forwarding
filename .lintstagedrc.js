module.exports = {
  '*.md': filenames => filenames.map(filename => `remark ${filename} -qfo`),
  '*.js': 'xo --fix',
  'package.json': 'fixpack'
};
