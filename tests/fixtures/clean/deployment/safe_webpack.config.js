// SAFE: source maps disabled in production
const path = require('path');

module.exports = {
  mode: 'production',
  entry: './src/index.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'bundle.js',
  },
  // SAFE: no source maps in production
  devtool: false,
};

// SAFE: production source maps explicitly disabled
const vueConfig = {
  productionSourceMap: false,
};
