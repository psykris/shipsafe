// Intentionally vulnerable: source maps enabled in production
const path = require('path');

module.exports = {
  mode: 'production',
  entry: './src/index.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'bundle.js',
  },
  // VULNERABLE: source maps expose full source code in production
  devtool: 'source-map',
};

// VULNERABLE: explicit production source map flag
const vueConfig = {
  productionSourceMap: true,
};
