// Intentionally vulnerable: CORS wildcard
const cors = require('cors');
app.use(cors({ origin: '*' }));
// Also vulnerable:
res.setHeader('Access-Control-Allow-Origin', '*');
