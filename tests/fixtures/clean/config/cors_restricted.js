// Correct: restricted CORS
const cors = require('cors');
app.use(cors({ origin: 'https://myapp.example.com' }));
