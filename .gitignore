// Hosts the static pages and runs the same API code as the Netlify function.
// Sessions are signed cookies, so restarts and multiple instances don't log anyone out.
const express = require('express');
const path = require('path');
const { handler } = require('./netlify/functions/api.js');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.redirect('/index.html'));

app.all('/api/*', express.text({ type: '*/*', limit: '4kb' }), async (req, res) => {
  try {
    const out = await handler({
      path: req.path, httpMethod: req.method, headers: req.headers,
      body: typeof req.body === 'string' && req.body ? req.body : null,
    });
    res.status(out.statusCode).set(out.headers || {}).send(out.body);
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => console.log('Panel running on port ' + port));
