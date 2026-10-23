import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DIST_DIR = path.join(__dirname, 'dist');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2'
};

function createRequestHandler(port) {
  return (req, res) => {
    // 1. Proxy API requests to Flask backend on port 5000
    if (req.url.startsWith('/api')) {
      const options = {
        hostname: '127.0.0.1',
        port: 5000,
        path: req.url,
        method: req.method,
        headers: { ...req.headers, host: '127.0.0.1:5000' }
      };

      const proxyReq = http.request(options, (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res, { end: true });
      });

      proxyReq.on('error', (err) => {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'error', message: 'Backend proxy error: ' + err.message }));
      });

      req.pipe(proxyReq, { end: true });
      return;
    }

    // 2. Serve static files from dist
    let safeUrl = req.url.split('?')[0];
    let filePath = path.join(DIST_DIR, safeUrl === '/' ? 'index.html' : safeUrl);

    fs.stat(filePath, (err, stats) => {
      if (err || !stats.isFile()) {
        filePath = path.join(DIST_DIR, 'index.html');
      }

      const ext = path.extname(filePath).toLowerCase();
      const contentType = MIME_TYPES[ext] || 'application/octet-stream';

      fs.readFile(filePath, (readErr, content) => {
        if (readErr) {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Internal Server Error');
          return;
        }
        res.writeHead(200, {
          'Content-Type': contentType,
          'Cache-Control': 'no-cache',
          'Access-Control-Allow-Origin': '*'
        });
        res.end(content);
      });
    });
  };
}

// Start listeners on both 5173 and 5174
const server5173 = http.createServer(createRequestHandler(5173));
server5173.listen(5173, '0.0.0.0', () => {
  console.log('[+] AegisAuth Web Client running at http://localhost:5173/');
  console.log('[+] Network access: http://127.0.0.1:5173/');
});

const server5174 = http.createServer(createRequestHandler(5174));
server5174.listen(5174, '0.0.0.0', () => {
  console.log('[+] AegisAuth Web Client mirror running at http://localhost:5174/');
});
