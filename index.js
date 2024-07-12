const http = require('http');
const fs = require('fs');
const path = './visitors.json';

const server = http.createServer((req, res) => {
  if (req.url === '/') {
    const ip = req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'];

    fs.readFile(path, 'utf8', (err, data) => {
      let visitors = [];
      if (!err && data) {
        visitors = JSON.parse(data);
      }

      visitors.push({ ip, userAgent, timestamp: new Date().toISOString() });
      if (visitors.length > 10) {
        visitors.shift();
      }

      fs.writeFile(path, JSON.stringify(visitors, null, 2), (err) => {
        if (err) throw err;

        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`<html><body>
          <h1>Last 10 visitors</h1>
          <ul>${visitors.map(visitor => `<li>${visitor.ip} - ${visitor.userAgent} - ${visitor.timestamp}</li>`).join('')}</ul>
          <p>Your IP: ${ip}</p>
          <p>Your User-Agent: ${userAgent}</p>
        </body></html>`);
      });
    });
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  }
});

server.listen(3000, () => {
  console.log('Server listening on port 3000');
});
