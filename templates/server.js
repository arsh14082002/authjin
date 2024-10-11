import dotenv from 'dotenv';
import { connectDB } from './src/config/db.js';
import http from 'http';
import app from './src/app.js';

dotenv.config();
connectDB();

const PORT = process.env.PORT || 3000;

const findAvailablePort = (port, maxPort = 65535) => {
  return new Promise((resolve) => {
    const server = http.createServer();
    server.listen(port, () => {
      server.close();
      resolve(port);
    });
    server.on('error', () => {
      if (port < maxPort) resolve(findAvailablePort(port + 1, maxPort));
      else resolve(null);
    });
  });
};

findAvailablePort(PORT).then((availablePort) => {
  if (availablePort) {
    app.listen(availablePort, () => {
      console.log(`Server running on port ${availablePort}`);
    });
  } else {
    console.error('No available ports found.');
  }
});
