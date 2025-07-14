import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { readdir } from 'fs/promises';
import { existsSync } from 'fs';

export default defineConfig({
  appType: 'mpa', // Disable default SPA middleware
  plugins: [
    react(),
    {
      configureServer(server) {
        server.middlewares.use(async (req, res, next) => {
          const url = req.url;
          const publicDir = resolve(server.config.root, 'public');

          // Custom handling for /logs
          if (url.startsWith('/logs')) {
            const logFileName = url.slice(6); // Extract log file name if any
            if (!logFileName) {
              const logsDir = resolve(server.config.root, "..", "logs");
              res.setHeader('Content-Type', 'application/json');
              res.end(JSON.stringify(await readdir(logsDir)));
              return;
            }
          } else if (url == '/' || url.startsWith('/view')) {
            req.url = "/index.html"
          }
          next();
          /*
          } else {
            const prefixes = [resolve(server.config.root, 'public'), server.config.root];
            for (const prefix of prefixes) {
              if (existsSync(resolve(prefix, '.' + url))) {
                next();
                break
              }
            }
            req.url = "/index.html"
            next();
          }
          */
        });
      },
    },
  ],
});
