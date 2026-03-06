import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { serve } from '@hono/node-server';
import config, { loadConfig } from './config.ts';
import { initializeOIDC } from './oidc.ts';

type ServeOptions = Parameters<typeof serve>[0];

/**
 * Initialize the authentication service configuration and OIDC
 * Call this before using createApp() or startServer()
 */
export async function initialize() {
  loadConfig();
  await initializeOIDC();
}

/**
 * Create and return the app instance without starting the server
 * Useful for programmatic usage or custom server setup
 */
export async function createApp() {
  const { default: app } = await import('./app.ts');
  return app;
}

/**
 * Utility function to conditionally create HTTPS server
 */
function createServeOptions(
  options: Omit<ServeOptions, 'createServer' | 'serverOptions'>,
) {
  const keyPath = config.HTTPS_KEY;
  const certPath = config.HTTPS_CERT;
  const isHttps = Boolean(keyPath) && Boolean(certPath);

  let serveOptions: ServeOptions;

  if (isHttps) {
    if (!keyPath || !certPath) {
      throw new Error(
        'Both HTTPS_KEY and HTTPS_CERT must be set to enable HTTPS',
      );
    }

    const key = readFileSync(keyPath);
    const cert = readFileSync(certPath);

    serveOptions = {
      createServer: createHttpsServer,
      serverOptions: {
        key,
        cert,
      },
      ...options,
    };
  } else {
    serveOptions = {
      createServer,
      ...options,
    };
  }

  return {
    serveOptions,
    isHttps,
  };
}

/**
 * Start the authentication server
 * @param port - Port to listen on (defaults to config.PORT or 3000)
 */
export async function startServer(port?: number) {
  const app = await createApp();
  const serverPort = port ?? config.PORT ?? 3000;

  const { serveOptions, isHttps } = createServeOptions({
    fetch: app.fetch,
    port: serverPort,
  });

  return new Promise<void>((resolve) => {
    serve(serveOptions, (info) => {
      console.log(
        `Server is running on ${isHttps ? 'https' : 'http'}://localhost:${info.port}`,
      );
      resolve();
    });
  });
}

// Re-export types and app
export type { AppType } from './app.ts';
export { default as config } from './config.ts';
