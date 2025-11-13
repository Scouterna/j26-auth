import './arktypeConfig.ts';

import { serveStatic } from '@hono/node-server/serve-static';
import { Scalar } from '@scalar/hono-api-reference';

import { Hono } from 'hono';
import { openAPIRouteHandler } from 'hono-openapi';
import auth from './resources/auth/routes.ts';
import { logger } from 'hono/logger';
import config from './config.ts';

const DOCS_URL = `${config.PUBLIC_URL.replace(/\/+$/, '')}/docs`;

const app = new Hono();

if (config.LOG_REQUESTS) {
  app.use(logger());
}

app
  .get('/', (c) => {
    return c.redirect(DOCS_URL);
  })
  .get(
    '/docs',
    Scalar({
      theme: 'saturn',
      url: './openapi',
      hideClientButton: true,
    }),
  )
  .get(
    '/openapi',
    // biome-ignore lint/suspicious/noExplicitAny: This helps with type performance.
    openAPIRouteHandler(app as any, {
      documentation: {
        info: {
          title: 'j26-auth',
          version: '0.0.0',
          description: 'Authentication service for Jamboree26',
        },
        servers: [
          {
            url: 'https://app.jamboree.se/auth',
            description: 'Production server',
          },
          {
            url: 'https://dev.j26.se/auth',
            description: 'Development server',
          },
        ],
        tags: [
          {
            name: 'public',
            description:
              'Public endpoints. These are the endpoints that you as a consumer should be using.',
          },
          {
            name: 'internal',
            description:
              'Internal endpoints. These are used by the authentication service and should never be called by a consumer service.',
          },
        ],
      },
    }),
  );

export const routes = app.route('/', auth);

app.use(
  '/static/*',
  serveStatic({
    root: new URL('../', import.meta.url).pathname,
    rewriteRequestPath: (path) => path.replace(/^\/auth\//, '/'),
    onNotFound: (path, c) => {
      console.log(`${path} is not found, you access ${c.req.path}`);
    },
  }),
);

// const rootApp = new Hono();
// rootApp.route('/', app);

// export default rootApp;
export default app;
export type AppType = typeof routes;
