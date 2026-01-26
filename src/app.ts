import './arktypeConfig.ts';

import { serveStatic } from '@hono/node-server/serve-static';
import { Scalar } from '@scalar/hono-api-reference';

import { Hono } from 'hono';
import { logger } from 'hono/logger';
import { openAPIRouteHandler } from 'hono-openapi';
import config from './config.ts';
import auth from './resources/auth/routes.ts';

const app = new Hono();

if (config.LOG_REQUESTS) {
  app.use(logger());
}

app
  .get('/', (c) => {
    const docsUrl = `${config.PUBLIC_URL.replace(/\/+$/, '')}/docs`;
    return c.redirect(docsUrl);
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
      // The excludeStaticFile option makes the /.well-known/ paths not show up in the docs
      excludeStaticFile: false,
      documentation: {
        info: {
          title: 'j26-auth',
          version: '0.0.0',
          description: 'Authentication service for Jamboree26',
        },
        servers: [
          {
            url: 'https://app.dev.j26.se/auth',
            description: 'Development server',
          },
          {
            url: 'https://app.jamboree.se/auth',
            description: 'Production server',
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
  }),
);

export default app;
export type AppType = typeof routes;
