import './arktypeConfig.ts';

import { serveStatic } from '@hono/node-server/serve-static';
import { Scalar } from '@scalar/hono-api-reference';

import { Hono } from 'hono';
import { openAPIRouteHandler } from 'hono-openapi';
import auth from './resources/auth/routes.ts';

const app = new Hono();

app
  .get('/', (c) => c.redirect('./docs'))
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
    onNotFound: (path, c) => {
      console.log(`${path} is not found, you access ${c.req.path}`);
    },
  }),
);

const rootApp = new Hono();
rootApp.route('/auth', app);

export default rootApp;
export type AppType = typeof routes;
