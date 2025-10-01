import './arktypeConfig.ts';

import { Scalar } from '@scalar/hono-api-reference';

import { Hono } from 'hono';
import { openAPISpecs } from 'hono-openapi';
import config from './config.ts';
import auth from './resources/auth/routes.ts';

const app = new Hono();

app
	.get('/', (c) => c.redirect(new URL('./docs', config.PUBLIC_URL)))
	.get(
		'/docs',
		Scalar({
			theme: 'saturn',
			url: '/openapi',
			hideClientButton: true,
		}),
	)
	.get(
		'/openapi',
		openAPISpecs(app, {
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

export default app;
export type AppType = typeof routes;
