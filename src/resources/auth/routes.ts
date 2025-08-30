import { Hono } from 'hono';
import { describeRoute } from 'hono-openapi';

const app = new Hono();

app.get(
	'/login',
	describeRoute({
		description: 'Redirects to the authentication provider login page.',
		responses: {
			302: {
				description: 'Redirect to authentication provider login page',
			},
		},
		validateResponse: {
			status: 500,
			message: 'Response validation failed. Please contact the service owner.',
		},
	}),
	async (c) => {
		return c.redirect('https://example.com/login');
	},
);

export default app;
