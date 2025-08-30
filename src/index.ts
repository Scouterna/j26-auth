import { serve } from '@hono/node-server';
import app from './app.ts';

import config, { loadConfig } from './config.ts';

loadConfig();

const port = config.PORT ?? 3000;

serve(
	{
		fetch: app.fetch,
		port,
	},
	(info) => {
		console.log(`Server is running on http://localhost:${info.port}`);
	},
);
