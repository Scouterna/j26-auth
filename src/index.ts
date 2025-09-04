import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { serve } from '@hono/node-server';
import config, { loadConfig } from './config.ts';
import  { initializeOIDC } from './oidc.ts';

type ServeOptions = Parameters<typeof serve>[0];

loadConfig();
await initializeOIDC()

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

async function main() {
	// Use dynamic import to make sure config is loaded before app is imported
	const { default: app } = await import('./app.ts');

	const port = config.PORT ?? 3000;

	const { serveOptions, isHttps } = createServeOptions({
		fetch: app.fetch,
		port,
	});

	serve(serveOptions, (info) => {
		console.log(
			`Server is running on ${isHttps ? 'https' : 'http'}://localhost:${info.port}`,
		);
	});
}

await main();
