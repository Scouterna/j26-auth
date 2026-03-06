/**
 * j26-auth - Authentication service for Jamboree26
 *
 * This module exports the authentication service for programmatic usage.
 *
 * @example
 * ```typescript
 * import { initialize, createApp } from 'j26-auth';
 *
 * // Initialize the service
 * await initialize();
 *
 * // Get the app instance
 * const app = await createApp();
 *
 * // Use it with your own server setup or testing framework
 * ```
 *
 * @example
 * ```typescript
 * import { initialize, startServer } from 'j26-auth';
 *
 * // Initialize and start the server programmatically
 * await initialize();
 * await startServer(3000);
 * ```
 */

export type { AppType } from './app.ts';
export { config, createApp, initialize, startServer } from './lib.ts';
