import { createRemoteJWKSet } from 'jose';
import * as openidClient from 'openid-client';
import config from './config.ts';

export const oidcConfig = await openidClient.discovery(
	new URL(config.OIDC_SERVER),
	config.OIDC_CLIENT_ID,
	config.OIDC_CLIENT_SECRET,
);

const serverMetadata = oidcConfig.serverMetadata();

if (!serverMetadata.jwks_uri) {
	throw new Error('OIDC provider does not have a JWKS URI');
}

export const JWKS = createRemoteJWKSet(new URL(serverMetadata.jwks_uri));
