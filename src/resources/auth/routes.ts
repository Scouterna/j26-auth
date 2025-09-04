import { type } from 'arktype';
import { type Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { CookieOptions } from 'hono/utils/cookie';
import { describeRoute } from 'hono-openapi';
import { validator } from 'hono-openapi/arktype';
import * as jose from 'jose';
import * as oidcClient from 'openid-client';
import config from '../../config.ts';
import { COOKIES } from '../../constants.ts';
import { JWKS, oidcConfig } from '../../oidc.ts';

const Tokens = type({
	access_token: 'string',
	expires_in: 'number',
	id_token: 'string',
	refresh_token: 'string',
	refresh_expires_in: 'number',
});
type Tokens = typeof Tokens.infer;

const TokenPayload = type({
	'+': 'delete',
	name: 'string',
	preferred_username: 'string',
	given_name: 'string',
	family_name: 'string',
	email: 'string',
});

const scope = 'openid profile email';

function redirectUriValid(uri: string | undefined): uri is string {
	if (!uri) return false;

	const redirectUri = new URL(uri);
	const publicUrl = new URL(config.PUBLIC_URL);
	return redirectUri.host === publicUrl.host;
}

function clearAuthCookies(c: Context) {
	for (const cookie of Object.values(COOKIES)) {
		deleteCookie(c, cookie);
	}
}

function setTokenCookies(c: Context, tokens: Tokens) {
	const expires = new Date(Date.now() + tokens.expires_in * 1000);

	const sensitiveCookieOptions: CookieOptions = {
		httpOnly: true,
		secure: true,
		sameSite: 'Strict',
		expires,
	};

	const publicCookieOptions: CookieOptions = {
		httpOnly: false,
		secure: true,
		sameSite: 'Strict',
		expires,
	};

	// Sensitive cookies
	setCookie(
		c,
		COOKIES.accessToken,
		tokens.access_token,
		sensitiveCookieOptions,
	);
	// setCookie(c, COOKIES.idToken, tokens.id_token, sensitiveCookieOptions);
	setCookie(
		c,
		COOKIES.refreshToken,
		tokens.refresh_token,
		sensitiveCookieOptions,
	);
	setCookie(
		c,
		COOKIES.refreshExpiresAt,
		(Date.now() + tokens.refresh_expires_in * 1000).toString(),
		sensitiveCookieOptions,
	);

	// Public cookies
	setCookie(
		c,
		COOKIES.expiresAt,
		expires.getTime().toString(),
		publicCookieOptions,
	);
}

const app = new Hono()
	.get(
		'/login',
		describeRoute({
			description: 'Redirects to the authentication provider login page.',
			responses: {
				302: { description: 'Redirect to authentication provider login page' },
				400: { description: 'Bad request' },
			},
			validateResponse: {
				status: 500,
				message:
					'Response validation failed. Please contact the service owner.',
			},
		}),
		validator(
			'query',
			type({
				'silent?': '"true"|"false"',
				redirect_uri: 'string',
			}),
		),
		async (c) => {
			const silent = c.req.valid('query').silent === 'true';
			const finalRedirectUri = c.req.valid('query').redirect_uri;

			if (!redirectUriValid(finalRedirectUri)) {
				return c.text('Invalid redirect URI', 400);
			}

			const redirectUri = new URL('./callback', config.PUBLIC_URL).href;

			const codeVerifier: string = oidcClient.randomPKCECodeVerifier();
			const codeChallenge: string =
				await oidcClient.calculatePKCECodeChallenge(codeVerifier);
			let nonce!: string;

			const parameters: Record<string, string> = {
				redirect_uri: redirectUri,
				scope,
				code_challenge: codeChallenge,
				code_challenge_method: 'S256',
			};

			if (silent) {
				parameters.prompt = 'none';
			}

			/**
			 * We cannot be sure the AS supports PKCE so we're going to use nonce too. Use
			 * of PKCE is backwards compatible even if the AS doesn't support it which is
			 * why we're using it regardless.
			 */
			if (!oidcConfig.serverMetadata().supportsPKCE()) {
				nonce = oidcClient.randomNonce();
				parameters.nonce = nonce;
			}

			const redirectTo = oidcClient.buildAuthorizationUrl(
				oidcConfig,
				parameters,
			);

			const cookieOptions: CookieOptions = {
				httpOnly: true,
				secure: true,
				sameSite: 'Strict',
				expires: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes
			};

			setCookie(c, COOKIES.oidcCodeVerifier, codeVerifier, cookieOptions);

			if (nonce) {
				setCookie(c, COOKIES.oidcNonce, nonce, cookieOptions);
			} else {
				deleteCookie(c, COOKIES.oidcNonce, cookieOptions);
			}

			setCookie(c, COOKIES.redirectUri, finalRedirectUri, cookieOptions);

			return c.redirect(redirectTo.href);
		},
	)
	.get(
		'/callback',
		describeRoute({
			description: 'Handles the callback from the authentication provider.',
			responses: {
				302: { description: 'Redirect to the application home page' },
			},
			validateResponse: {
				status: 500,
				message:
					'Response validation failed. Please contact the service owner.',
			},
		}),
		async (c) => {
			const finalRedirectUri = getCookie(c, COOKIES.redirectUri);

			if (!redirectUriValid(finalRedirectUri)) {
				return c.text('Invalid redirect URI', 400);
			}

			const url = new URL(c.req.url);

			const codeVerifier = getCookie(c, COOKIES.oidcCodeVerifier);
			const nonce = getCookie(c, COOKIES.oidcNonce);

			if (!codeVerifier) {
				return c.text('Missing code verifier', 400);
			}

			let rawTokens: oidcClient.TokenEndpointResponse &
				oidcClient.TokenEndpointResponseHelpers;

			try {
				rawTokens = await oidcClient.authorizationCodeGrant(oidcConfig, url, {
					pkceCodeVerifier: codeVerifier,
					expectedNonce: nonce,
					idTokenExpected: true,
				});
			} catch (e) {
				if (
					e instanceof oidcClient.AuthorizationResponseError &&
					e.error === 'login_required'
				) {
					clearAuthCookies(c);
					return c.redirect(finalRedirectUri);
				}

				throw e;
			}

			const tokens = Tokens(rawTokens);
			if (tokens instanceof type.errors) {
				return c.text('Invalid token response', 500);
			}

			setTokenCookies(c, tokens);

			return c.redirect(finalRedirectUri);
		},
	)
	.get(
		'/user',
		describeRoute({
			description:
				'Fetches the user information from the authentication provider.',
			responses: {
				200: { description: 'User information retrieved successfully' },
				401: { description: 'Unauthorized' },
			},
			validateResponse: {
				status: 500,
				message:
					'Response validation failed. Please contact the service owner.',
			},
		}),
		async (c) => {
			const accessToken = getCookie(c, COOKIES.accessToken);
			if (!accessToken) {
				return c.json({ error: 'Unauthorized' }, 401);
			}

			const { payload } = await jose.jwtVerify(accessToken, JWKS);

			const user = TokenPayload(payload);

			if (user instanceof type.errors) {
				return c.json({ error: 'Malformed token' }, 401);
			}

			return c.json({
				user: {
					name: user.name,
					preferredUsername: user.preferred_username,
					givenName: user.given_name,
					familyName: user.family_name,
					email: user.email,
				},
			});
		},
	)
	.get(
		'/refresh',
		describeRoute({
			description: 'Refreshes the access token using the refresh token.',
			responses: {
				200: { description: 'Access token refreshed successfully' },
				401: { description: 'No or invalid refresh token.' },
			},
			validateResponse: {
				status: 500,
				message:
					'Response validation failed. Please contact the service owner.',
			},
		}),
		async (c) => {
			const refreshToken = getCookie(c, COOKIES.refreshToken);
			if (!refreshToken) {
				return c.json({ error: 'Unauthorized' }, 401);
			}

			let rawTokens: oidcClient.TokenEndpointResponse &
				oidcClient.TokenEndpointResponseHelpers;

			try {
				rawTokens = await oidcClient.refreshTokenGrant(
					oidcConfig,
					refreshToken,
					{ scope },
				);
			} catch (e) {
				if (
					e instanceof oidcClient.ResponseBodyError &&
					e.error === 'invalid_grant'
				) {
					clearAuthCookies(c);
					return c.json({ error: 'Unauthorized' }, 401);
				}

				throw e;
			}

			const tokens = Tokens(rawTokens);
			if (tokens instanceof type.errors) {
				return c.text('Invalid token response', 500);
			}

			setTokenCookies(c, tokens);

			return c.json({});
		},
	);

export default app;
