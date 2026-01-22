import { type } from 'arktype';
import { type Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { CookieOptions } from 'hono/utils/cookie';
import { describeRoute, validator } from 'hono-openapi';
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

  return config.ALLOWED_REDIRECT_DOMAINS.some((domain) => {
    return redirectUri.host === domain;
  });
}

function clearAuthCookies(c: Context) {
  for (const cookie of Object.values(COOKIES)) {
    deleteCookie(c, cookie);
  }
}

function setTokenCookies(c: Context, tokens: Tokens) {
  const accessTokenExpires = new Date(Date.now() + tokens.expires_in * 1000);
  const refreshTokenExpires = new Date(
    Date.now() + tokens.refresh_expires_in * 1000,
  );

  const sensitiveCookieOptions: CookieOptions = {
    httpOnly: true,
    secure: !config.INSECURE_COOKIES,
    sameSite: 'Lax',
  };

  const publicCookieOptions: CookieOptions = {
    httpOnly: false,
    secure: !config.INSECURE_COOKIES,
    sameSite: 'Lax',
  };

  // Sensitive cookies
  setCookie(c, COOKIES.accessToken, tokens.access_token, {
    ...sensitiveCookieOptions,
    expires: accessTokenExpires,
  });
  setCookie(c, COOKIES.refreshToken, tokens.refresh_token, {
    ...sensitiveCookieOptions,
    expires: refreshTokenExpires,
  });
  setCookie(
    c,
    COOKIES.refreshExpiresAt,
    (Date.now() + tokens.refresh_expires_in * 1000).toString(),
    {
      ...sensitiveCookieOptions,
      expires: refreshTokenExpires,
    },
  );

  // Public cookies
  setCookie(c, COOKIES.expiresAt, accessTokenExpires.getTime().toString(), {
    ...publicCookieOptions,
    expires: accessTokenExpires,
  });
}

const app = new Hono()
  .get(
    '/login',
    describeRoute({
      tags: ['public'],
      summary: 'Login',
      description: `
Redirects to the authentication provider login page.

To initiate the login process, redirect the user to this endpoint. If you do not want the user to be prompted for login even if they're not logged in, you can use the \`silent\` query parameter.
`,
      responses: {
        302: { description: 'Redirect to authentication provider login page' },
        400: { description: 'Bad request' },
      },
    }),
    validator(
      'query',
      type({
        'silent?': type('"true"|"false"').describe(
          'If `true`, the user will not be prompted for login even if they are not logged in. This is useful for checking if the user is already logged in without interrupting their experience.',
          'self',
        ),
        redirect_uri: type('string').describe(
          'The URI to redirect to after login. Should be a user-facing page in your application, most likely the page the user was on before being redirected to the login page.',
        ),
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
        secure: !config.INSECURE_COOKIES,
        sameSite: 'Lax',
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
    '/refresh',
    describeRoute({
      tags: ['public'],
      summary: 'Refresh',
      description: `
Refreshes the access token using the refresh token.

This should be called *from the frontend* using \`fetch\` just before the token is about to expire. If you're developing an application you can use the script provided in the [j26-auth repository](https://github.com/scouterna/j26-auth) to do this for you.
`,
      responses: {
        200: { description: 'Access token refreshed successfully' },
        401: { description: 'No or invalid refresh token.' },
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
  )
  .get(
    '/user',
    describeRoute({
      tags: ['public'],
      summary: 'Get user info',
      description:
        'Fetches the user information from the authentication provider.',
      responses: {
        200: { description: 'User information retrieved successfully' },
        401: { description: 'Unauthorized' },
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
    '/callback',
    describeRoute({
      tags: ['internal'],
      description: 'Handles the callback from the authentication provider.',
      responses: {
        302: { description: 'Redirect to the application home page' },
      },
    }),
    async (c) => {
      const finalRedirectUri = getCookie(c, COOKIES.redirectUri);

      if (!redirectUriValid(finalRedirectUri)) {
        return c.text('Invalid redirect URI', 400);
      }

      const codeVerifier = getCookie(c, COOKIES.oidcCodeVerifier);
      const nonce = getCookie(c, COOKIES.oidcNonce);

      if (!codeVerifier) {
        return c.text('Missing code verifier', 400);
      }

      let rawTokens: oidcClient.TokenEndpointResponse &
        oidcClient.TokenEndpointResponseHelpers;

      const proxiedHost = c.req.header('X-Forwarded-Host');
      const proxiedPort = c.req.header('X-Forwarded-Port');
      const proxiedProto = c.req.header('X-Forwarded-Proto');

      // FIXME: Using the public URL for verification is not proper
      const url = new URL(c.req.url);
      const publicUrl = new URL(config.PUBLIC_URL);

      url.pathname =
        publicUrl.pathname.replace(/\/$/, '') +
        '/' +
        url.pathname.replace(/^\//, '');
      url.host = proxiedHost || publicUrl.host;
      url.port = proxiedPort || publicUrl.port;
      url.protocol = proxiedProto || publicUrl.protocol;

      console.log('Trying to redeem code at URL:', url.href);
      console.log('Headers:', c.req.header());

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
    '/certs',
    describeRoute({
      tags: ['public'],
      summary: 'Get certificates',
      description:
        "Returns the JSON Web Key Set (JWKS) containing the public keys used to verify the tokens. This endpoint is a convience feature that simply proxies the JWKS from the identity provider so that the consumer doesn't have to know where the identity provider is located.",
      responses: {
        200: { description: 'Access token refreshed successfully' },
        500: {
          description:
            'Something went wrong while returning the certificates from the identity provider.',
        },
      },
    }),
    async (c) => {
      const serverMetadata = oidcConfig.serverMetadata();
      if (!serverMetadata.jwks_uri) {
        console.error('JWKS URI not found in server metadata');
        return c.json(null, 500);
      }
      return fetch(serverMetadata.jwks_uri);
    },
  );

export default app;
