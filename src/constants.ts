const COOKIE_PREFIX = 'j26-auth_';

export const COOKIES = {
  oidcCodeVerifier: `${COOKIE_PREFIX}oidc-code-verifier`,
  oidcNonce: `${COOKIE_PREFIX}oidc-nonce`,
  accessToken: `${COOKIE_PREFIX}access-token`,
  refreshToken: `${COOKIE_PREFIX}refresh-token`,
  expiresAt: `${COOKIE_PREFIX}expires-at`,
  refreshExpiresAt: `${COOKIE_PREFIX}refresh-expires-at`,
  redirectUri: `${COOKIE_PREFIX}redirect-uri`,
};
