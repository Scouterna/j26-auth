(() => {
  const EXPIRES_AT_COOKIE = 'j26-auth_expires-at';
  const REFRESH_THRESHOLD_SECONDS = 10;

  async function refresh() {
    if (!window.__j26PreventRefresh) {
      await fetch('/auth/refresh');
    } else {
      console.debug('Token refresh prevented by __j26PreventRefresh');
    }

    scheduleRefresh();
  }

  function getExpiresAtFromCookie() {
    const match = document.cookie.match(
      new RegExp(`(^| )${EXPIRES_AT_COOKIE}=([^;]+)`),
    );
    if (match) {
      const expiresAt = parseInt(match[2], 10);
      if (!Number.isNaN(expiresAt)) {
        return expiresAt;
      }
    }
    return null;
  }

  function scheduleRefresh() {
    const expiresAt = getExpiresAtFromCookie();
    if (!expiresAt) {
      console.debug('No expires at cookie found');
    }

    console.log('Expires at:', expiresAt);

    let refreshIn = expiresAt
      ? expiresAt - Date.now() - REFRESH_THRESHOLD_SECONDS * 1000
      : 0;

    if (refreshIn < 0 && refreshIn > -REFRESH_THRESHOLD_SECONDS * 1000) {
      refreshIn = 1000;
    } else if (refreshIn <= 0) {
      refreshIn = 60_000;
    }

    console.debug(`Scheduling token refresh in ${Math.max(refreshIn, 0)} ms`);

    setTimeout(() => {
      refresh().catch((err) => {
        console.error('Error refreshing token:', err);
      });
    }, refreshIn);
  }

  scheduleRefresh();
})();
