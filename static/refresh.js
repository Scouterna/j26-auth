(() => {
  const EXPIRES_AT_COOKIE = 'j26-auth_expires-at';
  const RELOAD_FLAG_COOKIE = 'j26-auth_reload-flag';
  const REFRESH_THRESHOLD_SECONDS = 10;
  const RELOAD_FLAG_SECONDS = 120; // Lifetime of a cookie that prevent reload loops

  function hasReloadFlag() {
    return (
      document.cookie.match(new RegExp(`(^| )${RELOAD_FLAG_COOKIE}=`)) !== null
    );
  }

  function setReloadFlag() {
    const expires = new Date(
      Date.now() + RELOAD_FLAG_SECONDS * 1000,
    ).toUTCString();
    // biome-ignore lint/suspicious/noDocumentCookie: cookie store API is async, synchronous write needed here
    document.cookie = `${RELOAD_FLAG_COOKIE}=1; expires=${expires}; path=/`;
  }

  async function refresh(isInitialLoad = false) {
    if (!window.__j26PreventRefresh) {
      console.debug('Requesting token refresh');
      const res = await fetch('/auth/refresh');

      if (!res.ok) {
        console.warn(`Token refresh failed with status ${res.status}`);
      } else {
        console.info('Token refreshed successfully');

        if (isInitialLoad) {
          if (!hasReloadFlag()) {
            console.info('Reloading page to apply initial token');
            setReloadFlag();
            window.location.reload();
            return;
          }
          console.warn('Reload flag is active — skipping reload to prevent loop');
        }
      }
    } else {
      console.debug('Token refresh skipped (__j26PreventRefresh is set)');
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

  function scheduleRefresh(isInitialLoad = false) {
    const expiresAt = getExpiresAtFromCookie();

    if (!expiresAt) {
      console.warn('Auth expiry cookie not found — refreshing immediately');
      setTimeout(() => {
        refresh(isInitialLoad).catch((err) => {
          console.error('Unhandled error during token refresh:', err);
        });
      }, 0);
      return;
    }

    let refreshIn = expiresAt - Date.now() - REFRESH_THRESHOLD_SECONDS * 1000;

    if (refreshIn < 0 && refreshIn > -REFRESH_THRESHOLD_SECONDS * 1000) {
      console.warn('Token is expiring imminently — refreshing in 1s');
      refreshIn = 1000;
    } else if (refreshIn <= 0) {
      console.warn(
        `Token expired ${Math.round(-refreshIn / 1000)}s ago — retrying in 60s`,
      );
      refreshIn = 60_000;
    } else {
      console.debug(
        `Next token refresh in ${Math.round(refreshIn / 1000)}s (token expires at ${new Date(expiresAt).toISOString()})`,
      );
    }

    setTimeout(() => {
      refresh().catch((err) => {
        console.error('Unhandled error during token refresh:', err);
      });
    }, refreshIn);
  }

  scheduleRefresh(true);
})();
