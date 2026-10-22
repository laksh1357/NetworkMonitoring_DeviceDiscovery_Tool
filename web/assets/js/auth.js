(() => {
  const form = document.getElementById('admin-login-form');
  const passwordInput = document.getElementById('admin-password');
  const message = document.getElementById('auth-message');
  const logoutButton = document.getElementById('admin-logout');
  let csrfToken = null;
  let authenticated = false;

  function updateUI(status) {
    authenticated = Boolean(status.authenticated);
    csrfToken = status.csrf_token || null;
    form.hidden = authenticated || !status.configured;
    logoutButton.hidden = !authenticated;
    message.dataset.state = status.configured ? (authenticated ? 'success' : '') : 'error';
    message.textContent = !status.configured
      ? 'Live administration is locked. Configure LAN_WATCHTOWER_ADMIN_PASSWORD (16+ characters) and restart the backend.'
      : authenticated
        ? 'Authenticated administrator session · expires after 30 minutes or a server restart.'
        : 'Authenticate to access live inventory, telemetry, audit records, and controls.';
    document.querySelectorAll('[data-admin-content]').forEach(element => {
      element.hidden = !authenticated;
    });
    window.dispatchEvent(new CustomEvent('watchtower-auth-state', {
      detail: { authenticated, configured: status.configured, serviceAvailable: true },
    }));
  }

  async function requestJSON(path, options = {}) {
    const response = await fetch(path, {
      credentials: 'same-origin',
      ...options,
      headers: { Accept: 'application/json', ...options.headers },
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) {
      throw new Error(body?.error || `Request failed (${response.status})`);
    }
    if (!body) throw new Error(`Expected JSON from ${path}`);
    return { body, response };
  }

  async function refresh() {
    try {
      const { body } = await requestJSON('/api/auth/status');
      updateUI(body);
      return body;
    } catch (error) {
      authenticated = false;
      csrfToken = null;
      document.querySelectorAll('[data-admin-content]').forEach(element => {
        element.hidden = true;
      });
      message.dataset.state = 'error';
      message.textContent = `Cannot reach the local backend: ${error.message}`;
      form.hidden = true;
      logoutButton.hidden = true;
      window.dispatchEvent(new CustomEvent('watchtower-auth-state', {
        detail: { authenticated: false, serviceAvailable: false },
      }));
      return null;
    }
  }

  async function challengeResponse(password, challenge) {
    const encoder = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveKey'],
    );
    const hmacKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode('lan-watchtower-admin-v1'),
        iterations: challenge.iterations,
        hash: 'SHA-256',
      },
      baseKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      false,
      ['sign'],
    );
    const signature = await crypto.subtle.sign(
      'HMAC',
      hmacKey,
      encoder.encode(`${challenge.challenge_id}:${challenge.nonce}`),
    );
    return [...new Uint8Array(signature)]
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    message.dataset.state = '';
    message.textContent = 'Verifying 15-second cryptographic challenge…';
    const submitButton = form.querySelector('button[type="submit"]');
    submitButton.disabled = true;
    try {
      const password = passwordInput.value;
      const { body: challenge } = await requestJSON('/api/auth/challenge', { method: 'POST' });
      const response = await challengeResponse(password, challenge);
      const { body } = await requestJSON('/api/auth/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challenge_id: challenge.challenge_id,
          response,
        }),
      });
      csrfToken = body.csrf_token;
      passwordInput.value = '';
      await refresh();
    } catch (error) {
      message.dataset.state = 'error';
      message.textContent = error.message;
    } finally {
      submitButton.disabled = false;
    }
  });

  logoutButton.addEventListener('click', async () => {
    try {
      await requestJSON('/api/auth/logout', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrfToken || '' },
      });
      csrfToken = null;
      await refresh();
    } catch (error) {
      message.dataset.state = 'error';
      message.textContent = `Sign out failed: ${error.message}`;
    }
  });

  window.watchtowerAuth = {
    headers() {
      return csrfToken ? { 'X-CSRF-Token': csrfToken } : {};
    },
    refresh,
    get authenticated() {
      return authenticated;
    },
  };

  refresh();
})();
