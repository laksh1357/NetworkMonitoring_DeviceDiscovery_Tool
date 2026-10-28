(() => {
  const refreshIntervalMs = 5000;
  const TOKEN_KEY = 'lan_watchtower_token';
  const state = {
    devices: [],
    topologyNodes: [],
    scanRunning: false,
    user: null,
    topologyPositions: new Map(),
    topologyTransform: { zoom: 1, panX: 0, panY: 0 },
    topologyDrag: null,
  };
  const elements = {
    connection: document.getElementById('connection-status'),
    connectionLabel: document.getElementById('connection-label'),
    userPill: document.getElementById('user-pill'),
    userAvatar: document.getElementById('user-avatar-initials'),
    userName: document.getElementById('user-name-label'),
    userRole: document.getElementById('user-role-badge'),
    signoutBtn: document.getElementById('signout-button'),
    authModal: document.getElementById('auth-modal'),
    authForm: document.getElementById('auth-form'),
    authUsername: document.getElementById('auth-username'),
    authPassword: document.getElementById('auth-password'),
    authError: document.getElementById('auth-error-banner'),
    authSubmit: document.getElementById('auth-submit-btn'),
    error: document.getElementById('error-banner'),
    online: document.getElementById('metric-online'),
    total: document.getElementById('metric-total'),
    offline: document.getElementById('metric-offline'),
    alerts: document.getElementById('metric-alerts'),
    critical: document.getElementById('metric-critical'),
    health: document.getElementById('metric-health'),
    scans: document.getElementById('metric-scans'),
    subnet: document.getElementById('subnet-input'),
    scanForm: document.getElementById('scan-form'),
    scanState: document.getElementById('scan-state'),
    scanStart: document.getElementById('scan-start'),
    scanStop: document.getElementById('scan-stop'),
    scanSummary: document.getElementById('scan-summary'),
    scanPercent: document.getElementById('scan-percent'),
    scanProgress: document.getElementById('scan-progress'),
    progressTrack: document.querySelector('.progress-track'),
    scanDetail: document.getElementById('scan-detail'),
    search: document.getElementById('device-search'),
    deviceRows: document.getElementById('device-rows'),
    deviceCount: document.getElementById('inventory-count'),
    alertList: document.getElementById('alert-list'),
    canvas: document.getElementById('topology-canvas'),
    topologyEmpty: document.getElementById('topology-empty'),
    lastUpdated: document.getElementById('last-updated'),
  };

  function getToken() {
    return localStorage.getItem(TOKEN_KEY) || sessionStorage.getItem(TOKEN_KEY);
  }

  function setToken(token) {
    if (token) {
      localStorage.setItem(TOKEN_KEY, token);
    } else {
      localStorage.removeItem(TOKEN_KEY);
      sessionStorage.removeItem(TOKEN_KEY);
    }
  }

  function showAuthModal() {
    elements.authModal.hidden = false;
    elements.authError.hidden = true;
    elements.authPassword.value = '';
    elements.authUsername.focus();
  }

  function hideAuthModal() {
    elements.authModal.hidden = true;
    elements.authError.hidden = true;
    elements.authError.textContent = '';
  }

  function renderUserBadge(user) {
    if (!user) {
      elements.userPill.hidden = true;
      return;
    }
    const name = user.display_name || user.username || 'Operator';
    const initials = name.split(' ').map(s => s[0]).join('').slice(0, 2).toUpperCase() || 'OP';
    elements.userAvatar.textContent = initials;
    elements.userName.textContent = name;
    elements.userRole.textContent = user.role || 'operator';
    elements.userPill.hidden = false;
  }

  async function requestJSON(path, options = {}) {
    const headers = {
      Accept: 'application/json',
      ...window.watchtowerAuth?.headers(),
      ...options.headers,
    };
    const token = getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    const response = await fetch(path, {
      ...options,
      headers,
    });
    const contentType = response.headers.get('content-type') || '';
    const body = contentType.includes('application/json') ? await response.json() : null;
    if (response.status === 401 && path !== '/api/auth/login') {
      setToken(null);
      renderUserBadge(null);
      showAuthModal();
      throw new Error('Authentication required');
    }
    if (!response.ok) {
      if (response.status === 401) window.watchtowerAuth?.refresh();
      throw new Error(body?.error || `Request failed (${response.status})`);
    }
    if (!body) throw new Error(`Expected JSON from ${path}`);
    return body;
  }

  function reportError(error) {
    elements.error.textContent = `${error.message}. Start the LAN Watchtower backend and open this dashboard through it (or use Docker Compose).`;
    elements.error.hidden = false;
  }

  function clearError() {
    elements.error.hidden = true;
    elements.error.textContent = '';
  }

  function setConnection(online) {
    elements.connection.dataset.state = online ? 'online' : 'offline';
    elements.connectionLabel.textContent = online ? 'Backend connected' : 'Backend unavailable';
  }

  function setText(element, value) {
    element.textContent = value;
  }

  async function refreshSubnet() {
    const data = await requestJSON('/api/subnet');
    if (!elements.subnet.value) elements.subnet.value = data.subnet;
    elements.scanDetail.textContent = `Detected subnet: ${data.subnet} · ${data.num_hosts} host addresses · ${data.privileged ? 'ARP scan available' : 'limited discovery mode'}.`;
  }

  function renderMetrics(metrics) {
    setText(elements.online, metrics.online_devices ?? 0);
    setText(elements.total, metrics.total_devices ?? 0);
    setText(elements.offline, `Offline: ${metrics.offline_devices ?? 0} · Degraded: ${metrics.degraded_devices ?? 0}`);
    setText(elements.alerts, metrics.active_alerts ?? 0);
    setText(elements.critical, `Critical: ${metrics.critical_alerts ?? 0}`);
    setText(elements.health, `${metrics.network_health ?? 0}%`);
    setText(elements.scans, `Completed scans: ${metrics.scans_run ?? 0}`);
  }

  function renderDevices() {
    const query = elements.search.value.trim().toLowerCase();
    const matches = state.devices.filter(device =>
      [device.ip, device.hostname, device.vendor, device.device_type, device.custom_name]
        .some(value => String(value || '').toLowerCase().includes(query))
    );
    const fragment = document.createDocumentFragment();
    if (matches.length === 0) {
      const row = document.createElement('tr');
      const cell = document.createElement('td');
      cell.colSpan = 6;
      cell.className = 'empty-cell';
      cell.textContent = state.devices.length ? 'No devices match this filter.' : 'No devices have been discovered yet.';
      row.appendChild(cell);
      fragment.appendChild(row);
    } else {
      for (const device of matches) {
        const row = document.createElement('tr');
        const status = document.createElement('td');
        const statusTag = document.createElement('span');
        const normalizedStatus = String(device.status || 'Unknown').toLowerCase();
        statusTag.className = `status-tag status-${['online', 'offline'].includes(normalizedStatus) ? normalizedStatus : 'unknown'}`;
        statusTag.textContent = device.status || 'Unknown';
        status.appendChild(statusTag);
        row.append(status);
        appendCell(row, device.ip, 'mono');
        appendCell(row, device.custom_name || device.hostname || 'Unknown');
        appendCell(row, device.vendor || 'Unknown');
        appendCell(row, device.device_type || 'Unknown');
        appendCell(row, device.last_seen || '—', 'mono');
        fragment.appendChild(row);
      }
    }
    elements.deviceRows.replaceChildren(fragment);
    setText(elements.deviceCount, `${matches.length} of ${state.devices.length} devices`);
  }

  function appendCell(row, value, className = '') {
    const cell = document.createElement('td');
    cell.textContent = value == null || value === '' ? '—' : String(value);
    if (className) cell.className = className;
    row.appendChild(cell);
  }

  function renderAlerts(alerts) {
    const fragment = document.createDocumentFragment();
    if (alerts.length === 0) {
      const item = document.createElement('li');
      item.className = 'empty-state';
      item.textContent = 'No recent alerts.';
      fragment.appendChild(item);
    } else {
      for (const alert of alerts.slice(0, 12)) {
        const item = document.createElement('li');
        const severity = String(alert.severity || alert.type || 'warning').toLowerCase();
        item.className = 'alert-item';
        item.dataset.severity = severity;
        const heading = document.createElement('div');
        heading.className = 'alert-title';
        const title = document.createElement('span');
        title.textContent = alert.title || 'Alert';
        const timestamp = document.createElement('time');
        timestamp.className = 'alert-time';
        timestamp.textContent = alert.created_at || '';
        heading.append(title, timestamp);
        const message = document.createElement('p');
        message.className = 'alert-message';
        message.textContent = alert.message || '';
        item.append(heading, message);
        fragment.appendChild(item);
      }
    }
    elements.alertList.replaceChildren(fragment);
  }

  function renderScanStatus(status) {
    state.scanRunning = Boolean(status.running);
    const percent = Math.max(0, Math.min(100, Number(status.percent) || 0));
    elements.scanState.dataset.state = status.last_error ? 'error' : state.scanRunning ? 'running' : 'idle';
    setText(elements.scanState, status.last_error ? 'Error' : state.scanRunning ? 'Scanning' : 'Idle');
    setText(elements.scanSummary, state.scanRunning
      ? `${status.done || 0} / ${status.total || 0} hosts checked · ${status.discovered || 0} discovered`
      : status.last_completed ? `Last completed: ${status.last_completed} · ${status.discovered || 0} discovered` : 'No scan in progress');
    setText(elements.scanPercent, `${percent}%`);
    elements.scanProgress.style.width = `${percent}%`;
    elements.progressTrack.setAttribute('aria-valuenow', String(percent));
    elements.scanStart.disabled = state.scanRunning;
    elements.scanStop.disabled = !state.scanRunning;
    if (status.last_error) elements.scanDetail.textContent = status.last_error;
  }

  function drawTopology() {
    const canvas = elements.canvas;
    const rect = canvas.getBoundingClientRect();
    const ratio = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, Math.floor(rect.width * ratio));
    canvas.height = Math.max(1, Math.floor(rect.height * ratio));
    const context = canvas.getContext('2d');
    context.scale(ratio, ratio);
    const width = rect.width;
    const height = rect.height;
    context.clearRect(0, 0, width, height);
    elements.topologyEmpty.hidden = state.topologyNodes.length > 0;
    if (!state.topologyNodes.length) return;

    const columns = Math.max(1, Math.floor(width / 150));
    const rowCount = Math.ceil(state.topologyNodes.length / columns);
    context.save();
    context.translate(state.topologyTransform.panX, state.topologyTransform.panY);
    context.scale(state.topologyTransform.zoom, state.topologyTransform.zoom);
    state.topologyNodes.forEach((node, index) => {
      const col = index % columns;
      const row = Math.floor(index / columns);
      const position = state.topologyPositions.get(node.id);
      const x = position
        ? position.x * width
        : columns === 1 ? width / 2 : 60 + col * ((width - 120) / (columns - 1));
      const y = position
        ? position.y * height
        : rowCount === 1 ? height / 2 : 40 + row * ((height - 80) / (rowCount - 1));
      const online = String(node.status || '').toLowerCase() === 'online';
      const color = online ? '#10b981' : '#f59e0b';
      context.beginPath();
      context.arc(x, y, 12, 0, Math.PI * 2);
      context.fillStyle = online ? 'rgba(16,185,129,.18)' : 'rgba(245,158,11,.18)';
      context.fill();
      context.strokeStyle = color;
      context.lineWidth = 2;
      context.stroke();
      context.fillStyle = '#e2e8f0';
      context.font = '11px Inter, sans-serif';
      context.textAlign = 'center';
      context.fillText(node.hostname || node.ip || 'Device', x, y + 30, Math.min(130, width / columns));
      context.fillStyle = '#94a3b8';
      context.font = '10px "DM Mono", monospace';
      context.fillText(node.ip || '', x, y + 45, Math.min(130, width / columns));
    });
    context.restore();
  }

  function topologyWorldPoint(event) {
    const rect = elements.canvas.getBoundingClientRect();
    return {
      x: (event.clientX - rect.left - state.topologyTransform.panX) / state.topologyTransform.zoom,
      y: (event.clientY - rect.top - state.topologyTransform.panY) / state.topologyTransform.zoom,
    };
  }

  elements.canvas.addEventListener('pointerdown', event => {
    const point = topologyWorldPoint(event);
    const rect = elements.canvas.getBoundingClientRect();
    const columns = Math.max(1, Math.floor(rect.width / 150));
    const rowCount = Math.ceil(state.topologyNodes.length / columns);
    let selected = null;
    for (let index = state.topologyNodes.length - 1; index >= 0; index -= 1) {
      const node = state.topologyNodes[index];
      const col = index % columns;
      const row = Math.floor(index / columns);
      const position = state.topologyPositions.get(node.id);
      const x = position
        ? position.x * rect.width
        : columns === 1 ? rect.width / 2 : 60 + col * ((rect.width - 120) / (columns - 1));
      const y = position
        ? position.y * rect.height
        : rowCount === 1 ? rect.height / 2 : 40 + row * ((rect.height - 80) / (rowCount - 1));
      if (Math.hypot(point.x - x, point.y - y) <= 18) {
        selected = node.id;
        break;
      }
    }
    state.topologyDrag = {
      mode: selected ? 'node' : 'pan',
      nodeId: selected,
      pointerX: event.clientX,
      pointerY: event.clientY,
    };
    elements.canvas.setPointerCapture(event.pointerId);
    event.preventDefault();
  });

  elements.canvas.addEventListener('pointermove', event => {
    if (!state.topologyDrag) return;
    if (state.topologyDrag.mode === 'node') {
      const point = topologyWorldPoint(event);
      const rect = elements.canvas.getBoundingClientRect();
      state.topologyPositions.set(state.topologyDrag.nodeId, {
        x: Math.max(0, Math.min(1, point.x / rect.width)),
        y: Math.max(0, Math.min(1, point.y / rect.height)),
      });
    } else {
      state.topologyTransform.panX += event.clientX - state.topologyDrag.pointerX;
      state.topologyTransform.panY += event.clientY - state.topologyDrag.pointerY;
      state.topologyDrag.pointerX = event.clientX;
      state.topologyDrag.pointerY = event.clientY;
    }
    drawTopology();
  });

  function endTopologyDrag() {
    state.topologyDrag = null;
  }

  elements.canvas.addEventListener('pointerup', endTopologyDrag);
  elements.canvas.addEventListener('pointercancel', endTopologyDrag);
  elements.canvas.addEventListener('wheel', event => {
    event.preventDefault();
    const rect = elements.canvas.getBoundingClientRect();
    const pointerX = event.clientX - rect.left;
    const pointerY = event.clientY - rect.top;
    const oldZoom = state.topologyTransform.zoom;
    const newZoom = Math.max(0.5, Math.min(3, oldZoom * (event.deltaY < 0 ? 1.1 : 0.9)));
    const worldX = (pointerX - state.topologyTransform.panX) / oldZoom;
    const worldY = (pointerY - state.topologyTransform.panY) / oldZoom;
    state.topologyTransform.zoom = newZoom;
    state.topologyTransform.panX = pointerX - worldX * newZoom;
    state.topologyTransform.panY = pointerY - worldY * newZoom;
    drawTopology();
  }, { passive: false });

  async function refreshDashboard() {
    clearError();
    try {
      const [health, metrics, devices, alerts, scan, topology] = await Promise.all([
        requestJSON('/health'),
        requestJSON('/api/metrics'),
        requestJSON('/api/devices'),
        requestJSON('/api/alerts'),
        requestJSON('/api/scan/status'),
        requestJSON('/api/topology'),
      ]);
      setConnection(health.status === 'ok');
      state.devices = Array.isArray(devices) ? devices : [];
      state.topologyNodes = Array.isArray(topology.nodes) ? topology.nodes : [];
      renderMetrics(metrics);
      renderDevices();
      renderAlerts(Array.isArray(alerts) ? alerts : []);
      renderScanStatus(scan);
      drawTopology();
      setText(elements.lastUpdated, `Updated ${new Date().toLocaleTimeString()}`);
    } catch (error) {
      setConnection(false);
      reportError(error);
    }
  }

  elements.scanForm.addEventListener('submit', async event => {
    event.preventDefault();
    clearError();
    try {
      const result = await requestJSON('/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subnet: elements.subnet.value.trim() }),
      });
      elements.scanDetail.textContent = `Scan started for ${result.subnet}.`;
      await refreshDashboard();
    } catch (error) {
      reportError(error);
    }
  });

  elements.scanStop.addEventListener('click', async () => {
    clearError();
    try {
      await requestJSON('/api/scan/stop', { method: 'POST' });
      await refreshDashboard();
    } catch (error) {
      reportError(error);
    }
  });

  elements.authForm.addEventListener('submit', async event => {
    event.preventDefault();
    elements.authError.hidden = true;
    elements.authSubmit.disabled = true;
    elements.authSubmit.textContent = 'Verifying…';
    try {
      const result = await requestJSON('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: elements.authUsername.value.trim(),
          password: elements.authPassword.value,
        }),
      });
      setToken(result.token);
      state.user = result.user;
      renderUserBadge(result.user);
      hideAuthModal();
      await refreshSubnet().catch(() => {});
      await refreshDashboard();
    } catch (error) {
      elements.authError.textContent = error.message || 'Login failed';
      elements.authError.hidden = false;
    } finally {
      elements.authSubmit.disabled = false;
      elements.authSubmit.textContent = 'Sign in';
    }
  });

  const fillCredsBtn = document.getElementById('fill-default-creds');
  if (fillCredsBtn) {
    fillCredsBtn.addEventListener('click', () => {
      elements.authUsername.value = 'admin';
      elements.authPassword.value = 'admin123';
      elements.authError.hidden = true;
    });
  }

  const togglePwdBtn = document.getElementById('toggle-password-btn');
  if (togglePwdBtn) {
    togglePwdBtn.addEventListener('click', () => {
      const isPassword = elements.authPassword.type === 'password';
      elements.authPassword.type = isPassword ? 'text' : 'password';
      togglePwdBtn.textContent = isPassword ? 'Hide' : 'Show';
    });
  }

  if (elements.signoutBtn) {
    elements.signoutBtn.addEventListener('click', async () => {
      try {
        await requestJSON('/api/auth/logout', { method: 'POST' });
      } catch (_) {}
      setToken(null);
      state.user = null;
      renderUserBadge(null);
      showAuthModal();
    });
  }

  elements.search.addEventListener('input', renderDevices);
  document.getElementById('refresh-button').addEventListener('click', refreshDashboard);
  window.addEventListener('resize', drawTopology);

  window.addEventListener('watchtower-auth-state', event => {
    if (event.detail.authenticated) {
      refreshSubnet().catch(reportError);
      refreshDashboard();
    } else if (event.detail.serviceAvailable) {
      elements.connection.dataset.state = 'checking';
      elements.connectionLabel.textContent = event.detail.configured
        ? 'Admin login required'
        : 'Admin setup required';
    } else {
      setConnection(false);
    }
  });

  async function initAuth() {
    try {
      const res = await requestJSON('/api/auth/me');
      if (res.authenticated && res.user) {
        state.user = res.user;
        renderUserBadge(res.user);
        hideAuthModal();
        refreshSubnet().catch(reportError);
        refreshDashboard();
      } else {
        showAuthModal();
      }
    } catch (e) {
      showAuthModal();
    }
  }

  initAuth();
  window.setInterval(() => {
    if (getToken() || window.watchtowerAuth?.authenticated) {
      refreshDashboard();
    }
  }, refreshIntervalMs);
})();
