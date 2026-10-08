/**
 * NETMONITOR - NOC Operational Intelligence Engine Frontend Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  // Navigation View Switching
  const navItems = document.querySelectorAll('.nav-item');
  const viewPanels = document.querySelectorAll('.view-panel');

  navItems.forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      const targetViewId = item.getAttribute('data-view');
      navItems.forEach(nav => nav.classList.remove('active'));
      viewPanels.forEach(panel => panel.classList.remove('active'));

      item.classList.add('active');
      const targetPanel = document.getElementById(targetViewId);
      if (targetPanel) {
        targetPanel.classList.add('active');
      }
      if (targetViewId === 'view-topology') {
        renderFullTopologyMap();
      }
    });
  });

  // Tab switching in Inspector
  const tabBtns = document.querySelectorAll('.tabs-header .tab-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const parent = btn.closest('.card');
      parent.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      parent.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.classList.add('active');
      }
    });
  });

  // Live Telemetry Clock
  function updateTelemetryClock() {
    const el = document.getElementById('telemetry-time');
    if (el) {
      const now = new Date();
      el.textContent = `LIVE TELEMETRY ${now.toLocaleTimeString()}`;
    }
  }
  setInterval(updateTelemetryClock, 1000);
  updateTelemetryClock();

  // App State Data
  let devicesData = [];
  let alertsData = [];
  let metricsData = {};
  let selectedDeviceIp = '192.168.1.10';

  // Fetch API Helpers
  async function fetchJSON(url, options = {}) {
    try {
      const res = await fetch(url, options);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn(`Fetch error for ${url}:`, err);
      return null;
    }
  }

  // Load User Profile Data
  async function refreshUserProfile() {
    const profile = await fetchJSON('/api/profile');
    if (profile) {
      document.querySelector('.user-name').textContent = profile.display_name || 'Admin User';
      document.querySelector('.user-role').textContent = profile.role_title || 'Administrator';
      document.querySelector('.avatar').textContent = profile.avatar_initials || 'AU';
    }
  }

  // Load Activity Audit Logs
  async function refreshActivityLogs() {
    const logs = await fetchJSON('/api/activity');
    const tbody = document.getElementById('tbody-activity-logs');
    if (!tbody || !logs) return;
    tbody.innerHTML = '';

    logs.forEach(l => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="text-muted font-mono">${l.timestamp}</td>
        <td><strong>${l.user_name}</strong></td>
        <td><span class="badge warning">${l.action_type}</span></td>
        <td>${l.description}</td>
        <td class="font-mono">${l.ip || '-'}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  // Profile Editor Modal Logic
  const profileModal = document.getElementById('modal-profile-editor');

  document.querySelector('.user-profile')?.addEventListener('click', async () => {
    const profile = await fetchJSON('/api/profile') || {};
    document.getElementById('prof-input-name').value = profile.display_name || 'Admin User';
    document.getElementById('prof-input-role').value = profile.role_title || 'Administrator';
    document.getElementById('prof-input-email').value = profile.email || 'admin@network.local';
    document.getElementById('prof-input-initials').value = profile.avatar_initials || 'AU';
    if (profileModal) profileModal.classList.add('active');
  });

  function closeProfileModal() {
    if (profileModal) profileModal.classList.remove('active');
  }

  document.getElementById('profile-modal-close-btn')?.addEventListener('click', closeProfileModal);
  document.getElementById('profile-modal-cancel-btn')?.addEventListener('click', closeProfileModal);

  document.getElementById('profile-modal-save-btn')?.addEventListener('click', async () => {
    const payload = {
      display_name: document.getElementById('prof-input-name').value || 'Admin User',
      role_title: document.getElementById('prof-input-role').value || 'Administrator',
      email: document.getElementById('prof-input-email').value || 'admin@network.local',
      avatar_initials: document.getElementById('prof-input-initials').value || 'AU',
    };
    await fetchJSON('/api/profile/update', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    closeProfileModal();
    refreshUserProfile();
    refreshActivityLogs();
  });

  document.getElementById('btn-refresh-activity')?.addEventListener('click', refreshActivityLogs);

  // Load Dashboard Data
  async function refreshDashboardData() {
    const [metrics, devices, alerts, scanStatus] = await Promise.all([
      fetchJSON('/api/metrics'),
      fetchJSON('/api/devices'),
      fetchJSON('/api/alerts'),
      fetchJSON('/api/scan/status')
    ]);

    if (metrics) {
      metricsData = metrics;
      updateMetricCards(metrics);
      renderDonutChart(metrics.devices_by_type || {});
    }

    if (devices) {
      devicesData = devices;
      renderRecentDevicesTable(devices);
      renderFleetTable(devices);
      if (!selectedDeviceIp && devices.length > 0) {
        selectedDeviceIp = devices[0].ip;
      }
      updateDeviceInspector(selectedDeviceIp);
      renderMiniTopologyMap(devices);
    }

    if (alerts) {
      alertsData = alerts;
      renderAlertsStream(alerts);
    }

    if (scanStatus) {
      updateScanProgressUI(scanStatus);
    }
  }

  // Update Top Metric Cards
  function updateMetricCards(m) {
    document.getElementById('card-total-devices').textContent = m.total_devices || 0;
    document.getElementById('card-online-devices').textContent = m.online_devices || 0;
    document.getElementById('card-offline-devices').textContent = m.offline_devices || 0;
    document.getElementById('card-degraded-devices').textContent = m.degraded_devices || 0;

    const onlinePct = m.total_devices > 0 ? ((m.online_devices / m.total_devices) * 100).toFixed(1) : 100;
    const offlinePct = m.total_devices > 0 ? ((m.offline_devices / m.total_devices) * 100).toFixed(1) : 0;
    
    document.getElementById('card-online-pct').textContent = `${onlinePct}% of total`;
    document.getElementById('card-offline-pct').textContent = `${offlinePct}% of total`;
  }

  // Render Recently Discovered Devices Table
  function renderRecentDevicesTable(devs) {
    const tbody = document.getElementById('tbody-recent-devices');
    if (!tbody) return;
    tbody.innerHTML = '';

    const recent = devs.slice(0, 6);
    recent.forEach(d => {
      const tr = document.createElement('tr');
      tr.style.cursor = 'pointer';
      tr.addEventListener('click', () => {
        selectedDeviceIp = d.ip;
        updateDeviceInspector(d.ip);
      });

      const stClass = d.status.toLowerCase();
      const devName = d.custom_name || (d.hostname !== 'Unknown' ? d.hostname : d.ip);

      tr.innerHTML = `
        <td class="font-mono">${d.ip}</td>
        <td><strong>${devName}</strong></td>
        <td>${d.device_type || 'PC'}</td>
        <td>${d.vendor || 'Unknown'}</td>
        <td><span class="status-pill ${stClass}">● ${d.status}</span></td>
        <td class="text-muted">${d.last_seen || 'Just now'}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  // Update Live Device Inspector
  function updateDeviceInspector(ip) {
    const d = devicesData.find(dev => dev.ip === ip) || devicesData[0];
    if (!d) return;

    selectedDeviceIp = d.ip;

    const icons = {
      'Router': '🌐',
      'Switch': '🖧',
      'Server': '🖥️',
      'Access Point': '📶',
      'Printer': '🖨️',
      'Firewall': '🛡️',
      'PC/Workstation': '💻'
    };

    document.getElementById('insp-icon').textContent = icons[d.device_type] || '💻';
    document.getElementById('insp-name').textContent = d.custom_name || (d.hostname !== 'Unknown' ? d.hostname : d.ip);
    
    const stPill = document.getElementById('insp-status-pill');
    stPill.className = `status-pill ${d.status.toLowerCase()}`;
    stPill.textContent = `● ${d.status}`;

    document.getElementById('insp-ip-vendor').textContent = `${d.ip} | ${d.vendor || 'Unknown'}`;
    document.getElementById('insp-ip').textContent = d.ip;
    document.getElementById('insp-mac').textContent = d.mac || 'Unknown';
    document.getElementById('insp-vendor').textContent = d.vendor || 'Unknown';
    document.getElementById('insp-type').textContent = d.device_type || 'PC/Workstation';

    document.getElementById('edit-custom-name').value = d.custom_name || '';
    document.getElementById('edit-notes').value = d.notes || '';
  }

  // Device Editor & Add Device Modal Logic
  const modalOverlay = document.getElementById('modal-device-editor');
  let currentEditingIp = null;

  window.openDeviceModal = function(ip = null) {
    currentEditingIp = ip;
    if (!modalOverlay) return;

    const isNew = !ip;
    const d = isNew ? {} : (devicesData.find(dev => dev.ip === ip) || {});

    document.getElementById('modal-dev-title').textContent = isNew ? 'Add Custom Device' : `Manage Device (${ip})`;
    document.getElementById('modal-dev-status').className = `status-pill ${d.status ? d.status.toLowerCase() : 'online'}`;
    document.getElementById('modal-dev-status').textContent = `● ${d.status || 'Online'}`;

    document.getElementById('modal-input-ip').value = d.ip || '';
    document.getElementById('modal-input-ip').readOnly = !isNew;
    document.getElementById('modal-input-mac').value = d.mac || '';
    document.getElementById('modal-input-hostname').value = d.hostname || '';
    document.getElementById('modal-input-vendor').value = d.vendor || '';
    document.getElementById('modal-select-type').value = d.device_type || 'PC/Workstation';
    document.getElementById('modal-input-name').value = d.custom_name || '';
    document.getElementById('modal-input-location').value = d.location || 'Main Network';
    document.getElementById('modal-input-notes').value = d.notes || '';

    // HTTP / HTTPS Quick Connect Links
    const targetIp = d.ip || '127.0.0.1';
    document.getElementById('btn-conn-http').href = `http://${targetIp}`;
    document.getElementById('btn-conn-https').href = `https://${targetIp}`;

    modalOverlay.classList.add('active');
  };

  function closeDeviceModal() {
    if (modalOverlay) modalOverlay.classList.remove('active');
  }

  document.getElementById('modal-close-btn')?.addEventListener('click', closeDeviceModal);
  document.getElementById('modal-cancel-btn')?.addEventListener('click', closeDeviceModal);

  // Header "+ Add Device" Button
  document.getElementById('btn-header-add-device')?.addEventListener('click', () => {
    window.openDeviceModal(null);
  });

  // Modal Action: Live Ping Test
  document.getElementById('btn-action-ping')?.addEventListener('click', async () => {
    const ip = document.getElementById('modal-input-ip').value;
    if (!ip) return alert('Enter an IP address first');
    const res = await fetchJSON('/api/device/ping', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ip })
    });
    if (res && res.online) {
      alert(`Ping response from ${ip}: ${res.latency_ms ? res.latency_ms.toFixed(1) + ' ms' : 'Online'}`);
    } else {
      alert(`Ping failed for ${ip}. Device may be offline or blocking ICMP.`);
    }
  });

  // Modal Action: Delete Device
  document.getElementById('btn-action-delete')?.addEventListener('click', async () => {
    const ip = document.getElementById('modal-input-ip').value;
    if (!ip) return;
    if (confirm(`Delete device ${ip} from registry?`)) {
      await fetchJSON('/api/device/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
      });
      closeDeviceModal();
      refreshDashboardData();
    }
  });

  // Modal Action: Save Device Specs
  document.getElementById('modal-save-btn')?.addEventListener('click', async () => {
    const ip = document.getElementById('modal-input-ip').value;
    if (!ip) return alert('IP address is required');

    const payload = {
      ip: ip,
      mac: document.getElementById('modal-input-mac').value,
      hostname: document.getElementById('modal-input-hostname').value,
      vendor: document.getElementById('modal-input-vendor').value,
      device_type: document.getElementById('modal-select-type').value,
      custom_name: document.getElementById('modal-input-name').value,
      location: document.getElementById('modal-input-location').value,
      notes: document.getElementById('modal-input-notes').value,
    };

    const endpoint = currentEditingIp ? '/api/device/update' : '/api/device/create';
    await fetchJSON(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    closeDeviceModal();
    refreshDashboardData();
  });

  // Run Port Scanner Button
  document.getElementById('btn-run-port-scan')?.addEventListener('click', async () => {
    if (!selectedDeviceIp) return;
    const container = document.getElementById('port-results-container');
    container.innerHTML = '<span class="text-muted">Scanning common TCP ports...</span>';

    const res = await fetchJSON('/api/ports/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: selectedDeviceIp })
    });

    if (res && res.open_ports) {
      if (res.open_ports.length === 0) {
        container.innerHTML = `<span class="text-muted">${res.ip}: No open common TCP ports found.</span>`;
      } else {
        container.innerHTML = res.open_ports.map(p => `
          <div style="display:flex; justify-content:space-between; padding:4px 0; border-bottom:1px solid rgba(0,240,255,0.1);">
            <span class="font-mono" style="color:var(--cyan); font-weight:600;">Port ${p.port}</span>
            <span>${p.service}</span>
          </div>
        `).join('');
      }
    } else {
      container.innerHTML = '<span style="color:var(--red);">Port scan failed. Host may be offline.</span>';
    }
  });

  // Clear Database Button
  document.getElementById('btn-clear-db')?.addEventListener('click', async () => {
    if (confirm('Clear all stored device inventory, alerts, and scan history?')) {
      await fetchJSON('/api/database/clear', { method: 'POST' });
      selectedDeviceIp = null;
      devicesData = [];
      refreshDashboardData();
    }
  });

  // Detect Subnet Button
  document.getElementById('btn-detect-subnet')?.addEventListener('click', async () => {
    const data = await fetchJSON('/api/subnet');
    if (data && data.subnet) {
      document.getElementById('scan-subnet-input').value = data.subnet;
      const fullInput = document.getElementById('disc-full-subnet');
      if (fullInput) fullInput.value = data.subnet;
    }
  });

  // Quick Scan Button in Header
  document.getElementById('btn-quick-scan')?.addEventListener('click', async () => {
    const data = await fetchJSON('/api/subnet');
    const subnet = (data && data.subnet) ? data.subnet : '192.168.1.0/24';
    await fetchJSON('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subnet: subnet })
    });
    refreshDashboardData();
  });

  // Notifications Bell Header Button
  document.getElementById('btn-notifications')?.addEventListener('click', () => {
    document.querySelector('.nav-item[data-view="view-alerts"]')?.click();
  });

  // Navigation Shortcut Buttons
  document.getElementById('btn-open-full-topo')?.addEventListener('click', () => {
    document.querySelector('.nav-item[data-view="view-topology"]')?.click();
  });
  document.getElementById('btn-view-all-devices')?.addEventListener('click', () => {
    document.querySelector('.nav-item[data-view="view-devices"]')?.click();
  });

  // Launch Full Subnet Discovery Button
  document.getElementById('btn-launch-full-discovery')?.addEventListener('click', async () => {
    const subnet = document.getElementById('disc-full-subnet').value || '192.168.1.0/24';
    await fetchJSON('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subnet: subnet })
    });
    document.querySelector('.nav-item[data-view="view-dashboard"]')?.click();
    refreshDashboardData();
  });

  // Global & Fleet Search Filter Controls
  function applyDeviceSearch(query) {
    const q = (query || '').toLowerCase().trim();
    if (!q) {
      renderRecentDevicesTable(devicesData);
      renderFleetTable(devicesData);
      return;
    }
    const filtered = devicesData.filter(d => 
      (d.ip && d.ip.toLowerCase().includes(q)) ||
      (d.hostname && d.hostname.toLowerCase().includes(q)) ||
      (d.mac && d.mac.toLowerCase().includes(q)) ||
      (d.vendor && d.vendor.toLowerCase().includes(q)) ||
      (d.custom_name && d.custom_name.toLowerCase().includes(q)) ||
      (d.device_type && d.device_type.toLowerCase().includes(q))
    );
    renderRecentDevicesTable(filtered);
    renderFleetTable(filtered);
  }

  document.getElementById('global-search')?.addEventListener('keyup', (e) => {
    applyDeviceSearch(e.target.value);
  });
  document.getElementById('fleet-search-input')?.addEventListener('keyup', (e) => {
    applyDeviceSearch(e.target.value);
  });

  // Fleet Filter Tabs (All / Online / Offline)
  let activeFleetFilter = 'all';
  document.querySelectorAll('.fleet-filter-bar .filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.fleet-filter-bar .filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeFleetFilter = btn.getAttribute('data-filter');
      
      if (activeFleetFilter === 'all') {
        renderFleetTable(devicesData);
      } else {
        const filtered = devicesData.filter(d => d.status === activeFleetFilter);
        renderFleetTable(filtered);
      }
    });
  });

  // Topology Zoom Controls
  let topoZoomScale = 1.0;
  document.getElementById('topo-zoom-in')?.addEventListener('click', () => {
    topoZoomScale += 0.15;
    const svg = document.getElementById('full-topo-svg');
    if (svg) svg.style.transform = `scale(${topoZoomScale})`;
  });
  document.getElementById('topo-zoom-out')?.addEventListener('click', () => {
    topoZoomScale = Math.max(0.4, topoZoomScale - 0.15);
    const svg = document.getElementById('full-topo-svg');
    if (svg) svg.style.transform = `scale(${topoZoomScale})`;
  });
  document.getElementById('topo-reset')?.addEventListener('click', () => {
    topoZoomScale = 1.0;
    const svg = document.getElementById('full-topo-svg');
    if (svg) svg.style.transform = 'scale(1)';
  });
  document.getElementById('topo-add-node')?.addEventListener('click', () => {
    const ip = prompt('Enter custom node IP address (e.g. 192.168.1.99):', '192.168.1.99');
    if (ip) {
      const name = prompt('Enter node name:', 'Custom Switch');
      fetchJSON('/api/device/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip, custom_name: name || ip, device_type: 'Switch' })
      }).then(() => {
        refreshDashboardData();
        renderFullTopologyMap();
      });
    }
  });

  // Start Discovery Scan Button
  document.getElementById('btn-start-discovery')?.addEventListener('click', async () => {
    const subnet = document.getElementById('scan-subnet-input').value;
    await fetchJSON('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subnet: subnet })
    });
    refreshDashboardData();
  });

  // Update Scan Progress UI
  function updateScanProgressUI(st) {
    isScanningActive = !!st.running;
    const pBar = document.getElementById('scan-progress-bar');
    const pText = document.getElementById('scan-pct-text');
    const dot = document.getElementById('discovery-status-dot');

    if (st.running) {
      pBar.style.width = `${st.percent}%`;
      pText.textContent = `${st.percent}%`;
      dot.className = 'pulse-dot blue';
    } else {
      pBar.style.width = `${st.percent}%`;
      pText.textContent = st.percent === 100 ? 'Complete' : 'Idle';
      dot.className = 'pulse-dot green';
    }

    document.getElementById('cnt-scanned').textContent = st.done || 0;
    document.getElementById('cnt-discovered').textContent = st.discovered || 0;
    document.getElementById('cnt-online').textContent = st.online || 0;
    document.getElementById('cnt-offline').textContent = st.offline || 0;
  }

  // Render Alerts Stream
  function renderAlertsStream(alerts) {
    const container = document.getElementById('alerts-stream-container');
    const fullContainer = document.getElementById('full-alerts-container');

    const html = alerts.slice(0, 8).map(a => `
      <div class="alert-card-item ${a.severity}">
        <div class="alert-body">
          <span class="alert-title">${a.title}</span>
          <span class="alert-msg">${a.message}</span>
          <span class="alert-time">${a.timestamp}</span>
        </div>
      </div>
    `).join('');

    if (container) container.innerHTML = html;
    if (fullContainer) fullContainer.innerHTML = alerts.map(a => `
      <div class="alert-card-item ${a.severity}">
        <div class="alert-body">
          <span class="alert-title">${a.title} (${a.severity})</span>
          <span class="alert-msg">${a.message}</span>
          <span class="alert-time">${a.timestamp} | Target IP: ${a.ip || 'N/A'}</span>
        </div>
      </div>
    `).join('');
  }

  // Devices by Type Donut Chart Render
  function renderDonutChart(typesMap) {
    const svg = document.getElementById('donut-svg');
    const legend = document.getElementById('donut-legend-grid');
    const totalEl = document.getElementById('donut-total-count');
    if (!svg || !legend) return;

    const colors = {
      'Router': '#0077ff',
      'Switch': '#00f0ff',
      'Server': '#8a2be2',
      'PC/Workstation': '#00e676',
      'Access Point': '#ffb300',
      'Printer': '#ff3366',
      'Others': '#62778a'
    };

    let total = 0;
    Object.values(typesMap).forEach(v => total += v);
    if (totalEl) totalEl.textContent = total;

    svg.innerHTML = '';
    legend.innerHTML = '';

    let accumulatedAngle = 0;
    const radius = 55;
    const cx = 80, cy = 80;
    const circumference = 2 * Math.PI * radius;

    Object.entries(typesMap).forEach(([type, count]) => {
      const pct = total > 0 ? (count / total) : 0;
      const strokeDash = pct * circumference;
      const strokeGap = circumference - strokeDash;
      const color = colors[type] || colors['Others'];

      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', cx);
      circle.setAttribute('cy', cy);
      circle.setAttribute('r', radius);
      circle.setAttribute('fill', 'none');
      circle.setAttribute('stroke', color);
      circle.setAttribute('stroke-width', '18');
      circle.setAttribute('stroke-dasharray', `${strokeDash} ${strokeGap}`);
      circle.setAttribute('stroke-dashoffset', -accumulatedAngle);
      svg.appendChild(circle);

      accumulatedAngle += strokeDash;

      // Legend Item
      const legItem = document.createElement('div');
      legItem.className = 'd-leg-item';
      legItem.innerHTML = `
        <div class="d-leg-left">
          <span style="width:8px; height:8px; border-radius:50%; background:${color}; display:inline-block;"></span>
          <span>${type}</span>
        </div>
        <strong>${count}</strong>
      `;
      legend.appendChild(legItem);
    });
  }

  // Network Activity Line Chart Render
  function initActivityChart() {
    const canvas = document.getElementById('canvas-activity');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const times = ['12 AM', '04 AM', '08 AM', '12 PM', '04 PM', '08 PM'];
    const inbound = [25, 40, 32, 65, 80, 50];
    const outbound = [15, 22, 18, 45, 55, 38];

    function draw() {
      const w = canvas.width = canvas.parentElement.clientWidth;
      const h = canvas.height = canvas.parentElement.clientHeight || 180;

      ctx.clearRect(0, 0, w, h);

      // Grid lines
      ctx.strokeStyle = 'rgba(0, 240, 255, 0.08)';
      ctx.lineWidth = 1;
      for (let i = 0; i <= 4; i++) {
        const y = (h / 4) * i;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }

      // Draw Series
      function drawSeries(data, color, fillGradient) {
        ctx.beginPath();
        const step = w / (data.length - 1);
        data.forEach((val, i) => {
          const x = i * step;
          const y = h - (val / 100) * (h - 20) - 10;
          if (i === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        });

        ctx.strokeStyle = color;
        ctx.lineWidth = 2.5;
        ctx.stroke();

        ctx.lineTo(w, h);
        ctx.lineTo(0, h);
        ctx.closePath();
        ctx.fillStyle = fillGradient;
        ctx.fill();
      }

      const gradCyan = ctx.createLinearGradient(0, 0, 0, h);
      gradCyan.addColorStop(0, 'rgba(0, 240, 255, 0.25)');
      gradCyan.addColorStop(1, 'rgba(0, 240, 255, 0.0)');
      drawSeries(inbound, '#00f0ff', gradCyan);

      const gradGreen = ctx.createLinearGradient(0, 0, 0, h);
      gradGreen.addColorStop(0, 'rgba(0, 230, 118, 0.2)');
      gradGreen.addColorStop(1, 'rgba(0, 230, 118, 0.0)');
      drawSeries(outbound, '#00e676', gradGreen);
    }

    draw();
    window.addEventListener('resize', draw);
  }

  // Interactive Topology Maps (Mini & Full)
  function renderMiniTopologyMap(devs) {
    const svg = document.getElementById('mini-topo-svg');
    if (!svg) return;
    svg.innerHTML = '';

    const nodes = [
      { id: 'gw', name: 'Internet / Gateway', x: 200, y: 30, color: '#0077ff' },
      { id: 'fw', name: 'Firewall', x: 100, y: 90, color: '#ff3366' },
      { id: 'sw', name: 'Core Switch', x: 300, y: 90, color: '#00f0ff' },
      { id: 'srv', name: 'Servers', x: 400, y: 160, color: '#8a2be2' },
      { id: 'ap', name: 'Wi-Fi AP', x: 200, y: 160, color: '#ffb300' },
      { id: 'pc', name: 'Clients', x: 80, y: 160, color: '#00e676' }
    ];

    const links = [
      ['gw', 'fw'], ['gw', 'sw'], ['sw', 'srv'], ['sw', 'ap'], ['fw', 'pc']
    ];

    // Links
    links.forEach(([srcId, dstId]) => {
      const src = nodes.find(n => n.id === srcId);
      const dst = nodes.find(n => n.id === dstId);
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', src.x); line.setAttribute('y1', src.y);
      line.setAttribute('x2', dst.x); line.setAttribute('y2', dst.y);
      line.setAttribute('stroke', 'rgba(0, 240, 255, 0.3)');
      line.setAttribute('stroke-width', '1.8');
      svg.appendChild(line);
    });

    // Nodes
    nodes.forEach(n => {
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', n.x); circle.setAttribute('cy', n.y); circle.setAttribute('r', '14');
      circle.setAttribute('fill', 'rgba(14, 23, 38, 0.9)');
      circle.setAttribute('stroke', n.color);
      circle.setAttribute('stroke-width', '2');
      g.appendChild(circle);

      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      text.setAttribute('x', n.x); text.setAttribute('y', n.y + 26);
      text.setAttribute('text-anchor', 'middle');
      text.setAttribute('fill', '#8b9eb0');
      text.setAttribute('font-size', '10');
      text.textContent = n.name;
      g.appendChild(text);

      svg.appendChild(g);
    });
  }

  function renderFullTopologyMap() {
    const svg = document.getElementById('full-topo-svg');
    if (!svg) return;
    svg.innerHTML = '';

    const nodes = [
      { id: 'internet', label: 'Internet Gateway', ip: '192.168.1.1', x: 450, y: 50, color: '#0077ff' },
      { id: 'fw', label: 'Main Firewall', ip: '192.168.1.2', x: 250, y: 150, color: '#ff3366' },
      { id: 'c-sw', label: 'Core Switch 01', ip: '192.168.1.3', x: 650, y: 150, color: '#00f0ff' },
      { id: 'sw-1', label: 'Access SW-1', ip: '192.168.1.10', x: 150, y: 280, color: '#00f0ff' },
      { id: 'sw-2', label: 'Access SW-2', ip: '192.168.1.11', x: 350, y: 280, color: '#00f0ff' },
      { id: 'sw-3', label: 'Access SW-3', ip: '192.168.1.12', x: 550, y: 280, color: '#00f0ff' },
      { id: 'srv-1', label: 'App Server 01', ip: '192.168.1.20', x: 750, y: 280, color: '#8a2be2' },
      { id: 'srv-2', label: 'DB Server 01', ip: '192.168.1.22', x: 880, y: 280, color: '#8a2be2' },
      { id: 'ap-1', label: 'Lobby Wi-Fi AP', ip: '192.168.1.50', x: 250, y: 440, color: '#ffb300' },
      { id: 'client-1', label: 'Lakshya MacBook', ip: '192.168.1.101', x: 450, y: 440, color: '#00e676' },
      { id: 'client-2', label: 'Workstation 02', ip: '192.168.1.102', x: 650, y: 440, color: '#00e676' }
    ];

    const links = [
      ['internet', 'fw'], ['internet', 'c-sw'],
      ['fw', 'sw-1'], ['fw', 'sw-2'], ['c-sw', 'sw-3'], ['c-sw', 'srv-1'], ['c-sw', 'srv-2'],
      ['sw-1', 'ap-1'], ['sw-2', 'client-1'], ['sw-3', 'client-2']
    ];

    // Links
    links.forEach(([sId, dId]) => {
      const s = nodes.find(n => n.id === sId);
      const d = nodes.find(n => n.id === dId);
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', s.x); line.setAttribute('y1', s.y);
      line.setAttribute('x2', d.x); line.setAttribute('y2', d.y);
      line.setAttribute('stroke', 'rgba(0, 240, 255, 0.35)');
      line.setAttribute('stroke-width', '2');
      svg.appendChild(line);
    });

    // Nodes
    nodes.forEach(n => {
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('transform', `translate(${n.x}, ${n.y})`);

      const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      rect.setAttribute('x', '-70'); rect.setAttribute('y', '-22');
      rect.setAttribute('width', '140'); rect.setAttribute('height', '44');
      rect.setAttribute('rx', '8');
      rect.setAttribute('fill', 'rgba(14, 23, 38, 0.95)');
      rect.setAttribute('stroke', n.color);
      rect.setAttribute('stroke-width', '1.5');
      g.appendChild(rect);

      const t1 = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      t1.setAttribute('x', '0'); t1.setAttribute('y', '-4');
      t1.setAttribute('text-anchor', 'middle');
      t1.setAttribute('fill', '#fff');
      t1.setAttribute('font-weight', '600');
      t1.setAttribute('font-size', '11');
      t1.textContent = n.label;
      g.appendChild(t1);

      const t2 = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      t2.setAttribute('x', '0'); t2.setAttribute('y', '12');
      t2.setAttribute('text-anchor', 'middle');
      t2.setAttribute('fill', '#00f0ff');
      t2.setAttribute('font-size', '10');
      t2.setAttribute('font-family', 'monospace');
      t2.textContent = n.ip;
      g.appendChild(t2);

      svg.appendChild(g);
    });
  }

  // Fleet View Table & Filters
  function renderFleetTable(devs) {
    const tbody = document.getElementById('tbody-fleet-devices');
    if (!tbody) return;
    tbody.innerHTML = '';

    document.getElementById('flt-count-all').textContent = devs.length;
    document.getElementById('flt-count-online').textContent = devs.filter(d => d.status === 'Online').length;
    document.getElementById('flt-count-offline').textContent = devs.filter(d => d.status === 'Offline').length;

    devs.forEach(d => {
      const tr = document.createElement('tr');
      tr.style.cursor = 'pointer';
      const stClass = d.status.toLowerCase();
      const devName = d.custom_name || (d.hostname !== 'Unknown' ? d.hostname : d.ip);

      tr.innerHTML = `
        <td><strong>${devName}</strong></td>
        <td>${d.device_type || 'PC'}</td>
        <td class="font-mono">${d.ip}</td>
        <td class="font-mono">${d.mac || 'Unknown'}</td>
        <td>${d.vendor || 'Unknown'}</td>
        <td><span class="status-pill ${stClass}">● ${d.status}</span></td>
        <td class="font-mono">${d.latency_ms ? d.latency_ms + ' ms' : '-'}</td>
        <td class="text-muted">${d.last_seen || 'Just now'}</td>
        <td><button class="btn-sm primary-btn" onclick="window.openDeviceModal('${d.ip}')">Manage</button></td>
      `;
      tbody.appendChild(tr);
    });
  }

  // Export Handlers
  document.getElementById('btn-export-csv')?.addEventListener('click', () => {
    window.location.href = '/api/export/csv';
  });
  document.getElementById('btn-export-json')?.addEventListener('click', () => {
    window.location.href = '/api/export/json';
  });

  // Initial Load & Adaptive Real-Time Polling
  let isScanningActive = false;

  async function pollLoop() {
    await refreshDashboardData();
    await refreshActivityLogs();
    const nextDelay = isScanningActive ? 600 : 2500;
    setTimeout(pollLoop, nextDelay);
  }

  initActivityChart();
  refreshUserProfile();
  pollLoop();
});
