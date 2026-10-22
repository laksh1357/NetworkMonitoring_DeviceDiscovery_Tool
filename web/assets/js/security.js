(() => {
  const elements = {
    error: document.getElementById('security-error'),
    auditStatus: document.getElementById('audit-status'),
    auditCount: document.getElementById('audit-count'),
    auditRoot: document.getElementById('audit-root'),
    auditRows: document.getElementById('audit-rows'),
    auditScope: document.getElementById('audit-scope'),
    diskRead: document.getElementById('disk-read'),
    diskWrite: document.getElementById('disk-write'),
    honeypotState: document.getElementById('honeypot-state'),
    honeypotDetail: document.getElementById('honeypot-detail'),
    honeypotBadge: document.getElementById('honeypot-badge'),
    honeypotDescription: document.getElementById('honeypot-description'),
    quarantineState: document.getElementById('quarantine-state'),
    quarantineDetail: document.getElementById('quarantine-detail'),
    quarantineBadge: document.getElementById('quarantine-badge'),
    quarantineDescription: document.getElementById('quarantine-description'),
    storageZones: document.getElementById('storage-zones'),
    storageSampled: document.getElementById('storage-sampled'),
    updated: document.getElementById('security-updated'),
  };

  async function requestJSON(path) {
    const response = await fetch(path, {
      credentials: 'same-origin',
      headers: {
        Accept: 'application/json',
        ...window.watchtowerAuth?.headers(),
      },
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) {
      if (response.status === 401) window.watchtowerAuth?.refresh();
      throw new Error(body?.error || `Request failed (${response.status})`);
    }
    if (!body) throw new Error(`Expected JSON from ${path}`);
    return body;
  }

  function formatBytes(value) {
    if (!Number.isFinite(Number(value))) return 'Unavailable';
    const bytes = Number(value);
    if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KiB`;
    if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MiB`;
    return `${(bytes / 1024 ** 3).toFixed(2)} GiB`;
  }

  function renderStorage(storage) {
    const fragment = document.createDocumentFragment();
    for (const zone of storage.zones || []) {
      const card = document.createElement('article');
      card.className = 'storage-zone';
      const heading = document.createElement('div');
      heading.className = 'storage-zone-heading';
      const label = document.createElement('strong');
      label.textContent = zone.label;
      const volume = document.createElement('span');
      volume.textContent = `${formatBytes(zone.volume_free_bytes)} free`;
      heading.append(label, volume);

      const usage = document.createElement('div');
      usage.className = 'storage-usage';
      const used = document.createElement('span');
      used.textContent = zone.id === 'system'
        ? `${zone.volume_used_percent}% volume used`
        : `${formatBytes(zone.used_bytes)} managed data`;
      const total = document.createElement('span');
      total.textContent = `Volume ${formatBytes(zone.volume_total_bytes)}`;
      usage.append(used, total);

      const track = document.createElement('div');
      track.className = 'storage-track';
      const bar = document.createElement('span');
      const percent = zone.id === 'system'
        ? Number(zone.volume_used_percent) || 0
        : zone.volume_total_bytes > 0
          ? Number(zone.used_bytes) / Number(zone.volume_total_bytes) * 100
          : 0;
      bar.style.width = `${Math.max(0, Math.min(100, percent))}%`;
      track.appendChild(bar);

      const path = document.createElement('code');
      path.className = 'storage-path';
      path.textContent = zone.path;
      card.append(heading, usage, track, path);
      fragment.appendChild(card);
    }
    elements.storageZones.replaceChildren(fragment);
    elements.storageSampled.textContent = `Sampled ${new Date(storage.sampled_at * 1000).toLocaleTimeString()}`;
    if (storage.host_disk_io.status === 'available') {
      elements.diskRead.textContent = `${formatBytes(storage.host_disk_io.read_bytes_per_second)}/s`;
      elements.diskWrite.textContent = `${formatBytes(storage.host_disk_io.write_bytes_per_second)}/s`;
    } else {
      elements.diskRead.textContent = storage.host_disk_io.status === 'sampling' ? 'Sampling…' : 'Unavailable';
      elements.diskWrite.textContent = storage.host_disk_io.error || 'Waiting for a second host counter sample';
    }
  }

  function renderAudit(audit) {
    elements.auditStatus.textContent = audit.valid ? 'VERIFIED' : 'FAILED';
    elements.auditStatus.classList.toggle('integrity-good', audit.valid);
    elements.auditStatus.classList.toggle('integrity-bad', !audit.valid);
    elements.auditCount.textContent = `${audit.event_count} recorded events · checkpoint ${audit.checkpoint_sequence ?? 'not created'}`;
    elements.auditRoot.textContent = `Merkle root: ${audit.merkle_root}`;
    elements.auditScope.textContent = audit.scope;
    const fragment = document.createDocumentFragment();
    for (const event of audit.events || []) {
      const row = document.createElement('tr');
      appendCell(row, event.sequence, 'mono');
      appendCell(row, event.action);
      appendCell(row, event.actor);
      appendCell(row, event.occurred_at, 'mono');
      appendCell(row, event.leaf_hash, 'mono hash-cell');
      fragment.appendChild(row);
    }
    if (!fragment.childNodes.length) {
      const row = document.createElement('tr');
      const cell = document.createElement('td');
      cell.colSpan = 5;
      cell.className = 'empty-cell';
      cell.textContent = 'No admin or sensor events have been recorded yet.';
      row.appendChild(cell);
      fragment.appendChild(row);
    }
    elements.auditRows.replaceChildren(fragment);
  }

  function appendCell(row, value, className = '') {
    const cell = document.createElement('td');
    cell.textContent = value == null ? '—' : String(value);
    if (className) cell.className = className;
    row.appendChild(cell);
  }

  function renderSecurityStatus(status) {
    const honeypot = status.honeypot;
    elements.honeypotState.textContent = honeypot.running ? 'LISTENING' : 'DISABLED';
    elements.honeypotDetail.textContent = honeypot.running
      ? `Bound to ${honeypot.bind_address} · ports ${honeypot.ports.join(', ')}`
      : 'No listener sockets are open';
    elements.honeypotBadge.textContent = honeypot.running ? 'Active' : 'Disabled';
    elements.honeypotDescription.textContent = honeypot.running
      ? `Live connection-only decoys are listening on ${honeypot.bind_address}:${honeypot.ports.join(', ')}.`
      : 'The honeypot is actually disabled. Set the explicit backend environment variables to enable a private or loopback-only listener.';

    const quarantine = status.quarantine;
    elements.quarantineState.textContent = quarantine.configured ? 'MANUAL' : 'NOT CONFIGURED';
    elements.quarantineDetail.textContent = quarantine.automated
      ? 'Controller integration active'
      : 'No devices are blocked by Watchtower';
    elements.quarantineBadge.textContent = quarantine.configured ? 'Manual approval' : 'Unavailable';
    elements.quarantineDescription.textContent = quarantine.message;
  }

  async function refresh() {
    elements.error.hidden = true;
    try {
      const [storage, audit, status] = await Promise.all([
        requestJSON('/api/security/storage'),
        requestJSON('/api/security/audit'),
        requestJSON('/api/security/status'),
      ]);
      renderStorage(storage);
      renderAudit(audit);
      renderSecurityStatus(status);
      elements.updated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
    } catch (error) {
      elements.error.textContent = error.message;
      elements.error.hidden = false;
    }
  }

  document.getElementById('security-refresh').addEventListener('click', refresh);
  window.addEventListener('watchtower-auth-state', event => {
    if (event.detail.authenticated) refresh();
  });
  window.setInterval(() => {
    if (window.watchtowerAuth?.authenticated) refresh();
  }, 5000);
})();
