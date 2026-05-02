// views.js — table, graph, build, listeners, events, loot, chat

// ---- Table Rendering ----

function renderTable(beacons) {
    const tbody = document.getElementById('beacons-table-body');
    if (!tbody) return;

    tbody.innerHTML = '';
    beacons.slice().sort((a, b) => a.id - b.id).forEach(b => {
        if (b.shell_active) _activeShells.add(b.id);
        else _activeShells.delete(b.id);
        const status = beaconStatus(b);
        const os = (PLATFORM_MAP[b.platform] ?? String(b.platform)) + ' ' + (ARCH_MAP[b.arch] ?? String(b.arch));
        const integ = INTEGRITY_MAP[b.integrity] ?? String(b.integrity);

        // Beacon row
        const socksBadgeHtml = (b.socks_active && b.socks_port)
            ? ` <span class="badge-socks5">SOCKS</span>`
            : '';

        const tr = document.createElement('tr');
        tr.dataset.beaconId = b.id;
        tr.innerHTML = `
            <td>
                <div class="status-cell beacon-${status}">
                    <span class="card-badge badge-${status}">${status.toUpperCase()}</span>
                </div>
            </td>
            <td style="color: var(--amber)">${escapeHtml(b.hostname || '?')} <span class="badge-beacon">BEACON</span></td>
            <td>${escapeHtml(b.username || '—')}</td>
            <td>${escapeHtml(os)}</td>
            <td>${escapeHtml(integ)}</td>
            <td>${b.process_id}</td>
            <td style="color: var(--blue)">${escapeHtml(b.listener_name || '—')}</td>
            <td>${b.sleep}s</td>
            <td data-ts="${b.last_seen}">${timeAgo(b.last_seen)}</td>
        `;
        tr.addEventListener('contextmenu', (e) => { e.preventDefault(); showContextMenu(e, b); });
        tr.addEventListener('dblclick', () => openTerminal(b.id));
        tbody.appendChild(tr);

        // Session row (when session TCP is active)
        if (b.mode === 'session') {
            const sessRow = document.createElement('tr');
            sessRow.dataset.sessionId = b.id;
            sessRow.innerHTML = `
                <td>
                    <div class="status-cell beacon-active">
                        <span class="card-badge badge-active">ACTIVE</span>
                    </div>
                </td>
                <td style="color: #78dce8">${escapeHtml(b.hostname || '?')} <span class="badge-session">SESSION</span>${socksBadgeHtml}</td>
                <td>${escapeHtml(b.username || '—')}</td>
                <td>${escapeHtml(os)}</td>
                <td>${escapeHtml(integ)}</td>
                <td>${b.process_id}</td>
                <td style="color: var(--blue)">${escapeHtml(b.listener_name || '—')}</td>
                <td>realtime</td>
                <td>—</td>
            `;
            sessRow.addEventListener('dblclick', () => openTerminal('sess_' + b.id));
            sessRow.addEventListener('contextmenu', (e) => { e.preventDefault(); showContextMenu(e, b, false, true); });
            tbody.appendChild(sessRow);
        }

        // Shell row (when shell is active for this beacon)
        if (b.alive && _activeShells.has(b.id)) {
            const sr = document.createElement('tr');
            sr.innerHTML = `
                <td>
                    <div class="status-cell beacon-active">
                        <span class="card-badge badge-active">ACTIVE</span>
                    </div>
                </td>
                <td style="color: #AFA9EC">${escapeHtml(b.hostname || '?')} <span class="badge-session">SHELL</span></td>
                <td>${escapeHtml(b.username || '—')}</td>
                <td>${escapeHtml(os)}</td>
                <td>${escapeHtml(integ)}</td>
                <td>${b.process_id}</td>
                <td style="color: var(--blue)">${escapeHtml(b.listener_name || '—')}</td>
                <td>—</td>
                <td>—</td>
            `;
            sr.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                showContextMenu(e, b, true);
            });
            sr.addEventListener('dblclick', () => openShellTerminal(b.id));
            tbody.appendChild(sr);
        }
    });
}

// ---- Context Menu ----

let _activeCtxBeacon = null;

function hideContextMenu() {
    const menu = document.getElementById('context-menu');
    if (menu) menu.style.display = 'none';
}

function showContextMenu(e, beacon, isShellRow, isSessionRow) {
    e.preventDefault();
    _activeCtxBeacon = beacon;
    const menu = document.getElementById('context-menu');
    if (!menu) return;

    const ctxInteract = document.getElementById('ctx-interact');
    const ctxSession  = document.getElementById('ctx-session');
    const ctxFileBrowser = document.getElementById('ctx-filebrowser');
    const ctxKill     = document.getElementById('ctx-kill');
    const sep         = menu.querySelector('.context-separator');

    // Remove any previously injected SOCKS5 items
    menu.querySelectorAll('.ctx-socks-dynamic').forEach(el => el.parentNode.removeChild(el));

    if (isSessionRow) {
        ctxInteract.textContent = 'Interact';
        ctxInteract.onclick = () => { openTerminal('sess_' + beacon.id); hideContextMenu(); };
        ctxSession.style.display = 'none';
        if (ctxFileBrowser) {
            ctxFileBrowser.style.display = '';
            ctxFileBrowser.onclick = () => { openFileBrowser(beacon.id, true); hideContextMenu(); };
        }
        sep.style.display = '';
        ctxKill.textContent = 'Close Session';
        ctxKill.style.display = '';
        ctxKill.onclick = () => { closeSession(beacon.id); hideContextMenu(); };

        _injectSocksContextItems(menu, sep, beacon);
    } else if (isShellRow) {
        ctxInteract.textContent = 'Interact Shell';
        ctxInteract.onclick = () => { openShellTerminal(beacon.id); hideContextMenu(); };
        ctxSession.style.display = 'none';
        if (ctxFileBrowser) ctxFileBrowser.style.display = 'none';
        sep.style.display = 'none';
        ctxKill.textContent = 'Close Shell';
        ctxKill.onclick = () => { stopShell(beacon.id); hideContextMenu(); };
    } else {
        ctxInteract.textContent = 'Interact';
        ctxInteract.onclick = () => { openTerminal(beacon.id); hideContextMenu(); };
        if (beacon.alive) {
            ctxSession.style.display = '';
            if (ctxFileBrowser) {
                ctxFileBrowser.style.display = '';
                ctxFileBrowser.onclick = () => { openFileBrowser(beacon.id); hideContextMenu(); };
            }
            sep.style.display = '';
            ctxSession.onclick = () => { showShellModal(beacon.id, beacon.hostname || ''); hideContextMenu(); };
        } else {
            ctxSession.style.display = 'none';
            if (ctxFileBrowser) ctxFileBrowser.style.display = 'none';
            sep.style.display = '';
        }
        ctxKill.textContent = beacon.alive ? 'Kill Beacon' : 'Delete Beacon';
        ctxKill.onclick = () => { showKillModal(beacon.id, beacon.hostname, !beacon.alive); hideContextMenu(); };
    }

    menu.style.display = 'block';
    const mx = Math.min(e.clientX, window.innerWidth - menu.offsetWidth - 8);
    const my = Math.min(e.clientY, window.innerHeight - menu.offsetHeight - 8);
    menu.style.left = mx + 'px';
    menu.style.top = my + 'px';
}

function _injectSocksContextItems(menu, insertBefore, beacon) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;

    const b = _beacons[beacon.id] || beacon;
    const socksActive = !!(b.socks_active);

    const socksItem = document.createElement('div');
    socksItem.className = 'context-item ctx-socks ctx-socks-dynamic';

    if (socksActive) {
        socksItem.textContent = 'Stop SOCKS5';
        socksItem.onclick = () => {
            authFetch(tsUrl + '/api/socks/' + beacon.id, { method: 'DELETE' })
                .then(r => {
                    if (!r.ok) {
                        r.text().then(t => appendLine('[!] ' + t, 'err'));
                        return;
                    }
                    const bx = _beacons[beacon.id];
                    if (bx) {
                        bx.socks_active = false;
                        bx.socks_host   = '';
                        bx.socks_port   = 0;
                    }
                    removeSocksBadge(beacon.id);
                })
                .catch(err => appendLine('[!] socks stop error: ' + err.message, 'err'));
            hideContextMenu();
        };
    } else {
        socksItem.textContent = 'Start SOCKS5';
        socksItem.onclick = () => {
            authFetch(tsUrl + '/api/socks', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ beacon_id: beacon.id }),
            })
                .then(r => {
                    if (!r.ok) {
                        r.text().then(t => appendLine('[!] ' + t, 'err'));
                        return null;
                    }
                    return r.json();
                })
                .then(d => {
                    if (!d) return;
                    const bx = _beacons[beacon.id];
                    if (bx) {
                        bx.socks_active = true;
                        bx.socks_host   = d.host || '';
                        bx.socks_port   = d.port || 0;
                    }
                    updateSocksBadge(beacon.id, d.host || '', d.port || 0);
                })
                .catch(err => appendLine('[!] socks start error: ' + err.message, 'err'));
            hideContextMenu();
        };
    }

    menu.insertBefore(socksItem, insertBefore);
}

document.addEventListener('click', hideContextMenu);
document.addEventListener('contextmenu', (e) => {
    if (!e.target.closest('.node-victim') && !e.target.closest('#beacons-table tbody tr')) hideContextMenu();
});

// ---- Graph Rendering ----

let _manualPositions = {};
let _draggingNode = null;
let _dragOffset = { x: 0, y: 0 };
let _hasDragged = false;
let _mapZoom = 1.0;
let _mapPan = { x: 0, y: 0 };
let _isPanning = false;
let _panStart = { x: 0, y: 0 };

function initMapControls() {
    const container = document.getElementById('map-container');
    const viewport = document.getElementById('map-viewport');
    if (!container || !viewport) return;

    // Zoom
    container.addEventListener('wheel', (e) => {
        if (_currentView !== 'map') return;
        e.preventDefault();
        const zoomSpeed = 0.1;
        if (e.deltaY < 0) _mapZoom = Math.min(3.0, _mapZoom + zoomSpeed);
        else _mapZoom = Math.max(0.2, _mapZoom - zoomSpeed);
        updateMapTransform();
    }, { passive: false });

    // Pan Start
    container.addEventListener('mousedown', (e) => {
        if (_currentView !== 'map' || e.button !== 0) return;
        if (e.target.closest('.map-node')) return; // Don't pan if dragging a node

        _isPanning = true;
        _panStart.x = e.clientX - _mapPan.x * _mapZoom;
        _panStart.y = e.clientY - _mapPan.y * _mapZoom;
        container.style.cursor = 'grabbing';
        viewport.style.transition = 'none';
    });

    // Pan Move & Node Drag Move
    document.addEventListener('mousemove', (e) => {
        if (_isPanning) {
            _mapPan.x = (e.clientX - _panStart.x) / _mapZoom;
            _mapPan.y = (e.clientY - _panStart.y) / _mapZoom;
            updateMapTransform();
            return;
        }

        if (!_draggingNode) return;
        _hasDragged = true;
        const nodeContainer = document.getElementById('map-nodes');
        const rect = nodeContainer.getBoundingClientRect();

        // Correct mouse coordinates considering zoom AND pan
        let x = (e.clientX - rect.left) / _mapZoom + 50 - (_dragOffset.x / _mapZoom);
        let y = (e.clientY - rect.top) / _mapZoom + 50 - (_dragOffset.y / _mapZoom);

        _draggingNode.el.style.left = (x - 50) + 'px';
        _draggingNode.el.style.top = (y - 50) + 'px';
        _manualPositions[_draggingNode.id] = { x, y };

        const sPos = _manualPositions['server'];
        const svg = document.getElementById('map-svg');
        if (_draggingNode.id === 'server') {
            svg.querySelectorAll('line').forEach(l => {
                l.setAttribute('x1', x); l.setAttribute('y1', y);
            });
        } else {
            const line = document.getElementById('line-' + _draggingNode.id);
            if (line) {
                line.setAttribute('x2', x);
                line.setAttribute('y2', y);
            }
        }
    });

    document.addEventListener('mouseup', () => {
        if (_isPanning) {
            _isPanning = false;
            container.style.cursor = '';
            viewport.style.transition = 'transform 0.1s ease-out';
        }
        if (_draggingNode) {
            _draggingNode.el.style.transition = '';
            _draggingNode.el.style.zIndex = '';
            _draggingNode = null;
        }
    });
}

function updateMapTransform() {
    const viewport = document.getElementById('map-viewport');
    if (viewport) {
        viewport.style.transform = `scale(${_mapZoom}) translate(${_mapPan.x}px, ${_mapPan.y}px)`;
    }
}

// Call controls init
setTimeout(initMapControls, 100);

function renderMap(beacons) {
    const container = document.getElementById('map-nodes');
    const svg = document.getElementById('map-svg');
    const viewport = document.getElementById('map-viewport');
    if (!container || !svg || !viewport) return;

    // Apply current transform
    updateMapTransform();

    // Don't wipe if we are interacting
    if (_draggingNode || _isPanning) return;

    container.innerHTML = '';
    svg.innerHTML = '';

    const width = svg.clientWidth;
    const height = svg.clientHeight;
    const centerX = width / 2;
    const centerY = height / 2;
    const offset = 50;

    // 1. Teamserver (Center)
    if (!_manualPositions['server']) {
        _manualPositions['server'] = { x: centerX, y: centerY };
    }
    const sPos = _manualPositions['server'];

    const serverNode = document.createElement('div');
    serverNode.className = 'map-node node-server';
    serverNode.style.left = (sPos.x - offset) + 'px';
    serverNode.style.top = (sPos.y - offset) + 'px';
    serverNode.innerHTML = '<div class="node-icon"></div><div class="node-label">Teamserver</div>';
    initDraggable(serverNode, 'server');
    container.appendChild(serverNode);

    if (!beacons || beacons.length === 0) return;

    // 2. Beacons
    const radius = Math.min(centerX, centerY) * 0.65;
    beacons.forEach((b, i) => {
        const id = 'beacon-' + b.id;
        if (!_manualPositions[id]) {
            const angle = (i / beacons.length) * (2 * Math.PI);
            _manualPositions[id] = {
                x: centerX + radius * Math.cos(angle),
                y: centerY + radius * Math.sin(angle)
            };
        }

        const pos = _manualPositions[id];
        const node = document.createElement('div');
        node.className = 'map-node node-victim' + (b.platform === 0 ? ' linux' : '') + (!b.alive ? ' dead' : '');
        node.style.left = (pos.x - offset) + 'px';
        node.style.top = (pos.y - offset) + 'px';
        node.innerHTML = `<div class="node-icon"></div><div class="node-label">${escapeHtml(b.username || '?')}@${escapeHtml(b.hostname || '?')}</div>`;

        // Single click to interact (if not dragged)
        node.onclick = () => {
            if (!_hasDragged) openTerminal(b.id);
        };

        // Right click for context menu
        node.oncontextmenu = (e) => showContextMenu(e, b);

        initDraggable(node, id);
        container.appendChild(node);

        // Draw connection line
        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.id = 'line-' + id;
        line.setAttribute('x1', sPos.x);
        line.setAttribute('y1', sPos.y);
        line.setAttribute('x2', pos.x);
        line.setAttribute('y2', pos.y);
        line.setAttribute('class', 'connection-line');
        svg.appendChild(line);
    });
}

function initDraggable(el, id) {
    el.onmousedown = (e) => {
        if (e.button !== 0) return; // Left click only
        _draggingNode = { el, id };
        _hasDragged = false;
        const rect = el.getBoundingClientRect();
        _dragOffset.x = e.clientX - rect.left;
        _dragOffset.y = e.clientY - rect.top;
        el.style.transition = 'none';
        el.style.zIndex = 1000;
        e.preventDefault();
    };
}

// ---- Session list rendering ----

function _renderSessionsList(beacons) {
    const noMsg = document.getElementById('no-sessions');

    updateConnIndicator(true);

    const aliveBeacons = beacons.filter(b => b.alive).length;
    const titleEl = document.getElementById('sessions-title');
    if (titleEl) {
        titleEl.innerHTML = `Sessions <span class="count-minimal">// ${aliveBeacons} active</span>`;
    }

    if (_currentView === 'map') {
        renderMap(beacons);
    } else if (_currentView === 'table') {
        renderTable(beacons);
    }

    if (beacons.length === 0) {
        if (noMsg && _currentView !== 'map') {
            noMsg.innerHTML = 'No active beacons.' +
                '<span class="empty-quote">"You\'re gonna carry that weight."</span>';
            noMsg.style.display = '';
        } else if (noMsg) {
            noMsg.style.display = 'none';
        }
        if (_knownBeaconIds === null) _knownBeaconIds = new Set();
        return;
    }
    if (noMsg) noMsg.style.display = 'none';

    // Toast + event log for new beacons
    if (_knownBeaconIds === null) {
        _knownBeaconIds = new Set();
        _knownBeaconAlive = {};
        for (const b of beacons) {
            _knownBeaconIds.add(b.id);
            _knownBeaconAlive[b.id] = b.alive;
            _beaconModes[b.id] = b.mode || 'beacon';
        }
    } else {
        for (const b of beacons) {
            if (!_knownBeaconIds.has(b.id)) {
                _knownBeaconIds.add(b.id);
                _knownBeaconAlive[b.id] = b.alive;
                showToast(b.hostname || '?', b.username || '?');
            }
            _knownBeaconAlive[b.id] = b.alive;
            _beaconModes[b.id] = b.mode || 'beacon';
        }
    }
}

function _renderSessionsFromCache() {
    _renderSessionsList(Object.values(_beacons));
}

// ---- Event Log (server-persisted) ----

let _eventLog = [];

function _formatTs(date) {
    return String(date.getHours()).padStart(2, '0') + ':' +
           String(date.getMinutes()).padStart(2, '0') + ':' +
           String(date.getSeconds()).padStart(2, '0');
}

function _renderEventEntry(ts, msg) {
    const body = document.getElementById('event-log-body');
    if (!body) return;
    const emptyEl = body.querySelector('.event-log-empty');
    if (emptyEl) emptyEl.remove();
    const entry = document.createElement('div');
    entry.className = 'event-log-entry';
    const tsSpan = document.createElement('span');
    tsSpan.className = 'event-log-ts';
    tsSpan.textContent = ts;
    const msgSpan = document.createElement('span');
    msgSpan.className = 'event-log-msg';
    msgSpan.textContent = msg;
    entry.appendChild(tsSpan);
    entry.appendChild(msgSpan);
    body.appendChild(entry);
    body.scrollTop = body.scrollHeight;
}

function _appendEventEntry(evt) {
    const d  = new Date(evt.timestamp);
    const ts = _formatTs(d);
    _eventLog.push({ ts, type: evt.type, msg: evt.message });
    _renderEventEntry(ts, evt.message);
}

async function loadEventLog() {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    try {
        const resp = await authFetch(tsUrl + '/api/events');
        if (!resp.ok) return;
        const events = await resp.json();
        if (!events) return;

        const knownCount = _eventLog.length;
        if (events.length <= knownCount) return;

        if (knownCount === 0) {
            const body = document.getElementById('event-log-body');
            if (body) body.innerHTML = '';
        }

        for (let i = knownCount; i < events.length; i++) {
            _appendEventEntry(events[i]);
        }
    } catch (_) {}
}

function exportEventLog(e) {
    if (e) e.stopPropagation();
    if (_eventLog.length === 0) return;

    const date = new Date();
    const dateStr = date.toISOString().slice(0, 10);
    const lines = [
        '# BEBOP C2 — Event Log Export',
        '# Date: ' + date.toISOString(),
        '# Events: ' + _eventLog.length,
        '#' + '-'.repeat(60),
        '',
    ];

    const stripHtml = (s) => s.replace(/<[^>]*>/g, '');

    for (const ev of _eventLog) {
        lines.push('[' + ev.ts + '] ' + stripHtml(ev.msg));
    }

    lines.push('', '# END OF LOG');

    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = 'bebop-eventlog-' + dateStr + '.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// ---- Build page ----

function showBuildStatus(msg, cls) {
    const el = document.getElementById('build-status');
    if (!el) return;
    el.textContent = msg;
    el.className = 'build-status ' + (cls || '');
}

async function populateBuildListeners() {
    const tsUrl = getTsUrl();
    const sel = document.getElementById('buildListener');
    if (!sel) return;
    if (!tsUrl) { sel.innerHTML = '<option value="">— connect to teamserver first —</option>'; return; }

    try {
        const resp = await authFetch(tsUrl + '/api/listeners');
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const listeners = await resp.json();
        sel.innerHTML = '<option value="">— select a listener —</option>';
        for (const l of (listeners || [])) {
            const opt = document.createElement('option');
            opt.value = l.id;
            const certNote = l.scheme === 'https' ? (l.auto_cert ? ' [self-signed]' : ' [custom cert]') : '';
            opt.textContent = l.name + ' — ' + l.scheme + '://' + (l.host || '?') + ':' + l.port + certNote;
            if (!l.host) opt.disabled = true;
            sel.appendChild(opt);
        }
    } catch (e) {
        sel.innerHTML = '<option value="">— could not load listeners —</option>';
    }
}

function onListenerSelect(sel) {
    const hint = document.getElementById('listener-preview');
    if (!hint) return;
    const opt = sel.options[sel.selectedIndex];
    hint.textContent = opt && opt.value ? opt.textContent : '';
}

function onPlatformChange() {
    const platform = document.getElementById('buildPlatform')?.value || 'windows';
    const fmt = document.getElementById('buildFormat');
    if (!fmt) return;
    if (platform === 'linux') {
        fmt.innerHTML = '<option value="elf">Linux ELF Binary (static)</option>';
    } else {
        fmt.innerHTML = '<option value="exe">Windows Executable (.exe)</option>' +
                        '<option value="bin">Raw Shellcode (.bin)</option>';
    }
    updateBuildBtn();
}

function updateBuildBtn() {
    const platform = document.getElementById('buildPlatform')?.value || 'windows';
    const format = document.getElementById('buildFormat')?.value || 'exe';
    const btn = document.getElementById('build-btn');
    if (!btn) return;
    if (platform === 'linux') {
        btn.textContent = 'Compile beacon.elf';
    } else if (format === 'bin') {
        btn.textContent = 'Compile beacon.bin';
    } else {
        btn.textContent = 'Compile beacon.exe';
    }
}

async function buildBeacon() {
    const tsUrl = getTsUrl();
    if (!tsUrl) {
        showBuildStatus('Enter teamserver address and click Connect first.', 'err');
        return;
    }

    const sel        = document.getElementById('buildListener');
    const listenerId = sel ? parseInt(sel.value, 10) : NaN;
    const sleepDays  = parseInt(document.getElementById('buildSleepDays').value,  10) || 0;
    const sleepHours = parseInt(document.getElementById('buildSleepHours').value, 10) || 0;
    const sleepMins  = parseInt(document.getElementById('buildSleepMins').value,  10) || 0;
    const sleepSecs  = parseInt(document.getElementById('buildSleepSecs').value,  10) || 0;
    const sleepMs    = Math.max(1000, (sleepDays * 86400 + sleepHours * 3600 + sleepMins * 60 + sleepSecs) * 1000);
    const jitter     = parseInt(document.getElementById('buildJitter').value, 10);
    const format     = document.getElementById('buildFormat')?.value || 'exe';
    const platform   = document.getElementById('buildPlatform')?.value || 'windows';

    if (!listenerId || isNaN(listenerId)) {
        showBuildStatus('Select a listener first.', 'err');
        return;
    }

    const btn      = document.getElementById('build-btn');
    const filename = platform === 'linux' ? 'beacon.elf' : (format === 'bin' ? 'beacon.bin' : 'beacon.exe');
    btn.disabled = true;
    showBuildStatus('3, 2, 1, let\'s jam… compiling ' + filename, '');

    try {
        const resp = await authFetch(tsUrl + '/api/build', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({
                listener_id: listenerId,
                sleep_ms:    sleepMs,
                jitter_pct:  isNaN(jitter) ? 0 : jitter,
                format:      format,
                session_port: 4443,
                platform:    platform,
            })
        });
        if (!resp.ok) {
            const text = await resp.text();
            showBuildStatus('Build failed: ' + text, 'err');
            return;
        }
        const blob = await resp.blob();
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showBuildStatus(filename + ' ready — download started.', 'ok');
    } catch (e) {
        showBuildStatus('Error: ' + e.message, 'err');
    } finally {
        btn.disabled = false;
    }
}

// ---- Listeners page ----

async function loadListeners() {
    const tsUrl = getTsUrl();
    const tbody = document.getElementById('listeners-tbody');
    const noMsg = document.getElementById('no-listeners');
    const count = document.getElementById('listener-count');
    if (!tbody) return;

    if (!tsUrl) {
        tbody.innerHTML = '';
        if (noMsg) { noMsg.style.display = ''; }
        updateConnIndicator(false);
        return;
    }

    try {
        const resp = await authFetch(tsUrl + '/api/listeners');
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const listeners = await resp.json();

        updateConnIndicator(true);
        if (count) count.textContent = listeners.length ? '// ' + listeners.length + ' active' : '';

        if (!listeners || listeners.length === 0) {
            tbody.innerHTML = '';
            if (noMsg) noMsg.style.display = '';
            return;
        }
        if (noMsg) noMsg.style.display = 'none';

        tbody.innerHTML = '';
        listeners.forEach((l, i) => {
            const tr = document.createElement('tr');
            tr.style.animationDelay = (i * 0.04) + 's';
            tr.style.cursor = 'context-menu';

            const schemeBadge = '<span class="listener-badge badge-' + l.scheme + '">' + l.scheme.toUpperCase() + '</span>';
            const certBadge   = l.scheme === 'https'
                ? (l.auto_cert
                    ? '<span class="listener-badge badge-autocert">self-signed</span>'
                    : '<span class="listener-badge badge-realcert">custom</span>')
                : '<span style="color:var(--text-dim);font-family:\'Share Tech Mono\',monospace;font-size:11px;">—</span>';

            tr.innerHTML =
                '<td style="color:var(--text-dim);">' + l.id + '</td>' +
                '<td>' + escapeHtml(l.name) + '</td>' +
                '<td>' + schemeBadge + '</td>' +
                '<td style="font-family:\'Share Tech Mono\',monospace;">' + escapeHtml(l.host || '—') + '</td>' +
                '<td>' + l.port + '</td>' +
                '<td>' + certBadge + '</td>';
            tr.addEventListener('contextmenu', (e) => { e.preventDefault(); showListenerContextMenu(e, l); });
            tbody.appendChild(tr);
        });
    } catch (e) {
        if (noMsg) {
            noMsg.innerHTML = 'Cannot reach teamserver — ' + escapeHtml(e.message) +
                '<span style="display:block;font-style:italic;font-size:11px;margin-top:8px;opacity:0.6;">"The music\'s over. Try again."</span>';
            noMsg.style.display = '';
        }
        tbody.innerHTML = '';
        updateConnIndicator(false);
    }
}

function showListenerContextMenu(e, listener) {
    const menu = document.getElementById('listener-context-menu');
    if (!menu) return;
    const del = document.getElementById('ctx-listener-delete');
    if (del) {
        del.textContent = listener.is_default ? 'Default (cannot delete)' : 'Delete Listener';
        del.style.opacity = listener.is_default ? '0.4' : '';
        del.onclick = listener.is_default ? null : () => {
            confirmDeleteListener(listener.id, listener.name);
            menu.style.display = 'none';
        };
    }
    menu.style.display = 'block';
    const mx = Math.min(e.clientX, window.innerWidth - menu.offsetWidth - 8);
    const my = Math.min(e.clientY, window.innerHeight - menu.offsetHeight - 8);
    menu.style.left = mx + 'px';
    menu.style.top = my + 'px';
}

document.addEventListener('click', () => {
    const menu = document.getElementById('listener-context-menu');
    if (menu) menu.style.display = 'none';
});

let _deleteListenerId = null;

function confirmDeleteListener(id, name) {
    _deleteListenerId = id;
    const el = document.getElementById('delete-listener-target');
    if (el) el.textContent = name || ('listener #' + id);
    const modal = document.getElementById('delete-listener-modal');
    if (modal) modal.style.display = 'flex';
}

function cancelDeleteListener() {
    _deleteListenerId = null;
    const modal = document.getElementById('delete-listener-modal');
    if (modal) modal.style.display = 'none';
}

function execDeleteListener() {
    const id = _deleteListenerId;
    cancelDeleteListener();
    if (id == null) return;
    deleteListenerById(id);
}

async function deleteListenerById(id) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    try {
        const resp = await authFetch(tsUrl + '/api/listeners/' + id, { method: 'DELETE' });
        if (!resp.ok) throw new Error(await resp.text());
        loadListeners();
    } catch (e) {
        alert('Delete failed: ' + e.message);
    }
}

function showCreateModal() {
    const tsUrl = getTsUrl();
    if (!tsUrl) { alert('Connect to teamserver first.'); return; }

    // Clear fields safely
    const fields = ['ln-name', 'ln-host', 'ln-port', 'ln-cert', 'ln-key'];
    fields.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });

    const radios = document.querySelectorAll('input[name="ln-scheme"]');
    radios.forEach(r => { r.checked = r.value === 'http'; });

    const httpsFields = document.getElementById('https-fields');
    if (httpsFields) httpsFields.style.display = 'none';

    const headerList = document.getElementById('custom-headers-list');
    if (headerList) headerList.innerHTML = '';

    const statusEl = document.getElementById('create-status');
    if (statusEl) statusEl.textContent = '';

    const modal = document.getElementById('create-modal');
    if (modal) modal.style.display = 'flex';
}

function hideCreateModal() {
    const modal = document.getElementById('create-modal');
    if (modal) modal.style.display = 'none';
}

function onSchemeChange(el) {
    const isHttps = el.value === 'https';
    const httpsFields = document.getElementById('https-fields');
    if (httpsFields) httpsFields.style.display = isHttps ? '' : 'none';

    if (!isHttps) {
        const cert = document.getElementById('ln-cert');
        const key = document.getElementById('ln-key');
        if (cert) cert.value = '';
        if (key) key.value = '';
    }
}

function addHeaderRow() {
    const list = document.getElementById('custom-headers-list');
    if (!list) return;
    const pair = document.createElement('div');
    pair.className = 'header-pair';
    pair.innerHTML =
        '<input type="text" class="form-input-inline" placeholder="Header Name (e.g. Server)" title="Header name">' +
        '<input type="text" class="form-input-inline" placeholder="Value (e.g. nginx)" title="Header value">' +
        '<button type="button" class="btn-action-small" onclick="this.parentElement.remove()" style="border-color:var(--border-orange); color:var(--orange); min-width:32px;">&#x2715;</button>';
    list.appendChild(pair);
}

async function submitCreateListener() {
    const nameEl = document.getElementById('ln-name');
    const hostEl = document.getElementById('ln-host');
    const portEl = document.getElementById('ln-port');
    const certEl = document.getElementById('ln-cert');
    const keyEl  = document.getElementById('ln-key');
    const statusEl = document.getElementById('create-status');
    const schemeEl = document.querySelector('input[name="ln-scheme"]:checked');

    if (!nameEl || !hostEl || !portEl || !statusEl || !schemeEl) return;

    const name    = nameEl.value.trim();
    const scheme  = schemeEl.value;
    const host    = hostEl.value.trim();
    const port    = parseInt(portEl.value, 10);
    const certPem = certEl ? certEl.value.trim() : '';
    const keyPem  = keyEl ? keyEl.value.trim() : '';

    if (!name) { statusEl.textContent = 'name is required'; return; }
    if (!host) { statusEl.textContent = 'host is required'; return; }
    if (!port || port < 1 || port > 65535) { statusEl.textContent = 'valid port required (1-65535)'; return; }

    const customHeaders = {};
    document.querySelectorAll('#custom-headers-list .header-pair').forEach(pair => {
        const inputs = pair.querySelectorAll('input');
        if (inputs.length >= 2) {
            const k = inputs[0].value.trim();
            const v = inputs[1].value.trim();
            if (k) customHeaders[k] = v;
        }
    });

    const payload = {
        name,
        scheme,
        host,
        bind_addr: '0.0.0.0', // Fixed value
        port,
        cert_pem:  certPem,
        key_pem:   keyPem,
        custom_headers: Object.keys(customHeaders).length ? customHeaders : null,
    };

    const tsUrl = getTsUrl();
    try {
        const resp = await authFetch(tsUrl + '/api/listeners', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(payload),
        });
        if (!resp.ok) {
            statusEl.textContent = 'Error: ' + (await resp.text());
            return;
        }
        hideCreateModal();
        loadListeners();
    } catch (e) {
        statusEl.textContent = 'Error: ' + e.message;
    }
}

// ---- Log panel tab switching (events / loot) ----

let _activeLogTab = 'events';

function switchLogTab(tab) {
    _activeLogTab = tab;
    const evBody   = document.getElementById('event-log-body');
    const lootBody = document.getElementById('loot-log-body');
    const chatBody = document.getElementById('chat-log-body');
    if (!evBody || !lootBody) return;

    evBody.style.display   = tab === 'events' ? '' : 'none';
    lootBody.style.display = tab === 'loot'   ? '' : 'none';
    if (chatBody) chatBody.style.display = tab === 'chat' ? '' : 'none';

    document.querySelectorAll('.event-log-tab').forEach(el => {
        el.classList.toggle('active', el.dataset.tab === tab);
    });

    const exportBtn = document.getElementById('export-log-btn');
    if (exportBtn) exportBtn.style.display = tab === 'events' ? '' : 'none';

    if (tab === 'chat') {
        clearChatUnread();
        const input = document.getElementById('chat-input');
        if (input) input.focus();
        const msgs = document.getElementById('chat-messages');
        if (msgs) msgs.scrollTop = msgs.scrollHeight;
    }
}

// ---- Loot panel ----

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

let _lootSignature = '';

async function loadLootPanel() {
    const tsUrl = getTsUrl();
    const body = document.getElementById('loot-log-body');
    if (!body) return;
    if (!tsUrl) return;

    try {
        const resp = await authFetch(tsUrl + '/api/loot');
        if (!resp.ok) return;
        const files = await resp.json();

        if (!files || files.length === 0) {
            if (_lootSignature !== 'empty') {
                body.innerHTML = '<div class="event-log-empty">no loot yet&hellip; Download something from a beacon</div>';
                _lootSignature = 'empty';
            }
            return;
        }

        files.sort((a, b) => new Date(b.exfil_at) - new Date(a.exfil_at));

        const sig = files.map(f => f.label).join(',');
        if (sig === _lootSignature) return;
        _lootSignature = sig;

        body.innerHTML = '';
        files.forEach(f => {
            const d = new Date(f.exfil_at);
            const ts = String(d.getHours()).padStart(2, '0') + ':' +
                       String(d.getMinutes()).padStart(2, '0') + ':' +
                       String(d.getSeconds()).padStart(2, '0');

            const entry = document.createElement('div');
            entry.className = 'event-log-entry loot-entry';
            entry.innerHTML =
                '<span class="event-log-ts">' + ts + '</span>' +
                '<span class="event-log-msg">' +
                    '<span class="ev-action-new">' + escapeHtml(f.filename) + '</span>' +
                    ' <span class="ev-user">#' + f.beacon_id + '</span>' +
                    ' <span style="color:var(--text-dim);opacity:0.5">' + formatBytes(f.size) + '</span>' +
                '</span>' +
                '<span class="loot-actions">' +
                    '<button class="loot-dl-btn" onclick="downloadLootEntry(' + f.label + ',\'' + escapeHtml(f.filename) + '\')" title="Download"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg></button>' +
                    '<button class="loot-rm-btn" onclick="deleteLootEntry(' + f.label + ',this)" title="Delete"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg></button>' +
                '</span>';
            body.appendChild(entry);
        });
    } catch (_) {}
}

async function deleteLootEntry(label, btn) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    try {
        await authFetch(tsUrl + '/api/files/' + label, { method: 'DELETE' });
        if (btn) {
            const row = btn.closest('.loot-entry');
            if (row) row.remove();
        }
    } catch (_) {}
    loadLootPanel();
}

async function downloadLootEntry(label, filename) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    try {
        const resp = await authFetch(tsUrl + '/api/files/' + label);
        if (!resp.ok) return;
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (_) {}
}

// ---- Operator chat ----

function _handleChatMsg(action, data) {
    if (action === 'sync') {
        renderChatHistory(data || []);
    } else if (action === 'add') {
        appendChatMessage(data);
        const currentTab = document.querySelector('.event-log-tab.active')?.dataset.tab;
        if (currentTab !== 'chat') {
            showChatUnread();
        }
    }
}

function renderChatHistory(msgs) {
    const box = document.getElementById('chat-messages');
    if (!box) return;
    box.innerHTML = '';
    msgs.forEach(appendChatMessage);
}

function appendChatMessage(m) {
    const box = document.getElementById('chat-messages');
    if (!box) return;

    const row = document.createElement('div');
    row.className = 'chat-msg';

    const ts = document.createElement('span');
    ts.className = 'chat-ts';
    ts.textContent = formatChatTimestamp(m.timestamp);

    const op = document.createElement('span');
    op.className = 'chat-op';
    op.textContent = (m.operator || '?');
    op.style.color = operatorColor(m.operator || '?');

    const msg = document.createElement('span');
    msg.className = 'chat-text';
    msg.textContent = m.message || '';

    row.appendChild(ts);
    row.appendChild(op);
    row.appendChild(msg);
    box.appendChild(row);

    box.scrollTop = box.scrollHeight;
}

function formatChatTimestamp(ts) {
    const d = new Date(ts);
    if (isNaN(d.getTime())) {
        return '[--:--:--]';
    }
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    const ss = String(d.getSeconds()).padStart(2, '0');
    return `[${hh}:${mm}:${ss}]`;
}

function operatorColor(name) {
    let h = 5381;
    for (let i = 0; i < name.length; i++) {
        h = ((h << 5) + h + name.charCodeAt(i)) | 0;
    }
    const hue = Math.abs(h) % 360;
    return `hsl(${hue}, 70%, 65%)`;
}

function showChatUnread() {
    const dot = document.getElementById('chatUnreadDot');
    if (dot) dot.classList.add('has-unread');
}

function clearChatUnread() {
    const dot = document.getElementById('chatUnreadDot');
    if (dot) dot.classList.remove('has-unread');
}

function initChatForm() {
    const form = document.getElementById('chat-form');
    const input = document.getElementById('chat-input');
    if (!form || !input) return;

    form.addEventListener('submit', (e) => {
        e.preventDefault();
        const text = input.value.trim();
        if (!text) return;
        if (!_operatorWs || _operatorWs.readyState !== WebSocket.OPEN) return;
        _operatorWs.send(JSON.stringify({
            topic: 'chat',
            action: 'send',
            data: { message: text },
        }));
        input.value = '';
    });
}

document.addEventListener('DOMContentLoaded', initChatForm);
