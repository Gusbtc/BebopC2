// core.js — constants, state, utilities, auth, UI helpers

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
    } else {
        if (mapView) mapView.style.display = 'flex';
        if (btnMap) btnMap.classList.add('active');
        const noMsg = document.getElementById('no-sessions');
        if (noMsg) noMsg.style.display = 'none';
    }
    if (_operatorWs && _operatorWs.readyState === WebSocket.OPEN) {
        _renderSessionsFromCache();
    } else {
        loadSessions();
    }
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
    if (document.getElementById('mcp-page-body')) loadMCPPanel('mcp-page-body');
}

function initSettings() {
    ensureSettingsModal();
    const ipEl   = document.getElementById('tsIp');
    const portEl = document.getElementById('tsPort');
    if (ipEl)   ipEl.value   = localStorage.getItem('tsIp')   || '';
    if (portEl) portEl.value = localStorage.getItem('tsPort')  || '';
    updateConnIndicator(false);
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
    const originalUrl = url;
    if (token) {
        if (!options.headers) options.headers = {};
        if (options.headers instanceof Headers) {
            options.headers.set('Authorization', 'Bearer ' + token);
        } else {
            options.headers['Authorization'] = 'Bearer ' + token;
        }
    }
    let resp;
    try {
        resp = await fetch(url, options);
    } catch (e) {
        if (!isTeamserverUrl(originalUrl)) throw e;
        const proxyOptions = Object.assign({}, options);
        proxyOptions.headers = cloneHeaders(options.headers);
        resp = await fetch('/api/proxy?url=' + encodeURIComponent(originalUrl), proxyOptions);
    }
    if (resp.status === 401) {
        localStorage.removeItem('authToken');
        window.location.href = '/login';
        throw new Error('unauthorized');
    }
    return resp;
}

async function makeWebSocketURL(path) {
    const tsUrl = getTsUrl();
    if (!tsUrl) throw new Error('teamserver not configured');
    const ticketResp = await authFetch(tsUrl + '/api/ws-ticket', { method: 'POST' });
    if (!ticketResp.ok) throw new Error(await ticketResp.text());
    const ticketBody = await ticketResp.json();
    if (!ticketBody || !ticketBody.ticket) throw new Error('websocket ticket unavailable');
    const wsProto = tsUrl.startsWith('https') ? 'wss' : 'ws';
    const wsHost = tsUrl.replace(/^https?:\/\//, '');
    return wsProto + '://' + wsHost + path + '?ticket=' + encodeURIComponent(ticketBody.ticket);
}

function isTeamserverUrl(url) {
    const tsUrl = getTsUrl();
    return !!tsUrl && typeof url === 'string' && url.startsWith(tsUrl + '/');
}

function cloneHeaders(headers) {
    const out = {};
    if (!headers) return out;
    if (headers instanceof Headers) {
        headers.forEach((value, key) => { out[key] = value; });
        return out;
    }
    Object.keys(headers).forEach(key => { out[key] = headers[key]; });
    return out;
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
    'BEBOP COMMANDS - WINDOWS',
    '',
    '[ IDENTITY / TARGET ]',
    '  whoami                    Current user context',
    '  hostname                  Hostname',
    '  domain                    Domain / AD membership',
    '  getpid                    Beacon process ID',
    '  getintegrity              Token integrity level',
    '  sysinfo                   OS, arch, memory',
    '  drives                    Logical drives',
    '  uptime                    Time since boot',
    '',
    '[ FILES ]',
    '  pwd                       Current directory',
    '  cd <path>                 Change directory',
    '  ls [path]                 List directory (alias: dir)',
    '  cat <file>                Read file',
    '  stat <path>               File metadata',
    '  mkdir <path>              Create directory',
    '  rm <file>                 Delete file',
    '  rmdir <path>              Remove empty directory',
    '  cp <src> <dst>            Copy file',
    '  mv <src> <dst>            Move or rename',
    '',
    '[ PROCESS / SERVICES ]',
    '  ps                        Process list',
    '  kill <pid>                Terminate process',
    '  services                  Win32 services',
    '  schtasks-enum [target]    Scheduled tasks',
    '  safe-harbor               Process reconnaissance',
    '',
    '[ NETWORK / PIVOTING ]',
    '  ipconfig                  Network adapters',
    '  arp                       ARP cache',
    '  netstat                   TCP/UDP connections',
    '  dns <name>                Resolve hostname',
    '  xpipe [pipe]              Named pipes and DACLs',
    '  socks5 start [port]       Start SOCKS5 proxy',
    '  socks5 stop               Stop SOCKS5 proxy',
    '',
    '[ DOMAIN / DIRECTORY ]',
    '  ldapsearch <filter> [attrs]        LDAP search',
    '  adcs_enum [target]                ADCS enumeration',
    '  password-policy [server]          Password and lockout policy',
    '  net-shares [target]               Network shares',
    '  local-sessions                    Local/RDP sessions',
    '  netloggedon [host]                Logged-on users',
    '',
    '[ PRIVILEGE / CREDENTIALS ]',
    '  privs                     Token privileges',
    '  groups                    Current user groups',
    '  priv-always-install-elevated       AlwaysInstallElevated policy',
    '  priv-autologon                     Winlogon AutoLogon values',
    '  priv-credential-manager            Credential Manager entries',
    '  priv-hijackable-path               Writable PATH directories',
    '  priv-modifiable-autorun            Writable autorun executables',
    '  priv-modifiable-service            Modifiable service permissions',
    '  priv-powershell-history            PSReadLine history location',
    '  priv-token-privileges              Current token privileges',
    '  priv-uac-status                    UAC and integrity status',
    '  priv-unquoted-service-path         Unquoted service paths',
    '',
    '[ HOST DATA / REGISTRY ]',
    '  env                       Environment variables',
    '  getenv <var>              One environment variable',
    '  clipboard                 Clipboard text',
    '  reg_query <H\\key> <val>   Read registry value',
    '  reg_set <H\\key> <val> <data>  Write REG_SZ value',
    '  regsession [host]         Registry session hives',
    '  msi-search                Cached MSI installer metadata',
    '',
    '[ SQL SERVER ]',
    '  sql-1434udp <ip>                   SQL Browser info',
    '  sql-info <server> [db]             SQL Server information',
    '  sql-whoami <server> [db] [link]    SQL login, user, roles',
    '  sql-impersonate <server> [db]      Impersonation rights',
    '  sql-links <server> [db] [link]     Linked servers',
    '  sql-users <server> [db] [link]     Database users',
    '  sql-databases <server> [db]        Databases',
    '  sql-tables <server> [db] [link]    Tables',
    '  sql-columns <server> <table> [db]  Columns',
    '  sql-rows <server> <table> [db]     Row count',
    '  sql-search <server> <term> [db]    Column-name search',
    '  sql-query <server> <query> [db]    Custom SQL query',
    '  sql-agentstatus <server> [db]      SQL Agent status and jobs',
    '  sql-checkrpc <server> [db]         Linked-server RPC status',
    '',
    '[ EXECUTION / MODULES ]',
    '  shell                     Interactive shell (session mode)',
    '  shell <cmd>               Run via cmd.exe /c',
    '  runas <user> <pass> <cmd> Run as another user',
    '  <program> [args]          Direct process execution',
    '  execute-assembly [args]         Run assembly with file picker',
    '  execute-assembly <name> [args]  Run assembly from library',
    '  inline-assembly [args]          Run in-process with file picker',
    '  inline-assembly <name> [args]   Run in-process from library',
    '  inline-assembly --mode bridge   Managed bridge capture',
    '  inline-assembly --mode auto     Same as bridge',
    '  bof-execute [args]                    Run .o/.obj with file picker',
    '  bof-execute <name.o|name.obj> [args]  Run BOF from library',
    '',
    '[ LIBRARY ]',
    '  assembly-upload <name>          Upload .exe to library',
    '  assembly-list                   List uploaded assemblies',
    '  assembly-delete <name>          Delete uploaded assembly',
    '  bof-upload <name.o|name.obj>          Upload BOF to library',
    '  bof-list                              List operator and built-in BOFs',
    '',
    '[ TRANSFER / CONTROL ]',
    '  download <remote>             Download from target',
    '  upload <remote>               Upload to target',
    '  sleep <sec> [jitter]          Set callback interval',
    '  interactive                   Start real-time session',
    '  exit                          Terminate beacon',
    '',
    '[ OPERATOR ]',
    '  Library tab                   Upload/delete operator .o, .obj, .exe files',
    '  help                          Show this reference',
    '  clear                         Clear terminal',
];

const HELP_TEXT_LINUX = [
    '',
    'BEBOP COMMANDS - LINUX',
    '',
    '[ TARGET ]',
    '  whoami / id               User context',
    '  hostname                  Hostname and kernel',
    '',
    '[ FILES ]',
    '  pwd                       Current directory',
    '  cd <path>                 Change directory',
    '  ls [path]                 List directory',
    '  cat <file>                Read file',
    '  mkdir <path>              Create directory',
    '  rm [-r] <path>            Delete file or directory',
    '  cp <src> <dst>            Copy file',
    '  mv <src> <dst>            Move or rename',
    '  chmod <mode> <path>       Change permissions',
    '',
    '[ PROCESS / ENV ]',
    '  ps                        Process list',
    '  kill [sig] <pid>          Send signal',
    '  env                       Environment variables',
    '  getenv <var>              One environment variable',
    '',
    '[ NETWORK ]',
    '  ipconfig / ifconfig       Network interfaces',
    '  netstat                   TCP/UDP connections',
    '  curl <url>                HTTP GET request',
    '  portscan <host> <ports>   TCP connect scan',
    '',
    '[ COLLECTION / REMOTE ]',
    '  triagedirectory [path]    Find sensitive files',
    '  ssh <user@host> <cmd>     Execute command over SSH',
    '',
    '[ TRANSFER / CONTROL ]',
    '  download <remote>         Download from target',
    '  upload <remote>           Upload to target',
    '  sleep <sec> [jitter]      Set callback interval',
    '  interactive               Start real-time session',
    '  socks5 start [port]       Start SOCKS5 proxy',
    '  socks5 stop               Stop SOCKS5 proxy',
    '  exit                      Terminate beacon',
    '',
    '[ SHELL / OPERATOR ]',
    '  shell <cmd>               Run via /bin/sh -c',
    '  help                      Show this reference',
    '  clear                     Clear terminal',
];

// ---- Utilities ----

const VALID_COMMANDS_LINUX = [
    'whoami', 'id', 'hostname', 'pwd', 'cd', 'ls', 'cat', 'mkdir',
    'rm', 'cp', 'mv', 'chmod', 'ps', 'kill', 'env', 'getenv',
    'ipconfig', 'ifconfig', 'netstat', 'curl', 'portscan',
    'triagedirectory', 'ssh',
    'sleep', 'interactive', 'shell', 'exit', 'help', 'clear',
    'download', 'upload', 'socks5',
];

const BUILTIN_BOF_COMMANDS = [
    'ldapsearch', 'adcs_enum', 'password-policy',
    'local-sessions', 'net-shares', 'regsession', 'netloggedon', 'schtasks-enum',
    'xpipe', 'msi-search', 'safe-harbor',
    'priv-always-install-elevated', 'priv-autologon', 'priv-credential-manager',
    'priv-hijackable-path', 'priv-modifiable-autorun', 'priv-modifiable-service',
    'priv-powershell-history', 'priv-token-privileges', 'priv-uac-status',
    'priv-unquoted-service-path',
    'sql-1434udp', 'sql-info', 'sql-whoami', 'sql-impersonate', 'sql-links',
    'sql-users', 'sql-databases', 'sql-tables', 'sql-columns', 'sql-rows',
    'sql-search', 'sql-query', 'sql-agentstatus', 'sql-checkrpc',
];

const VALID_COMMANDS = [
    'whoami', 'hostname', 'domain', 'getpid', 'getintegrity',
    'sysinfo', 'drives', 'env', 'getenv', 'pwd', 'cd', 'ls', 'dir',
    'cat', 'stat', 'mkdir', 'rm', 'rmdir', 'cp', 'mv', 'ps', 'kill',
    'ipconfig', 'arp', 'netstat', 'dns',
    'privs', 'groups', 'services', 'uptime',
    'reg_query', 'reg_set', 'clipboard', 'runas',
    'shell', 'sleep', 'interactive', 'exit', 'help', 'clear',
    'download', 'upload', 'socks5',
    'execute-assembly', 'inline-assembly', 'bof-execute', 'bof-upload', 'bof-list', 'assembly-upload', 'assembly-list', 'assembly-delete',
    ...BUILTIN_BOF_COMMANDS,
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
    const now = Math.floor(Date.now() / 1000);
    let changed = false;
    for (const b of Object.values(_beacons || {})) {
        const wasAlive = b.alive;
        b.alive = beaconIsAliveNow(b, now);
        if (b.alive !== wasAlive) changed = true;
    }
    if (changed) _renderSessionsFromCache();
}, 1000);

function beaconAliveDeadline(b) {
    const sleep = Math.max(0, parseInt(b && b.sleep, 10) || 0);
    const lastSeen = parseInt(b && b.last_seen, 10) || 0;
    return lastSeen + sleep + 10;
}

function beaconIsAliveNow(b, now) {
    if (!b) return false;
    if (b.mode === 'session') return true;
    const lastSeen = parseInt(b.last_seen, 10) || 0;
    if (!lastSeen) return false;
    return (now || Math.floor(Date.now() / 1000)) < beaconAliveDeadline(b);
}

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
    const cached = id == null ? null : _beacons[id];
    const isDelete = _killIsDead || (cached && !beaconIsAliveNow(cached));
    let deleteLastSeen = 0;
    cancelKill();
    if (id == null) return;
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    try {
        if (isDelete) {
            const fresh = await refreshBeaconBeforeDelete(tsUrl, id);
            if (fresh && beaconIsAliveNow(fresh)) {
                alert('Beacon checked in again. Delete canceled. Use Kill Beacon to terminate it.');
                return;
            }
            if (!fresh) {
                loadSessions();
                return;
            }
            deleteLastSeen = parseInt(fresh.last_seen, 10) || 0;
        }
        const deleteQuery = isDelete ? ('?delete=1&action=delete&last_seen=' + encodeURIComponent(String(deleteLastSeen))) : '';
        const resp = await authFetch(tsUrl + '/api/sessions/' + id + deleteQuery, { method: 'DELETE' });
        if (resp.status === 409) {
            alert((await resp.text()) || 'Delete canceled. Beacon is active.');
            loadSessions();
            return;
        }
        if (!resp.ok) throw new Error(await resp.text());
        if (isDelete) {
            delete _beacons[id];
            _renderSessionsFromCache();
        }
    } catch (e) {
        console.error('kill beacon:', e);
        alert('Beacon action failed: ' + (e && e.message ? e.message : e));
    }
    loadSessions();
}

async function refreshBeaconBeforeDelete(tsUrl, id) {
    const resp = await authFetch(tsUrl + '/api/sessions', { cache: 'no-store' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const beacons = await resp.json();
    let fresh = null;
    _beacons = {};
    (beacons || []).forEach(b => {
        b.alive = beaconIsAliveNow(b);
        if (String(b.id) === String(id)) fresh = Object.assign({}, b);
        _beacons[b.id] = b;
    });
    _renderSessionsFromCache();
    return fresh;
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

function _isFbTab(id) {
    return typeof id === 'string' && (id.startsWith('fb_') || id.startsWith('fbs_'));
}
function _fbTabBid(id) {
    if (typeof id === 'string' && id.startsWith('fbs_')) return parseInt(id.slice(4), 10);
    if (typeof id === 'string' && id.startsWith('fb_')) return parseInt(id.slice(3), 10);
    return id;
}

function _actualBid() {
    if (typeof beaconId === 'string') {
        if (beaconId.startsWith('fbs_')) return parseInt(beaconId.slice(4), 10);
        if (beaconId.startsWith('fb_')) return parseInt(beaconId.slice(3), 10);
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

// ---- ANSI constants ----

const ANSI = {
    reset: '\x1b[0m',
    amber: '\x1b[33m',
    cream: '\x1b[97m',
    red:   '\x1b[91m',
    dim:   '\x1b[2m',
};

const PROMPT_STR = ANSI.amber + '[BEBOP ~]$ ' + ANSI.reset;
