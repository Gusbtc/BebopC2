// filebrowser.js — file browser tree, operations, context menu

// ---- File Browser ----

const _fbStates = {};
const _pendingFileBrowserTasks = {};
let _fbRegistering = 0;
const _fbResultBuffer = [];
let _fbDeletePath = null;
let _fbDeleteBid = null;
const FB_CACHE_MAX_DIRS = 200;
const _fbSaveTimers = {};

function _fbGetState(bid, stateKey, isSession) {
    const key = stateKey || ('fb_' + bid);
    if (!_fbStates[key]) {
        const b = _beacons[bid];
        const isWindows = b && b.platform === 2;
        const sep = isWindows ? '\\' : '/';
        _fbStates[key] = {
            tree: {},
            expanded: new Set(),
            selected: null,
            root: isWindows ? 'C:\\' : '/',
            sep: sep,
            isSession: !!isSession,
            touched: {},
            cacheLoaded: false,
        };
    }
    return _fbStates[key];
}

function _fbTouch(state, path) {
    if (!state || !path) return;
    if (!state.touched) state.touched = {};
    state.touched[path] = Date.now();
}

function _fbSetNode(state, path, node) {
    if (!state || !path) return;
    if (!state.tree) state.tree = {};
    state.tree[path] = node || {};
    _fbTouch(state, path);
}

function _fbParentPath(path, sep, root) {
    if (!path || path === root) return root;
    const lastSep = path.lastIndexOf(sep);
    if (lastSep > 0) return path.slice(0, lastSep);
    return root;
}

function _fbSerializeForBeacon(bid, isSession) {
    const stateKey = (isSession ? 'fbs_' : 'fb_') + bid;
    const state = _fbStates[stateKey];
    if (!state || !state.tree || Object.keys(state.tree).length === 0) return null;

    const keep = {};
    const required = new Set();
    required.add(state.root);
    if (state.selected) required.add(_fbParentPath(state.selected, state.sep, state.root));
    for (const p of (state.expanded || new Set())) required.add(p);

    const keys = Object.keys(state.tree);
    const sorted = keys.slice().sort((a, b) => (state.touched[b] || 0) - (state.touched[a] || 0));
    const addPath = function(path) {
        if (!path || !state.tree[path] || Object.prototype.hasOwnProperty.call(keep, path)) return;
        const node = Object.assign({}, state.tree[path]);
        node.touched = state.touched[path] || node.touched || Date.now();
        keep[path] = node;
    };

    required.forEach(addPath);
    for (const path of sorted) {
        if (Object.keys(keep).length >= FB_CACHE_MAX_DIRS) break;
        addPath(path);
    }

    return {
        tree: keep,
        expanded: Array.from(state.expanded || []),
        selected: state.selected || '',
        root: state.root,
        sep: state.sep,
        saved_at: Math.floor(Date.now() / 1000),
    };
}

function _fbApplyCache(state, cache) {
    if (!state || !cache || !cache.tree) return false;
    state.tree = cache.tree || {};
    state.expanded = new Set(cache.expanded || []);
    state.selected = cache.selected || null;
    state.root = cache.root || state.root;
    state.sep = cache.sep || state.sep;
    state.touched = {};
    Object.keys(state.tree).forEach(path => {
        state.touched[path] = state.tree[path].touched || (cache.saved_at ? cache.saved_at * 1000 : Date.now());
        if (state.tree[path] && state.tree[path].touched) delete state.tree[path].touched;
    });
    return true;
}

async function _fbRestoreFromServer(bid, stateKey, isSession) {
    const state = _fbGetState(bid, stateKey, isSession);
    if (state.cacheLoaded) return false;
    state.cacheLoaded = true;

    let terminalState = _beaconStates[bid];
    if (!terminalState && typeof _loadTerminalFromServer === 'function') {
        terminalState = await _loadTerminalFromServer(bid);
        if (terminalState) _beaconStates[bid] = terminalState;
    }
    const cache = terminalState ? terminalState[isSession ? 'sessionFileBrowser' : 'fileBrowser'] : null;
    return _fbApplyCache(state, cache);
}

function _fbSaveDebounced(bid) {
    if (bid == null) return;
    clearTimeout(_fbSaveTimers[bid]);
    _fbSaveTimers[bid] = setTimeout(() => _fbPersistNow(bid), 700);
}

async function _fbPersistNow(bid) {
    const tsUrl = getTsUrl();
    if (!tsUrl || bid == null) return;
    try {
        const resp = await authFetch(tsUrl + '/api/terminal/' + bid);
        let current = {};
        if (resp.ok) current = await resp.json();

        const fileBrowser = _fbSerializeForBeacon(bid, false) || current.file_browser || null;
        const sessionFileBrowser = _fbSerializeForBeacon(bid, true) || current.session_file_browser || null;
        await authFetch(tsUrl + '/api/terminal/' + bid, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                output_log: current.output_log || [],
                cmd_history: current.cmd_history || [],
                poll_since: current.poll_since || 0,
                file_browser: fileBrowser,
                session_file_browser: sessionFileBrowser,
            }),
        });
    } catch (_) {}
}

function _fbNodeKey(parentPath, name, sep) {
    if (parentPath === sep || parentPath.endsWith(sep)) return parentPath + name;
    return parentPath + sep + name;
}

function _fbFormatSize(bytes) {
    if (bytes == null || bytes < 0) return '';
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

function _fbFlushBuffer() {
    const copy = _fbResultBuffer.splice(0);
    for (const data of copy) {
        if (data.label != null && _pendingFileBrowserTasks[data.label]) {
            _fbHandleResult(data);
        }
    }
}

function _fbSendTask(bid, path, useSession) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;

    const stateKey = useSession ? ('fbs_' + bid) : ('fb_' + bid);

    _fbRegistering++;

    const body = {
        beacon_id: bid,
        type: 12,
        code: 0,
        args: 'filebrowser ' + path,
    };
    if (!useSession) body.transport = 'http';

    authFetch(tsUrl + '/api/task', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    }).then(resp => {
        if (!resp.ok) {
            const state = _fbGetState(bid, stateKey, useSession);
            _fbSetNode(state, path, { error: 'task failed (HTTP ' + resp.status + ')' });
            _fbSaveDebounced(bid);
            _fbRender(bid, stateKey);
            return;
        }
        return resp.json();
    }).then(rj => {
        if (rj && rj.label) {
            _pendingFileBrowserTasks[rj.label] = { bid, path, stateKey, useSession };
            _tabLabels[rj.label] = stateKey;
        }
    }).catch(err => {
        const state = _fbGetState(bid, stateKey, useSession);
        _fbSetNode(state, path, { error: err.message });
        _fbSaveDebounced(bid);
        _fbRender(bid, stateKey);
    }).finally(() => {
        _fbRegistering--;
        if (_fbRegistering === 0 && _fbResultBuffer.length > 0) {
            _fbFlushBuffer();
        }
    });
}

function _fbHandleResult(data) {
    const info = _pendingFileBrowserTasks[data.label];
    if (!info) return;
    delete _pendingFileBrowserTasks[data.label];

    const { bid, path, stateKey, useSession } = info;
    const state = _fbGetState(bid, stateKey, useSession);

    try {
        const output = data.output || '';
        const jsonStart = output.indexOf('[');
        if (jsonStart < 0) {
            state.tree[path] = { error: output || 'empty response' };
            _fbRender(bid, stateKey);
            return;
        }
        const entries = JSON.parse(output.slice(jsonStart));
        _fbSetNode(state, path, { entries: entries });
    } catch (e) {
        _fbSetNode(state, path, { error: 'parse error: ' + e.message });
    }
    _fbSaveDebounced(bid);
    _fbRender(bid, stateKey);
}

function _fbRender(bid, stateKey) {
    const container = document.getElementById('fb-tree');
    if (!container) return;
    const sk = stateKey || beaconId;
    if (!_isFbTab(sk)) return;
    if (sk !== beaconId) return;

    const isSession = sk.startsWith('fbs_');
    const state = _fbGetState(bid, sk, isSession);
    container.innerHTML = '';
    _fbRenderChildren(container, state, state.root, 0, bid);
    _fbUpdateDetail(bid);
}

function _fbRenderChildren(container, state, parentPath, depth, bid) {
    const node = state.tree[parentPath];
    if (!node) {
        // Loading
        const spinner = document.createElement('div');
        spinner.className = 'fb-empty';
        spinner.style.paddingLeft = ((depth + 1) * 16 + 24) + 'px';
        spinner.innerHTML = '<div class="fb-spinner"></div>';
        container.appendChild(spinner);
        return;
    }
    if (node.error) {
        const errEl = document.createElement('div');
        errEl.className = 'fb-error';
        errEl.style.paddingLeft = ((depth + 1) * 16 + 24) + 'px';
        errEl.textContent = node.error;
        container.appendChild(errEl);
        return;
    }
    if (!node.entries || node.entries.length === 0) {
        const emptyEl = document.createElement('div');
        emptyEl.className = 'fb-empty';
        emptyEl.style.paddingLeft = ((depth + 1) * 16 + 24) + 'px';
        emptyEl.textContent = '(empty)';
        container.appendChild(emptyEl);
        return;
    }

    // Sort: directories first, then alphabetical
    const sorted = node.entries.slice().sort((a, b) => {
        const aDir = a.type === 'dir' || a.type === 'link_dir' ? 0 : 1;
        const bDir = b.type === 'dir' || b.type === 'link_dir' ? 0 : 1;
        if (aDir !== bDir) return aDir - bDir;
        return (a.name || '').localeCompare(b.name || '');
    });

    for (const entry of sorted) {
        const isDir = entry.type === 'dir' || entry.type === 'link_dir';
        const isLink = entry.type === 'link' || entry.type === 'link_dir';
        const fullPath = _fbNodeKey(parentPath, entry.name, state.sep);
        const isExpanded = state.expanded.has(fullPath);
        const isSelected = state.selected === fullPath;

        const row = document.createElement('div');
        row.className = 'fb-node' + (isSelected ? ' selected' : '');
        row.style.paddingLeft = (depth * 16 + 8) + 'px';

        // Toggle arrow
        const toggle = document.createElement('span');
        toggle.className = 'fb-node-toggle' + (isDir ? (isExpanded ? ' expanded' : '') : ' spacer');
        if (isDir) {
            toggle.innerHTML = '<svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor"><path d="M2.5 1L8 5L2.5 9Z"/></svg>';
        }
        row.appendChild(toggle);

        // Icon
        const icon = document.createElement('img');
        icon.className = 'fb-node-icon';
        icon.src = isDir ? '/static/img/folder.png' : '/static/img/file.png';
        row.appendChild(icon);

        // Name
        const nameSpan = document.createElement('span');
        nameSpan.className = 'fb-node-name' + (isDir ? ' dir-name' : '') + (isLink ? ' link-name' : '');
        nameSpan.textContent = entry.name;
        row.appendChild(nameSpan);

        // Link target
        if (isLink && entry.target) {
            const targetSpan = document.createElement('span');
            targetSpan.className = 'fb-node-target';
            targetSpan.textContent = '-> ' + entry.target;
            row.appendChild(targetSpan);
        }

        // Refresh button for dirs
        if (isDir) {
            const refresh = document.createElement('span');
            refresh.className = 'fb-node-refresh';
            refresh.textContent = '↻';
            refresh.addEventListener('click', (function(b, p) { return function(e) { e.stopPropagation(); _fbRefreshDir(b, p); }; })(bid, fullPath));
            row.appendChild(refresh);
        }

        // Click handler
        row.addEventListener('click', (function(b, fp, dir) { return function() {
            if (dir) _fbToggleDir(b, fp);
            else _fbSelectItem(b, fp);
        }; })(bid, fullPath, isDir));

        // Right-click handler
        row.addEventListener('contextmenu', (function(b, fp) { return function(e) {
            e.preventDefault();
            _fbSelectItem(b, fp);
            _fbShowContextMenu(e, b, fp);
        }; })(bid, fullPath));

        // Store entry data on the row for detail lookup
        row._fbEntry = entry;
        row._fbPath = fullPath;

        container.appendChild(row);

        // Render children if expanded
        if (isDir && isExpanded) {
            _fbRenderChildren(container, state, fullPath, depth + 1, bid);
        }
    }
}

function _fbUpdateDetail(bid) {
    const textEl = document.getElementById('fb-detail-text');
    if (!textEl) return;
    const state = _fbGetState(bid, beaconId);
    if (!state.selected) {
        textEl.textContent = 'Select an item to view details';
        return;
    }

    // Find the entry
    const sep = state.sep;
    const lastSep = state.selected.lastIndexOf(sep);
    const parentPath = lastSep > 0 ? state.selected.slice(0, lastSep) : state.root;
    const name = lastSep >= 0 ? state.selected.slice(lastSep + 1) : state.selected;
    const parentNode = state.tree[parentPath];
    if (!parentNode || !parentNode.entries) {
        textEl.textContent = state.selected;
        return;
    }
    const entry = parentNode.entries.find(function(e) { return e.name === name; });
    if (!entry) {
        textEl.textContent = state.selected;
        return;
    }

    let detail = '<span class="fb-detail-label">PATH</span><span class="fb-detail-value">' + escapeHtml(state.selected) + '</span>';
    if (entry.size != null && entry.type !== 'dir') {
        detail += '<span class="fb-detail-label" style="margin-left:16px">SIZE</span><span class="fb-detail-value">' + _fbFormatSize(entry.size) + '</span>';
    }
    if (entry.mode) {
        detail += '<span class="fb-detail-label" style="margin-left:16px">MODE</span><span class="fb-detail-value">' + escapeHtml(entry.mode) + '</span>';
    }
    if (entry.owner) {
        detail += '<span class="fb-detail-label" style="margin-left:16px">OWNER</span><span class="fb-detail-value">' + escapeHtml(entry.owner) + '</span>';
    }
    textEl.innerHTML = detail;
}

function _fbToggleDir(bid, path) {
    const sk = beaconId;
    const isSession = typeof sk === 'string' && sk.startsWith('fbs_');
    const state = _fbGetState(bid, sk, isSession);
    if (state.expanded.has(path)) {
        state.expanded.delete(path);
    } else {
        state.expanded.add(path);
        if (!state.tree[path]) {
            _fbSendTask(bid, path, isSession);
        }
    }
    state.selected = path;
    _fbSaveDebounced(bid);
    _fbRender(bid, sk);
}

function _fbRefreshDir(bid, path) {
    const sk = beaconId;
    const isSession = typeof sk === 'string' && sk.startsWith('fbs_');
    const state = _fbGetState(bid, sk, isSession);
    delete state.tree[path];
    if (state.touched) delete state.touched[path];
    state.expanded.add(path);
    _fbSaveDebounced(bid);
    _fbSendTask(bid, path, isSession);
    _fbRender(bid, sk);
}

function _fbSelectItem(bid, path) {
    const sk = beaconId;
    const isSession = typeof sk === 'string' && sk.startsWith('fbs_');
    const state = _fbGetState(bid, sk, isSession);
    state.selected = path;
    _fbSaveDebounced(bid);
    _fbRender(bid, sk);
}

function openFileBrowser(bid, useSession) {
    const tabKey = useSession ? ('fbs_' + bid) : ('fb_' + bid);

    if (_openTabs.has(tabKey)) {
        _switchTab(tabKey);
        document.body.classList.add('panel-open');
        return;
    }

    _saveBeaconState(beaconId);

    beaconId = tabKey;

    const termEl = document.getElementById('terminal');
    const shellEl = document.getElementById('shell-terminal');
    const fbEl = document.getElementById('file-browser');
    if (termEl) termEl.style.display = 'none';
    if (shellEl) shellEl.style.display = 'none';
    if (fbEl) fbEl.style.display = 'flex';

    document.body.classList.add('panel-open');

    const stateKey = tabKey;
    const state = _fbGetState(bid, stateKey, useSession);

    const cached = _beacons && _beacons[bid];
    const hostname = (cached && cached.hostname) || '?';
    _openTabs.set(tabKey, { hostname: hostname, fbSession: !!useSession });
    _renderTabs();
    _saveTabs();

    _fbRestoreFromServer(bid, stateKey, useSession).finally(function() {
        if (!state.tree[state.root]) {
            _fbSendTask(bid, state.root, useSession);
        }
        state.expanded.add(state.root);
        _fbSaveDebounced(bid);
        _fbRender(bid, stateKey);
    });
}

function _fbShowContextMenu(e, bid, path) {
    const menu = document.getElementById('fb-context-menu');
    if (!menu) return;
    menu.innerHTML = '';

    const state = _fbGetState(bid, beaconId);
    const sep = state.sep;
    const lastSep = path.lastIndexOf(sep);
    const parentPath = lastSep > 0 ? path.slice(0, lastSep) : state.root;
    const name = lastSep >= 0 ? path.slice(lastSep + 1) : path;
    const parentNode = state.tree[parentPath];
    const entry = parentNode && parentNode.entries ? parentNode.entries.find(function(en) { return en.name === name; }) : null;
    const isDir = entry && (entry.type === 'dir' || entry.type === 'link_dir');

    _fbAddMenuItem(menu, 'Copy Path', function() { _fbCopyPath(path); });
    _fbAddMenuSep(menu);

    if (!isDir) {
        _fbAddMenuItem(menu, 'Download', function() { _fbDownload(bid, path); });
        _fbAddMenuItem(menu, 'Cat', function() { _fbCat(bid, path); });
        _fbAddMenuSep(menu);
    }

    if (isDir) {
        _fbAddMenuItem(menu, 'Upload Here', function() { _fbUploadHere(bid, path); });
        _fbAddMenuItem(menu, 'New Folder', function() { _fbNewFolder(bid, path); });
        _fbAddMenuSep(menu);
    }

    const dangerItem = document.createElement('div');
    dangerItem.className = 'context-item ctx-danger';
    dangerItem.textContent = 'Delete';
    dangerItem.onclick = function() { _fbDeleteConfirm(bid, path); _fbHideContextMenu(); };
    menu.appendChild(dangerItem);

    menu.style.display = 'block';
    const mx = Math.min(e.clientX, window.innerWidth - menu.offsetWidth - 8);
    const my = Math.min(e.clientY, window.innerHeight - menu.offsetHeight - 8);
    menu.style.left = mx + 'px';
    menu.style.top = my + 'px';

    setTimeout(function() {
        document.addEventListener('click', _fbHideContextMenu, { once: true });
    }, 0);
}

function _fbHideContextMenu() {
    const menu = document.getElementById('fb-context-menu');
    if (menu) menu.style.display = 'none';
}

function _fbAddMenuItem(menu, label, onclick) {
    const item = document.createElement('div');
    item.className = 'context-item';
    item.textContent = label;
    item.onclick = function() { onclick(); _fbHideContextMenu(); };
    menu.appendChild(item);
}

function _fbAddMenuSep(menu) {
    const sep = document.createElement('div');
    sep.className = 'context-separator';
    menu.appendChild(sep);
}

function _fbCopyPath(path) {
    navigator.clipboard.writeText(path).catch(function() {});
}

function _fbDownload(bid, path) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    const b = _beacons[bid];
    const isSession = b && b.mode === 'session';
    const body = { beacon_id: bid, type: 4, code: 0, args: path };
    if (!isSession) body.transport = 'http';
    authFetch(tsUrl + '/api/task', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    }).then(function(resp) {
        if (!resp.ok) return;
        return resp.json();
    }).then(function(rj) {
        if (rj && rj.label) _tabLabels[rj.label] = 'fb_' + bid;
    }).catch(function() {});
}

async function _fbCat(bid, path) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    const b = _beacons[bid];
    const isSession = b && b.mode === 'session';
    const body = { beacon_id: bid, type: 12, code: 0, args: 'cat ' + path };
    if (!isSession) body.transport = 'http';

    const termTabId = isSession ? 'sess_' + bid : bid;
    await openTerminal(termTabId);

    appendLine('[+] cat queued: ' + path, 'hint');

    const resp = await authFetch(tsUrl + '/api/task', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    if (resp.ok) {
        const rj = await resp.json();
        if (rj && rj.label && !isSession) _tabLabels[rj.label] = beaconId;
        _pendingTasks[beaconId] = (_pendingTasks[beaconId] || 0) + 1;
    }
}

function _fbDeleteConfirm(bid, path) {
    _fbDeleteBid = bid;
    _fbDeletePath = path;
    const el = document.getElementById('fb-delete-target');
    if (el) el.textContent = path;
    const modal = document.getElementById('fb-delete-modal');
    if (modal) modal.style.display = 'flex';
}

function cancelFbDelete() {
    _fbDeleteBid = null;
    _fbDeletePath = null;
    const modal = document.getElementById('fb-delete-modal');
    if (modal) modal.style.display = 'none';
}

function confirmFbDelete() {
    const bid = _fbDeleteBid;
    const path = _fbDeletePath;
    cancelFbDelete();
    if (bid == null || !path) return;

    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    const b = _beacons[bid];
    const isSession = b && b.mode === 'session';
    const body = { beacon_id: bid, type: 12, code: 0, args: 'rm ' + path };
    if (!isSession) body.transport = 'http';
    authFetch(tsUrl + '/api/task', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    }).then(function() {
        // Refresh parent
        const state = _fbGetState(bid, beaconId);
        const sep = state.sep;
        const lastSep = path.lastIndexOf(sep);
        const parentPath = lastSep > 0 ? path.slice(0, lastSep) : state.root;
        setTimeout(function() { _fbRefreshDir(bid, parentPath); }, 1500);
    }).catch(function() {});
}

function _fbUploadHere(bid, dirPath) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    let picker = document.getElementById('fb-upload-picker');
    if (!picker) {
        picker = document.createElement('input');
        picker.type = 'file';
        picker.id = 'fb-upload-picker';
        picker.style.display = 'none';
        document.body.appendChild(picker);
    }
    picker.onchange = function() {
        const file = picker.files[0];
        if (!file) return;
        const state = _fbGetState(bid, beaconId);
        const dest = _fbNodeKey(dirPath, file.name, state.sep);
        const fd = new FormData();
        fd.append('beacon_id', String(bid));
        fd.append('dest_path', dest);
        fd.append('file', file);
        authFetch(tsUrl + '/api/upload', { method: 'POST', body: fd }).then(function(r) {
            if (!r.ok) return;
            return r.json();
        }).then(function(j) {
            if (j && j.label) _tabLabels[j.label] = 'fb_' + bid;
            setTimeout(function() { _fbRefreshDir(bid, dirPath); }, 3000);
        }).catch(function() {});
        picker.value = '';
    };
    picker.click();
}

function _fbNewFolder(bid, dirPath) {
    let modal = document.getElementById('fb-newfolder-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'fb-newfolder-modal';
        modal.className = 'modal-backdrop';
        modal.hidden = true;
        modal.innerHTML = [
            '<div class="modal-card" role="dialog" aria-modal="true">',
            '  <span class="modal-tab">// new folder</span>',
            '  <button type="button" class="modal-close" aria-label="Close">&times;</button>',
            '  <h3 class="modal-title">Create Folder</h3>',
            '  <p class="modal-subtitle">enter a name for the new directory</p>',
            '  <div class="modal-row"><div class="modal-field" style="flex:1">',
            '    <label for="fb-newfolder-input">folder name</label>',
            '    <input id="fb-newfolder-input" type="text" placeholder="my-folder" autocomplete="off" spellcheck="false">',
            '  </div></div>',
            '  <div class="modal-footer"><div class="modal-actions">',
            '    <button type="button" class="btn-ghost" data-action="cancel">cancel</button>',
            '    <button type="button" data-action="create">create</button>',
            '  </div></div>',
            '</div>',
        ].join('');
        document.body.appendChild(modal);
        modal.addEventListener('click', function(e) { if (e.target === modal) closeFbNewFolder(); });
        modal.querySelector('.modal-close').addEventListener('click', closeFbNewFolder);
        modal.querySelector('[data-action="cancel"]').addEventListener('click', closeFbNewFolder);
    }

    const input = document.getElementById('fb-newfolder-input');
    input.value = '';
    modal.hidden = false;
    requestAnimationFrame(function() { modal.classList.add('open'); });
    setTimeout(function() { input.focus(); }, 40);

    function closeFbNewFolder() {
        modal.classList.remove('open');
        setTimeout(function() { modal.hidden = true; }, 180);
    }

    function submit() {
        const name = input.value.trim();
        if (!name) return;
        closeFbNewFolder();
        const tsUrl = getTsUrl();
        if (!tsUrl) return;
        const state = _fbGetState(bid, beaconId);
        const fullPath = _fbNodeKey(dirPath, name, state.sep);
        const b = _beacons[bid];
        const isSession = b && b.mode === 'session';
        const body = { beacon_id: bid, type: 12, code: 0, args: 'mkdir ' + fullPath };
        if (!isSession) body.transport = 'http';
        authFetch(tsUrl + '/api/task', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        }).then(function() {
            setTimeout(function() { _fbRefreshDir(bid, dirPath); }, 1500);
        }).catch(function() {});
    }

    const createBtn = modal.querySelector('[data-action="create"]');
    const handler = function() { submit(); createBtn.removeEventListener('click', handler); };
    createBtn.addEventListener('click', handler);

    const keyHandler = function(e) {
        if (e.key === 'Escape') { closeFbNewFolder(); input.removeEventListener('keydown', keyHandler); }
        else if (e.key === 'Enter') { submit(); input.removeEventListener('keydown', keyHandler); }
    };
    input.addEventListener('keydown', keyHandler);
}
