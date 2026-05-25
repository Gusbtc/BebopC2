// websocket.js — operator WebSocket, message handlers, initialization

// ── Operator WebSocket (replaces polling) ──────────────────────────
let _operatorWs = null;
let _wsReconnectDelay = 1000;
let _wsReconnectTimer = null;
let _operatorWsConnecting = false;

async function connectOperatorWs() {
    if (_operatorWsConnecting || (_operatorWs && _operatorWs.readyState <= WebSocket.OPEN)) return;

    _operatorWsConnecting = true;
    let wsUrl;
    try {
        wsUrl = await makeWebSocketURL('/ws/operator');
    } catch (_) {
        _operatorWsConnecting = false;
        _wsReconnectTimer = setTimeout(() => {
            connectOperatorWs();
        }, _wsReconnectDelay);
        _wsReconnectDelay = Math.min(_wsReconnectDelay * 2, 30000);
        return;
    }
    _operatorWs = new WebSocket(wsUrl);
    _operatorWsConnecting = false;

    _operatorWs.onopen = () => {
        _wsReconnectDelay = 1000;
        updateConnIndicator(true);
    };

    _operatorWs.onclose = () => {
        _operatorWs = null;
        updateConnIndicator(false);
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
        case 'library':
            _handleLibraryMsg(action, data);
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
        _beacons[data.id] = data;
        _renderSessionsFromCache();
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

    // File browser result intercept + buffering
    if (data.label != null && _fbRegistering > 0 && !_pendingFileBrowserTasks[data.label]) {
        _fbResultBuffer.push(data);
        return;
    }
    if (data.label != null && _pendingFileBrowserTasks[data.label]) {
        _fbHandleResult(data);
        return;
    }

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
        exit_code: data.exit_code,
        stdout: data.stdout || '',
        stderr: data.stderr || '',
        exception: data.exception || '',
        duration_ms: data.duration_ms || 0,
        truncated: !!data.truncated,
        mode: data.mode || '',
        diagnostics: data.diagnostics || '',
        received_at: data.received_at
    };

    if (result.type === 3) {
        appendLine('[+] ' + (result.output || 'upload complete'), 'output');
        if (_term) _term.scrollToBottom();
        _serverSaveDirty = true;
        return;
    } else if (result.type === 4) {
        appendLine('[+] exfil complete: ' + (result.filename || '?'), 'output');
        appendLine('    check the LOOT tab to download or delete', 'hint');
        loadLootPanel();
    } else if (result.type === 2) {
        appendLine('[+] ' + (result.output || 'config updated'), 'hint');
    } else if (_isInlineAssemblyResult(result)) {
        appendLine(_formatInlineAssemblyOutput(result), 'output');
    } else {
        if (result.output) {
            appendLine(result.output, 'output');
        } else {
            appendLine('[*] task completed (no output)', 'hint');
        }
    }
    if (data.received_at > pollSince) pollSince = data.received_at;
    if (_term) _term.scrollToBottom();
    if (!_promptVisible) _writePrompt();
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
        if (_eventLog.length === 0 && typeof _renderEventEmpty === 'function') {
            _renderEventEmpty();
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

function _handleLibraryMsg(action, data) {
    if (action === 'add' || action === 'delete' || action === 'sync') {
        loadLibraryPanel();
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
    const row = document.querySelector('#beacons-table tbody tr[data-beacon-id="' + beaconId + '"], #beacons-table tbody tr[data-session-id="' + beaconId + '"]');
    if (!row) return;
    const cell = row.cells[1];
    if (!cell) return;
    let badge = cell.querySelector('.badge-socks5');
    if (!badge) {
        badge = document.createElement('span');
        badge.className = 'badge-socks5';
        cell.appendChild(badge);
    }
    badge.textContent = 'SOCKS';
}

function removeSocksBadge(beaconId) {
    const row = document.querySelector('#beacons-table tbody tr[data-beacon-id="' + beaconId + '"], #beacons-table tbody tr[data-session-id="' + beaconId + '"]');
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
        if (_beacons && Object.keys(_beacons).length > 0) {
            _renderSessionsFromCache();
            return;
        }
        if (_currentView === 'map') {
            renderMap([]);
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
        loadSessions();
        loadEventLog();
        loadLootPanel();
        loadLibraryPanel();

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
        const _restoredIsFb = _isFbTab(_restoredActiveId);
        if (_restoredIsFb) {
            beaconId = _restoredActiveId;
            document.body.classList.add('panel-open');
            const termEl = document.getElementById('terminal');
            const fbEl = document.getElementById('file-browser');
            if (termEl) termEl.style.display = 'none';
            if (fbEl) fbEl.style.display = 'flex';
            _renderTabs();
            const _fbRestoreId = _restoredActiveId;
            const _waitForSync = setInterval(function() {
                const fbBid = _fbTabBid(_fbRestoreId);
                if (!_beacons[fbBid]) return;
                clearInterval(_waitForSync);
                const isSession = typeof _fbRestoreId === 'string' && _fbRestoreId.startsWith('fbs_');
                const state = _fbGetState(fbBid, _fbRestoreId, isSession);
                const renderFileBrowser = function() {
                    if (!state.tree[state.root]) {
                        state.expanded.add(state.root);
                        _fbSendTask(fbBid, state.root, isSession);
                    }
                    _fbRender(fbBid, _fbRestoreId);
                };
                if (typeof _fbRestoreFromServer === 'function') {
                    _fbRestoreFromServer(fbBid, _fbRestoreId, isSession).finally(renderFileBrowser);
                } else {
                    renderFileBrowser();
                }
            }, 200);
        } else {
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
                if (!_promptVisible) _writePrompt();
                if (_term) { _term.scrollToBottom(); _term.focus(); }
            });
        }
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

document.addEventListener('DOMContentLoaded', initChatForm);
