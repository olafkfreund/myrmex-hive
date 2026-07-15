        let currentTab = 'dashboard';
        let connectedAgentsDetails = {};
        let toolsCatalog = {};
        let currentConfigData = null;
        let authToken = localStorage.getItem('mcp_hive_token');

        // Check if token is passed in query string
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.has('token')) {
            authToken = urlParams.get('token');
            localStorage.setItem('mcp_hive_token', authToken);
            // clean up URL query string
            const url = new URL(window.location.href);
            url.searchParams.delete('token');
            window.history.replaceState({}, document.title, url.pathname);
        }

        function checkAuth() {
            if (!authToken) {
                document.getElementById('login-modal').style.display = 'flex';
                return false;
            }
            document.getElementById('login-modal').style.display = 'none';
            return true;
        }

        function submitLoginToken() {
            const input = document.getElementById('login-token-input').value.trim();
            if (input) {
                authToken = input;
                localStorage.setItem('mcp_hive_token', authToken);
                document.getElementById('login-modal').style.display = 'none';
                initPortal();
            }
        }

        async function authFetch(url, options = {}) {
            if (!options.headers) {
                options.headers = {};
            }
            if (authToken) {
                options.headers['Authorization'] = 'Bearer ' + authToken;
            }
            try {
                const res = await fetch(url, options);
                if (res.status === 401) {
                    localStorage.removeItem('mcp_hive_token');
                    authToken = null;
                    checkAuth();
                    throw new Error('Unauthorized');
                }
                return res;
            } catch (err) {
                if (err.message === 'Unauthorized') {
                    throw err;
                }
                throw err;
            }
        }

        function switchTab(tabId) {
            if (!checkAuth()) return;
            // aria-current tracks .active so screen readers announce which
            // section is showing. Not role="tab"/aria-selected: that pattern
            // obliges arrow-key navigation, and a role without its behaviour is
            // worse than no role at all.
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('active');
                btn.removeAttribute('aria-current');
            });
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            const activeBtn = Array.from(document.querySelectorAll('.tab-btn')).find(btn => btn.innerText.toLowerCase() === tabId.toLowerCase() || (tabId === 'keys' && btn.innerText.includes('SSH')));
            if (activeBtn) {
                activeBtn.classList.add('active');
                activeBtn.setAttribute('aria-current', 'true');
            }
            
            const targetContent = document.getElementById(tabId);
            if (targetContent) targetContent.classList.add('active');

            currentTab = tabId;
            // Leaving the Fleet tab must halt its auto-refresh timer so we
            // never keep polling /api/fleet in the background.
            if (tabId !== 'fleet') {
                stopFleetAutoRefresh();
            }
            if (tabId === 'playground') {
                loadTools();
            } else if (tabId === 'keys') {
                loadKeys();
            } else if (tabId === 'config') {
                loadConfig();
            } else if (tabId === 'fleet') {
                loadFleet();
            } else if (tabId === 'approvals') {
                loadApprovals();
            } else if (tabId === 'audit') {
                loadAudit();
            }
        }

        // --- Audit log viewer (#111) -------------------------------------
        //
        // Read-only. The gateway verifies every signature server-side against
        // the live host key; this only renders the verdict. It deliberately
        // never computes or infers "valid" itself — a portal that guessed
        // green would be worse than no viewer at all.
        let auditDebounce = null;
        function debouncedLoadAudit() {
            clearTimeout(auditDebounce);
            auditDebounce = setTimeout(loadAudit, 250);
        }

        function clearAuditFilters() {
            ['audit-f-actor', 'audit-f-agent', 'audit-f-action', 'audit-f-since', 'audit-f-until']
                .forEach(id => { document.getElementById(id).value = ''; });
            loadAudit();
        }

        // datetime-local gives "2026-07-15T10:30"; the log stores RFC3339 UTC.
        function auditTimeParam(id) {
            const v = document.getElementById(id).value;
            if (!v) return '';
            const d = new Date(v);
            return isNaN(d) ? '' : d.toISOString();
        }

        async function loadAudit() {
            const tbody = document.getElementById('audit-tbody');
            const alertBox = document.getElementById('audit-alert');
            alertBox.innerHTML = '';

            const params = new URLSearchParams();
            const actor = document.getElementById('audit-f-actor').value.trim();
            const agent = document.getElementById('audit-f-agent').value.trim();
            const action = document.getElementById('audit-f-action').value.trim();
            const since = auditTimeParam('audit-f-since');
            const until = auditTimeParam('audit-f-until');
            if (actor) params.set('actor', actor);
            if (agent) params.set('agent', agent);
            if (action) params.set('action', action);
            if (since) params.set('since', since);
            if (until) params.set('until', until);

            try {
                const res = await authFetch('/api/audit?' + params.toString());
                if (res.status === 404) {
                    tbody.innerHTML = '<tr class="empty-row"><td colspan="9">Audit logging is not enabled. Set <code>audit_log_path</code> in the gateway config.</td></tr>';
                    document.getElementById('audit-count').innerText = 'disabled';
                    return;
                }
                if (res.status === 403) {
                    tbody.innerHTML = '<tr class="empty-row"><td colspan="9">The audit log is admin-only.</td></tr>';
                    document.getElementById('audit-count').innerText = 'forbidden';
                    return;
                }
                if (!res.ok) throw new Error(await res.text());
                const data = await res.json();
                const s = data.summary || {};

                // The summary covers the WHOLE log, not the filtered view: the
                // PrevSig chain only means anything over the complete file, so
                // a count derived from a filter would misrepresent it.
                if (s.tampered) {
                    alertBox.innerHTML = '<div class="alert alert-danger">' +
                        '<strong>Audit log verification FAILED.</strong> ' +
                        htmlEscape(String(s.signature_failures || 0)) + ' signature failure(s), ' +
                        htmlEscape(String(s.chain_failures || 0)) + ' chain break(s) across ' +
                        htmlEscape(String(s.total || 0)) + ' entries. First problem on line ' +
                        htmlEscape(String(s.first_bad_line || 0)) + ': ' +
                        htmlEscape(s.first_bad_reason || '') + '</div>';
                } else if (s.total > 0) {
                    alertBox.innerHTML = '<div class="alert alert-success">' +
                        'All ' + htmlEscape(String(s.total)) + ' entries verified against the gateway host key: ' +
                        'signatures valid, chain intact.</div>';
                }

                document.getElementById('audit-count').innerText =
                    data.filtered + ' of ' + (s.total || 0) + ' entries' + (data.truncated ? ' (truncated)' : '');

                const rows = data.entries || [];
                if (rows.length === 0) {
                    tbody.innerHTML = '<tr class="empty-row"><td colspan="9">No entries match these filters.</td></tr>';
                    return;
                }

                tbody.innerHTML = rows.map(e => {
                    let sigCell;
                    if (e.signature_valid && e.chain_valid) {
                        sigCell = '<span class="status-badge status-online">verified</span>';
                    } else if (!e.signature_valid && e.chain_valid) {
                        sigCell = '<span class="status-badge status-offline" title="' + htmlEscape(e.verify_error || '') + '">tampered</span>';
                    } else if (e.signature_valid && !e.chain_valid) {
                        // Signature fine, chain broken: an entry was removed or
                        // reordered around this one.
                        sigCell = '<span class="status-badge status-offline" title="' + htmlEscape(e.verify_error || '') + '">chain break</span>';
                    } else {
                        sigCell = '<span class="status-badge status-offline" title="' + htmlEscape(e.verify_error || '') + '">invalid</span>';
                    }
                    return '<tr>' +
                        '<td>' + htmlEscape(String(e.line)) + '</td>' +
                        '<td>' + htmlEscape(e.timestamp || '') + '</td>' +
                        '<td>' + htmlEscape(e.token_id || '') + '</td>' +
                        '<td>' + htmlEscape(e.role || '') + '</td>' +
                        '<td>' + htmlEscape(e.action || '') + '</td>' +
                        '<td>' + htmlEscape(e.agent_id || '') + '</td>' +
                        '<td><code>' + htmlEscape(e.command || '') + '</code></td>' +
                        '<td>' + htmlEscape(e.status || '') + '</td>' +
                        '<td>' + sigCell + '</td>' +
                        '</tr>';
                }).join('');
            } catch (e) {
                alertBox.innerHTML = '<div class="alert alert-danger">Failed to load audit log: ' + htmlEscape(e.message) + '</div>';
            }
        }

        async function fetchStatus() {
            if (!authToken) return;
            try {
                const res = await authFetch('/api/status');
                if (!res.ok) throw new Error('Failed to fetch status');
                const data = await res.json();

                // Update counts
                document.getElementById('count-agents').innerText = data.agents ? data.agents.length : 0;

                // Pending approvals badge (#112). fetchStatus already polls
                // every 5s from whichever tab you are on, so this is also the
                // "cleared in real time" half — no extra timer or endpoint.
                const badge = document.getElementById('approvals-badge');
                const pending = data.pending_approvals || 0;
                badge.textContent = pending;
                badge.hidden = pending === 0;
                badge.setAttribute('aria-label', pending + ' pending approval' + (pending === 1 ? '' : 's'));
                document.getElementById('count-upstreams').innerText = data.upstreams ? data.upstreams.length : 0;

                // Update Edge Agents List
                const agentsList = document.getElementById('agents-list');
                if (!data.agents || data.agents.length === 0) {
                    agentsList.innerHTML = '<li class="item-row"><span class="item-name">No agents connected. Connect agents outbound to port 2222.</span></li>';
                } else {
                    agentsList.innerHTML = data.agents.map(agent => {
                        connectedAgentsDetails[agent.id] = agent;
                        return '<li class="item-row" style="cursor: pointer; transition: all 0.2s;" onclick="showAgentDetails(\'' + agent.id + '\')">' +
                            '<span class="item-name">' + agent.id + '</span>' +
                            '<span class="item-meta" style="color: var(--accent);">' + agent.ip + ' | ' + agent.os_version + '</span>' +
                            '</li>';
                    }).join('');
                }

                // Update Upstream List
                const upstreamsList = document.getElementById('upstreams-list');
                if (!data.upstreams || data.upstreams.length === 0) {
                    upstreamsList.innerHTML = '<li class="item-row"><span class="item-name">No upstream servers configured.</span></li>';
                } else {
                    upstreamsList.innerHTML = data.upstreams.map(up => {
                        let dotClass = 'connecting';
                        if (up.status === 'connected') dotClass = 'connected';
                        else if (up.status.startsWith('error')) dotClass = 'error';

                        return '<li class="item-row">' +
                            '<span class="item-name"><span class="status-dot ' + dotClass + '"></span>' + up.name + '</span>' +
                            '<div class="upstream-actions">' +
                                '<span class="item-meta" style="margin-right: 15px;">' + up.status + ' (' + up.url + ')</span>' +
                                '<button class="btn btn-danger" style="padding: 4px 8px; font-size: 11px;" onclick="deleteUpstream(\'' + up.name + '\')">Remove</button>' +
                            '</div>' +
                        '</li>';
                    }).join('');
                }
            } catch (err) {
                console.error(err);
            }
        }

        async function loadTools() {
            const playToolSelect = document.getElementById('play-tool');
            playToolSelect.innerHTML = '<option value="">Loading tools...</option>';
            try {
                const res = await authFetch('/api/tools');
                if (!res.ok) throw new Error('Failed to load tools');
                const data = await res.json();
                
                toolsCatalog = {};
                playToolSelect.innerHTML = '<option value="">-- Select a tool to run --</option>';

                if (data.tools && data.tools.length > 0) {
                    data.tools.forEach(t => {
                        toolsCatalog[t.name] = t;
                        const option = document.createElement('option');
                        option.value = t.name;
                        option.innerText = t.name;
                        playToolSelect.appendChild(option);
                    });
                } else {
                    playToolSelect.innerHTML = '<option value="">No tools registered. Wait for agents.</option>';
                }
            } catch (err) {
                playToolSelect.innerHTML = '<option value="">Error loading tools</option>';
                console.error(err);
            }
        }

        function onToolSelect() {
            const toolName = document.getElementById('play-tool').value;
            const descBox = document.getElementById('tool-description-box');
            const descEl = document.getElementById('tool-description');
            const argsArea = document.getElementById('play-args');

            if (!toolName || !toolsCatalog[toolName]) {
                descBox.style.display = 'none';
                argsArea.value = '{}';
                return;
            }

            const tool = toolsCatalog[toolName];
            descEl.innerText = tool.description || 'No description provided.';
            descBox.style.display = 'block';

            // Prefill arguments structure if schema exists
            const argsObj = {};
            if (tool.inputSchema && tool.inputSchema.properties) {
                Object.keys(tool.inputSchema.properties).forEach(prop => {
                    const p = tool.inputSchema.properties[prop];
                    argsObj[prop] = p.type === 'string' ? '' : (p.type === 'array' ? [] : (p.type === 'object' ? {} : null));
                });
            }
            argsArea.value = JSON.stringify(argsObj, null, 2);
        }

        async function callTool() {
            const toolName = document.getElementById('play-tool').value;
            const argsText = document.getElementById('play-args').value;
            const termOut = document.getElementById('terminal-out');
            const runBtn = document.getElementById('run-btn');
            const respStatus = document.getElementById('response-status');

            if (!toolName) {
                alert('Please select a tool first!');
                return;
            }

            let argsParsed;
            try {
                argsParsed = JSON.parse(argsText);
            } catch (e) {
                alert('Arguments must be valid JSON: ' + e.message);
                return;
            }

            termOut.innerText = 'Calling tool ' + toolName + '...\nWaiting for response...';
            termOut.style.color = '#d1d5db';
            respStatus.innerText = 'Running';
            runBtn.disabled = true;
            runBtn.innerHTML = '<span class="spinner"></span> <span>Running...</span>';

            try {
                const res = await authFetch('/api/call', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: toolName, arguments: argsParsed })
                });

                if (!res.ok) {
                    const text = await res.text();
                    throw new Error(text || 'HTTP error ' + res.status);
                }

                const data = await res.json();
                runBtn.disabled = false;
                runBtn.innerHTML = '<span>Execute Tool</span>';

                if (data.error) {
                    termOut.innerText = 'Error (' + data.error.code + '): ' + data.error.message;
                    termOut.style.color = 'var(--danger)';
                    respStatus.innerText = 'Failed';
                } else {
                    termOut.innerText = JSON.stringify(data.result, null, 2);
                    termOut.style.color = '#34d399';
                    respStatus.innerText = 'Success';
                }
            } catch (err) {
                termOut.innerText = 'Call failed:\n' + err.message;
                termOut.style.color = 'var(--danger)';
                respStatus.innerText = 'Error';
                runBtn.disabled = false;
                runBtn.innerHTML = '<span>Execute Tool</span>';
            }
        }

        async function loadKeys() {
            const area = document.getElementById('ssh-keys-area');
            area.value = 'Loading authorized keys...';
            try {
                const res = await authFetch('/api/keys');
                if (!res.ok) throw new Error();
                const data = await res.json();
                area.value = data.keys || '';
            } catch (e) {
                area.value = 'Failed to load keys.';
            }
        }

        async function saveKeys() {
            const btn = document.getElementById('save-keys-btn');
            const alertBox = document.getElementById('keys-alert');
            const originalText = btn.innerText;

            btn.disabled = true;
            btn.innerText = 'Saving...';
            alertBox.innerHTML = '';

            try {
                const res = await authFetch('/api/keys', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ keys: document.getElementById('ssh-keys-area').value })
                });
                if (!res.ok) throw new Error(await res.text());
                
                alertBox.innerHTML = '<div class="alert alert-success">Authorized keys saved successfully!</div>';
            } catch (e) {
                alertBox.innerHTML = '<div class="alert alert-danger">Failed to save keys: ' + e.message + '</div>';
            } finally {
                btn.disabled = false;
                btn.innerText = originalText;
            }
        }

        async function loadConfig() {
            try {
                const res = await authFetch('/api/config');
                if (!res.ok) throw new Error();
                const data = await res.json();
                currentConfigData = data;

                document.getElementById('cfg-listen').value = data.listen_addr || '';
                document.getElementById('cfg-http').value = data.http_addr || '';
                document.getElementById('cfg-ollama-url').value = data.ollama_url || '';
                document.getElementById('cfg-ollama-model').value = data.ollama_model || '';
                document.getElementById('cfg-antigravity-token').value = data.antigravity_token || '';

                const webMcpUrl = window.location.origin + '/sse?token=' + (authToken || 'YOUR_AUTH_TOKEN');
                const connectionBox = document.getElementById('webmcp-connection-string');
                if (connectionBox) {
                    connectionBox.innerText = webMcpUrl;
                }
            } catch (e) {
                console.error('Failed to load config');
            }
        }

        async function saveConfig() {
            const alertBox = document.getElementById('config-alert');
            alertBox.innerHTML = '';

            if (!currentConfigData) return;

            const updatedConfig = {
                ...currentConfigData,
                listen_addr: document.getElementById('cfg-listen').value,
                http_addr: document.getElementById('cfg-http').value,
                ollama_url: document.getElementById('cfg-ollama-url').value,
                ollama_model: document.getElementById('cfg-ollama-model').value,
                antigravity_token: document.getElementById('cfg-antigravity-token').value
            };

            try {
                const res = await authFetch('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(updatedConfig)
                });
                if (!res.ok) throw new Error(await res.text());
                
                const data = await res.json();
                currentConfigData = data.config;
                alertBox.innerHTML = '<div class="alert alert-success">Gateway settings saved successfully!</div>';
            } catch (e) {
                alertBox.innerHTML = '<div class="alert alert-danger">Failed to save config: ' + e.message + '</div>';
            }
        }

        async function addUpstream() {
            const alertBox = document.getElementById('upstream-alert');
            const nameEl = document.getElementById('up-name');
            const transport = document.getElementById('up-transport').value;

            alertBox.innerHTML = '';
            const name = nameEl.value.trim();
            if (!name) {
                alertBox.innerHTML = '<div class="alert alert-danger">Server Name is required!</div>';
                return;
            }

            if (!currentConfigData) {
                await loadConfig();
            }

            const extServers = currentConfigData.external_mcp_servers || [];
            const legacyServers = currentConfigData.upstream_servers || [];

            // Check if name already exists
            if (extServers.some(s => s.name === name) || legacyServers.some(s => s.name === name)) {
                alertBox.innerHTML = '<div class="alert alert-danger">A connection with name "' + name + '" already exists!</div>';
                return;
            }

            let newServer = { name: name, transport: transport };

            if (transport === 'sse') {
                const urlEl = document.getElementById('up-url');
                const url = urlEl.value.trim();
                if (!url) {
                    alertBox.innerHTML = '<div class="alert alert-danger">SSE URL is required!</div>';
                    return;
                }
                if (!url.toLowerCase().startsWith('https://')) {
                    alertBox.innerHTML = '<div class="alert alert-danger">Upstream connections must use secure HTTPS (URL must start with https://)</div>';
                    return;
                }
                newServer.url = url;
            } else {
                const cmdEl = document.getElementById('up-cmd');
                const argsEl = document.getElementById('up-args');
                const envEl = document.getElementById('up-env');

                const cmd = cmdEl.value.trim();
                if (!cmd) {
                    alertBox.innerHTML = '<div class="alert alert-danger">Subprocess Command is required!</div>';
                    return;
                }
                newServer.command = cmd;

                // Parse arguments
                let args = [];
                const rawArgs = argsEl.value.trim();
                if (rawArgs) {
                    args = rawArgs.split(/\s+/).map(s => s.trim()).filter(s => s);
                }
                newServer.args = args;

                // Parse env
                let env = {};
                const rawEnv = envEl.value.trim();
                if (rawEnv) {
                    rawEnv.split(',').forEach(kv => {
                        const parts = kv.split('=');
                        if (parts.length >= 2) {
                            const k = parts[0].trim();
                            const v = parts.slice(1).join('=').trim();
                            if (k) env[k] = v;
                        }
                    });
                }
                newServer.env = env;
            }

            extServers.push(newServer);

            const updatedConfig = {
                ...currentConfigData,
                external_mcp_servers: extServers
            };

            try {
                const res = await authFetch('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(updatedConfig)
                });
                if (!res.ok) throw new Error(await res.text());

                const data = await res.json();
                currentConfigData = data.config;
                nameEl.value = '';
                document.getElementById('up-url').value = '';
                document.getElementById('up-cmd').value = '';
                document.getElementById('up-args').value = '';
                document.getElementById('up-env').value = '';
                alertBox.innerHTML = '<div class="alert alert-success">External MCP server registered successfully!</div>';
                fetchStatus();
            } catch (e) {
                alertBox.innerHTML = '<div class="alert alert-danger">Registration failed: ' + e.message + '</div>';
            }
        }

        async function deleteUpstream(name) {
            if (!confirm('Are you sure you want to remove upstream connection "' + name + '"?')) return;

            if (!currentConfigData) {
                await loadConfig();
            }

            const extServers = (currentConfigData.external_mcp_servers || []).filter(s => s.name !== name);
            const legacyServers = (currentConfigData.upstream_servers || []).filter(s => s.name !== name);

            const updatedConfig = {
                ...currentConfigData,
                upstream_servers: legacyServers,
                external_mcp_servers: extServers
            };

            try {
                const res = await authFetch('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(updatedConfig)
                });
                if (!res.ok) throw new Error(await res.text());
                const data = await res.json();
                currentConfigData = data.config;
                fetchStatus();
            } catch (e) {
                alert('Deletion failed: ' + e.message);
            }
        }

        function toggleTransportFields() {
            const transport = document.getElementById('up-transport').value;
            if (transport === 'sse') {
                document.getElementById('sse-fields').style.display = 'block';
                document.getElementById('stdio-fields').style.display = 'none';
            } else {
                document.getElementById('sse-fields').style.display = 'none';
                document.getElementById('stdio-fields').style.display = 'block';
            }
        }

        // ---- Fleet Inventory (issue #38: GET /api/fleet) ----
        let fleetAutoRefreshTimer = null;

        function htmlEscape(str) {
            return String(str == null ? '' : str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function buildFleetUrl() {
            const status = document.getElementById('fleet-status').value;
            const tag = document.getElementById('fleet-tag').value.trim();
            const os = document.getElementById('fleet-os').value.trim();
            const params = new URLSearchParams();
            if (status && status !== 'all') params.set('status', status);
            if (tag) params.set('tag', tag);
            if (os) params.set('os', os);
            const qs = params.toString();
            return '/api/fleet' + (qs ? '?' + qs : '');
        }

        // latest_metrics is raw agent JSON; show cpu/mem/disk if present, else n/a.
        function renderFleetMetrics(raw) {
            if (raw === null || raw === undefined) return '<span class="mini-na">n/a</span>';
            let m = raw;
            if (typeof raw === 'string') {
                try { m = JSON.parse(raw); } catch (e) { return '<span class="mini-na">n/a</span>'; }
            }
            if (!m || typeof m !== 'object') return '<span class="mini-na">n/a</span>';
            const parts = [];
            if (typeof m.cpu_usage_percent === 'number') {
                parts.push('<span>CPU <strong>' + m.cpu_usage_percent.toFixed(1) + '%</strong></span>');
            }
            if (typeof m.mem_used_percent === 'number') {
                parts.push('<span>Mem <strong>' + m.mem_used_percent.toFixed(1) + '%</strong></span>');
            }
            if (typeof m.disk_used_percent === 'number') {
                parts.push('<span>Disk <strong>' + m.disk_used_percent.toFixed(1) + '%</strong></span>');
            }
            if (parts.length === 0) return '<span class="mini-na">n/a</span>';
            return '<div class="mini-metrics">' + parts.join('') + '</div>';
        }

        // --- Agent detail (#109) -----------------------------------------
        //
        // Shows what nothing else surfaces: metric history. Tool calls and
        // read_logs are LINKS to the Audit and Playground tabs, which already
        // do both — rebuilding an audit table and a tool caller in here would
        // be two more things to keep in step.
        function closeAgentDetail() {
            document.getElementById('agent-detail').hidden = true;
        }

        // The gateway stores get_metrics output verbatim, so pull the three
        // fields the alerting path already parses (alertMetrics).
        function metricCell(raw, key) {
            try {
                const m = typeof raw === 'string' ? JSON.parse(raw) : raw;
                const v = m && m[key];
                return typeof v === 'number' ? v.toFixed(1) : '-';
            } catch (e) {
                return '-';
            }
        }

        async function openAgentDetail(agentId) {
            const panel = document.getElementById('agent-detail');
            const tbody = document.getElementById('agent-detail-history');
            panel.hidden = false;
            document.getElementById('agent-detail-title').textContent = agentId;

            // Deep-links to the tabs that already do these jobs.
            document.getElementById('agent-detail-audit').onclick = function () {
                document.getElementById('audit-f-agent').value = agentId;
                switchTab('audit');
            };
            document.getElementById('agent-detail-logs').onclick = function () {
                switchTab('playground');
                const sel = document.getElementById('tool-select');
                if (sel) {
                    const opt = Array.from(sel.options).find(function (o) {
                        return o.value === agentId + '__read_logs';
                    });
                    if (opt) {
                        sel.value = opt.value;
                        sel.dispatchEvent(new Event('change'));
                    }
                }
            };

            try {
                const res = await authFetch('/api/fleet?agent=' + encodeURIComponent(agentId));
                if (res.status === 403) {
                    document.getElementById('agent-detail-info').innerHTML =
                        '<div class="alert alert-danger">Your token is not scoped to this agent.</div>';
                    tbody.innerHTML = '<tr class="empty-row"><td colspan="4">-</td></tr>';
                    return;
                }
                if (!res.ok) throw new Error(await res.text());
                const all = await res.json();
                const a = (all || []).find(function (x) { return x.id === agentId; });
                if (!a) {
                    document.getElementById('agent-detail-info').innerHTML =
                        '<div class="alert alert-danger">Agent not connected.</div>';
                    return;
                }

                document.getElementById('agent-detail-info').innerHTML =
                    '<div><strong>OS:</strong> ' + htmlEscape(a.os || '-') + '</div>' +
                    '<div><strong>IP:</strong> ' + htmlEscape(a.ip || '-') + '</div>' +
                    '<div><strong>Last seen:</strong> ' + htmlEscape(a.last_seen || '-') + '</div>' +
                    '<div><strong>Services:</strong> ' + htmlEscape(String((a.services || []).length)) + '</div>' +
                    '<div><strong>Open ports:</strong> ' + htmlEscape((a.ports || []).join(', ') || '-') + '</div>';

                const history = a.history || [];
                if (history.length === 0) {
                    tbody.innerHTML = '<tr class="empty-row"><td colspan="4">No metric history. Set <code>metrics_poll_seconds</code> to collect it.</td></tr>';
                    return;
                }
                // Newest first.
                tbody.innerHTML = history.slice().reverse().map(function (s) {
                    return '<tr>' +
                        '<td>' + htmlEscape(s.timestamp || '') + '</td>' +
                        '<td>' + metricCell(s.raw, 'cpu_usage_percent') + '</td>' +
                        '<td>' + metricCell(s.raw, 'mem_used_percent') + '</td>' +
                        '<td>' + metricCell(s.raw, 'disk_used_percent') + '</td>' +
                        '</tr>';
                }).join('');
            } catch (e) {
                document.getElementById('agent-detail-info').innerHTML =
                    '<div class="alert alert-danger">Failed to load agent: ' + htmlEscape(e.message) + '</div>';
            }
        }

        function renderFleet(agents) {
            const tbody = document.getElementById('fleet-tbody');
            const countEl = document.getElementById('fleet-count');
            if (!Array.isArray(agents) || agents.length === 0) {
                tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No agents match the current filters.</td></tr>';
                countEl.innerText = '0 agents';
                return;
            }
            countEl.innerText = agents.length + (agents.length === 1 ? ' agent' : ' agents');
            tbody.innerHTML = agents.map(function(a) {
                const online = a.online === true;
                const dotClass = online ? 'online' : 'stale';
                const statusLabel = online ? 'online' : 'stale';
                const tags = Array.isArray(a.tags) && a.tags.length
                    ? a.tags.map(function(t){ return '<span class="tag-pill">' + htmlEscape(t) + '</span>'; }).join('')
                    : '<span class="mini-na">-</span>';
                const lastSeen = a.last_seen ? htmlEscape(a.last_seen) : '<span class="mini-na">-</span>';
                return '<tr>' +
                    '<td><button class="link-btn" onclick="openAgentDetail(' + JSON.stringify(a.id) + ')">' + htmlEscape(a.id) + '</button><div class="item-meta">' + htmlEscape(a.ip || '') + '</div></td>' +
                    '<td><span class="item-name"><span class="status-dot ' + dotClass + '"></span>' + statusLabel + '</span></td>' +
                    '<td>' + (a.os ? htmlEscape(a.os) : '<span class="mini-na">-</span>') + '</td>' +
                    '<td>' + tags + '</td>' +
                    '<td>' + lastSeen + '</td>' +
                    '<td>' + renderFleetMetrics(a.latest_metrics) + '</td>' +
                '</tr>';
            }).join('');
        }

        async function loadFleet() {
            const tbody = document.getElementById('fleet-tbody');
            const alertBox = document.getElementById('fleet-alert');
            alertBox.innerHTML = '';
            try {
                const res = await authFetch(buildFleetUrl());
                if (!res.ok) {
                    let msg = 'HTTP ' + res.status;
                    if (res.status === 403) {
                        msg = 'Forbidden: a valid token is required to view the fleet';
                    } else {
                        try { const t = await res.text(); if (t) msg += ': ' + t; } catch (e) {}
                    }
                    throw new Error(msg);
                }
                const data = await res.json();
                renderFleet(data);
            } catch (e) {
                // Stop auto-refresh on any error so we never hammer the gateway.
                stopFleetAutoRefresh();
                alertBox.innerHTML = '<div class="alert alert-danger">Failed to load fleet: ' + htmlEscape(e.message) + '</div>';
                tbody.innerHTML = '<tr class="empty-row"><td colspan="6">Unable to load fleet data.</td></tr>';
            }
        }

        function toggleFleetAutoRefresh() {
            const box = document.getElementById('fleet-autorefresh');
            if (box && box.checked) {
                stopFleetAutoRefresh(true);
                fleetAutoRefreshTimer = setInterval(loadFleet, 5000);
                loadFleet();
            } else {
                stopFleetAutoRefresh(true);
            }
        }

        function stopFleetAutoRefresh(keepCheckbox) {
            if (fleetAutoRefreshTimer !== null) {
                clearInterval(fleetAutoRefreshTimer);
                fleetAutoRefreshTimer = null;
            }
            if (!keepCheckbox) {
                const box = document.getElementById('fleet-autorefresh');
                if (box) box.checked = false;
            }
        }

        // ---- Approval Queue (issue #38: GET/POST /api/approvals) ----
        function renderApprovals(list) {
            const tbody = document.getElementById('approvals-tbody');
            const countEl = document.getElementById('approvals-count');
            if (!Array.isArray(list) || list.length === 0) {
                tbody.innerHTML = '<tr class="empty-row"><td colspan="7">No pending approvals.</td></tr>';
                countEl.innerText = '0 pending';
                return;
            }
            countEl.innerText = list.length + ' pending';
            tbody.innerHTML = list.map(function(a) {
                const id = htmlEscape(a.id);
                const tier = a.tier ? '<span class="tier-pill">' + htmlEscape(a.tier) + '</span>' : '<span class="mini-na">-</span>';
                const requestedBy = htmlEscape(a.role || '-') + (a.token_id ? ' <span class="item-meta">(' + htmlEscape(a.token_id) + ')</span>' : '');
                return '<tr id="appr-row-' + id + '">' +
                    '<td><span class="item-meta">' + id + '</span></td>' +
                    '<td>' + htmlEscape(a.agent_id || '-') + '</td>' +
                    '<td><span class="item-name">' + htmlEscape(a.tool || '-') + '</span></td>' +
                    '<td>' + tier + '</td>' +
                    '<td>' + requestedBy + '</td>' +
                    '<td>' + (a.created_at ? htmlEscape(a.created_at) : '<span class="mini-na">-</span>') + '</td>' +
                    '<td><div class="row-actions">' +
                        '<button class="btn" style="padding:6px 12px; font-size:12px;" onclick="decideApproval(\'' + id + '\', \'approve\')">Approve</button>' +
                        '<button class="btn btn-danger" style="padding:6px 12px; font-size:12px;" onclick="decideApproval(\'' + id + '\', \'reject\')">Reject</button>' +
                    '</div><div class="item-meta" id="appr-result-' + id + '" style="margin-top:6px;"></div></td>' +
                '</tr>';
            }).join('');
        }

        async function loadApprovals() {
            const tbody = document.getElementById('approvals-tbody');
            const alertBox = document.getElementById('approvals-alert');
            alertBox.innerHTML = '';
            try {
                const res = await authFetch('/api/approvals');
                if (!res.ok) {
                    let msg = 'HTTP ' + res.status;
                    if (res.status === 403) {
                        msg = 'Forbidden: operator or admin token required to view approvals';
                    } else {
                        try { const t = await res.text(); if (t) msg += ': ' + t; } catch (e) {}
                    }
                    throw new Error(msg);
                }
                const data = await res.json();
                renderApprovals(data);
            } catch (e) {
                alertBox.innerHTML = '<div class="alert alert-danger">Failed to load approvals: ' + htmlEscape(e.message) + '</div>';
                tbody.innerHTML = '<tr class="empty-row"><td colspan="7">Unable to load approvals.</td></tr>';
            }
        }

        async function decideApproval(id, decision) {
            const resultEl = document.getElementById('appr-result-' + id);
            const row = document.getElementById('appr-row-' + id);
            if (row) {
                row.querySelectorAll('button').forEach(function(b){ b.disabled = true; });
            }
            if (resultEl) {
                resultEl.style.color = 'var(--text-secondary)';
                resultEl.innerText = decision === 'approve' ? 'Approving...' : 'Rejecting...';
            }
            try {
                const res = await authFetch('/api/approvals', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id: id, decision: decision })
                });
                if (!res.ok) {
                    let msg = 'HTTP ' + res.status;
                    let bodyText = '';
                    try { bodyText = await res.text(); } catch (e) {}
                    if (res.status === 403) {
                        msg = 'Admin token required to decide approvals';
                    } else if (bodyText) {
                        msg += ': ' + bodyText.trim();
                    }
                    if (resultEl) {
                        resultEl.style.color = 'var(--danger)';
                        resultEl.innerText = msg;
                    }
                    if (row) row.querySelectorAll('button').forEach(function(b){ b.disabled = false; });
                    return;
                }
                let payload = null;
                try { payload = await res.json(); } catch (e) {}
                if (resultEl) {
                    resultEl.style.color = 'var(--success)';
                    let summary = decision === 'approve' ? 'Approved & executed.' : 'Rejected.';
                    if (payload && payload.error) {
                        resultEl.style.color = 'var(--danger)';
                        summary = 'Executed with error: ' + (payload.error.message || JSON.stringify(payload.error));
                    }
                    resultEl.innerText = summary;
                }
                // Refresh the queue shortly so the decided item drops off.
                setTimeout(loadApprovals, 800);
            } catch (e) {
                if (resultEl) {
                    resultEl.style.color = 'var(--danger)';
                    resultEl.innerText = 'Request failed: ' + e.message;
                }
                if (row) row.querySelectorAll('button').forEach(function(b){ b.disabled = false; });
            }
        }

        function initPortal() {
            if (!checkAuth()) return;
            fetchStatus();
        }

        // Initialize status polling
        initPortal();
        setInterval(fetchStatus, 5000);

        // --- Assistant Logic ---
        let assistantOpen = false;
        let assistantHistory = [];
        let speechRecognition = null;
        let isListening = false;

        function toggleAssistant() {
            const win = document.getElementById('assistant-window');
            assistantOpen = !assistantOpen;
            win.style.display = assistantOpen ? 'flex' : 'none';
            if (assistantOpen) {
                document.getElementById('assistant-input-field').focus();
            }
        }

        // Initialize Speech Recognition
        const SpeechRecognitionApi = window.SpeechRecognition || window.webkitSpeechRecognition;
        if (SpeechRecognitionApi) {
            speechRecognition = new SpeechRecognitionApi();
            speechRecognition.continuous = false;
            speechRecognition.interimResults = false;
            speechRecognition.lang = 'en-US';

            speechRecognition.onstart = () => {
                isListening = true;
                const micBtn = document.getElementById('ast-mic-btn');
                if (micBtn) {
                    micBtn.classList.add('mic-active');
                    micBtn.title = 'Listening... Click to stop';
                }
            };

            speechRecognition.onresult = (event) => {
                const transcript = event.results[0][0].transcript;
                const inputField = document.getElementById('assistant-input-field');
                if (inputField) {
                    inputField.value = transcript;
                }
                sendAssistantMessage();
            };

            speechRecognition.onerror = (event) => {
                console.error('Speech recognition error:', event.error);
                stopListening();
            };

            speechRecognition.onend = () => {
                stopListening();
            };
        } else {
            const micBtn = document.getElementById('ast-mic-btn');
            if (micBtn) micBtn.style.display = 'none';
        }

        function toggleVoiceInput() {
            if (!speechRecognition) return;
            if (isListening) {
                speechRecognition.stop();
            } else {
                speechRecognition.start();
            }
        }

        function stopListening() {
            isListening = false;
            const micBtn = document.getElementById('ast-mic-btn');
            if (micBtn) {
                micBtn.classList.remove('mic-active');
                micBtn.title = 'Start Voice Input';
            }
        }

        function speakText(text) {
            const voiceActive = document.getElementById('ast-voice-active').checked;
            if (!voiceActive) return;
            if ('speechSynthesis' in window) {
                window.speechSynthesis.cancel();
                // strip markdown formatting and JSON blocks
                let clean = text;
                clean = clean.replace(/\x60\x60\x60json[\s\S]*?\x60\x60\x60/g, '');
                clean = clean.replace(/\x60\x60\x60[\s\S]*?\x60\x60\x60/g, '');
                clean = clean.replace(/[\*#_\x60\[\]]/g, '');
                
                const utterance = new SpeechSynthesisUtterance(clean);
                window.speechSynthesis.speak(utterance);
            }
        }

        function renderMarkdown(text) {
            if (!text) return '';
            
            // Escape HTML
            let html = text
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');
            
            // Code blocks
            html = html.replace(/\x60\x60\x60(.*?)\n([\s\S]*?)\x60\x60\x60/g, function(match, lang, code) {
                return '<pre><code class="language-' + lang.trim() + '">' + code.trim() + '</code></pre>';
            });

            // Inline code
            html = html.replace(/\x60([^\x60]+)\x60/g, '<code>$1</code>');

            // Headers
            html = html.replace(/^#### (.*?)$/gm, '<h4>$1</h4>');
            html = html.replace(/^### (.*?)$/gm, '<h3>$1</h3>');
            html = html.replace(/^## (.*?)$/gm, '<h2>$1</h2>');
            html = html.replace(/^# (.*?)$/gm, '<h1>$1</h1>');

            // Bold
            html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
            html = html.replace(/__([^_]+)__/g, '<strong>$1</strong>');

            // Italic
            html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
            html = html.replace(/_([^_]+)_/g, '<em>$1</em>');

            // Lists
            const lines = html.split('\n');
            let inList = false;
            let listType = null;
            for (let i = 0; i < lines.length; i++) {
                let line = lines[i].trim();
                let matchUl = line.match(/^[\*\-\+]\s+(.*)$/);
                let matchOl = line.match(/^(\d+)\.\s+(.*)$/);

                if (matchUl) {
                    let content = matchUl[1];
                    let prefix = '';
                    if (!inList || listType !== 'ul') {
                        prefix = (inList ? '</' + listType + '>' : '') + '<ul>';
                        inList = true;
                        listType = 'ul';
                    }
                    lines[i] = prefix + '<li>' + content + '</li>';
                } else if (matchOl) {
                    let content = matchOl[2];
                    let prefix = '';
                    if (!inList || listType !== 'ol') {
                        prefix = (inList ? '</' + listType + '>' : '') + '<ol>';
                        inList = true;
                        listType = 'ol';
                    }
                    lines[i] = prefix + '<li>' + content + '</li>';
                } else {
                    if (inList) {
                        lines[i] = '</' + listType + '>' + lines[i];
                        inList = false;
                        listType = null;
                    }
                }
            }
            if (inList) {
                lines[lines.length - 1] += '</' + listType + '>';
            }
            html = lines.join('\n');

            // Replace newlines with <br> excluding pre blocks
            const parts = html.split(/(<pre>[\s\S]*?<\/pre>)/);
            for (let i = 0; i < parts.length; i++) {
                if (!parts[i].startsWith('<pre>')) {
                    parts[i] = parts[i].replace(/\n/g, '<br>');
                }
            }
            html = parts.join('');

            return html;
        }

        function appendAssistantMessage(role, text, type = 'text') {
            const chatLog = document.getElementById('assistant-chat-log');
            if (!chatLog) return;
            const msgEl = document.createElement('div');
            msgEl.className = 'ast-msg ' + role;
            if (type === 'code') {
                const pre = document.createElement('pre');
                pre.style.whiteSpace = 'pre-wrap';
                pre.style.margin = '0';
                pre.innerText = text;
                msgEl.appendChild(pre);
            } else if (role === 'assistant' || role === 'user' || role === 'system') {
                msgEl.innerHTML = renderMarkdown(text);
            } else {
                msgEl.innerText = text;
            }
            chatLog.appendChild(msgEl);
            chatLog.scrollTop = chatLog.scrollHeight;
        }

        async function sendAssistantMessage() {
            const inputField = document.getElementById('assistant-input-field');
            if (!inputField) return;
            const prompt = inputField.value.trim();
            if (!prompt) return;

            inputField.value = '';
            appendAssistantMessage('user', prompt);

            await runAgentLoop(prompt);
        }

        async function runAgentLoop(userPrompt) {
            const provider = document.getElementById('ast-provider').value;
            
            const countAgents = document.getElementById('count-agents').innerText;
            const countUpstreams = document.getElementById('count-upstreams').innerText;
            
            const toolNames = Object.keys(toolsCatalog);
            
            const systemPrompt = 
                'You are the Myrmex Assistant. You can monitor status and run approved commands using tools.' +
                ' Context: Connected Edge Agents count = ' + countAgents + '; Registered Upstream Servers count = ' + countUpstreams + '.' +
                ' Available tools: ' + JSON.stringify(toolNames) + '.' +
                ' If you need to perform an action (e.g. check status, run command, read logs), respond with a SINGLE JSON command block:' +
                ' {"call": "tool_name", "arguments": {...}}' +
                ' Do not include other text when calling a tool. If you do not need any tools to answer, respond normally with plain text.';

            let promptToModel = userPrompt;
            let loopCount = 0;
            const maxLoops = 5;

            while (loopCount < maxLoops) {
                loopCount++;
                try {
                    const statusEl = document.createElement('div');
                    statusEl.className = 'ast-msg system';
                    statusEl.innerText = 'Thinking...';
                    const chatLog = document.getElementById('assistant-chat-log');
                    if (chatLog) {
                        chatLog.appendChild(statusEl);
                        chatLog.scrollTop = chatLog.scrollHeight;
                    }

                    const chatBody = {
                        provider: provider,
                        prompt: promptToModel,
                        history: assistantHistory,
                        system: systemPrompt
                    };

                    const res = await authFetch('/api/chat', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(chatBody)
                    });

                    statusEl.remove();

                    if (!res.ok) {
                        const errText = await res.text();
                        appendAssistantMessage('system', 'Error: ' + errText);
                        break;
                    }

                    const data = await res.json();
                    const reply = data.response ? data.response.trim() : '';

                    if (!reply) {
                        appendAssistantMessage('system', 'Empty response from model.');
                        break;
                    }

                    let isToolCall = false;
                    let toolCallObj = null;

                    let jsonText = reply;
                    const jsonMatch = reply.match(/\x60\x60\x60json\s*([\s\S]*?)\s*\x60\x60\x60/) || reply.match(/\x60\x60\x60\s*([\s\S]*?)\s*\x60\x60\x60/);
                    if (jsonMatch) {
                        jsonText = jsonMatch[1].trim();
                    }

                    try {
                        const parsed = JSON.parse(jsonText);
                        if (parsed && typeof parsed === 'object' && parsed.call) {
                            isToolCall = true;
                            toolCallObj = parsed;
                        }
                    } catch (e) {
                        // Not a JSON tool call
                    }

                    if (isToolCall) {
                        assistantHistory.push({ role: 'user', text: promptToModel });
                        assistantHistory.push({ role: 'assistant', text: reply });

                        appendAssistantMessage('agent-action', '[Executing tool]: ' + toolCallObj.call + '\nArguments: ' + JSON.stringify(toolCallObj.arguments), 'code');

                        try {
                            const callRes = await authFetch('/api/call', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ name: toolCallObj.call, arguments: toolCallObj.arguments })
                            });

                            if (!callRes.ok) {
                                const errText = await callRes.text();
                                throw new Error(errText || 'HTTP ' + callRes.status);
                            }

                            const callData = await callRes.json();
                            let resultStr = '';
                            if (callData.error) {
                                resultStr = 'Tool Error: ' + callData.error.message;
                            } else {
                                resultStr = JSON.stringify(callData.result);
                            }

                            promptToModel = 'Tool result: ' + resultStr;
                        } catch (err) {
                            promptToModel = 'Failed to execute tool ' + toolCallObj.call + ': ' + err.message;
                        }
                    } else {
                        assistantHistory.push({ role: 'user', text: promptToModel });
                        assistantHistory.push({ role: 'assistant', text: reply });

                        appendAssistantMessage('assistant', reply);
                        speakText(reply);
                        break;
                    }
                } catch (err) {
                    appendAssistantMessage('system', 'Agent loop error: ' + err.message);
                    break;
                }
            }
        }

        // --- Agent Details Drawer Logic & Metrics Polling ---
        let activeAgentDetailsId = null;
        let agentDetailsTimeout = null;

        async function fetchAgentMetrics(agentId) {
            if (activeAgentDetailsId !== agentId) return;

            const loadingEl = document.getElementById('det-metrics-loading');
            const contentEl = document.getElementById('det-metrics-content');

            try {
                const res = await authFetch('/api/call', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: agentId + '__get_metrics', arguments: {} })
                });

                if (!res.ok) throw new Error(await res.text());
                const data = await res.json();
                
                if (data.error) throw new Error(data.error.message);
                if (activeAgentDetailsId !== agentId) return;

                // Parse metrics JSON from RPC result content
                const metricsText = data.result && data.result.content && data.result.content[0] && data.result.content[0].text;
                if (!metricsText) throw new Error('No metrics returned');

                const metrics = JSON.parse(metricsText);

                // Update UI fields
                document.getElementById('det-load-1m').innerText = metrics.load_avg_1m !== undefined ? metrics.load_avg_1m.toFixed(2) : '-';
                document.getElementById('det-load-5m').innerText = metrics.load_avg_5m !== undefined ? metrics.load_avg_5m.toFixed(2) : '-';
                document.getElementById('det-load-15m').innerText = metrics.load_avg_15m !== undefined ? metrics.load_avg_15m.toFixed(2) : '-';

                // CPU
                const cpuVal = metrics.cpu_usage_percent || 0;
                document.getElementById('det-cpu-val').innerText = cpuVal.toFixed(1) + '%';
                const cpuFill = document.getElementById('det-cpu-fill');
                cpuFill.style.width = cpuVal.toFixed(1) + '%';
                updateBarColor(cpuFill, cpuVal);

                // Memory
                const memUsedPct = metrics.mem_used_percent || 0;
                const memUsed = metrics.mem_used_mb || 0;
                const memTotal = metrics.mem_total_mb || 0;
                document.getElementById('det-mem-val').innerText = memUsedPct.toFixed(1) + '% (' + Math.round(memUsed) + ' / ' + Math.round(memTotal) + ' MB)';
                const memFill = document.getElementById('det-mem-fill');
                memFill.style.width = memUsedPct.toFixed(1) + '%';
                updateBarColor(memFill, memUsedPct);

                // Disk
                const diskUsedPct = metrics.disk_used_percent || 0;
                const diskUsed = metrics.disk_used_gb || 0;
                const diskTotal = metrics.disk_total_gb || 0;
                document.getElementById('det-disk-val').innerText = diskUsedPct.toFixed(1) + '% (' + Math.round(diskUsed) + ' / ' + Math.round(diskTotal) + ' GB)';
                const diskFill = document.getElementById('det-disk-fill');
                diskFill.style.width = diskUsedPct.toFixed(1) + '%';
                updateBarColor(diskFill, diskUsedPct);

                loadingEl.style.display = 'none';
                contentEl.style.display = 'block';

            } catch (err) {
                if (activeAgentDetailsId === agentId) {
                    loadingEl.innerText = 'Failed to load metrics: ' + err.message;
                    loadingEl.style.display = 'block';
                    contentEl.style.display = 'none';
                }
            }

            // Schedule next check if drawer is still open on this agent
            if (activeAgentDetailsId === agentId) {
                agentDetailsTimeout = setTimeout(function() { fetchAgentMetrics(agentId); }, 5000);
            }
        }

        function updateBarColor(el, val) {
            el.classList.remove('warning', 'danger');
            if (val >= 90) {
                el.classList.add('danger');
            } else if (val >= 75) {
                el.classList.add('warning');
            }
        }

        function showAgentDetails(agentId) {
            const agent = connectedAgentsDetails[agentId];
            if (!agent) return;

            activeAgentDetailsId = agentId;
            if (agentDetailsTimeout) {
                clearTimeout(agentDetailsTimeout);
                agentDetailsTimeout = null;
            }

            document.getElementById('det-id').innerText = agent.id;
            document.getElementById('det-ip').innerText = agent.ip;
            document.getElementById('det-os').innerText = agent.os_version || 'Loading...';

            const servicesEl = document.getElementById('det-services');
            servicesEl.innerHTML = '';
            if (agent.running_services && agent.running_services.length > 0) {
                agent.running_services.forEach(svc => {
                    const span = document.createElement('span');
                    span.className = 'svc-tag';
                    span.innerText = svc;
                    servicesEl.appendChild(span);
                });
            } else {
                servicesEl.innerHTML = '<span style="font-size:13px; color:var(--text-secondary);">None detected or loading...</span>';
            }

            const portsEl = document.getElementById('det-ports');
            portsEl.innerHTML = '';
            if (agent.open_ports && agent.open_ports.length > 0) {
                agent.open_ports.forEach(port => {
                    const span = document.createElement('span');
                    span.className = 'port-tag';
                    span.innerText = port;
                    portsEl.appendChild(span);
                });
            } else {
                portsEl.innerHTML = '<span style="font-size:13px; color:var(--text-secondary);">None detected or loading...</span>';
            }

            // Reset metrics UI
            const loadingEl = document.getElementById('det-metrics-loading');
            const contentEl = document.getElementById('det-metrics-content');
            loadingEl.innerText = 'Loading system metrics...';
            loadingEl.style.display = 'block';
            contentEl.style.display = 'none';

            document.getElementById('agent-details-drawer').classList.add('open');

            // Trigger fetch
            fetchAgentMetrics(agentId);
        }

        function closeAgentDetails() {
            activeAgentDetailsId = null;
            if (agentDetailsTimeout) {
                clearTimeout(agentDetailsTimeout);
                agentDetailsTimeout = null;
            }
            document.getElementById('agent-details-drawer').classList.remove('open');
        }
