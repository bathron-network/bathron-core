/**
 * P&A LP Explorer — Dedicated LP browsing page
 *
 * Self-contained: registry discovery, LP WebSocket, card rendering, detail view.
 * Design: aligned with BATHRON Block Explorer (bathron-explorer.php)
 */

// =============================================================================
// CONFIGURATION
// =============================================================================

const CONFIG = {
    REGISTRY_URL: 'https://registry.example'  /* TODO-PUBLIC-SEED */,
    REGISTRY_TIMEOUT_MS: 3000,
    LP_TIMEOUT_MS: 4000,
    LP_REGISTRY: [],
    SHOW_ALL_LPS: true,
};

// =============================================================================
// WEBSOCKET CLIENT
// =============================================================================

class PnaWebSocket {
    constructor(url, handlers) {
        this.url = url;
        this.handlers = handlers;
        this.ws = null;
        this.reconnectDelay = 1000;
        this.maxReconnectDelay = 30000;
        this.subs = {};
        this._closed = false;
    }

    connect() {
        if (this._closed) return;
        try {
            this.ws = new WebSocket(this.url);
        } catch (e) {
            console.warn(`[ws] Failed to create WebSocket for ${this.url}:`, e);
            this._scheduleReconnect();
            return;
        }

        this.ws.onopen = () => {
            console.log(`[ws] Connected: ${this.url}`);
            this.reconnectDelay = 1000;
            for (const [channel, data] of Object.entries(this.subs)) {
                this.ws.send(JSON.stringify({ type: 'subscribe', channel, data }));
            }
            this._startPing();
        };

        this.ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                const handler = this.handlers[msg.type];
                if (handler) handler(msg.data, msg);
            } catch (e) {
                console.warn('[ws] Parse error:', e);
            }
        };

        this.ws.onclose = () => {
            this._stopPing();
            this._scheduleReconnect();
        };

        this.ws.onerror = () => {};
    }

    subscribe(channel, data = {}) {
        this.subs[channel] = data;
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({ type: 'subscribe', channel, data }));
        }
    }

    get connected() {
        return this.ws && this.ws.readyState === WebSocket.OPEN;
    }

    close() {
        this._closed = true;
        if (this.ws) this.ws.close();
    }

    _startPing() {
        this._stopPing();
        this._pingTimer = setInterval(() => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                try { this.ws.send(JSON.stringify({ type: 'ping' })); } catch (e) {}
            }
        }, 25000);
    }

    _stopPing() {
        if (this._pingTimer) {
            clearInterval(this._pingTimer);
            this._pingTimer = null;
        }
    }

    _scheduleReconnect() {
        if (this._closed) return;
        setTimeout(() => this.connect(), this.reconnectDelay);
        this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay);
    }
}

// =============================================================================
// STATE
// =============================================================================

let registryWs = null;
let lpWebSockets = {};
let lpWsInfoCache = {};

let activeFilter = 'all';   // 'all', 'online', 'tier1'
let searchQuery = '';

const View = {
    current: 'list',       // 'list' or 'detail'
    detailEndpoint: null,
};

// =============================================================================
// UTILITIES
// =============================================================================

function formatNumber(num, decimals = 2) {
    if (num >= 1000000) return (num / 1000000).toFixed(2) + 'M';
    if (num >= 1000) {
        return num.toLocaleString('en-US', {
            minimumFractionDigits: decimals,
            maximumFractionDigits: decimals,
        });
    }
    return num.toFixed(decimals);
}

function formatRateNum(n) {
    if (n == null || isNaN(n)) return '-';
    if (n >= 10000) return n.toFixed(0).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    if (n >= 100) return n.toFixed(2);
    if (n >= 1) return n.toFixed(4);
    if (n >= 0.0001) return n.toFixed(6);
    return n.toFixed(8);
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// =============================================================================
// REGISTRY & LP DISCOVERY
// =============================================================================

function applyRegistryLPs(lps) {
    CONFIG.LP_REGISTRY = lps;
    connectLPWebSockets();
    renderLPList();
    renderPairsSummary();
    updateStats();
}

function connectLPWebSockets() {
    const allEndpoints = CONFIG.LP_REGISTRY.map(lp => lp.endpoint);

    // Close removed
    for (const url of Object.keys(lpWebSockets)) {
        if (!allEndpoints.includes(url)) {
            lpWebSockets[url].close();
            delete lpWebSockets[url];
        }
    }

    // Connect new
    for (const url of allEndpoints) {
        if (lpWebSockets[url]) continue;
        const wsUrl = url.replace(/^http/, 'ws') + '/ws';
        const lpWs = new PnaWebSocket(wsUrl, {
            lp_info: (data) => {
                if (!lpWsInfoCache[url]) lpWsInfoCache[url] = {};
                lpWsInfoCache[url].info = data;
                lpWsInfoCache[url].ts = Date.now();
                updateLPCard(url);
            },
            inventory: (data) => {
                if (!lpWsInfoCache[url]) lpWsInfoCache[url] = {};
                lpWsInfoCache[url].inventory = data;
                lpWsInfoCache[url].ts = Date.now();
                updateLPCard(url);
            },
            pong: () => {},
        });
        lpWs.connect();
        lpWs.subscribe('inventory');
        lpWebSockets[url] = lpWs;
    }
}

// =============================================================================
// FILTERING
// =============================================================================

function getFilteredLPs() {
    let lps = CONFIG.LP_REGISTRY;

    // Tier filter (checkbox)
    if (!CONFIG.SHOW_ALL_LPS) {
        lps = lps.filter(lp => lp.tier === 1);
    }

    // Pill filter
    if (activeFilter === 'online') {
        lps = lps.filter(lp => lp.status === 'online' || lp.status === 'new');
    } else if (activeFilter === 'tier1') {
        lps = lps.filter(lp => lp.tier === 1);
    }

    // Search query
    if (searchQuery) {
        const q = searchQuery.toLowerCase();
        lps = lps.filter(lp => {
            const wsCache = lpWsInfoCache[lp.endpoint] || {};
            const info = wsCache.info || null;
            const cached = lp.cached_info || {};
            const name = (info?.name || cached?.name || cached?.lp_id || '').toLowerCase();
            const addr = (lp.address || '').toLowerCase();
            const pairs = Object.keys(info?.pairs || cached?.pairs || {}).join(' ').toLowerCase();
            const endpoint = (lp.endpoint || '').toLowerCase();
            return name.includes(q) || addr.includes(q) || pairs.includes(q) || endpoint.includes(q);
        });
    }

    return lps;
}

function setFilter(filter, el) {
    activeFilter = filter;
    document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
    if (el) el.classList.add('active');
    renderLPList();
    updateStats();
}

function filterLPs() {
    const input = document.getElementById('lp-search');
    searchQuery = input ? input.value.trim() : '';
    renderLPList();
    updateStats();
}

function toggleFilter() {
    const checkbox = document.getElementById('show-all-lps');
    CONFIG.SHOW_ALL_LPS = checkbox ? checkbox.checked : true;
    renderLPList();
    updateStats();
}

// =============================================================================
// LP LIST RENDERING
// =============================================================================

async function renderLPList() {
    const container = document.getElementById('exp-lp-list');
    if (!container) return;

    const lps = getFilteredLPs();

    // Update count badge
    const badge = document.getElementById('lp-count-badge');
    if (badge) badge.textContent = lps.length;

    if (lps.length === 0) {
        container.innerHTML = '<div class="empty-state">No LPs discovered yet. LPs register on-chain via OP_RETURN transactions.</div>';
        return;
    }

    // Fetch info via HTTP for LPs not yet in WS cache
    const needsFetch = lps.filter(lp => !lpWsInfoCache[lp.endpoint]?.info);
    if (needsFetch.length > 0) {
        const results = await Promise.allSettled(
            needsFetch.map(lp =>
                fetch(`${lp.endpoint}/api/lp/info`, { signal: AbortSignal.timeout(CONFIG.LP_TIMEOUT_MS) })
                    .then(r => r.ok ? r.json() : null)
                    .catch(() => null)
            )
        );
        needsFetch.forEach((lp, i) => {
            const result = results[i]?.status === 'fulfilled' ? results[i].value : null;
            if (result) {
                if (!lpWsInfoCache[lp.endpoint]) lpWsInfoCache[lp.endpoint] = {};
                lpWsInfoCache[lp.endpoint].info = result;
                lpWsInfoCache[lp.endpoint].ts = Date.now();
            }
        });
    }

    container.innerHTML = lps.map(lp => buildCardHTML(lp)).join('');
}

function buildCardHTML(lp) {
    const wsCache = lpWsInfoCache[lp.endpoint] || {};
    const info = wsCache.info || null;
    const cached = lp.cached_info || {};
    const wsConnected = lpWebSockets[lp.endpoint]?.connected || false;

    const name = escapeHtml(info?.name || cached?.name || cached?.lp_id || lp.address?.slice(0, 12) || 'Unknown LP');
    const status = lp.status || 'offline';
    const tier = lp.tier || 2;
    const tierLabel = tier === 1 ? 'Operator' : 'Community';
    const tierClass = tier === 1 ? 'tier-1' : 'tier-2';

    // Pairs
    const pairsObj = info?.pairs || cached?.pairs || {};
    const pairs = Object.keys(pairsObj);
    const pairPills = pairs.map(p => `<span class="lp-pair-pill">${escapeHtml(p)}</span>`).join('');

    // Inventory dots
    const inv = info?.inventory || cached?.inventory || {};
    const lpAssets = new Set();
    pairs.forEach(p => p.split('/').forEach(a => lpAssets.add(a.toLowerCase())));
    if (lpAssets.size === 0) ['btc', 'm1', 'usdc'].forEach(a => lpAssets.add(a));
    const invDots = [...lpAssets].map(asset => {
        const avail = inv[asset + '_available'] !== false;
        return `<span class="lp-inv-item"><span class="lp-inv-dot ${avail ? 'available' : 'unavailable'}"></span>${asset.toUpperCase()}</span>`;
    }).join('');

    // Connection tag
    const connTag = wsConnected
        ? '<span class="lp-live-tag">LIVE</span>'
        : '<span class="lp-http-tag">HTTP</span>';

    // Stats
    const rep = cached?.reputation || {};
    const swaps = info?.stats?.swaps_completed || cached?.swaps_total || 0;
    const successRate = rep.success_rate != null ? Math.round(rep.success_rate * 100) + '%' : '-';

    return `
    <div class="exp-card" data-endpoint="${escapeHtml(lp.endpoint)}" onclick="openDetail('${escapeHtml(lp.endpoint)}')">
        <div class="lp-header">
            <span class="lp-status-dot ${status}"></span>
            <span class="lp-name">${name}</span>
            ${connTag}
            <span class="tier-badge ${tierClass}">${tierLabel}</span>
        </div>
        ${pairPills ? `<div class="lp-pairs">${pairPills}</div>` : ''}
        <div class="exp-card-footer">
            <div class="lp-inventory">${invDots}</div>
            <div class="exp-card-stats">
                <span>${swaps} swaps</span>
                <span>${successRate} success</span>
            </div>
        </div>
    </div>`;
}

function updateLPCard(endpoint) {
    // Update card in list
    const card = document.querySelector(`.exp-card[data-endpoint="${endpoint}"]`);
    if (card) {
        const lp = CONFIG.LP_REGISTRY.find(l => l.endpoint === endpoint);
        if (lp) {
            const temp = document.createElement('div');
            temp.innerHTML = buildCardHTML(lp);
            card.replaceWith(temp.firstElementChild);
        }
    }
    updateStats();
    renderPairsSummary();

    // Update detail if open
    if (View.current === 'detail' && View.detailEndpoint === endpoint) {
        renderDetail(endpoint);
    }
}

// =============================================================================
// STATS & BANNER
// =============================================================================

function updateStats() {
    const lps = getFilteredLPs();
    const allLps = CONFIG.LP_REGISTRY;
    const online = allLps.filter(lp => lp.status === 'online' || lp.status === 'new').length;
    const tier1 = allLps.filter(lp => lp.tier === 1).length;
    const liveWs = Object.values(lpWebSockets).filter(ws => ws.connected).length;

    // Collect unique pairs
    const allPairs = new Set();
    allLps.forEach(lp => {
        const wsCache = lpWsInfoCache[lp.endpoint] || {};
        const info = wsCache.info || null;
        const cached = lp.cached_info || {};
        const pairs = Object.keys(info?.pairs || cached?.pairs || {});
        pairs.forEach(p => allPairs.add(p));
    });

    // Stats cards
    const elTotal = document.getElementById('stat-total');
    const elOnline = document.getElementById('stat-online');
    const elOperators = document.getElementById('stat-operators');
    const elLive = document.getElementById('stat-live');

    if (elTotal) elTotal.textContent = allLps.length;
    if (elOnline) elOnline.textContent = online;
    if (elOperators) elOperators.textContent = tier1;
    if (elLive) elLive.textContent = liveWs;

    // Network banner
    const elBannerTotal = document.getElementById('banner-total-lps');
    const elBannerOnline = document.getElementById('banner-online');
    const elBannerPairs = document.getElementById('banner-pairs');
    const elBannerWs = document.getElementById('banner-ws');

    if (elBannerTotal) elBannerTotal.textContent = allLps.length;
    if (elBannerOnline) elBannerOnline.textContent = online;
    if (elBannerPairs) elBannerPairs.textContent = allPairs.size;
    if (elBannerWs) elBannerWs.textContent = liveWs;
}

// =============================================================================
// PAIRS SUMMARY TABLE
// =============================================================================

function renderPairsSummary() {
    const card = document.getElementById('pairs-summary-card');
    const body = document.getElementById('pairs-summary-body');
    const countEl = document.getElementById('pairs-count');
    if (!card || !body) return;

    // Aggregate pairs across all LPs
    const pairMap = {};  // pair -> { lps: [], bestBid, bestAsk }

    CONFIG.LP_REGISTRY.forEach(lp => {
        const wsCache = lpWsInfoCache[lp.endpoint] || {};
        const info = wsCache.info || null;
        const cached = lp.cached_info || {};
        const pairsObj = info?.pairs || cached?.pairs || {};
        const name = info?.name || cached?.name || cached?.lp_id || lp.address?.slice(0, 12) || '?';

        for (const [pairKey, p] of Object.entries(pairsObj)) {
            if (!pairMap[pairKey]) {
                pairMap[pairKey] = { lps: [], bestBid: null, bestAsk: null };
            }
            pairMap[pairKey].lps.push(name);
            if (p.rate_bid != null && (pairMap[pairKey].bestBid == null || p.rate_bid > pairMap[pairKey].bestBid)) {
                pairMap[pairKey].bestBid = p.rate_bid;
            }
            if (p.rate_ask != null && (pairMap[pairKey].bestAsk == null || p.rate_ask < pairMap[pairKey].bestAsk)) {
                pairMap[pairKey].bestAsk = p.rate_ask;
            }
        }
    });

    const entries = Object.entries(pairMap);
    if (entries.length === 0) {
        card.style.display = 'none';
        return;
    }

    card.style.display = '';
    if (countEl) countEl.textContent = entries.length;

    const rows = entries.map(([pair, data]) => `
        <tr>
            <td class="pair-name">${escapeHtml(pair)}</td>
            <td class="pair-lps">${data.lps.length}</td>
            <td class="pair-best-bid">${formatRateNum(data.bestBid)}</td>
            <td class="pair-best-ask">${formatRateNum(data.bestAsk)}</td>
        </tr>
    `).join('');

    body.innerHTML = `
        <table>
            <thead><tr>
                <th>Pair</th><th>LPs</th><th>Best Bid</th><th>Best Ask</th>
            </tr></thead>
            <tbody>${rows}</tbody>
        </table>`;
}

// =============================================================================
// LP DETAIL VIEW
// =============================================================================

function openDetail(endpoint) {
    const lp = CONFIG.LP_REGISTRY.find(l => l.endpoint === endpoint);
    if (!lp) return;

    View.current = 'detail';
    View.detailEndpoint = endpoint;

    document.getElementById('exp-list-view').style.display = 'none';
    document.getElementById('exp-detail-view').style.display = '';

    // Hide filter bar in detail view
    const filterBar = document.querySelector('.filter-bar');
    if (filterBar) filterBar.style.display = 'none';

    renderDetail(endpoint);
}

function renderDetail(endpoint) {
    const lp = CONFIG.LP_REGISTRY.find(l => l.endpoint === endpoint);
    if (!lp) return;

    const wsCache = lpWsInfoCache[endpoint] || {};
    const info = wsCache.info || null;
    const liveInv = wsCache.inventory || null;
    const cached = lp.cached_info || {};
    const wsConnected = lpWebSockets[endpoint]?.connected || false;

    const name = info?.name || cached?.lp_id || lp.address?.slice(0, 12) || 'Unknown LP';
    const title = document.getElementById('exp-detail-title');
    if (title) title.textContent = name;

    const body = document.getElementById('exp-detail-body');
    if (body) body.innerHTML = buildDetailHTML(lp, info, liveInv, cached, wsConnected);
}

function closeDetail() {
    View.current = 'list';
    View.detailEndpoint = null;

    document.getElementById('exp-detail-view').style.display = 'none';
    document.getElementById('exp-list-view').style.display = '';

    // Show filter bar again
    const filterBar = document.querySelector('.filter-bar');
    if (filterBar) filterBar.style.display = '';
}

function buildDetailHTML(lp, info, liveInv, cached, wsConnected) {
    const status = lp.status || 'offline';
    const tier = lp.tier || 2;
    const tierLabel = tier === 1 ? 'Operator' : 'Community';
    const tierClass = tier === 1 ? 'tier-1' : 'tier-2';
    const version = info?.version || cached?.version || '-';

    // Status bar
    let html = `
    <div class="lpd-status-bar">
        <span class="lp-status-dot ${status}"></span>
        <span class="lpd-status-text">${status}</span>
        <span class="tier-badge ${tierClass}">${tierLabel}</span>
        ${wsConnected ? '<span class="lp-live-tag">LIVE</span>' : '<span class="lpd-no-ws">HTTP</span>'}
        <span class="lpd-version">v${escapeHtml(version)}</span>
    </div>`;

    // LP-level stats
    const rep = cached?.reputation || {};
    const totalSwaps = info?.stats?.swaps_completed || cached?.swaps_total || 0;
    const successRate = rep.success_rate != null ? Math.round(rep.success_rate * 100) + '%' : '-';
    const uptimeHrs = info?.stats?.uptime_hours != null ? info.stats.uptime_hours.toFixed(1) + 'h' : '-';

    // Stats grid
    html += `
    <div class="lpd-section">
        <div class="lpd-kv-grid">
            <div class="lpd-kv"><span class="lpd-k">Swaps</span><span class="lpd-v">${totalSwaps}</span></div>
            <div class="lpd-kv"><span class="lpd-k">Success</span><span class="lpd-v">${successRate}</span></div>
            <div class="lpd-kv"><span class="lpd-k">Uptime</span><span class="lpd-v">${uptimeHrs}</span></div>
        </div>
    </div>`;

    // Pairs table
    const pairs = info?.pairs ? Object.entries(info.pairs) : [];
    if (pairs.length > 0) {
        const rows = pairs.map(([pairKey, p]) => {
            const minVal = p.min != null ? formatRateNum(p.min) : '-';
            const maxVal = p.max != null && p.max < 1e12 ? formatRateNum(p.max) : '-';

            const baseAsset = pairKey.split('/')[0].toLowerCase();
            const amount = liveInv ? liveInv[baseAsset] : null;
            const boolAvail = info?.inventory?.[baseAsset + '_available'] !== false;
            let availText = '-';
            if (amount != null) {
                if (baseAsset === 'btc') availText = amount.toFixed(8);
                else if (baseAsset === 'm1') availText = Math.round(amount).toLocaleString();
                else availText = formatNumber(amount, 2);
            }
            const availClass = (amount != null ? amount > 0 : boolAvail) ? 'lpd-avail-ok' : 'lpd-avail-empty';

            return `<tr>
                <td class="lpd-pair-name">${escapeHtml(pairKey)}</td>
                <td class="lpd-rate-bid">${formatRateNum(p.rate_bid)}</td>
                <td class="lpd-rate-ask">${formatRateNum(p.rate_ask)}</td>
                <td class="lpd-minmax">${minVal}</td>
                <td class="lpd-minmax">${maxVal}</td>
                <td class="${availClass}">${availText}</td>
            </tr>`;
        }).join('');

        html += `
        <div class="lpd-section">
            <h4 class="lpd-section-title">Pairs</h4>
            <div class="lpd-table-scroll">
            <table class="lpd-table lpd-unified">
                <thead><tr>
                    <th>Pair</th><th>Bid</th><th>Ask</th><th>Min</th><th>Max</th><th>Available</th>
                </tr></thead>
                <tbody>${rows}</tbody>
            </table>
            </div>
        </div>`;
    } else {
        html += `<div class="lpd-section"><div class="empty-state">No pairs configured</div></div>`;
    }

    // On-chain info (block explorer detail-grid style)
    const addrFull = lp.address || '-';
    html += `
    <div class="lpd-section">
        <h4 class="lpd-section-title">On-chain Registration</h4>
        <div class="lpd-detail-grid">
            <div class="dg-label">Address</div>
            <div class="dg-value">${escapeHtml(addrFull)}</div>
            <div class="dg-label">Endpoint</div>
            <div class="dg-value"><a href="${escapeHtml(lp.endpoint)}" target="_blank" rel="noopener">${escapeHtml(lp.endpoint)}</a></div>`;

    if (lp.txid) {
        html += `
            <div class="dg-label">Registration TX</div>
            <div class="dg-value">${escapeHtml(lp.txid)}</div>`;
    }
    if (lp.height) {
        html += `
            <div class="dg-label">Registered at</div>
            <div class="dg-value">Block ${lp.height}</div>`;
    }

    html += `
        </div>
    </div>`;

    return html;
}

// =============================================================================
// INITIALIZATION
// =============================================================================

document.addEventListener('DOMContentLoaded', async () => {
    console.log('[explorer] Initializing LP Explorer...');

    let loaded = false;

    // WS registry
    const registryWsUrl = CONFIG.REGISTRY_URL.replace(/^http/, 'ws') + '/ws';
    registryWs = new PnaWebSocket(registryWsUrl, {
        lps: (data) => {
            if (data.lps && data.lps.length > 0) {
                applyRegistryLPs(data.lps);
                if (!loaded) {
                    loaded = true;
                    console.log(`[ws] Registry: ${data.lps.length} LPs`);
                }
            }
        },
        lp_update: (data) => {
            const idx = CONFIG.LP_REGISTRY.findIndex(lp => lp.endpoint === data.endpoint);
            if (idx >= 0) CONFIG.LP_REGISTRY[idx] = data;
            else CONFIG.LP_REGISTRY.push(data);
            connectLPWebSockets();
            updateLPCard(data.endpoint);
            updateStats();
        },
        pong: () => {},
    });
    registryWs.connect();

    // HTTP fallback
    await new Promise(r => setTimeout(r, 3000));
    if (!loaded) {
        console.log('[explorer] WS pending, trying HTTP...');
        try {
            const resp = await fetch(
                `${CONFIG.REGISTRY_URL}/api/registry/lps/online`,
                { signal: AbortSignal.timeout(CONFIG.REGISTRY_TIMEOUT_MS) }
            );
            if (resp.ok) {
                const data = await resp.json();
                if (data.lps && data.lps.length > 0) {
                    applyRegistryLPs(data.lps);
                    loaded = true;
                    console.log(`[explorer] HTTP: ${data.lps.length} LPs`);
                }
            }
        } catch (e) {
            console.warn('[explorer] HTTP fallback failed:', e.message);
        }
    }

    if (!loaded) {
        console.warn('[explorer] No LPs discovered. Waiting for WS...');
    }

    // Periodic refresh
    setInterval(() => {
        renderLPList();
        renderPairsSummary();
    }, 30000);

    console.log('[explorer] Ready');
});

// Expose to window
window.openDetail = openDetail;
window.closeDetail = closeDetail;
window.toggleFilter = toggleFilter;
window.setFilter = setFilter;
window.filterLPs = filterLPs;
