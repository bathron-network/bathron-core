/**
 * pna - Minimal Trustless Cross-Chain Swap
 *
 * Supports: BTC <-> USDC via M1 settlement rail (FlowSwap 3-Secret)
 * User generates S_user client-side, LP handles all HTLCs.
 */

// =============================================================================
// ASSETS CONFIGURATION
// =============================================================================

const ASSETS = {
    BTC: {
        symbol: 'BTC',
        name: 'Bitcoin',
        icon: '\u20bf',
        network: 'Bitcoin Signet',
        decimals: 8,
        color: '#f7931a',
        addressPattern: /^(tb1|[mn2])[a-zA-HJ-NP-Z0-9]{25,62}$/,
        addressPlaceholder: 'tb1q...',
    },
    USDC: {
        symbol: 'USDC',
        name: 'USDC',
        icon: '$',
        network: 'Base',
        decimals: 6,
        color: '#2775ca',
        addressPattern: /^0x[a-fA-F0-9]{40}$/,
        addressPlaceholder: '0x...',
    },
    M1: {
        symbol: 'M1',
        name: 'M1',
        icon: '\u039c',
        network: 'BATHRON',
        decimals: 8,
        color: '#3b82f6',
        addressPattern: /^[xy][a-zA-HJ-NP-Z0-9]{33}$/,
        addressPlaceholder: 'y...',
    },
    PIVX: {
        symbol: 'PIVX',
        name: 'PIVX',
        icon: 'P',
        network: 'PIVX Testnet',
        decimals: 8,
        color: '#6b3fa0',
        addressPattern: /^[yY][a-zA-HJ-NP-Z0-9]{25,34}$/,
        addressPlaceholder: 'y...',
        explorer: 'https://testnet.pivx.org/tx/',
    },
    DASH: {
        symbol: 'DASH',
        name: 'Dash',
        icon: 'D',
        network: 'Dash Testnet',
        decimals: 8,
        color: '#008ce7',
        addressPattern: /^[yY][a-zA-HJ-NP-Z0-9]{25,34}$/,
        addressPlaceholder: 'y...',
        explorer: 'https://testnet-insight.dashevo.org/insight/tx/',
    },
    ZEC: {
        symbol: 'ZEC',
        name: 'Zcash',
        icon: 'Z',
        network: 'Zcash Testnet',
        decimals: 8,
        color: '#f4b728',
        addressPattern: /^t[a-zA-HJ-NP-Z0-9]{34}$/,
        addressPlaceholder: 'tm...',
        explorer: 'https://explorer.testnet.z.cash/tx/',
    },
};

// Mock rates (relative to USD)
const MOCK_RATES = {
    BTC: 98500,
    USDC: 1,
    M1: 1,  // mock display rate only — M1 is sats, 1:1 with M0 (burned BTC); no peg exists
    PIVX: 0.25,
    DASH: 28,
    ZEC: 35,
};

// =============================================================================
// CONFIGURATION
// =============================================================================

const CONFIG = {
    // LP endpoints - loaded dynamically from registry or lp-config.json at startup.
    SDK_URLS: [],
    // PNA LP Registry (permissionless on-chain discovery)
    REGISTRY_URL: 'https://registry.example'  /* TODO-PUBLIC-SEED */,
    REGISTRY_TIMEOUT_MS: 3000,
    LP_REGISTRY: [],         // Populated from registry: [{endpoint, tier, address, ...}]
    SHOW_ALL_LPS: false,     // false = Tier 1 only by default
    STATUS_REFRESH_MS: 5000,
    QUOTE_REFRESH_MS: 10000,
    LP_TIMEOUT_MS: 4000,
    MIN_AMOUNT: 0.0001,
    MAX_AMOUNT: {
        BTC: 1.0,
        USDC: 100000,
        M1: 100000,
    },
};

// =============================================================================
// EVM / MetaMask Configuration (USDC -> BTC reverse flow)
// =============================================================================

const EVM_CONFIG = {
    CHAIN_ID: 84532,                // Base Sepolia
    CHAIN_ID_HEX: '0x14a34',
    CHAIN_NAME: 'Base Sepolia',
    RPC_URL: 'https://sepolia.base.org',
    EXPLORER_URL: 'https://sepolia.basescan.org',
    USDC_ADDRESS: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
    HTLC3S_ADDRESS: '0x2493EaaaBa6B129962c8967AaEE6bF11D0277756',
    USDC_DECIMALS: 6,
};

// Minimal ABIs
const USDC_ABI = [
    'function approve(address spender, uint256 amount) returns (bool)',
    'function allowance(address owner, address spender) view returns (uint256)',
];

const HTLC3S_ABI = [
    'function create(address recipient, address token, uint256 amount, bytes32 hashUser, bytes32 hashLP1, bytes32 hashLP2, uint256 timelock) returns (bytes32)',
    'event HTLCCreated(bytes32 indexed id, address indexed sender, address indexed recipient, address token, uint256 amount, bytes32 hashUser, bytes32 hashLP1, bytes32 hashLP2, uint256 timelock)',
];

// MetaMask state
let metamaskState = {
    connected: false,
    address: null,
    provider: null,
    signer: null,
};

// Current LP info (fetched from SDK)
let currentLP = {
    id: null,
    name: 'Connecting...',
    pairs: {},
    inventory: {},
};

// Current quote (fetched from SDK)
let currentQuote = null;

// =============================================================================
// STATE
// =============================================================================

const State = {
    fromAsset: 'BTC',
    toAsset: 'USDC',
    inputAmount: 0,
    outputAmount: 0,
    destAddress: '',
    currentSwap: null,   // Active FlowSwap state
    S_user: null,        // User's secret (client-side only)
    statusInterval: null,
    modalTarget: null,   // 'from' or 'to'
    activeLpUrl: null,   // Selected LP URL for current swap
    routeType: null,     // 'full' or 'perleg'
    routeLegs: null,     // { leg1: {..., _url}, leg2: {..., _url} } when perleg
    _lpExplorerLoaded: false, // LP explorer lazy-load flag
};

/**
 * Get the active LP URL. Falls back to first configured LP.
 */
function getLpUrl() {
    return State.activeLpUrl || CONFIG.SDK_URLS[0];
}

// =============================================================================
// SESSION PERSISTENCE (sessionStorage)
// =============================================================================

/**
 * Save active swap state to sessionStorage so it survives page refresh.
 * SECURITY: S_user is stored in sessionStorage (tab-scoped, cleared on tab close).
 */
function saveSwapSession() {
    if (!State.currentSwap || !State.S_user) return;
    try {
        const session = {
            S_user: State.S_user,
            swap: State.currentSwap,
            lpUrl: State.activeLpUrl,
            ts: Date.now(),
        };
        sessionStorage.setItem('pna_swap_session', JSON.stringify(session));
    } catch (e) {
        console.warn('[pna] Failed to save swap session:', e);
    }
}

/**
 * Restore swap session from sessionStorage (called on page load).
 * Returns the session object or null if none/expired.
 */
function loadSwapSession() {
    try {
        const raw = sessionStorage.getItem('pna_swap_session');
        if (!raw) return null;
        const session = JSON.parse(raw);
        // Expire after 2 hours (aligned with shortest HTLC timelock)
        if (Date.now() - session.ts > 2 * 60 * 60 * 1000) {
            sessionStorage.removeItem('pna_swap_session');
            return null;
        }
        if (!session.S_user || !session.swap || !session.swap.swap_id) return null;
        return session;
    } catch (e) {
        console.warn('[pna] Failed to load swap session:', e);
        return null;
    }
}

/**
 * Clear saved swap session (on completion, reset, or expiry).
 */
function clearSwapSession() {
    sessionStorage.removeItem('pna_swap_session');
}

// =============================================================================
// WEBSOCKET CLIENT
// =============================================================================

class PnaWebSocket {
    constructor(url, handlers) {
        this.url = url;
        this.handlers = handlers;  // {type: callback}
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
            // Restore subscriptions
            for (const [channel, data] of Object.entries(this.subs)) {
                this.ws.send(JSON.stringify({ type: 'subscribe', channel, data }));
            }
            // Start keepalive pings every 25s
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

    unsubscribe(channel) {
        delete this.subs[channel];
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({ type: 'unsubscribe', channel }));
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

// WS instances (initialized in DOMContentLoaded)
let registryWs = null;
let lpWebSockets = {};  // url -> PnaWebSocket
let lpWsInfoCache = {}; // url -> { info: lp_info data, inventory: {btc, m1, usdc, ...}, ts: timestamp }

// =============================================================================
// DOM ELEMENTS
// =============================================================================

const DOM = {
    inputAmount: document.getElementById('input-amount'),
    outputAmount: document.getElementById('output-amount'),
    rateValue: document.getElementById('rate-value'),
    routeValue: document.getElementById('route-value'),
    timeValue: document.getElementById('time-value'),
    btcFinalityValue: document.getElementById('btc-finality-value'),
    destAddress: document.getElementById('dest-address'),
    destLabel: document.getElementById('dest-label'),
    swapBtn: document.getElementById('swap-btn'),
    swapModal: document.getElementById('swap-modal'),
    swapId: document.getElementById('swap-id'),
    statusMessage: document.getElementById('status-message'),
    newSwapBtn: document.getElementById('new-swap-btn'),
    btcSentBtn: document.getElementById('btc-sent-btn'),
    // Deposit box
    depositBox: document.getElementById('deposit-box'),
    depositAmount: document.getElementById('deposit-amount'),
    depositAddress: document.getElementById('deposit-address'),
    // Tx links
    txLinks: document.getElementById('tx-links'),
    txLinkBtc: document.getElementById('tx-link-btc'),
    txLinkEvm: document.getElementById('tx-link-evm'),
    // Asset selectors
    fromIcon: document.getElementById('from-icon'),
    fromName: document.getElementById('from-name'),
    fromNetwork: document.getElementById('from-network'),
    fromBalance: document.getElementById('from-balance'),
    toIcon: document.getElementById('to-icon'),
    toName: document.getElementById('to-name'),
    toNetwork: document.getElementById('to-network'),
    // Modal
    assetModal: document.getElementById('asset-modal'),
    assetList: document.getElementById('asset-list'),
    // Verification modal
    verifyModal: document.getElementById('verify-modal'),
    verifyUsdcAmount: document.getElementById('verify-usdc-amount'),
    verifyEvmLink: document.getElementById('verify-evm-link'),
    verifyHUser: document.getElementById('verify-h-user'),
    verifyHLp1: document.getElementById('verify-h-lp1'),
    verifyHLp2: document.getElementById('verify-h-lp2'),
    verifyBtcLink: document.getElementById('verify-btc-link'),
    verifyWarning: document.getElementById('verify-warning'),
    verifyWarningText: document.getElementById('verify-warning-text'),
    verifyConfirmBtn: document.getElementById('verify-confirm-btn'),
};

// =============================================================================
// CRYPTO UTILITIES (client-side secret generation)
// =============================================================================

/**
 * Generate a 32-byte random secret as hex string.
 * Uses Web Crypto API for secure randomness.
 */
function generateSecret() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Compute SHA256 hash of hex string.
 * Uses ethers.js (works over HTTP, no crypto.subtle needed).
 */
async function sha256hex(hexStr) {
    return ethers.sha256('0x' + hexStr).slice(2);
}

// =============================================================================
// METAMASK CONNECTION (for USDC -> BTC reverse flow)
// =============================================================================

async function connectMetaMask() {
    if (!window.ethereum) {
        throw new Error('MetaMask not installed. Please install MetaMask to swap USDC.');
    }

    const provider = new ethers.BrowserProvider(window.ethereum);

    // Request accounts
    const accounts = await provider.send('eth_requestAccounts', []);
    if (!accounts || accounts.length === 0) {
        throw new Error('No MetaMask account selected');
    }

    // Switch to Base Sepolia if needed
    try {
        await window.ethereum.request({
            method: 'wallet_switchEthereumChain',
            params: [{ chainId: EVM_CONFIG.CHAIN_ID_HEX }],
        });
    } catch (switchError) {
        // Chain not added — add it
        if (switchError.code === 4902) {
            await window.ethereum.request({
                method: 'wallet_addEthereumChain',
                params: [{
                    chainId: EVM_CONFIG.CHAIN_ID_HEX,
                    chainName: EVM_CONFIG.CHAIN_NAME,
                    rpcUrls: [EVM_CONFIG.RPC_URL],
                    blockExplorerUrls: [EVM_CONFIG.EXPLORER_URL],
                    nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 },
                }],
            });
        } else {
            throw switchError;
        }
    }

    const signer = await provider.getSigner();

    metamaskState = {
        connected: true,
        address: accounts[0],
        provider,
        signer,
    };

    console.log('[pna] MetaMask connected:', accounts[0]);
    return metamaskState;
}

/**
 * Approve USDC + create 3-secret HTLC on EVM via MetaMask.
 * Returns the htlc_id from the contract event.
 */
async function createUSDCHTLC(params) {
    const { signer } = metamaskState;
    if (!signer) throw new Error('MetaMask not connected');

    const amountRaw = BigInt(Math.round(params.amount * (10 ** EVM_CONFIG.USDC_DECIMALS)));

    // Step 1: Approve USDC spending
    console.log('[pna] Approving USDC:', amountRaw.toString());
    const usdc = new ethers.Contract(EVM_CONFIG.USDC_ADDRESS, USDC_ABI, signer);
    const approveTx = await usdc.approve(EVM_CONFIG.HTLC3S_ADDRESS, amountRaw);
    await approveTx.wait();
    console.log('[pna] USDC approved, tx:', approveTx.hash);

    // Step 2: Create HTLC
    const timelock = Math.floor(Date.now() / 1000) + params.timelock_seconds;
    console.log('[pna] Creating HTLC3S, timelock:', timelock);

    const htlc3s = new ethers.Contract(EVM_CONFIG.HTLC3S_ADDRESS, HTLC3S_ABI, signer);
    const createTx = await htlc3s.create(
        params.recipient,
        EVM_CONFIG.USDC_ADDRESS,
        amountRaw,
        '0x' + params.H_user,
        '0x' + params.H_lp1,
        '0x' + params.H_lp2,
        timelock,
    );

    const receipt = await createTx.wait();
    console.log('[pna] HTLC created, tx:', createTx.hash);

    // Extract htlc_id from event logs
    // The HTLCCreated event has `bytes32 indexed id` as topics[1]
    let htlcId = null;
    const contractAddr = EVM_CONFIG.HTLC3S_ADDRESS.toLowerCase();
    for (const logEntry of receipt.logs) {
        if (logEntry.address.toLowerCase() === contractAddr && logEntry.topics.length >= 2) {
            htlcId = logEntry.topics[1]; // indexed htlc_id
            break;
        }
    }

    if (!htlcId) {
        // Fallback: use tx hash as reference
        console.warn('[pna] Could not extract htlc_id from event, using tx hash');
        htlcId = createTx.hash;
    }

    return {
        htlc_id: htlcId,
        lock_txhash: createTx.hash,
        approve_txhash: approveTx.hash,
    };
}

// =============================================================================
// ASSET SELECTION
// =============================================================================

function openAssetModal(target) {
    State.modalTarget = target;

    const currentAsset = target === 'from' ? State.fromAsset : State.toAsset;
    const otherAsset = target === 'from' ? State.toAsset : State.fromAsset;

    let html = '';
    for (const [symbol, asset] of Object.entries(ASSETS)) {
        const isSelected = symbol === currentAsset;
        const isOtherSide = symbol === otherAsset;
        const isDisabled = asset.disabled;

        html += `
            <div class="asset-item ${isSelected ? 'selected' : ''} ${isDisabled ? 'disabled' : ''}"
                 ${isDisabled ? '' : `onclick="selectAsset('${symbol}')"`}
                 ${isDisabled ? 'title="' + (asset.disabledReason || 'Unavailable') + '"' : ''}>
                <span class="asset-item-icon" style="color: ${asset.color}${isDisabled ? '; opacity: 0.4' : ''}">${asset.icon}</span>
                <div class="asset-item-info">
                    <span class="asset-item-name" ${isDisabled ? 'style="opacity: 0.5"' : ''}>${asset.name}</span>
                    <span class="asset-item-network">${isDisabled ? asset.disabledReason : asset.network}</span>
                </div>
                ${isSelected ? '<span class="asset-item-check">&#10003;</span>' : ''}
                ${isOtherSide ? '<span class="asset-item-swap">&#8644;</span>' : ''}
            </div>
        `;
    }

    DOM.assetList.innerHTML = html;
    DOM.assetModal.classList.remove('hidden');
}

function closeAssetModal() {
    DOM.assetModal.classList.add('hidden');
    State.modalTarget = null;
}

function closeSwapModal() {
    if (State.currentSwap) {
        const currentState = State.currentSwap.state || '';
        const terminalStates = ['completed', 'failed', 'expired', 'refunded'];
        if (terminalStates.includes(currentState)) {
            // Swap finished — full reset
            resetSwap();
            return;
        }
        // Before user sent funds — just hide modal, keep form intact
        if (currentState === 'awaiting_btc' || currentState === 'awaiting_usdc') {
            DOM.swapModal.classList.add('hidden');
            // Stop polling
            if (State.statusInterval) {
                clearInterval(State.statusInterval);
                State.statusInterval = null;
            }
            State.currentSwap = null;
            State.S_user = null;
            State.activeLpUrl = null;
            // Re-enable swap button
            DOM.swapBtn.classList.remove('loading');
            updateButtonState();
            return;
        }
        // Funds in flight — can't close
        return;
    }
    resetSwap();
}

async function selectAsset(symbol) {
    if (!State.modalTarget) return;

    const otherAsset = State.modalTarget === 'from' ? State.toAsset : State.fromAsset;

    // If selecting the asset from the other side, swap them
    if (symbol === otherAsset) {
        const temp = State.fromAsset;
        State.fromAsset = State.toAsset;
        State.toAsset = temp;
    } else {
        // Normal selection
        if (State.modalTarget === 'from') {
            State.fromAsset = symbol;
        } else {
            State.toAsset = symbol;
        }
    }

    closeAssetModal();
    updateAssetDisplay();
    await updateRateDisplay();
    await onInputChange();
}

async function swapDirection() {
    // Save current INPUT value (stays the same, just different asset)
    const previousInput = State.inputAmount;

    // Swap from and to assets
    const temp = State.fromAsset;
    State.fromAsset = State.toAsset;
    State.toAsset = temp;

    // Keep the same INPUT value (now it's the other asset)
    State.inputAmount = previousInput;

    // Update display (asset labels)
    updateAssetDisplay();

    // Recalculate output with new direction
    if (State.inputAmount > 0) {
        DOM.outputAmount.textContent = '...';
        const newOutput = await calculateOutput(State.inputAmount);
        State.outputAmount = newOutput;

        if (currentQuote && currentQuote.error === 'min') {
            const minDec = currentQuote.asset === 'BTC' ? 8 : 2;
            DOM.outputAmount.textContent = `Min: ${formatNumber(currentQuote.minAmount, minDec)} ${currentQuote.asset}`;
            updateQuoteBreakdown(null);
        } else if (currentQuote && currentQuote.error === 'max') {
            const maxDec = currentQuote.asset === 'BTC' ? 8 : 2;
            DOM.outputAmount.textContent = `Max: ${formatNumber(currentQuote.maxAmount, maxDec)} ${currentQuote.asset}`;
            updateQuoteBreakdown(null);
        } else {
            updateOutputDisplay();
            updateQuoteBreakdown(currentQuote);
        }
    } else {
        DOM.outputAmount.textContent = '0.00';
        updateQuoteBreakdown(null);
    }

    await updateRateDisplay();
    updateButtonState();
}

function updateAssetDisplay() {
    const from = ASSETS[State.fromAsset];
    const to = ASSETS[State.toAsset];

    // Update from side
    DOM.fromIcon.textContent = from.icon;
    DOM.fromIcon.style.color = from.color;
    DOM.fromName.textContent = from.symbol;
    DOM.fromNetwork.textContent = from.network;

    // Update to side
    DOM.toIcon.textContent = to.icon;
    DOM.toIcon.style.color = to.color;
    DOM.toName.textContent = to.symbol;
    DOM.toNetwork.textContent = to.network;

    // Update destination address placeholder
    DOM.destAddress.placeholder = to.addressPlaceholder;
    DOM.destLabel.textContent = `Your ${to.symbol} address (${to.network})`;

}

// =============================================================================
// LP & QUOTE FETCHING
// =============================================================================

async function fetchLPInfo() {
    try {
        // Query all LPs in parallel
        const results = await Promise.allSettled(
            CONFIG.SDK_URLS.map(url =>
                fetch(`${url}/api/lp/info`, { signal: AbortSignal.timeout(CONFIG.LP_TIMEOUT_MS) })
                    .then(r => r.ok ? r.json() : null)
                    .then(data => data ? { ...data, _url: url } : null)
            )
        );

        const online = results
            .filter(r => r.status === 'fulfilled' && r.value)
            .map(r => r.value);

        if (online.length === 0) {
            currentLP.name = 'LP Offline';
            updateLPDisplay();
            return null;
        }

        // Use first available LP as default info
        const first = online[0];
        currentLP = {
            id: first.lp_id,
            name: online.length > 1 ? `${online.length} LPs online` : first.name,
            pairs: first.pairs,
            inventory: first.inventory,
        };

        console.log(`[pna] ${online.length} LP(s) online:`, online.map(lp => lp.name || lp.lp_id));
        updateLPDisplay();
        return first;
    } catch (e) {
        console.error('[pna] Failed to fetch LP info:', e);
        currentLP.name = 'LP Offline';
        updateLPDisplay();
        return null;
    }
}

async function fetchQuote(fromAsset, toAsset, amount) {
    if (amount <= 0) return null;

    try {
        // Query all LPs in parallel for best rate
        const quoteUrl = (base) => `${base}/api/quote?from=${fromAsset}&to=${toAsset}&amount=${amount}`;

        const results = await Promise.allSettled(
            CONFIG.SDK_URLS.map(url =>
                fetch(quoteUrl(url), { signal: AbortSignal.timeout(CONFIG.LP_TIMEOUT_MS) })
                    .then(async r => {
                        if (!r.ok) {
                            const error = await r.json().catch(() => ({}));
                            return { _error: error.detail || `HTTP ${r.status}`, _url: url };
                        }
                        const data = await r.json();
                        return { ...data, _url: url };
                    })
            )
        );

        const quotes = results
            .filter(r => r.status === 'fulfilled' && r.value && !r.value._error)
            .map(r => r.value);

        // Check for error messages from rejected quotes
        const errors = results
            .filter(r => r.status === 'fulfilled' && r.value && r.value._error)
            .map(r => r.value);

        if (quotes.length === 0) {
            // Use first error for user feedback
            if (errors.length > 0) {
                const errorMsg = errors[0]._error;
                if (errorMsg.includes('below minimum')) {
                    const match = errorMsg.match(/minimum: ([\d.]+)/);
                    if (match) {
                        currentQuote = { error: 'min', minAmount: parseFloat(match[1]), asset: fromAsset };
                    }
                } else if (errorMsg.includes('above maximum')) {
                    const match = errorMsg.match(/maximum: ([\d.]+)/);
                    if (match) {
                        currentQuote = { error: 'max', maxAmount: parseFloat(match[1]), asset: fromAsset };
                    }
                }
                console.warn('[pna] All quotes rejected:', errorMsg);
            }
            return null;
        }

        // Liquidity-first: filter LPs that can actually fill the order
        const fillable = quotes.filter(q => q.inventory_ok !== false);

        if (fillable.length === 0) {
            // No LP has enough liquidity — find best max_amount for feedback
            const bestMax = quotes.reduce((a, b) =>
                parseFloat(b.max_amount || 0) > parseFloat(a.max_amount || 0) ? b : a
            );
            currentQuote = { error: 'max', maxAmount: bestMax.max_amount, asset: fromAsset };
            console.warn(`[pna] No LP has enough liquidity. Best max: ${bestMax.max_amount} ${fromAsset}`);
            return null;
        }

        // Among fillable LPs, pick best rate (highest toAmount for user)
        const best = fillable.reduce((a, b) =>
            parseFloat(b.toAmount || b.to_amount || 0) > parseFloat(a.toAmount || a.to_amount || 0) ? b : a
        );

        // Store the selected LP URL — but don't override during active swap
        if (!State.currentSwap) {
            State.activeLpUrl = best._url;
        }
        console.log(`[pna] Best quote from ${best._url}: ${best.toAmount || best.to_amount} (${quotes.length} LP(s) responded)`);

        currentQuote = best;
        return currentQuote;
    } catch (e) {
        console.error('[pna] Quote error:', e);
        currentQuote = null;
        return null;
    }
}

// =============================================================================
// PER-LEG ROUTING (Blueprint 16 — Multi-LP)
// =============================================================================

/**
 * Query all LPs for a single leg (X→M1 or M1→Y).
 */
async function fetchLegQuotes(fromAsset, toAsset, amount) {
    if (amount <= 0) return [];
    const results = await Promise.allSettled(
        CONFIG.SDK_URLS.map(url =>
            fetch(`${url}/api/quote/leg?from=${fromAsset}&to=${toAsset}&amount=${amount}`,
                { signal: AbortSignal.timeout(CONFIG.LP_TIMEOUT_MS) })
                .then(async r => {
                    if (!r.ok) return null;
                    const data = await r.json();
                    return { ...data, _url: url };
                })
        )
    );
    return results
        .filter(r => r.status === 'fulfilled' && r.value)
        .map(r => r.value);
}

/**
 * Liquidity-first, then best price — for a single leg.
 */
function selectBestLeg(quotes) {
    if (!quotes || quotes.length === 0) return null;
    const fillable = quotes.filter(q => q.inventory_ok !== false);
    if (fillable.length === 0) return null;
    return fillable.reduce((a, b) =>
        parseFloat(b.to_amount || 0) > parseFloat(a.to_amount || 0) ? b : a
    );
}

/**
 * Compose a per-leg route: query leg 1 (from→M1), then leg 2 (M1→to).
 */
async function fetchPerLegRoute(fromAsset, toAsset, amount) {
    // Only for cross-chain (both sides != M1)
    if (fromAsset === 'M1' || toAsset === 'M1') return null;

    try {
        // Leg 1: from → M1
        const leg1Quotes = await fetchLegQuotes(fromAsset, 'M1', amount);
        const bestLeg1 = selectBestLeg(leg1Quotes);
        if (!bestLeg1) return null;

        // Leg 2: M1 → to (use leg 1 output as input)
        const leg2Quotes = await fetchLegQuotes('M1', toAsset, bestLeg1.to_amount);
        let bestLeg2 = selectBestLeg(leg2Quotes);
        if (!bestLeg2) return null;

        // Same-LP bias: prefer keeping both legs on the same LP when the
        // difference is negligible (< 0.1%). Single-LP is simpler and more
        // reliable (1 atomic swap vs 2 coordinated legs).
        if (bestLeg1.lp_id !== bestLeg2.lp_id) {
            const sameLpLeg2 = leg2Quotes.find(q =>
                q.lp_id === bestLeg1.lp_id && q.inventory_ok !== false
            );
            if (sameLpLeg2) {
                const diff = Math.abs(
                    parseFloat(bestLeg2.to_amount) - parseFloat(sameLpLeg2.to_amount)
                );
                const threshold = parseFloat(bestLeg2.to_amount) * 0.001; // 0.1%
                if (diff <= threshold) {
                    console.log(`[pna] Same-LP bias: keeping ${bestLeg1.lp_name} for both legs (diff=${diff.toFixed(4)})`);
                    bestLeg2 = sameLpLeg2;
                }
            }
        }

        return {
            type: 'perleg',
            leg1: bestLeg1,
            leg2: bestLeg2,
            total_output: bestLeg2.to_amount,
            total_spread: bestLeg1.spread_percent + bestLeg2.spread_percent,
            route: `${fromAsset} \u2192 M1 (${bestLeg1.lp_name}) \u2192 ${toAsset} (${bestLeg2.lp_name})`,
            settlement_time_seconds: bestLeg1.settlement_time_seconds + bestLeg2.settlement_time_seconds,
            settlement_time_human: `~${Math.ceil(
                (bestLeg1.settlement_time_seconds + bestLeg2.settlement_time_seconds) / 60
            )} min`,
            confirmations_required: bestLeg1.confirmations_required,
            confirmations_breakdown: bestLeg1.confirmations_breakdown,
        };
    } catch (e) {
        console.warn('[pna] Per-leg route error:', e);
        return null;
    }
}

/**
 * Compare full-route (single LP) vs per-leg (multi-LP). Pick best output.
 */
async function fetchBestRoute(fromAsset, toAsset, amount) {
    if (amount <= 0) return null;

    // M1 direct legs — skip per-leg composition
    if (fromAsset === 'M1' || toAsset === 'M1') {
        const quote = await fetchQuote(fromAsset, toAsset, amount);
        if (quote) {
            State.routeType = 'full';
            State.routeLegs = null;
        }
        return quote;
    }

    // Query both in parallel
    const [fullResult, perLegResult] = await Promise.allSettled([
        fetchQuote(fromAsset, toAsset, amount),
        fetchPerLegRoute(fromAsset, toAsset, amount),
    ]);

    const fullRoute = fullResult.status === 'fulfilled' ? fullResult.value : null;
    const perLeg = perLegResult.status === 'fulfilled' ? perLegResult.value : null;

    if (!fullRoute && !perLeg) return null;

    // Only full-route available
    if (!perLeg) {
        State.routeType = 'full';
        State.routeLegs = null;
        return fullRoute;
    }

    // Build a currentQuote-compatible object from per-leg
    function buildPerLegQuote(pl) {
        const effectiveRate = pl.total_output / amount;
        const spreadFrac = (pl.total_spread || 0) / 100;
        const marketRate = spreadFrac < 1 ? effectiveRate / (1 - spreadFrac) : effectiveRate;
        return {
            lp_id: `${pl.leg1.lp_id}+${pl.leg2.lp_id}`,
            lp_name: `${pl.leg1.lp_name} + ${pl.leg2.lp_name}`,
            from_asset: fromAsset,
            to_asset: toAsset,
            from_amount: amount,
            to_amount: pl.total_output,
            rate: effectiveRate,
            rate_market: marketRate,
            route: pl.route,
            spread_percent: pl.total_spread || 0,
            settlement_time_seconds: pl.settlement_time_seconds,
            settlement_time_human: pl.settlement_time_human,
            confirmations_required: pl.confirmations_required,
            confirmations_breakdown: pl.confirmations_breakdown,
            inventory_ok: true,
            min_amount: pl.leg1.min_amount,
            max_amount: pl.leg1.max_amount,
        };
    }

    // Only per-leg available
    if (!fullRoute) {
        State.routeType = 'perleg';
        State.routeLegs = { leg1: perLeg.leg1, leg2: perLeg.leg2 };
        State.activeLpUrl = null;
        currentQuote = buildPerLegQuote(perLeg);
        return currentQuote;
    }

    // Both available — compare to_amount
    const fullOutput = parseFloat(fullRoute.to_amount || 0);
    const perLegOutput = parseFloat(perLeg.total_output || 0);

    if (perLegOutput > fullOutput) {
        State.routeType = 'perleg';
        State.routeLegs = { leg1: perLeg.leg1, leg2: perLeg.leg2 };
        State.activeLpUrl = null;
        currentQuote = buildPerLegQuote(perLeg);
        console.log(`[pna] Per-leg route wins: ${perLegOutput} > ${fullOutput} (full)`);
        return currentQuote;
    }

    // Full-route wins (or tie)
    State.routeType = 'full';
    State.routeLegs = null;
    console.log(`[pna] Full-route wins: ${fullOutput} >= ${perLegOutput} (per-leg)`);
    return fullRoute;
}

function updateLPDisplay() {
    // Update LP name in header if element exists
    const lpNameEl = document.getElementById('lp-name');
    if (lpNameEl) {
        lpNameEl.textContent = currentLP.name;
    }
}

function updateTierDisplay() {
    // Show tier badge for the active LP
    const badge = document.getElementById('lp-tier-badge');
    if (!badge) return;

    if (CONFIG.LP_REGISTRY.length === 0) {
        badge.style.display = 'none';
        return;
    }

    // Find the active LP in registry
    const activeLp = CONFIG.LP_REGISTRY.find(
        lp => lp.endpoint === (State.activeLpUrl || CONFIG.SDK_URLS[0])
    );
    if (activeLp && activeLp.tier === 1) {
        badge.textContent = 'Operator';
        badge.className = 'tier-badge tier-1';
        badge.style.display = 'inline-block';
    } else if (activeLp) {
        badge.textContent = 'Community LP';
        badge.className = 'tier-badge tier-2';
        badge.style.display = 'inline-block';
    } else {
        badge.style.display = 'none';
    }

    // Update LP count display
    const countEl = document.getElementById('lp-count');
    if (countEl) {
        const tier1 = CONFIG.LP_REGISTRY.filter(lp => lp.tier === 1).length;
        const total = CONFIG.LP_REGISTRY.length;
        countEl.textContent = `${total} LP${total > 1 ? 's' : ''} (${tier1} verified)`;
    }
}

function toggleShowAllLPs() {
    const checkbox = document.getElementById('show-all-lps');
    if (!checkbox) return;
    CONFIG.SHOW_ALL_LPS = checkbox.checked;

    if (CONFIG.LP_REGISTRY.length > 0) {
        CONFIG.SDK_URLS = CONFIG.LP_REGISTRY
            .filter(lp => CONFIG.SHOW_ALL_LPS || lp.tier === 1)
            .map(lp => lp.endpoint);
        if (CONFIG.SDK_URLS.length === 0) {
            CONFIG.SDK_URLS = CONFIG.LP_REGISTRY.map(lp => lp.endpoint);
        }
        console.log(`[pna] Show all: ${CONFIG.SHOW_ALL_LPS}, active LPs: ${CONFIG.SDK_URLS.length}`);
        connectLPWebSockets();
        fetchLPInfo();
        updateTierDisplay();
    }
}

// =============================================================================
// RATE & QUOTE
// =============================================================================

function getRoute(fromAsset, toAsset) {
    // Use route from quote if available
    if (currentQuote && currentQuote.route) {
        return currentQuote.route;
    }
    // Default: Direct pairs via M1 rail
    if (fromAsset === 'M1' || toAsset === 'M1') {
        return `${fromAsset} → ${toAsset}`;
    }
    // Cross-chain needs M1 hop
    return `${fromAsset} → M1 → ${toAsset}`;
}

function getSettlementTime(fromAsset, toAsset) {
    // Use time from quote if available
    if (currentQuote && currentQuote.settlement_time_human) {
        return currentQuote.settlement_time_human;
    }
    // Default estimates
    if (fromAsset === 'BTC') {
        return '~20 min (6 BTC conf)';
    }
    if (fromAsset === 'M1') {
        return '~1 min';
    }
    return '~2 min';
}

async function updateRateDisplay() {
    // Use a small reference amount for rate display (avoids inflated settlement time)
    const refAmount = State.fromAsset === 'BTC' ? 0.001 : (State.fromAsset === 'USDC' ? 50 : 1);
    const quote = await fetchBestRoute(State.fromAsset, State.toAsset, refAmount);

    if (quote) {
        // Format rate display
        const rate = quote.rate;
        let rateStr;
        if (rate >= 1000) {
            rateStr = `1 ${State.fromAsset} = ${formatNumber(rate, 2)} ${State.toAsset}`;
        } else if (rate >= 1) {
            rateStr = `1 ${State.fromAsset} = ${rate.toFixed(4)} ${State.toAsset}`;
        } else {
            rateStr = `1 ${State.fromAsset} = ${rate.toFixed(8)} ${State.toAsset}`;
        }

        DOM.rateValue.textContent = rateStr;
        // Route display: detailed per-leg or simple
        if (State.routeLegs && State.routeLegs.leg1 && State.routeLegs.leg2) {
            const l1 = State.routeLegs.leg1;
            const l2 = State.routeLegs.leg2;
            const r1 = parseFloat(l1.rate || 0);
            const r2 = parseFloat(l2.rate || 0);
            // Format leg rate: show inverted when < 0.01 (e.g. 1 USDC = 1,490 M1)
            function fmtLegRate(r, from, to) {
                if (r >= 100) return formatNumber(r, 0);
                if (r >= 0.01) return r.toFixed(4);
                // Tiny rate — show inverted for readability
                const inv = 1 / r;
                return `1 ${to}=${formatNumber(inv, 0)} ${from}`;
            }
            // Sanitize LP names to prevent XSS from malicious LP endpoints
            const esc = (s) => {
                const d = document.createElement('div');
                d.textContent = s;
                return d.innerHTML;
            };
            DOM.routeValue.innerHTML =
                `<div class="route-leg">` +
                    `<span class="route-leg-pair">${esc(l1.from_asset)} \u2192 ${esc(l1.to_asset)}</span>` +
                    `<span class="route-leg-lp">${esc(l1.lp_name)}</span>` +
                    `<span class="route-leg-rate">${esc(fmtLegRate(r1, l1.from_asset, l1.to_asset))}</span>` +
                `</div>` +
                `<div class="route-leg">` +
                    `<span class="route-leg-pair">${esc(l2.from_asset)} \u2192 ${esc(l2.to_asset)}</span>` +
                    `<span class="route-leg-lp">${esc(l2.lp_name)}</span>` +
                    `<span class="route-leg-rate">${esc(fmtLegRate(r2, l2.from_asset, l2.to_asset))}</span>` +
                `</div>`;
        } else {
            DOM.routeValue.textContent = quote.route;
        }
        // Settlement = M1 rail (~1 min), BTC finality = separate
        const m1Finality = (quote.confirmations_breakdown && quote.confirmations_breakdown.m1_finality) || 60;
        DOM.timeValue.textContent = `~${Math.ceil(m1Finality / 60)} min (M1 rail)`;

        if (quote.confirmations_breakdown) {
            const cb = quote.confirmations_breakdown;
            if (cb.confirmations === 0) {
                DOM.btcFinalityValue.textContent = 'Instant (0-conf)';
            } else {
                const btcMin = Math.ceil(cb.asset_time / 60);
                DOM.btcFinalityValue.textContent = `~${btcMin} min (${cb.confirmations} conf)`;
            }
        } else {
            DOM.btcFinalityValue.textContent = quote.settlement_time_human;
        }

        // Update limits
        CONFIG.MIN_AMOUNT = quote.min_amount;
        CONFIG.MAX_AMOUNT[State.fromAsset] = quote.max_amount;
    } else {
        DOM.rateValue.textContent = 'LP offline';
        DOM.routeValue.textContent = getRoute(State.fromAsset, State.toAsset);
        DOM.timeValue.textContent = '~1 min (M1 rail)';
        DOM.btcFinalityValue.textContent = '-';
    }
}

async function calculateOutput(inputAmount) {
    if (inputAmount <= 0) return 0;

    // Fetch best route (full-route vs per-leg)
    const quote = await fetchBestRoute(State.fromAsset, State.toAsset, inputAmount);

    if (quote) {
        return quote.to_amount;
    }

    // Fallback: use last known rate
    if (currentQuote && currentQuote.rate) {
        return inputAmount * currentQuote.rate;
    }

    return 0;
}

// =============================================================================
// QUOTE BREAKDOWN
// =============================================================================

function formatAmountWithSats(amount, asset) {
    if (asset === 'BTC') {
        const sats = Math.round(amount * 1e8);
        return `${amount.toFixed(8)} BTC (${sats.toLocaleString()} sats)`;
    }
    if (asset === 'M1') {
        const sats = Math.round(amount * 1e8);
        return `${sats.toLocaleString()} M1`;
    }
    if (asset === 'USDC') {
        return `${amount.toFixed(2)} USDC`;
    }
    return `${amount.toFixed(ASSETS[asset]?.decimals || 8)} ${asset}`;
}

function formatRateDisplay(rate, fromAsset, toAsset) {
    if (rate == null || isNaN(rate)) return '-';
    if (rate >= 1000) return `1 ${fromAsset} = ${formatNumber(rate, 2)} ${toAsset}`;
    if (rate >= 1) return `1 ${fromAsset} = ${rate.toFixed(4)} ${toAsset}`;
    return `1 ${fromAsset} = ${rate.toFixed(8)} ${toAsset}`;
}

function updateQuoteBreakdown(quote) {
    const el = document.getElementById('quote-breakdown');
    if (!quote || !quote.from_amount || quote.error) {
        el.style.display = 'none';
        return;
    }

    document.getElementById('bd-send').textContent =
        formatAmountWithSats(quote.from_amount, State.fromAsset);
    document.getElementById('bd-receive').textContent =
        formatAmountWithSats(quote.to_amount, State.toAsset);
    document.getElementById('bd-rate-market').textContent =
        formatRateDisplay(quote.rate_market, State.fromAsset, State.toAsset);
    document.getElementById('bd-spread').textContent =
        quote.spread_percent > 0 ? `${quote.spread_percent.toFixed(2)}%` : 'None';
    document.getElementById('bd-rate-effective').textContent =
        formatRateDisplay(quote.rate, State.fromAsset, State.toAsset);

    el.style.display = '';
}

// =============================================================================
// INPUT HANDLING
// =============================================================================

// Debounce timer for input changes
let inputDebounceTimer = null;

function updateOutputDisplay() {
    if (State.toAsset === 'BTC') {
        DOM.outputAmount.textContent = State.outputAmount.toFixed(8);
    } else if (State.toAsset === 'USDC') {
        DOM.outputAmount.textContent = formatNumber(State.outputAmount, 2);
    } else if (State.toAsset === 'M1') {
        const sats = Math.round(State.outputAmount * 1e8);
        DOM.outputAmount.textContent = sats.toLocaleString();
    } else {
        DOM.outputAmount.textContent = formatNumber(State.outputAmount, ASSETS[State.toAsset]?.decimals || 4);
    }
}

// silent=true: periodic refresh (no loading flash, keep current values until new data)
// silent=false: user typing (show '...' loading indicator)
async function onInputChange(silent = false) {
    const value = parseFloat(DOM.inputAmount.value) || 0;
    State.inputAmount = value;

    // Always cancel pending debounce (prevents stale timer firing after clear)
    if (inputDebounceTimer) {
        clearTimeout(inputDebounceTimer);
        inputDebounceTimer = null;
    }

    if (value <= 0) {
        DOM.outputAmount.textContent = '0.00';
        updateQuoteBreakdown(null);
        updateButtonState();
        return;
    }

    // Only show loading flash on user-initiated input
    if (!silent) {
        DOM.outputAmount.textContent = '...';
    }

    const delay = silent ? 0 : 300;
    inputDebounceTimer = setTimeout(async () => {
        try {
            State.outputAmount = await calculateOutput(value);

            // Check for errors (min/max)
            if (currentQuote && currentQuote.error === 'min') {
                const minDec = currentQuote.asset === 'BTC' ? 8 : 2;
                DOM.outputAmount.textContent = `Min: ${formatNumber(currentQuote.minAmount, minDec)} ${currentQuote.asset}`;
                updateQuoteBreakdown(null);
                updateButtonState();
                return;
            }
            if (currentQuote && currentQuote.error === 'max') {
                const maxDec = currentQuote.asset === 'BTC' ? 8 : 2;
                DOM.outputAmount.textContent = `Max: ${formatNumber(currentQuote.maxAmount, maxDec)} ${currentQuote.asset}`;
                updateQuoteBreakdown(null);
                updateButtonState();
                return;
            }

            updateOutputDisplay();
            updateQuoteBreakdown(currentQuote);

            // Update BTC finality info
            if (currentQuote && !currentQuote.error && currentQuote.confirmations_breakdown) {
                const cb = currentQuote.confirmations_breakdown;
                if (cb.confirmations === 0) {
                    DOM.btcFinalityValue.textContent = 'Instant (0-conf)';
                } else {
                    const btcMin = Math.ceil(cb.asset_time / 60);
                    DOM.btcFinalityValue.textContent = `~${btcMin} min (${cb.confirmations} conf)`;
                }
            }
        } catch (e) {
            console.error('[pna] Quote calculation error:', e);
            // On silent refresh error, keep previous values visible
            if (!silent) {
                DOM.outputAmount.textContent = '0.00';
                updateQuoteBreakdown(null);
            }
        }
        updateButtonState();
    }, delay);
}

function onAddressChange() {
    State.destAddress = DOM.destAddress.value.trim();
    updateButtonState();
}

function updateButtonState() {
    const btn = DOM.swapBtn;
    const btnText = btn.querySelector('.btn-text');
    const fromAsset = ASSETS[State.fromAsset];
    const toAsset = ASSETS[State.toAsset];

    const hasAmount = State.inputAmount >= CONFIG.MIN_AMOUNT;
    const maxAmount = CONFIG.MAX_AMOUNT[State.fromAsset];
    const notTooMuch = State.inputAmount <= maxAmount;
    const hasAddress = toAsset.addressPattern.test(State.destAddress);

    // For USDC->BTC, check MetaMask
    const needsMetaMask = State.fromAsset === 'USDC';
    const hasMetaMask = !!window.ethereum;

    if (!hasAmount) {
        btnText.textContent = 'Enter amount';
        btn.disabled = true;
    } else if (!notTooMuch) {
        btnText.textContent = `Max ${maxAmount} ${State.fromAsset}`;
        btn.disabled = true;
    } else if (!hasAddress) {
        btnText.textContent = `Enter ${toAsset.symbol} address`;
        btn.disabled = true;
    } else if (needsMetaMask && !hasMetaMask) {
        btnText.textContent = 'Install MetaMask';
        btn.disabled = true;
    } else {
        btnText.textContent = `Swap ${State.fromAsset} \u2192 ${State.toAsset}`;
        btn.disabled = false;
    }
}

// =============================================================================
// FLOWSWAP 3S - Real Swap Flow
// =============================================================================

async function initiateSwap() {
    if (DOM.swapBtn.disabled) return;

    // Per-leg route: use multi-LP init (X→M1 on LP_IN, M1→Y on LP_OUT)
    if (State.routeType === 'perleg' && State.routeLegs) {
        const perLegSources = ['BTC', 'DASH', 'PIVX', 'ZEC'];
        if (perLegSources.includes(State.fromAsset) && State.toAsset === 'USDC') {
            return await initiatePerLegSwap();
        }
        // Reverse per-leg not yet supported — fall through to single-LP
        console.log('[pna] Per-leg reverse not supported yet, falling back to single LP');
    }

    if (State.fromAsset === 'BTC' && State.toAsset === 'USDC') {
        return await initiateSwapBtcToUsdc();
    } else if (State.fromAsset === 'USDC' && State.toAsset === 'BTC') {
        return await initiateSwapUsdcToBtc();
    } else {
        setStatusMessage('error', `${State.fromAsset} → ${State.toAsset}: use per-leg route via LP registry`);
    }
}

// ---- PER-LEG: X → M1 (LP_IN) + M1 → USDC (LP_OUT) ----

async function initiatePerLegSwap() {
    const btn = DOM.swapBtn;
    const btnText = btn.querySelector('.btn-text');
    const fromAsset = State.fromAsset;  // BTC, DASH, PIVX, ZEC
    const toAsset = State.toAsset;      // USDC

    try {
        btn.classList.add('loading');
        btnText.textContent = 'Initializing multi-LP swap...';
        btn.disabled = true;

        const S_user = generateSecret();
        const H_user = await sha256hex(S_user);
        State.S_user = S_user;
        console.log('[pna] Per-leg swap: H_user:', H_user.slice(0, 16) + '...');

        const leg1 = State.routeLegs.leg1;  // X→M1 (LP_IN)
        const leg2 = State.routeLegs.leg2;  // M1→USDC (LP_OUT)

        // Step 1: Init LP_OUT (M1→USDC) — get H_lp2 + lp_m1_address
        console.log('[pna] Per-leg step 1: init LP_OUT at', leg2._url);
        const outResp = await fetch(`${leg2._url}/api/flowswap/init-leg`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                leg: `${leg2.from_asset || 'M1'}/${leg2.to_asset || 'USDC'}`,
                from_asset: leg2.from_asset || 'M1',
                to_asset: leg2.to_asset || 'USDC',
                amount: leg2.from_amount || leg1.to_amount,
                H_user: H_user,
                user_usdc_address: State.destAddress,
            }),
        });
        if (!outResp.ok) {
            const err = await outResp.json();
            throw new Error(`LP_OUT init failed: ${err.detail || outResp.status}`);
        }
        const outData = await outResp.json();
        console.log('[pna] LP_OUT init-leg:', outData);

        // Step 2: Init LP_IN (X→M1) — with LP_OUT's H_lp2 + M1 address
        const inLeg = `${leg1.from_asset || fromAsset}/M1`;
        console.log('[pna] Per-leg step 2: init LP_IN at', leg1._url, 'leg:', inLeg);
        const inResp = await fetch(`${leg1._url}/api/flowswap/init-leg`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                leg: inLeg,
                from_asset: leg1.from_asset || fromAsset,
                to_asset: 'M1',
                amount: State.inputAmount,
                H_user: H_user,
                H_lp_other: outData.H_lp2,
                lp_out_m1_address: outData.lp_m1_address,
            }),
        });
        if (!inResp.ok) {
            const err = await inResp.json();
            throw new Error(`LP_IN init failed: ${err.detail || inResp.status}`);
        }
        const inData = await inResp.json();
        console.log('[pna] LP_IN init-leg:', inData);

        // Step 3: Store multi-LP swap state (generic for any source chain)
        // source_deposit (generic) or btc_deposit (backward compat)
        const deposit = inData.source_deposit || inData.btc_deposit || {};
        State.currentSwap = {
            swap_id: inData.swap_id,
            swap_id_out: outData.swap_id,
            is_perleg: true,
            lp_in_url: leg1._url,
            lp_out_url: leg2._url,
            lp_in_name: leg1.lp_name,
            lp_out_name: leg2.lp_name,
            state: inData.state,
            direction: 'forward',
            from_asset: fromAsset,
            to_asset: toAsset,
            from_amount: State.inputAmount,
            to_amount: State.outputAmount,
            dest_address: State.destAddress,
            // Generic deposit info
            source_deposit_address: deposit.address,
            source_deposit_amount_sats: deposit.amount_sats,
            source_deposit_amount_human: deposit.amount_human || deposit.amount_btc,
            // BTC backward compat
            btc_deposit_address: deposit.address,
            btc_amount_sats: deposit.amount_sats,
            btc_amount_btc: deposit.amount_btc || deposit.amount_human,
            instant_min_feerate: (inData.btc_deposit || {}).instant_min_feerate || 4,
            usdc_amount: outData.usdc_output ? outData.usdc_output.amount : State.outputAmount,
            evm_htlc_id: null,
            H_user: H_user,
            H_lp1: inData.H_lp1,
            H_lp2: outData.H_lp2,
            plan_expires_at: Math.min(inData.plan_expires_at || 0, outData.plan_expires_at || 0),
            // Per-leg coordination state
            _perleg_m1_notified: false,
            _perleg_secret_delivered: false,
        };

        showFlowSwapStatus(State.currentSwap);
        startPerLegPolling();

    } catch (error) {
        console.error('[pna] Per-leg swap init error:', error);
        setStatusMessage('error', 'Multi-LP swap failed: ' + error.message);
        btn.classList.remove('loading');
        btnText.textContent = `Swap ${fromAsset} \u2192 ${toAsset}`;
        btn.disabled = false;
    }
}

function startPerLegPolling() {
    if (State.statusInterval) {
        clearInterval(State.statusInterval);
    }

    // Subscribe via WS for instant state updates
    if (State.currentSwap) {
        wsSubscribeSwap(State.currentSwap.swap_id);
    }

    State.statusInterval = setInterval(async () => {
        if (!State.currentSwap || !State.currentSwap.is_perleg) return;

        // Skip HTTP poll if WS is connected (WS handles real-time)
        const lpWs = lpWebSockets[State.currentSwap.lp_in_url];
        if (lpWs && lpWs.connected) return;

        const swap = State.currentSwap;

        try {
            // Poll LP_IN status (HTTP fallback)
            const inResp = await fetch(`${swap.lp_in_url}/api/flowswap/${swap.swap_id}`);
            if (!inResp.ok) return;
            const inData = await inResp.json();

            const prevState = swap.state;
            swap.state = inData.state;

            // Allow funded states to re-process (stability countdown)
            const fundedStates = ['btc_funded', 'dash_funded', 'pivx_funded', 'zec_funded'];
            if (prevState === inData.state && !fundedStates.includes(inData.state)) return;
            console.log(`[pna] Per-leg LP_IN state: ${prevState} -> ${inData.state}`);

            const srcAsset = swap.from_asset || 'BTC';

            switch (inData.state) {
                case 'awaiting_btc':
                case 'awaiting_dash':
                case 'awaiting_pivx':
                case 'awaiting_zec':
                    updateStepProgress(1);
                    setStatusMessage('pending', `Waiting for ${srcAsset} deposit...`);
                    break;

                case 'btc_funded':
                case 'dash_funded':
                case 'pivx_funded':
                case 'zec_funded':
                    updateStepProgress(2);
                    DOM.btcSentBtn.classList.add('hidden');
                    DOM.depositBox.classList.add('hidden');
                    if (inData.stability_check_until) {
                        const remaining = inData.stability_check_until - Math.floor(Date.now() / 1000);
                        if (remaining > 0) {
                            setStatusMessage('pending', `Verifying deposit... ${remaining}s`);
                        } else {
                            setStatusMessage('pending', 'Deposit verified. LP_IN locking M1...');
                        }
                    } else {
                        setStatusMessage('pending', `${srcAsset} detected. ${swap.lp_in_name || 'LP_IN'} locking M1...`);
                    }
                    break;

                case 'm1_locked':
                    // LP_IN locked M1 → notify LP_OUT
                    updateStepProgress(2);
                    if (!swap._perleg_m1_notified) {
                        setStatusMessage('pending', `M1 locked by ${swap.lp_in_name || 'LP_IN'}. Notifying ${swap.lp_out_name || 'LP_OUT'}...`);
                        swap._perleg_m1_notified = true;

                        const m1_outpoint = inData.m1 ? inData.m1.htlc_outpoint : (inData.m1_htlc_outpoint || '');
                        console.log('[pna] Per-leg: notifying LP_OUT m1-locked, outpoint=', m1_outpoint);

                        try {
                            const m1Resp = await fetch(`${swap.lp_out_url}/api/flowswap/${swap.swap_id_out}/m1-locked`, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                    m1_htlc_outpoint: m1_outpoint,
                                    H_lp1: swap.H_lp1,
                                }),
                            });
                            if (!m1Resp.ok) {
                                const err = await m1Resp.json();
                                console.error('[pna] m1-locked notification failed:', err);
                                setStatusMessage('error', `LP_OUT USDC lock failed: ${err.detail || 'unknown error'}`);
                                return;
                            }
                            const m1Data = await m1Resp.json();
                            console.log('[pna] LP_OUT locked USDC, got S_lp2');

                            // Deliver S_lp2 to LP_IN
                            setStatusMessage('pending', `USDC locked by ${swap.lp_out_name || 'LP_OUT'}. Delivering secret...`);
                            const delResp = await fetch(`${swap.lp_in_url}/api/flowswap/${swap.swap_id}/deliver-secret`, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ S_lp2: m1Data.S_lp2 }),
                            });
                            if (!delResp.ok) {
                                const err = await delResp.json();
                                console.error('[pna] deliver-secret failed:', err);
                                setStatusMessage('error', `Secret delivery failed: ${err.detail || 'unknown error'}`);
                                return;
                            }
                            swap._perleg_secret_delivered = true;
                            swap.evm_htlc_id = m1Data.evm_htlc_id;
                            console.log('[pna] Per-leg: secret delivered, LP_IN ready for presign');
                            // Next poll will see lp_locked and autoPresign
                        } catch (e) {
                            console.error('[pna] Per-leg coordination error:', e);
                            setStatusMessage('error', 'Multi-LP coordination failed: ' + e.message);
                        }
                    }
                    break;

                case 'lp_locked':
                    updateStepProgress(2);
                    setStatusMessage('pending', 'Both LPs locked. Completing swap...');
                    DOM.btcSentBtn.classList.add('hidden');
                    DOM.depositBox.classList.add('hidden');
                    autoPresignPerLeg();
                    break;

                case 'btc_claimed':
                    updateStepProgress(3);
                    setStatusMessage('pending', `${srcAsset} claimed by LP. Waiting for USDC delivery...`);
                    if (inData.btc && inData.btc.claim_txid) {
                        showTxLink('btc', inData.btc.claim_txid);
                    }
                    break;

                case 'completing':
                case 'completed':
                    // Per-leg: LP_IN completes fast (just BTC claim).
                    // For user-facing completion, poll LP_OUT (USDC delivery).
                    if (swap._perleg_btc_claimed_notified && swap.lp_out_url && swap.swap_id_out) {
                        try {
                            const outResp = await fetch(`${swap.lp_out_url}/api/flowswap/${swap.swap_id_out}`);
                            if (outResp.ok) {
                                const outData = await outResp.json();
                                console.log(`[pna] Per-leg LP_OUT state: ${outData.state}`);
                                if (outData.state === 'completed') {
                                    updateStepProgress(4);
                                    setStatusMessage('success', 'Swap complete!');
                                    if (outData.evm && outData.evm.claim_txhash) {
                                        showTxLink('evm', outData.evm.claim_txhash);
                                    }
                                    DOM.newSwapBtn.classList.remove('hidden');
                                    clearInterval(State.statusInterval);
                                    State.statusInterval = null;
                                } else if (outData.state === 'completing') {
                                    updateStepProgress(3);
                                    setStatusMessage('pending', 'Finalizing... USDC being sent to your wallet.');
                                } else if (outData.state === 'failed') {
                                    setStatusMessage('error', `LP_OUT failed: ${outData.error || 'Unknown error'}`);
                                    DOM.newSwapBtn.classList.remove('hidden');
                                    clearInterval(State.statusInterval);
                                    State.statusInterval = null;
                                }
                                // lp_locked or btc_claimed: still waiting, keep polling
                            }
                        } catch (outErr) {
                            console.warn('[pna] Per-leg LP_OUT poll error:', outErr);
                        }
                    } else if (inData.state === 'completed') {
                        // Single-LP fallback or LP_OUT not yet notified
                        updateStepProgress(4);
                        setStatusMessage('success', 'Swap complete!');
                        DOM.newSwapBtn.classList.remove('hidden');
                        clearInterval(State.statusInterval);
                        State.statusInterval = null;
                    } else {
                        updateStepProgress(3);
                        setStatusMessage('pending', 'Finalizing... USDC being sent to your wallet.');
                    }
                    break;

                case 'failed':
                    setStatusMessage('error', `Swap failed: ${inData.error || 'Unknown error'}`);
                    DOM.newSwapBtn.classList.remove('hidden');
                    clearInterval(State.statusInterval);
                    State.statusInterval = null;
                    break;

                case 'expired':
                    setStatusMessage('error', 'Plan expired. No funds were locked.');
                    DOM.newSwapBtn.classList.remove('hidden');
                    DOM.btcSentBtn.classList.add('hidden');
                    DOM.depositBox.classList.add('hidden');
                    clearInterval(State.statusInterval);
                    State.statusInterval = null;
                    break;
            }
        } catch (e) {
            console.warn('[pna] Per-leg poll error:', e);
        }
    }, CONFIG.STATUS_REFRESH_MS);
}

async function autoPresignPerLeg() {
    if (!State.currentSwap || !State.S_user || !State.currentSwap.is_perleg) return;

    const swap = State.currentSwap;
    console.log('[pna] Per-leg: sending S_user to LP_IN...');

    updateStepProgress(3);
    setStatusMessage('pending', 'Completing settlement...');

    try {
        const response = await fetch(`${swap.lp_in_url}/api/flowswap/${swap.swap_id}/presign`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ S_user: State.S_user }),
        });

        if (!response.ok) {
            const err = await response.json();
            console.error('[pna] Per-leg presign failed:', err);
            setStatusMessage('error', `Presign failed: ${err.detail || 'unknown'}`);
            return;
        }

        const data = await response.json();
        console.log('[pna] Per-leg presign success:', data);

        // Per-leg: relay source chain claim proof + revealed S_lp1 to LP_OUT
        const claimTxid = data.btc_claim_txid || data.source_claim_txid;
        const srcAsset = swap.from_asset || 'BTC';
        if (claimTxid && data.S_lp1 && swap.swap_id_out && swap.lp_out_url) {
            setStatusMessage('pending', `${srcAsset} claimed. Notifying LP_OUT...`);
            try {
                const outResp = await fetch(`${swap.lp_out_url}/api/flowswap/${swap.swap_id_out}/btc-claimed`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        btc_claim_txid: claimTxid,
                        S_user: State.S_user,
                        S_lp1: data.S_lp1,
                    }),
                });
                if (outResp.ok) {
                    swap._perleg_btc_claimed_notified = true;
                    console.log('[pna] Per-leg: LP_OUT notified of source chain claim');
                    setStatusMessage('pending', 'LP_OUT completing... USDC being sent.');
                } else {
                    const err = await outResp.json();
                    console.error('[pna] Per-leg btc-claimed notification failed:', err);
                    setStatusMessage('error', `LP_OUT notification failed: ${err.detail || 'unknown'}`);
                }
            } catch (relayErr) {
                console.error('[pna] Per-leg btc-claimed relay error:', relayErr);
                setStatusMessage('error', 'Failed to notify LP_OUT: ' + relayErr.message);
            }
        } else {
            setStatusMessage('pending', 'BTC claimed. Waiting for USDC delivery...');
        }
    } catch (e) {
        console.error('[pna] Per-leg presign error:', e);
        setStatusMessage('error', 'Presign failed: ' + e.message);
    }
}

// ---- BTC -> USDC (existing forward flow) ----

async function initiateSwapBtcToUsdc() {
    const btn = DOM.swapBtn;
    const btnText = btn.querySelector('.btn-text');

    try {
        btn.classList.add('loading');
        btnText.textContent = 'Creating HTLCs...';
        btn.disabled = true;

        const S_user = generateSecret();
        const H_user = await sha256hex(S_user);
        State.S_user = S_user;
        console.log('[pna] Generated H_user:', H_user.slice(0, 16) + '...');

        const initBody = {
            from_asset: 'BTC',
            to_asset: 'USDC',
            amount: State.inputAmount,
            H_user: H_user,
            user_usdc_address: State.destAddress,
        };

        const response = await fetch(`${getLpUrl()}/api/flowswap/init`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(initBody),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || `HTTP ${response.status}`);
        }

        const data = await response.json();
        console.log('[pna] FlowSwap init response:', data);

        State.currentSwap = {
            swap_id: data.swap_id,
            state: data.state,
            direction: 'forward',
            from_asset: 'BTC',
            to_asset: 'USDC',
            from_amount: State.inputAmount,
            to_amount: State.outputAmount,
            dest_address: State.destAddress,
            btc_deposit_address: data.btc_deposit.address,
            btc_amount_sats: data.btc_deposit.amount_sats,
            btc_amount_btc: data.btc_deposit.amount_btc,
            instant_min_feerate: data.btc_deposit.instant_min_feerate || 4,
            usdc_amount: data.usdc_output.amount,
            evm_htlc_id: null,  // Populated after LP locks (user-commits-first)
            H_user: H_user,
            H_lp1: data.hashlocks.H_lp1,
            H_lp2: data.hashlocks.H_lp2,
            plan_expires_at: data.plan_expires_at || 0,
        };

        showFlowSwapStatus(State.currentSwap);
        startFlowSwapPolling(data.swap_id);
        saveSwapSession();

    } catch (error) {
        console.error('[pna] FlowSwap init error:', error);
        setStatusMessage('error', 'Swap failed: ' + error.message);
        btn.classList.remove('loading');
        btnText.textContent = `Swap BTC \u2192 USDC`;
        btn.disabled = false;
    }
}

// ---- USDC -> BTC (new reverse flow via MetaMask) ----

async function initiateSwapUsdcToBtc() {
    const btn = DOM.swapBtn;
    const btnText = btn.querySelector('.btn-text');

    try {
        btn.classList.add('loading');
        btnText.textContent = 'Connecting MetaMask...';
        btn.disabled = true;

        // Step 1: Connect MetaMask
        await connectMetaMask();
        btnText.textContent = 'Creating HTLCs...';

        // Step 2: Generate user secret
        const S_user = generateSecret();
        const H_user = await sha256hex(S_user);
        State.S_user = S_user;
        console.log('[pna] Generated H_user:', H_user.slice(0, 16) + '...');

        // Step 3: Call LP init (USDC -> BTC)
        const initBody = {
            from_asset: 'USDC',
            to_asset: 'BTC',
            amount: State.inputAmount,
            H_user: H_user,
            user_btc_claim_address: State.destAddress,
        };

        const response = await fetch(`${getLpUrl()}/api/flowswap/init`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(initBody),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || `HTTP ${response.status}`);
        }

        const data = await response.json();
        console.log('[pna] FlowSwap reverse init:', data);

        // Step 4: Store swap state
        State.currentSwap = {
            swap_id: data.swap_id,
            state: data.state,
            direction: 'reverse',
            from_asset: 'USDC',
            to_asset: 'BTC',
            from_amount: State.inputAmount,
            to_amount: State.outputAmount,
            dest_address: State.destAddress,
            usdc_amount: data.usdc_deposit.amount,
            btc_amount_btc: data.btc_output.amount_btc,
            btc_amount_sats: data.btc_output.amount_sats,
            H_user: H_user,
            H_lp1: data.hashlocks.H_lp1,
            H_lp2: data.hashlocks.H_lp2,
            usdc_deposit_params: data.usdc_deposit,
            plan_expires_at: data.plan_expires_at || 0,
        };

        // Step 5: Show status and create USDC HTLC via MetaMask
        showFlowSwapStatusReverse(State.currentSwap);
        startFlowSwapPolling(data.swap_id);

        // Step 6: Create USDC HTLC on-chain
        btnText.textContent = 'Approve USDC...';
        setStatusMessage('pending', 'Approve USDC in MetaMask...');

        const htlcResult = await createUSDCHTLC({
            amount: data.usdc_deposit.amount,
            recipient: data.usdc_deposit.recipient,
            timelock_seconds: data.usdc_deposit.timelock_seconds,
            H_user: H_user,
            H_lp1: data.hashlocks.H_lp1,
            H_lp2: data.hashlocks.H_lp2,
        });

        console.log('[pna] USDC HTLC created:', htlcResult);
        State.currentSwap.evm_htlc_id = htlcResult.htlc_id;
        State.currentSwap.evm_lock_txhash = htlcResult.lock_txhash;

        // Step 7: Notify LP (with retry on 503/network failure)
        setStatusMessage('pending', 'USDC locked. Notifying LP...');
        updateStepProgress(2);

        let fundedOk = false;
        const maxRetries = 3;
        for (let attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                const fundedResp = await fetch(
                    `${getLpUrl()}/api/flowswap/${data.swap_id}/usdc-funded`,
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ htlc_id: htlcResult.htlc_id }),
                    }
                );

                if (fundedResp.ok) {
                    fundedOk = true;
                    console.log('[pna] usdc-funded confirmed by LP');
                    break;
                }

                const errBody = await fundedResp.json().catch(() => ({}));
                const detail = errBody.detail || `HTTP ${fundedResp.status}`;

                if (fundedResp.status === 503 && attempt < maxRetries) {
                    // RPC unavailable — retry after delay
                    const wait = attempt * 3;
                    console.warn(`[pna] usdc-funded attempt ${attempt}/${maxRetries}: ${detail} — retry in ${wait}s`);
                    setStatusMessage('pending', `LP verifying USDC on-chain... retry ${attempt}/${maxRetries}`);
                    await new Promise(r => setTimeout(r, wait * 1000));
                    continue;
                }

                // Non-retryable error (400, 404, etc.) or last retry failed
                console.error(`[pna] usdc-funded failed: ${detail}`);
                setStatusMessage('error', `LP verification failed: ${detail}`);
                break;
            } catch (netErr) {
                if (attempt < maxRetries) {
                    const wait = attempt * 3;
                    console.warn(`[pna] usdc-funded network error attempt ${attempt}/${maxRetries}: ${netErr} — retry in ${wait}s`);
                    setStatusMessage('pending', `Network error, retrying... (${attempt}/${maxRetries})`);
                    await new Promise(r => setTimeout(r, wait * 1000));
                } else {
                    console.error('[pna] usdc-funded all retries failed:', netErr);
                    setStatusMessage('error', 'Cannot reach LP. Your USDC is safe — retry the swap or wait for refund.');
                }
            }
        }

        if (!fundedOk) {
            // Don't silently continue — show actionable error
            setStatusMessage('error',
                'LP could not verify your USDC HTLC. ' +
                'Your funds are safe and will auto-refund after timelock. ' +
                'You can also refresh and retry.');
            btn.classList.remove('loading');
            btnText.textContent = `Swap USDC \u2192 BTC`;
            btn.disabled = false;
            return;
        }

        // Step 8: Wait for LP to lock (user-commits-first model)
        // autoPresign deferred to lp_locked state via polling
        setStatusMessage('pending', 'USDC confirmed. LP locking BTC + M1...');

    } catch (error) {
        console.error('[pna] FlowSwap reverse error:', error);
        let msg = error.message;
        if (msg.includes('user rejected')) msg = 'Transaction rejected in MetaMask';
        setStatusMessage('error', 'Swap failed: ' + msg);
        btn.classList.remove('loading');
        btnText.textContent = `Swap USDC \u2192 BTC`;
        btn.disabled = false;
    }
}

function showFlowSwapStatus(swap) {
    DOM.swapModal.classList.remove('hidden');
    DOM.swapId.textContent = swap.swap_id;

    // Show deposit box with BTC address + feerate recommendation
    DOM.depositBox.classList.remove('hidden');
    DOM.depositAmount.textContent = `${swap.btc_amount_btc} BTC`;
    DOM.depositAddress.textContent = swap.btc_deposit_address;

    const feerate = swap.instant_min_feerate || 4;
    const feerateEl = document.getElementById('min-feerate');
    if (feerateEl) feerateEl.textContent = feerate;
    const feeSatsEl = document.getElementById('min-fee-sats');
    if (feeSatsEl) feeSatsEl.textContent = Math.ceil(feerate * 140);

    // Update step labels for FlowSwap
    document.getElementById('step1-title').textContent = 'Fund BTC';
    document.getElementById('step1-desc').textContent = 'Send BTC to HTLC address';
    document.getElementById('step2-title').textContent = 'Confirmations';
    document.getElementById('step2-desc').textContent = 'Waiting for BTC confirmation';
    document.getElementById('step3-title').textContent = 'Settlement';
    document.getElementById('step3-desc').textContent = 'LP claims BTC, USDC released';
    document.getElementById('step4-title').textContent = `${swap.usdc_amount} USDC`;
    document.getElementById('step4-desc').textContent = `To ${swap.dest_address.slice(0, 8)}...`;

    updateStepProgress(1);
    setStatusMessage('pending', 'Waiting for BTC deposit...');

    // Show "I've sent BTC" button
    DOM.btcSentBtn.classList.remove('hidden');
}

function showFlowSwapStatusReverse(swap) {
    DOM.swapModal.classList.remove('hidden');
    DOM.swapId.textContent = swap.swap_id;

    // No deposit box for reverse — user locks USDC via MetaMask
    DOM.depositBox.classList.add('hidden');
    DOM.btcSentBtn.classList.add('hidden');

    // Update step labels for reverse flow
    document.getElementById('step1-title').textContent = 'Lock USDC';
    document.getElementById('step1-desc').textContent = 'Approve + create HTLC via MetaMask';
    document.getElementById('step2-title').textContent = 'LP Notified';
    document.getElementById('step2-desc').textContent = 'LP verifies USDC HTLC on-chain';
    document.getElementById('step3-title').textContent = 'Settlement';
    document.getElementById('step3-desc').textContent = 'LP claims USDC, BTC released';
    document.getElementById('step4-title').textContent = `${swap.btc_amount_btc} BTC`;
    document.getElementById('step4-desc').textContent = `To ${swap.dest_address.slice(0, 12)}...`;

    updateStepProgress(1);
    setStatusMessage('pending', 'Connecting MetaMask...');
}

function updateStepProgress(currentStep) {
    const steps = document.querySelectorAll('.step');

    steps.forEach((step, index) => {
        const stepNum = index + 1;
        step.classList.remove('active', 'completed');

        if (stepNum < currentStep) {
            step.classList.add('completed');
        } else if (stepNum === currentStep) {
            step.classList.add('active');
        }
    });
}

function setStatusMessage(type, message) {
    DOM.statusMessage.className = `status-message ${type}`;
    DOM.statusMessage.textContent = message;
}

// =============================================================================
// FLOWSWAP POLLING & STATE MACHINE
// =============================================================================

function startFlowSwapPolling(swapId) {
    // Clear any existing interval
    if (State.statusInterval) {
        clearInterval(State.statusInterval);
    }

    // Subscribe via WS for instant state updates
    wsSubscribeSwap(swapId);

    // HTTP fallback polling (slower interval when WS connected)
    State.statusInterval = setInterval(async () => {
        if (!State.currentSwap) return;

        // If WS connected, reduce poll frequency (WS handles real-time)
        const lpWs = lpWebSockets[getLpUrl()];
        if (lpWs && lpWs.connected) return;

        try {
            const response = await fetch(`${getLpUrl()}/api/flowswap/${swapId}`);
            if (!response.ok) return;

            const data = await response.json();
            handleFlowSwapStateChange(data);
        } catch (e) {
            console.warn('[pna] Poll error:', e);
        }
    }, CONFIG.STATUS_REFRESH_MS);
}

function handleFlowSwapStateChange(data) {
    const swap = State.currentSwap;
    if (!swap) return;

    const prevState = swap.state;
    swap.state = data.state;

    // Allow btc_funded to re-process (stability countdown updates)
    if (prevState === data.state && data.state !== 'btc_funded') return;

    console.log(`[pna] State: ${prevState} -> ${data.state}`);

    // Persist swap state to sessionStorage (survives page refresh)
    saveSwapSession();

    const isReverse = swap.direction === 'reverse';

    switch (data.state) {
        // --- Forward flow (BTC -> USDC) ---
        case 'awaiting_btc':
            updateStepProgress(1);
            setStatusMessage('pending', 'Waiting for BTC deposit...');
            break;

        case 'btc_funded':
            updateStepProgress(2);
            DOM.btcSentBtn.classList.add('hidden');
            DOM.depositBox.classList.add('hidden');

            // Show stability countdown or locking message
            if (data.stability_check_until) {
                const remaining = data.stability_check_until - Math.floor(Date.now() / 1000);
                if (remaining > 0) {
                    setStatusMessage('pending', `Verifying deposit... ${remaining}s`);
                } else {
                    setStatusMessage('pending', 'Deposit verified. LP locking USDC + M1...');
                }
            } else {
                setStatusMessage('pending', 'BTC detected. LP locking USDC + M1...');
            }

            if (data.btc && data.btc.fund_txid) {
                showTxLink('btc', data.btc.fund_txid);
            }
            // autoPresign moved to lp_locked (user-commits-first model)
            break;

        case 'lp_locked':
            updateStepProgress(2);
            setStatusMessage('pending', isReverse
                ? 'LP locked BTC + M1. Completing swap...'
                : 'LP locked USDC + M1. Completing swap...');
            DOM.btcSentBtn.classList.add('hidden');
            DOM.depositBox.classList.add('hidden');

            // Show LP lock TX links
            if (data.evm && data.evm.htlc_id) {
                swap.evm_htlc_id = data.evm.htlc_id;
            }
            if (data.evm && data.evm.lock_txhash) {
                showTxLink('evm', data.evm.lock_txhash);
            }
            if (data.btc && data.btc.fund_txid) {
                showTxLink('btc', data.btc.fund_txid);
            }

            // Show verification popup — user must confirm before sending S_user
            if (!State._verifyPending) {
                State._verifyPending = true;
                showVerifyModal(data);
            }
            break;

        case 'btc_claimed':
            updateStepProgress(3);
            if (isReverse) {
                setStatusMessage('pending', 'BTC sent to your address. Finalizing...');
            } else {
                const claimConfs = (data.btc && data.btc.claim_confs) || 0;
                setStatusMessage('pending',
                    `BTC claimed by LP. Waiting for confirmation (${claimConfs}/1)...`);
            }
            DOM.depositBox.classList.add('hidden');

            if (data.btc && data.btc.claim_txid) {
                showTxLink('btc', data.btc.claim_txid);
            }
            break;

        // --- Reverse flow (USDC -> BTC) ---
        case 'awaiting_usdc':
            updateStepProgress(1);
            setStatusMessage('pending', 'Create USDC HTLC via MetaMask...');
            break;

        case 'usdc_funded':
            updateStepProgress(2);
            setStatusMessage('pending', 'USDC locked. LP locking BTC + M1...');
            if (swap.evm_lock_txhash) {
                showTxLink('evm', swap.evm_lock_txhash);
            }
            break;

        // --- Common terminal states ---
        case 'expired':
            clearSwapSession();
            setStatusMessage('error', 'Plan expired. No funds were locked by LP.');
            DOM.newSwapBtn.classList.remove('hidden');
            DOM.btcSentBtn.classList.add('hidden');
            DOM.depositBox.classList.add('hidden');

            if (State.statusInterval) {
                clearInterval(State.statusInterval);
                State.statusInterval = null;
            }
            break;

        case 'completing':
            updateStepProgress(3);
            if (isReverse) {
                setStatusMessage('pending', 'Finalizing... BTC being sent to your wallet.');
            } else {
                const confs2 = (data.btc && data.btc.claim_confs) || 0;
                if (confs2 < 1) {
                    setStatusMessage('pending',
                        `Waiting for BTC confirmation (${confs2}/1) before USDC release...`);
                } else {
                    setStatusMessage('pending', 'BTC confirmed. USDC being sent to your wallet...');
                }
            }
            break;

        case 'completed':
            clearSwapSession();
            updateStepProgress(4);
            DOM.depositBox.classList.add('hidden');

            if (isReverse) {
                setStatusMessage('success',
                    `Success! ${swap.btc_amount_btc} BTC sent to ${swap.dest_address.slice(0, 12)}...`);
                if (data.btc && data.btc.claim_txid) {
                    showTxLink('btc', data.btc.claim_txid);
                }
            } else {
                const displayDecimals = swap.usdc_amount >= 1000 ? 2 : 4;
                setStatusMessage('success',
                    `Success! ${formatNumber(swap.usdc_amount, displayDecimals)} USDC sent to ${swap.dest_address.slice(0, 10)}...`);
                if (data.evm && data.evm.claim_txhash) {
                    showTxLink('evm', data.evm.claim_txhash);
                }
            }

            DOM.btcSentBtn.classList.add('hidden');
            DOM.newSwapBtn.classList.remove('hidden');

            if (State.statusInterval) {
                clearInterval(State.statusInterval);
                State.statusInterval = null;
            }
            break;

        case 'failed':
            clearSwapSession();
            setStatusMessage('error', isReverse
                ? 'Swap failed. USDC is safe if HTLC was not created.'
                : 'Swap failed. Your BTC is safe if unfunded.');
            DOM.newSwapBtn.classList.remove('hidden');
            DOM.btcSentBtn.classList.add('hidden');

            if (State.statusInterval) {
                clearInterval(State.statusInterval);
                State.statusInterval = null;
            }
            break;

        case 'refunded': {
            clearSwapSession();
            const refundTxid = data.btc?.refund_txid || '';
            const refundAddr = data.btc?.refund_address || '';
            let refundMsg = 'Swap timed out. BTC auto-refunded.';
            if (refundAddr) refundMsg += ` Sent to ${refundAddr.slice(0, 12)}...`;
            setStatusMessage('warning', refundMsg);
            if (refundTxid) showTxLink('btc', refundTxid);
            DOM.newSwapBtn.classList.remove('hidden');
            DOM.btcSentBtn.classList.add('hidden');

            if (State.statusInterval) {
                clearInterval(State.statusInterval);
                State.statusInterval = null;
            }
            break;
        }
    }
}

function showTxLink(chain, txid) {
    DOM.txLinks.classList.remove('hidden');

    if (chain === 'btc') {
        DOM.txLinkBtc.classList.remove('hidden');
        DOM.txLinkBtc.href = `https://mempool.space/signet/tx/${txid}`;
        DOM.txLinkBtc.textContent = `BTC TX: ${txid.slice(0, 8)}...`;
    } else if (chain === 'evm') {
        DOM.txLinkEvm.classList.remove('hidden');
        DOM.txLinkEvm.href = `https://sepolia.basescan.org/tx/${txid}`;
        DOM.txLinkEvm.textContent = `USDC TX: ${txid.slice(0, 10)}...`;
    }
}

// =============================================================================
// USER ACTIONS
// =============================================================================

/**
 * User clicks "I've sent BTC" — notify LP to check funding.
 */
async function notifyBtcFunded() {
    if (!State.currentSwap) return;

    const swap = State.currentSwap;
    const btn = DOM.btcSentBtn;
    const srcAsset = swap.from_asset || 'BTC';
    btn.textContent = 'Checking...';
    btn.disabled = true;

    // Determine endpoint based on source asset
    const lpUrl = swap.is_perleg ? swap.lp_in_url : getLpUrl();
    const fundedEndpoint = (srcAsset === 'BTC')
        ? `${lpUrl}/api/flowswap/${swap.swap_id}/btc-funded`
        : `${lpUrl}/api/flowswap/${swap.swap_id}/chain-funded`;

    try {
        const response = await fetch(fundedEndpoint, {
            method: 'POST',
        });

        if (!response.ok) {
            const error = await response.json();
            const msg = error.detail || `${srcAsset} not confirmed yet`;
            setStatusMessage('pending', msg + '. Please wait and try again.');
            btn.textContent = `I've sent ${srcAsset}`;
            btn.disabled = false;
            return;
        }

        const data = await response.json();
        console.log(`[pna] ${srcAsset} funded:`, data);

        swap.state = data.state;
        updateStepProgress(2);
        setStatusMessage('pending', `${srcAsset} confirmed (${data.confirmations} conf). LP locking M1...`);
        btn.classList.add('hidden');
        DOM.depositBox.classList.add('hidden');

        if (data.btc_fund_txid || data.source_fund_txid) {
            showTxLink('btc', data.btc_fund_txid || data.source_fund_txid);
        }

        // autoPresign deferred to lp_locked state (user-commits-first model)
        // State polling will detect lp_locked and call autoPresign()

    } catch (e) {
        console.error('[pna] BTC funded error:', e);
        setStatusMessage('error', 'Error checking BTC: ' + e.message);
        btn.textContent = "I've sent BTC";
        btn.disabled = false;
    }
}

/**
 * Auto-send S_user to LP after LP has locked on-chain (lp_locked state).
 * LP uses all 3 secrets to claim BTC -> USDC auto-claims.
 * GUARD: Only runs if user explicitly confirmed via verify modal (_verifyPending flag).
 */
async function autoPresign() {
    if (!State.currentSwap || !State.S_user) return;

    const swap = State.currentSwap;
    console.log('[pna] Sending S_user (presign)...');

    updateStepProgress(3);
    setStatusMessage('pending', 'Completing settlement...');

    try {
        const response = await fetch(`${getLpUrl()}/api/flowswap/${swap.swap_id}/presign`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ S_user: State.S_user }),
        });

        if (!response.ok) {
            const error = await response.json();
            console.error('[pna] Presign failed:', error);
            setStatusMessage('error', `Presign failed: ${error.detail || 'Unknown error'}. Retrying...`);
            // Re-show verify modal so user can retry
            State._verifyPending = true;
            return;
        }

        const data = await response.json();
        console.log('[pna] Presign response:', data);

        swap.state = data.state;
        setStatusMessage('pending', 'BTC claimed. USDC being sent...');

        if (data.btc_claim_txid) {
            showTxLink('btc', data.btc_claim_txid);
        }

    } catch (e) {
        console.error('[pna] Presign error:', e);
    }
}

/**
 * Show verification modal before sending S_user.
 * Displays LP lock details so the user can verify before committing.
 */
function showVerifyModal(data) {
    if (!State.currentSwap) return;
    const swap = State.currentSwap;

    // Populate USDC amount
    const usdcAmount = data.usdc_amount || swap.usdc_amount || swap.to_amount || 0;
    DOM.verifyUsdcAmount.textContent = `${usdcAmount} USDC`;

    // EVM HTLC link (lock TX on Basescan)
    const evmLockTx = (data.evm && data.evm.lock_txhash) || '';
    const evmHtlcId = (data.evm && data.evm.htlc_id) || swap.evm_htlc_id || '';
    const contractAddr = (data.evm && data.evm.contract_address) || '';
    if (evmLockTx) {
        DOM.verifyEvmLink.href = `https://sepolia.basescan.org/tx/${evmLockTx}`;
        DOM.verifyEvmLink.textContent = 'View on Basescan';
    } else if (contractAddr && evmHtlcId) {
        DOM.verifyEvmLink.href = `https://sepolia.basescan.org/address/${contractAddr}`;
        DOM.verifyEvmLink.textContent = 'View contract';
    } else {
        DOM.verifyEvmLink.removeAttribute('href');
        DOM.verifyEvmLink.textContent = 'Pending...';
    }

    // Hashlocks
    const hUser = (data.hashlocks && data.hashlocks.H_user) || swap.H_user || '';
    const hLp1 = (data.hashlocks && data.hashlocks.H_lp1) || swap.H_lp1 || '';
    const hLp2 = (data.hashlocks && data.hashlocks.H_lp2) || swap.H_lp2 || '';
    DOM.verifyHUser.textContent = hUser ? hUser.slice(0, 16) + '...' : '-';
    DOM.verifyHUser.title = hUser;
    DOM.verifyHLp1.textContent = hLp1 ? hLp1.slice(0, 16) + '...' : '-';
    DOM.verifyHLp1.title = hLp1;
    DOM.verifyHLp2.textContent = hLp2 ? hLp2.slice(0, 16) + '...' : '-';
    DOM.verifyHLp2.title = hLp2;

    // BTC deposit TX
    const btcFundTxid = (data.btc && data.btc.fund_txid) || '';
    if (btcFundTxid) {
        DOM.verifyBtcLink.href = `https://mempool.space/signet/tx/${btcFundTxid}`;
        DOM.verifyBtcLink.textContent = btcFundTxid.slice(0, 16) + '...';
    } else {
        DOM.verifyBtcLink.removeAttribute('href');
        DOM.verifyBtcLink.textContent = '-';
    }

    // Validation warnings
    const warnings = [];
    const expectedUsdc = parseFloat(swap.to_amount || swap.usdc_amount || 0);
    if (expectedUsdc > 0 && usdcAmount > 0) {
        const diff = Math.abs(usdcAmount - expectedUsdc) / expectedUsdc;
        if (diff > 0.01) {
            warnings.push(`USDC amount mismatch: expected ${expectedUsdc}, got ${usdcAmount}`);
        }
    }
    if (!hUser || !hLp1 || !hLp2) {
        warnings.push('Missing hashlock(s) — LP may not have locked correctly');
    }
    if (!evmHtlcId && !evmLockTx) {
        warnings.push('No EVM HTLC detected — USDC may not be locked');
    }

    if (warnings.length > 0) {
        DOM.verifyWarningText.textContent = warnings.join('. ');
        DOM.verifyWarning.classList.remove('hidden');
    } else {
        DOM.verifyWarning.classList.add('hidden');
    }

    // Show the modal
    DOM.verifyModal.classList.remove('hidden');
    setStatusMessage('pending', 'LP locked. Verify details and confirm swap.');

    console.log('[pna] Verification modal shown', { usdcAmount, evmLockTx, hUser: hUser.slice(0, 16) });
}

/**
 * User confirmed the LP locks — proceed with presign (send S_user).
 */
function confirmPresign() {
    State._verifyPending = false;
    // Hide verify modal
    DOM.verifyModal.classList.add('hidden');
    // Proceed with actual presign
    autoPresign();
}

/**
 * User cancelled — do not send S_user. BTC will refund after HTLC timeout.
 */
function cancelPresign() {
    State._verifyPending = false;
    DOM.verifyModal.classList.add('hidden');
    setStatusMessage('error', 'Swap cancelled. Your BTC will refund after HTLC timeout.');
    DOM.newSwapBtn.classList.remove('hidden');
    clearSwapSession();
    console.log('[pna] User cancelled presign — S_user NOT sent');
}

/**
 * Copy BTC deposit address to clipboard.
 */
function copyDepositAddress() {
    const address = DOM.depositAddress.textContent;
    const btn = DOM.depositBox.querySelector('.copy-btn');

    // Fallback for HTTP (no navigator.clipboard)
    const textarea = document.createElement('textarea');
    textarea.value = address;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);

    btn.classList.add('copied');
    btn.textContent = '\u2713';
    setTimeout(() => {
        btn.classList.remove('copied');
        btn.textContent = '\u2398';
    }, 2000);
}

// =============================================================================
// RESET
// =============================================================================

function resetSwap() {
    clearSwapSession();
    State.currentSwap = null;
    State.S_user = null;
    State.activeLpUrl = null;
    State.inputAmount = 0;
    State.outputAmount = 0;

    DOM.inputAmount.value = '';
    DOM.outputAmount.textContent = '0.00';
    DOM.destAddress.value = '';


    DOM.swapModal.classList.add('hidden');
    DOM.newSwapBtn.classList.add('hidden');
    DOM.btcSentBtn.classList.add('hidden');
    DOM.depositBox.classList.add('hidden');
    DOM.txLinks.classList.add('hidden');
    DOM.txLinkBtc.classList.add('hidden');
    DOM.txLinkEvm.classList.add('hidden');

    document.querySelectorAll('.step').forEach(step => {
        step.classList.remove('active', 'completed');
    });

    DOM.swapBtn.classList.remove('loading');
    updateButtonState();

    if (State.statusInterval) {
        clearInterval(State.statusInterval);
        State.statusInterval = null;
    }
}

// =============================================================================
// SWAP EXPLORER
// =============================================================================

async function loadSwapExplorer() {
    const container = document.getElementById('explorer-list');
    if (!container) return;

    try {
        // Query all LPs and merge swap history
        const results = await Promise.allSettled(
            CONFIG.SDK_URLS.map(url =>
                fetch(`${url}/api/swaps?limit=4`, { signal: AbortSignal.timeout(CONFIG.LP_TIMEOUT_MS) })
                    .then(r => r.ok ? r.json() : { swaps: [] })
            )
        );

        const allSwaps = results
            .filter(r => r.status === 'fulfilled' && r.value && r.value.swaps)
            .flatMap(r => r.value.swaps);

        // Deduplicate by swap_id, sort by created_at desc
        const seen = new Set();
        const data = { swaps: allSwaps.filter(s => {
            if (seen.has(s.swap_id)) return false;
            seen.add(s.swap_id);
            return true;
        }).sort((a, b) => (b.created_at || 0) - (a.created_at || 0)).slice(0, 4) };

        if (!data.swaps || data.swaps.length === 0) {
            container.innerHTML = '<div class="explorer-empty">No swaps yet. Be the first!</div>';
            return;
        }

        container.innerHTML = data.swaps.map(swap => {
            const fromDisp = swap.from_display || `${(swap.from_amount || 0).toFixed(8)} ${swap.from_asset}`;
            const toDisp = swap.to_display || `${swap.to_amount} ${swap.to_asset}`;
            const rateDisp = swap.rate_display || '';
            const statusClass = getExplorerStatusClass(swap.status);
            const statusLabel = getExplorerStatusLabel(swap.status);
            const timeStr = swap.created_at ? formatExplorerTime(swap.created_at) : '-';
            const durationStr = swap.duration_seconds ? formatExplorerDuration(swap.duration_seconds) : '';

            // TX links
            const btcTxid = swap.btc_claim_txid || swap.btc_fund_txid || '';
            const evmTxhash = swap.evm_claim_txhash || '';

            return `
            <div class="explorer-item" onclick="toggleExplorerDetail(this)">
                <div class="explorer-row">
                    <div class="explorer-main">
                        <span class="explorer-id">${swap.swap_id.slice(0, 12)}...</span>
                        <span class="explorer-badge ${statusClass}">${statusLabel}</span>
                    </div>
                    <div class="explorer-time">${timeStr}</div>
                </div>
                <div class="explorer-amounts">
                    <span class="explorer-from">${fromDisp}</span>
                    <span class="explorer-arrow">\u2192</span>
                    <span class="explorer-to">${toDisp}</span>
                </div>
                <div class="explorer-detail hidden">
                    ${rateDisp ? `<div class="explorer-detail-row"><span>Rate</span><span>${rateDisp}</span></div>` : ''}
                    ${durationStr ? `<div class="explorer-detail-row"><span>Duration</span><span>${durationStr}</span></div>` : ''}
                    ${btcTxid ? `<div class="explorer-detail-row"><span>BTC TX</span><a href="https://mempool.space/signet/tx/${btcTxid}" target="_blank" rel="noopener">${btcTxid.slice(0, 16)}...</a></div>` : ''}
                    ${evmTxhash ? `<div class="explorer-detail-row"><span>USDC TX</span><a href="https://sepolia.basescan.org/tx/${evmTxhash}" target="_blank" rel="noopener">${evmTxhash.slice(0, 16)}...</a></div>` : ''}
                </div>
            </div>`;
        }).join('');

    } catch (e) {
        console.error('[pna] Explorer error:', e);
        container.innerHTML = '<div class="explorer-empty">Could not load swaps</div>';
    }
}

function toggleExplorerDetail(el) {
    const detail = el.querySelector('.explorer-detail');
    if (detail) detail.classList.toggle('hidden');
}

function getExplorerStatusClass(status) {
    if (status === 'claimed' || status === 'completed') return 'success';
    if (status === 'pending' || status === 'htlc_created') return 'pending';
    if (status === 'claiming') return 'active';
    if (status === 'expired' || status === 'refunded') return 'error';
    return 'pending';
}

function getExplorerStatusLabel(status) {
    const map = {
        'claimed': 'Completed',
        'completed': 'Completed',
        'pending': 'Pending',
        'htlc_created': 'HTLC Created',
        'claiming': 'Settling',
        'expired': 'Expired',
        'refunded': 'Refunded',
    };
    return map[status] || status;
}

function formatExplorerTime(ts) {
    const d = new Date(ts * 1000);
    const now = new Date();
    const diff = Math.floor((now - d) / 1000);

    if (diff < 60) return 'just now';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';

    return d.toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' });
}

function formatExplorerDuration(sec) {
    if (sec < 60) return sec + 's';
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return m + 'm ' + s + 's';
}

// Expose
window.toggleExplorerDetail = toggleExplorerDetail;

// =============================================================================
// TAB NAVIGATION
// =============================================================================

function switchTab(tabId) {
    // Update buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabId);
    });
    // Update content
    document.querySelectorAll('.tab-content').forEach(panel => {
        panel.classList.toggle('active', panel.id === `tab-${tabId}`);
    });
    // Lazy-load LP explorer on first visit
    if (tabId === 'lps' && !State._lpExplorerLoaded) {
        State._lpExplorerLoaded = true;
        loadLPExplorer();
    }
}

window.switchTab = switchTab;

// =============================================================================
// LP EXPLORER
// =============================================================================

async function loadLPExplorer() {
    const container = document.getElementById('lp-explorer-list');
    if (!container) return;

    if (CONFIG.LP_REGISTRY.length === 0) {
        container.innerHTML = '<div class="explorer-empty">No LPs discovered yet. LPs register on-chain via OP_RETURN transactions.</div>';
        return;
    }

    updateLPExplorerSummary();

    // Fetch info via HTTP for LPs not yet in WS cache
    const needsHttpFetch = CONFIG.LP_REGISTRY.filter(lp => !lpWsInfoCache[lp.endpoint]?.info);
    const infoResults = await Promise.allSettled(
        needsHttpFetch.map(lp =>
            fetch(`${lp.endpoint}/api/lp/info`, { signal: AbortSignal.timeout(CONFIG.LP_TIMEOUT_MS) })
                .then(r => r.ok ? r.json() : null)
                .catch(() => null)
        )
    );
    needsHttpFetch.forEach((lp, i) => {
        const result = infoResults[i]?.status === 'fulfilled' ? infoResults[i].value : null;
        if (result) {
            if (!lpWsInfoCache[lp.endpoint]) lpWsInfoCache[lp.endpoint] = {};
            lpWsInfoCache[lp.endpoint].info = result;
            lpWsInfoCache[lp.endpoint].ts = Date.now();
        }
    });

    container.innerHTML = CONFIG.LP_REGISTRY.map(lp => buildLPCardHTML(lp)).join('');
}

function updateLPExplorerSummary() {
    const summary = document.getElementById('lp-explorer-summary');
    if (!summary) return;
    const online = CONFIG.LP_REGISTRY.filter(lp => lp.status === 'online' || lp.status === 'new').length;
    const tier1 = CONFIG.LP_REGISTRY.filter(lp => lp.tier === 1).length;
    summary.textContent = `${CONFIG.LP_REGISTRY.length} registered \u00b7 ${online} online \u00b7 ${tier1} operator-backed`;
}

/**
 * LP card — clean and minimal. Click opens detail page.
 */
function buildLPCardHTML(lp) {
    const wsCache = lpWsInfoCache[lp.endpoint] || {};
    const info = wsCache.info || null;
    const cached = lp.cached_info || {};
    const wsConnected = lpWebSockets[lp.endpoint]?.connected || false;

    const name = info?.name || cached?.name || cached?.lp_id || lp.address?.slice(0, 12) || 'Unknown LP';
    const status = lp.status || 'offline';
    const tier = lp.tier || 2;
    const tierLabel = tier === 1 ? 'Operator' : 'Community';
    const tierClass = tier === 1 ? 'tier-1' : 'tier-2';

    // Pair pills — use WS info, fallback to registry cached_info
    const pairsObj = info?.pairs || cached?.pairs || {};
    const pairs = Object.keys(pairsObj);
    const pairPills = pairs.map(p => `<span class="lp-pair-pill">${escapeHtml(p)}</span>`).join('');

    // Inventory dots — derive assets from LP's pairs
    const inv = info?.inventory || cached?.inventory || {};
    const lpAssets = new Set();
    pairs.forEach(p => p.split('/').forEach(a => lpAssets.add(a.toLowerCase())));
    if (lpAssets.size === 0) ['btc', 'm1', 'usdc'].forEach(a => lpAssets.add(a));
    const invDots = [...lpAssets].map(asset => {
        const avail = inv[asset + '_available'] !== false;
        return `<span class="lp-inv-item"><span class="lp-inv-dot ${avail ? 'available' : 'unavailable'}"></span>${asset.toUpperCase()}</span>`;
    }).join('');

    // Connection indicator — consistent between cards and detail
    const connTag = wsConnected
        ? '<span class="lp-live-tag">LIVE</span>'
        : '<span class="lp-http-tag">HTTP</span>';

    return `
    <div class="lp-card" data-lp-endpoint="${escapeHtml(lp.endpoint)}" onclick="openLPDetail('${escapeHtml(lp.endpoint)}')">
        <div class="lp-header">
            <span class="lp-status-dot ${escapeHtml(status)}"></span>
            <span class="lp-name">${escapeHtml(name)}</span>
            ${connTag}
            <span class="tier-badge ${tierClass}">${tierLabel}</span>
            <span class="lp-status-label">${escapeHtml(status)}</span>
        </div>
        ${pairPills ? `<div class="lp-pairs">${pairPills}</div>` : ''}
        <div class="lp-inventory">${invDots}</div>
    </div>`;
}

/**
 * Format a rate number for display (compact).
 */
function formatRateNum(n) {
    if (n == null || isNaN(n)) return '-';
    if (n >= 10000) return n.toFixed(0).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    if (n >= 100) return n.toFixed(2);
    if (n >= 1) return n.toFixed(4);
    if (n >= 0.0001) return n.toFixed(6);
    return n.toFixed(8);
}

/**
 * Open the full LP detail page (switches to LP Detail tab).
 */
function openLPDetail(endpoint) {
    const lp = CONFIG.LP_REGISTRY.find(l => l.endpoint === endpoint);
    if (!lp) return;

    const detailTab = document.getElementById('tab-lpdetail');
    const title = document.getElementById('lp-detail-title');
    const body = document.getElementById('lp-detail-body');
    const emptyState = document.getElementById('lpd-empty-state');
    if (!detailTab || !body) return;

    detailTab.dataset.endpoint = endpoint;

    const wsCache = lpWsInfoCache[endpoint] || {};
    const info = wsCache.info || null;
    const liveInv = wsCache.inventory || null;
    const cached = lp.cached_info || {};
    const wsConnected = lpWebSockets[endpoint]?.connected || false;

    const name = info?.name || cached?.lp_id || lp.address?.slice(0, 12) || 'Unknown LP';
    if (title) title.textContent = name;

    body.innerHTML = buildLPDetailHTML(lp, info, liveInv, cached, wsConnected);
    if (emptyState) emptyState.style.display = 'none';

    switchTab('lpdetail');
}

function closeLPDetail() {
    const detailTab = document.getElementById('tab-lpdetail');
    if (detailTab) delete detailTab.dataset.endpoint;
    // Clear stale content
    const body = document.getElementById('lp-detail-body');
    if (body) body.innerHTML = '';
    const emptyState = document.getElementById('lpd-empty-state');
    if (emptyState) emptyState.style.display = '';
    switchTab('lps');
}
window.closeLPDetail = closeLPDetail;

/**
 * Build the full detail page content for an LP.
 * Single unified table: Pair | Bid | Ask | Min | Max | Available | Swaps | Success | Uptime
 */
function buildLPDetailHTML(lp, info, liveInv, cached, wsConnected) {
    const status = lp.status || 'offline';
    const tier = lp.tier || 2;
    const tierLabel = tier === 1 ? 'Operator' : 'Community';
    const tierClass = tier === 1 ? 'tier-1' : 'tier-2';
    const version = info?.version || cached?.version || '-';

    // --- Status bar ---
    let statusHTML = `
    <div class="lpd-status-bar">
        <span class="lp-status-dot ${status}"></span>
        <span class="lpd-status-text">${escapeHtml(status)}</span>
        <span class="tier-badge ${tierClass}">${tierLabel}</span>
        ${wsConnected ? '<span class="lp-live-tag">LIVE</span>' : '<span class="lpd-no-ws">HTTP</span>'}
        <span class="lpd-version">v${escapeHtml(version)}</span>
    </div>`;

    // --- LP-level stats ---
    const rep = cached?.reputation || {};
    const totalSwaps = info?.stats?.swaps_completed || cached?.swaps_total || 0;
    const successRate = rep.success_rate != null ? Math.round(rep.success_rate * 100) + '%' : '-';
    const uptimeHrs = info?.stats?.uptime_hours != null ? info.stats.uptime_hours.toFixed(1) + 'h' : '-';

    // --- Unified table: one row per pair ---
    const pairs = info?.pairs ? Object.entries(info.pairs) : [];
    let tableHTML = '';
    if (pairs.length > 0) {
        const rowCount = pairs.length;
        const rows = pairs.map(([pairKey, p], idx) => {
            const minVal = p.min != null ? formatRateNum(p.min) : '-';
            const maxVal = p.max != null && p.max < 1e12 ? formatRateNum(p.max) : '-';

            // Available: look up base asset inventory
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

            // LP-level stats: rowspan on first row only
            const statsCell = idx === 0
                ? `<td class="lpd-stat-cell" rowspan="${rowCount}">${totalSwaps}</td>
                   <td class="lpd-stat-cell" rowspan="${rowCount}">${successRate}</td>
                   <td class="lpd-stat-cell" rowspan="${rowCount}">${uptimeHrs}</td>`
                : '';

            return `<tr>
                <td class="lpd-pair-name">${escapeHtml(pairKey)}</td>
                <td class="lpd-rate-bid">${formatRateNum(p.rate_bid)}</td>
                <td class="lpd-rate-ask">${formatRateNum(p.rate_ask)}</td>
                <td class="lpd-minmax">${minVal}</td>
                <td class="lpd-minmax">${maxVal}</td>
                <td class="${availClass}">${availText}</td>
                ${statsCell}
            </tr>`;
        }).join('');

        tableHTML = `
        <div class="lpd-section">
            <div class="lpd-table-scroll">
            <table class="lpd-table lpd-unified">
                <thead><tr>
                    <th>Pair</th><th>Bid</th><th>Ask</th><th>Min</th><th>Max</th><th>Available</th>
                    <th>Swaps</th><th>Success</th><th>Uptime</th>
                </tr></thead>
                <tbody>${rows}</tbody>
            </table>
            </div>
        </div>`;
    } else {
        tableHTML = `<div class="lpd-section"><div class="explorer-empty">No pairs configured</div></div>`;
    }

    // --- On-chain info ---
    const addrFull = lp.address || '-';

    const chainHTML = `
    <div class="lpd-section">
        <h4 class="lpd-section-title">On-chain</h4>
        <div class="lpd-kv-list">
            <div class="lpd-kv"><span class="lpd-k">Address</span><code class="lpd-v">${escapeHtml(addrFull)}</code></div>
            <div class="lpd-kv"><span class="lpd-k">Endpoint</span><a href="${escapeHtml(lp.endpoint)}" target="_blank" rel="noopener" class="lpd-v">${escapeHtml(lp.endpoint)}</a></div>
            ${lp.txid ? `<div class="lpd-kv"><span class="lpd-k">Registration TX</span><code class="lpd-v">${escapeHtml(lp.txid)}</code></div>` : ''}
            ${lp.height ? `<div class="lpd-kv"><span class="lpd-k">Registered at</span><span class="lpd-v">Block ${lp.height}</span></div>` : ''}
        </div>
    </div>`;

    return statusHTML + tableHTML + chainHTML;
}

/**
 * Live-update LP card or detail page when WS data arrives.
 */
function updateLPExplorerCard(endpoint) {
    // Update card in list
    if (State._lpExplorerLoaded) {
        const card = document.querySelector(`.lp-card[data-lp-endpoint="${endpoint}"]`);
        if (card) {
            const lp = CONFIG.LP_REGISTRY.find(l => l.endpoint === endpoint);
            if (lp) {
                const temp = document.createElement('div');
                temp.innerHTML = buildLPCardHTML(lp);
                card.replaceWith(temp.firstElementChild);
            }
        }
        updateLPExplorerSummary();
    }

    // Update detail tab if open on this LP
    const detailTab = document.getElementById('tab-lpdetail');
    if (detailTab && detailTab.classList.contains('active') && detailTab.dataset.endpoint === endpoint) {
        const lp = CONFIG.LP_REGISTRY.find(l => l.endpoint === endpoint);
        if (lp) {
            const wsCache = lpWsInfoCache[endpoint] || {};
            const body = document.getElementById('lp-detail-body');
            if (body) {
                body.innerHTML = buildLPDetailHTML(
                    lp, wsCache.info || null, wsCache.inventory || null,
                    lp.cached_info || {}, lpWebSockets[endpoint]?.connected || false
                );
            }
        }
    }
}

window.openLPDetail = openLPDetail;

// =============================================================================
// UTILITIES
// =============================================================================

/** Escape HTML to prevent XSS from LP-provided data. */
function escapeHtml(str) {
    if (str == null) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

function formatNumber(num, decimals = 2) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(2) + 'M';
    }
    if (num >= 1000) {
        return num.toLocaleString('en-US', {
            minimumFractionDigits: decimals,
            maximumFractionDigits: decimals
        });
    }
    return num.toFixed(decimals);
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// =============================================================================
// EVENT LISTENERS
// =============================================================================

DOM.inputAmount.addEventListener('input', () => onInputChange(false));
DOM.destAddress.addEventListener('input', onAddressChange);
DOM.swapBtn.addEventListener('click', (e) => {
    if (DOM.swapBtn.disabled) {
        // Shake the button
        DOM.swapBtn.classList.add('shake');
        setTimeout(() => DOM.swapBtn.classList.remove('shake'), 400);

        // Highlight the missing field
        const hasAmount = State.inputAmount >= CONFIG.MIN_AMOUNT;
        const toAsset = ASSETS[State.toAsset];
        const hasAddress = toAsset.addressPattern.test(State.destAddress);

        if (!hasAmount) {
            DOM.inputAmount.classList.add('highlight-missing');
            DOM.inputAmount.focus();
            setTimeout(() => DOM.inputAmount.classList.remove('highlight-missing'), 2000);
        } else if (!hasAddress) {
            DOM.destAddress.classList.add('highlight-missing');
            DOM.destAddress.focus();
            setTimeout(() => DOM.destAddress.classList.remove('highlight-missing'), 2000);
        }
        return;
    }
    initiateSwap();
});
DOM.newSwapBtn.addEventListener('click', resetSwap);

// Close modal on backdrop click
DOM.assetModal?.querySelector('.modal-backdrop')?.addEventListener('click', closeAssetModal);

// Close modals on escape
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        if (!DOM.assetModal.classList.contains('hidden')) {
            closeAssetModal();
        } else if (!DOM.swapModal.classList.contains('hidden')) {
            closeSwapModal();
        }
    }
});

// Smooth scroll to "how it works"
document.querySelector('.learn-more')?.addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('how-it-works').scrollIntoView({ behavior: 'smooth' });
});

// Expose functions for inline onclick handlers
window.openAssetModal = openAssetModal;
window.closeAssetModal = closeAssetModal;
window.closeSwapModal = closeSwapModal;
window.selectAsset = selectAsset;
window.swapDirection = swapDirection;
window.resetSwap = resetSwap;
window.notifyBtcFunded = notifyBtcFunded;
window.copyDepositAddress = copyDepositAddress;
window.toggleShowAllLPs = toggleShowAllLPs;

// =============================================================================
// INITIALIZATION
// =============================================================================

/**
 * Apply LP list from registry data (used by both WS and HTTP).
 */
function applyRegistryLPs(lps) {
    CONFIG.LP_REGISTRY = lps;
    CONFIG.SDK_URLS = lps
        .filter(lp => CONFIG.SHOW_ALL_LPS || lp.tier === 1)
        .map(lp => lp.endpoint);
    if (CONFIG.SDK_URLS.length === 0) {
        CONFIG.SDK_URLS = lps.map(lp => lp.endpoint);
    }
    updateTierDisplay();
    connectLPWebSockets();
}

/**
 * Connect WS to each discovered LP. Manages lifecycle (close removed, add new).
 */
function connectLPWebSockets() {
    // Connect to ALL registry LPs (not just SDK_URLS) for full Explorer coverage
    const allEndpoints = CONFIG.LP_REGISTRY.map(lp => lp.endpoint);
    // Close WS for LPs no longer in the registry
    for (const url of Object.keys(lpWebSockets)) {
        if (!allEndpoints.includes(url)) {
            lpWebSockets[url].close();
            delete lpWebSockets[url];
        }
    }
    // Connect WS to new LPs
    for (const url of allEndpoints) {
        if (lpWebSockets[url]) continue;
        const wsUrl = url.replace(/^http/, 'ws') + '/ws';
        const lpWs = new PnaWebSocket(wsUrl, {
            lp_info: (data) => {
                currentLP = {
                    id: data.lp_id,
                    name: data.name,
                    pairs: data.pairs,
                    inventory: data.inventory,
                };
                updateLPDisplay();
                // Cache for LP Explorer
                if (!lpWsInfoCache[url]) lpWsInfoCache[url] = {};
                lpWsInfoCache[url].info = data;
                lpWsInfoCache[url].ts = Date.now();
                updateLPExplorerCard(url);
            },
            quote: (data) => {
                // WS quote push — update display if matches current pair
                if (data.from_asset === State.fromAsset && data.to_asset === State.toAsset) {
                    currentQuote = data;
                    if (data.to_amount !== undefined) {
                        State.outputAmount = data.to_amount;
                        const toAsset = State.toAsset;
                        if (toAsset === 'BTC') {
                            DOM.outputAmount.textContent = data.to_amount.toFixed(8);
                        } else if (toAsset === 'M1') {
                            DOM.outputAmount.textContent = Math.round(data.to_amount * 100000000).toLocaleString();
                        } else {
                            DOM.outputAmount.textContent = formatNumber(data.to_amount, 2);
                        }
                        updateQuoteBreakdown(data);
                        updateButtonState();
                    }
                }
            },
            swap_update: (data) => {
                if (State.currentSwap && data.swap_id === State.currentSwap.swap_id) {
                    handleFlowSwapStateChange(data);
                }
            },
            inventory: (data) => {
                // Cache inventory for LP Explorer
                if (!lpWsInfoCache[url]) lpWsInfoCache[url] = {};
                lpWsInfoCache[url].inventory = data;
                lpWsInfoCache[url].ts = Date.now();
                updateLPExplorerCard(url);
            },
            error: (data) => {
                console.warn('[ws] LP error:', data.message);
            },
            pong: () => {},
        });
        lpWs.connect();
        // Auto-subscribe to inventory updates
        lpWs.subscribe('inventory');
        lpWebSockets[url] = lpWs;
    }
}

/**
 * Subscribe active LP WS to quote updates for current pair.
 */
function wsSubscribeQuote() {
    if (State.inputAmount <= 0) return;
    const lpUrl = getLpUrl();
    const lpWs = lpWebSockets[lpUrl];
    if (lpWs && lpWs.connected) {
        lpWs.subscribe('quotes', {
            from: State.fromAsset,
            to: State.toAsset,
            amount: State.inputAmount,
        });
    }
}

/**
 * Subscribe to swap updates via WS (replaces polling).
 */
function wsSubscribeSwap(swapId) {
    const lpUrl = getLpUrl();
    const lpWs = lpWebSockets[lpUrl];
    if (lpWs && lpWs.connected) {
        lpWs.subscribe('swap', { swap_id: swapId });
        console.log(`[ws] Subscribed to swap ${swapId}`);
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    console.log('[pna] Initializing FlowSwap 3S...');

    // --- Step 1: Connect to Registry via WebSocket (with HTTP fallback) ---
    let lpSourceLoaded = false;

    // Race: WS and HTTP in parallel — use whichever responds first
    const registryWsUrl = CONFIG.REGISTRY_URL.replace(/^http/, 'ws') + '/ws';
    let wsResolve;
    const wsReady = new Promise(r => { wsResolve = r; });

    registryWs = new PnaWebSocket(registryWsUrl, {
        lps: (data) => {
            if (data.lps && data.lps.length > 0) {
                applyRegistryLPs(data.lps);
                if (!lpSourceLoaded) {
                    lpSourceLoaded = true;
                    console.log(`[ws] Registry: ${data.lps.length} LPs discovered`);
                    wsResolve();
                    // Trigger initial data fetches now that we have LPs
                    Promise.allSettled([
                        fetchLPInfo(),
                        updateRateDisplay(),
                        loadSwapExplorer(),
                    ]).then(() => updateButtonState());
                }
            }
        },
        lp_update: (data) => {
            const idx = CONFIG.LP_REGISTRY.findIndex(lp => lp.endpoint === data.endpoint);
            if (idx >= 0) CONFIG.LP_REGISTRY[idx] = data;
            else CONFIG.LP_REGISTRY.push(data);
            CONFIG.SDK_URLS = CONFIG.LP_REGISTRY
                .filter(lp => (CONFIG.SHOW_ALL_LPS || lp.tier === 1) && lp.status !== 'offline')
                .map(lp => lp.endpoint);
            if (CONFIG.SDK_URLS.length === 0) {
                CONFIG.SDK_URLS = CONFIG.LP_REGISTRY.map(lp => lp.endpoint);
            }
            updateTierDisplay();
            connectLPWebSockets();
            // Live-update LP Explorer card
            if (State._lpExplorerLoaded && data.endpoint) {
                updateLPExplorerCard(data.endpoint);
                updateLPExplorerSummary();
            }
        },
        pong: () => {},
    });
    registryWs.connect();

    // HTTP fetch fires immediately in parallel with WS
    const httpFetch = (async () => {
        try {
            const registryResp = await fetch(
                `${CONFIG.REGISTRY_URL}/api/registry/lps/online`,
                { signal: AbortSignal.timeout(CONFIG.REGISTRY_TIMEOUT_MS) }
            );
            if (registryResp.ok && !lpSourceLoaded) {
                const data = await registryResp.json();
                if (data.lps && data.lps.length > 0 && !lpSourceLoaded) {
                    applyRegistryLPs(data.lps);
                    lpSourceLoaded = true;
                    console.log(`[pna] Registry HTTP: ${data.lps.length} LPs discovered`);
                }
            }
        } catch (e) {
            console.warn('[pna] Registry HTTP failed:', e.message);
        }
    })();

    // Wait for whichever responds first (WS or HTTP), max 2s
    await Promise.race([
        wsReady,
        httpFetch,
        new Promise(r => setTimeout(r, 2000)),
    ]);

    if (!lpSourceLoaded) {
        console.warn('[pna] No LPs discovered yet. Waiting for WS reconnect...');
    }

    // Show loading state
    DOM.rateValue.textContent = 'Loading...';
    updateAssetDisplay();

    // If we have LPs from HTTP fallback, fetch data now
    if (lpSourceLoaded) {
        await Promise.allSettled([
            fetchLPInfo(),
            updateRateDisplay(),
            loadSwapExplorer(),
        ]);
        updateButtonState();
    }

    // --- Step 1.5: Recover in-flight swap from sessionStorage ---
    const savedSession = loadSwapSession();
    if (savedSession) {
        console.log('[pna] Recovering swap from session:', savedSession.swap.swap_id);
        State.S_user = savedSession.S_user;
        State.currentSwap = savedSession.swap;
        State.activeLpUrl = savedSession.lpUrl;

        // Re-open the swap modal and start polling
        DOM.swapModal.classList.remove('hidden');
        DOM.swapId.textContent = savedSession.swap.swap_id;
        setStatusMessage('pending', 'Recovering swap...');

        // Poll LP for current state
        startFlowSwapPolling(savedSession.swap.swap_id);

        // Fetch current state immediately
        try {
            const lpUrl = savedSession.lpUrl || getLpUrl();
            const resp = await fetch(`${lpUrl}/api/flowswap/${savedSession.swap.swap_id}`);
            if (resp.ok) {
                const data = await resp.json();
                handleFlowSwapStateChange(data);
                console.log('[pna] Swap recovered, state:', data.state);
            } else {
                setStatusMessage('warning', 'Swap recovery: LP not responding. Polling...');
            }
        } catch (e) {
            console.warn('[pna] Swap recovery fetch error:', e);
            setStatusMessage('warning', 'Reconnecting to LP...');
        }
    }

    // --- Step 2: Periodic fallback for quotes (when WS unavailable) ---
    setInterval(async () => {
        if (State.currentSwap) return;
        // Check if any LP WS is connected — if so, use WS for quotes
        const lpUrl = getLpUrl();
        const lpWs = lpWebSockets[lpUrl];
        if (lpWs && lpWs.connected) {
            // WS handles quote pushes — just update subscription if pair changed
            wsSubscribeQuote();
            return;
        }
        // HTTP fallback
        if (State.inputAmount > 0) {
            await onInputChange(true);
        } else {
            await updateRateDisplay();
        }
    }, CONFIG.QUOTE_REFRESH_MS);

    // Refresh explorers every 30s
    setInterval(loadSwapExplorer, 30000);
    setInterval(() => {
        if (State._lpExplorerLoaded) loadLPExplorer();
    }, 30000);

    console.log('[pna] Ready - FlowSwap 3S');
});
