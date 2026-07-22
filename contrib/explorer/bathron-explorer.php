<?php
/*
    BATHRON Explorer - Custom Block Explorer for BATHRON
    Based on RPC Ace by Robin Leffmann

    Licensed under CC BY-NC-SA 4.0
*/

// Pas de cache navigateur : la page est live (auto-refresh) — évite les vues figées
// type "0 burns" servies depuis un HTML mis en cache par le navigateur.
if (!headers_sent()) {
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
}

// ============ CONFIGURATION ============
const RPC_HOST = '127.0.0.1';
const RPC_PORT = 27175;  // BATHRON testnet RPC port
const RPC_USER = 'testuser';
const RPC_PASS = 'testpass123';

const COIN_NAME = 'BATHRON';
const COIN_TICKER = 'sats';  // Base money (Genesis Clean terminology)
const NETWORK = 'Testnet';
const BLOCKS_PER_LIST = 15;
const REFRESH_TIME = 30;
const MNS_PER_PAGE = 25;

require_once('easybitcoin.php');

// ============ TX TYPE DEFINITIONS (BP30) ============
// Transaction types from primitives/transaction.h
const TX_TYPES = [
    0 => ['name' => 'Standard', 'class' => 'badge-standard', 'desc' => 'Standard transaction'],
    1 => ['name' => 'ProReg', 'class' => 'badge-proreg', 'desc' => 'Operator node registration'],
    2 => ['name' => 'ProUpServ', 'class' => 'badge-proupserv', 'desc' => 'MN service update'],
    3 => ['name' => 'ProUpReg', 'class' => 'badge-proupreg', 'desc' => 'MN registration update'],
    4 => ['name' => 'ProUpRev', 'class' => 'badge-prouprev', 'desc' => 'MN revocation'],
    // BP30 Lock-Based Settlement (M0/M1 model)
    20 => ['name' => 'TX_LOCK', 'class' => 'badge-lock', 'desc' => 'M0 → Vault + M1 Receipt'],
    21 => ['name' => 'TX_UNLOCK', 'class' => 'badge-unlock', 'desc' => 'Vault + M1 → M0'],
    22 => ['name' => 'TX_TRANSFER', 'class' => 'badge-transfer', 'desc' => 'M1 Receipt transfer'],
    // BTC SPV burn→mint pipeline
    31 => ['name' => 'TX_BURN_CLAIM', 'class' => 'badge-lock', 'desc' => 'Claim M0 from BTC burn proof'],
    32 => ['name' => 'TX_MINT_M0BTC', 'class' => 'badge-unlock', 'desc' => 'Mint spendable M0 (finalized burn)'],
    33 => ['name' => 'TX_BTC_HEADERS', 'class' => 'badge-transfer', 'desc' => 'BTC SPV headers publication'],
    // BP02 HTLC settlement (M1 atomic swaps)
    40 => ['name' => 'HTLC_CREATE', 'class' => 'badge-lock', 'desc' => 'M1 Receipt → HTLC P2SH'],
    41 => ['name' => 'HTLC_CLAIM', 'class' => 'badge-unlock', 'desc' => 'HTLC + preimage → M1 Receipt'],
    42 => ['name' => 'HTLC_REFUND', 'class' => 'badge-transfer', 'desc' => 'Expired HTLC → M1 Receipt'],
    43 => ['name' => 'HTLC_CREATE_3S', 'class' => 'badge-lock', 'desc' => 'M1 Receipt → 3-secret HTLC (FlowSwap)'],
    44 => ['name' => 'HTLC_CLAIM_3S', 'class' => 'badge-unlock', 'desc' => '3 preimages → M1 Receipt'],
    45 => ['name' => 'HTLC_REFUND_3S', 'class' => 'badge-transfer', 'desc' => 'Expired 3S HTLC → M1 Receipt'],
];

/**
 * Get TX type info from type code
 */
function getTxTypeInfo($type) {
    return TX_TYPES[$type] ?? ['name' => 'Unknown', 'class' => 'badge-unknown', 'desc' => 'Unknown type'];
}

/**
 * Get asset class from asset name (from RPC)
 * RPC now returns asset type directly, this just maps to CSS class
 */
function getAssetClass($asset) {
    switch ($asset) {
        case 'M1': return 'asset-m1';
        case 'Vault': return 'asset-vault';
        case 'Pool': return 'asset-vault';
        default: return 'asset-m0';
    }
}

/**
 * Get TX type badge HTML
 */
function getTxTypeBadge($type, $isCoinbase = false) {
    if ($isCoinbase) {
        return '<span class="badge badge-coinbase" title="Block reward">Coinbase</span>';
    }
    $info = getTxTypeInfo($type);
    return '<span class="badge ' . $info['class'] . '" title="' . htmlspecialchars($info['desc']) . '">' . $info['name'] . '</span>';
}

/**
 * Format satoshi amount for display
 * BATHRON: 1 M0 = 1 satoshi (raw integer display)
 */
function formatSats($amount, $showUnit = true) {
    $formatted = number_format((int)$amount, 0, '.', ',');
    return $showUnit ? $formatted . ' sats' : $formatted;
}

// ============ RPC CLASS ============
class BATHRONExplorer
{
    private static $rpc = null;

    private static function getRpc()
    {
        if (self::$rpc === null) {
            self::$rpc = new Bitcoin(RPC_USER, RPC_PASS, RPC_HOST, RPC_PORT);
        }
        return self::$rpc;
    }

    public static function getNetworkInfo()
    {
        $rpc = self::getRpc();

        // ========================================
        // ONE RPC: getexplorerdata (atomic snapshot)
        // Contains: supply, burns, blockchain, peers, mempool, btcspv, finality, invariants, network
        // ========================================
        $explorerData = null;
        try {
            $explorerData = @$rpc->getexplorerdata();
        } catch (Exception $e) {
            // getexplorerdata not available - return minimal data
            return [
                'blocks' => 0, 'difficulty' => 0, 'chain' => 'unknown', 'connections' => 0,
                'version' => '', 'protocolversion' => 0, 'hashrate' => 0,
                'masternodes_active' => 0, 'masternodes_total' => 0, 'operators_count' => 0,
                'mempool_size' => 0, 'mempool_bytes' => 0, 'r_percent' => 0,
                'm0_total' => 0, 'm0_circulating' => 0, 'm0_mn_collateral' => 0, 'm0_shield' => 0,
                'fees_recycled' => 0, 'm0_vaulted_active' => 0, 'm0_savingspool' => 0,
                'm1_supply' => 0, 'm2_locked' => 0, 'treasury' => 0, 'yield_vault' => 0,
                'a6_left' => 0, 'a6_right' => 0, 'invariants_ok' => true,
                'finality_lag' => 0, 'finality_status' => 'unknown', 'last_finalized' => 0,
                'btcspv_tip' => 0, 'btcspv_initialized' => false,
            ];
        }

        // ========================================
        // Extract all data from single RPC response
        // ========================================

        // Supply
        $supply = $explorerData['supply'] ?? [];
        $m0TotalSupply = floatval($supply['m0_total'] ?? '0');
        $mnCollateral = floatval($supply['mn_collateral'] ?? '0');
        $m0Circulating = floatval($supply['m0_circulating'] ?? '0');
        $m0VaultedActive = floatval($supply['m0_vaulted'] ?? '0');
        $m0Shielded = floatval($supply['m0_shielded'] ?? '0');
        $m1Supply = floatval($supply['m1_supply'] ?? '0');
        $feesRecycled = floatval($supply['fees_recycled'] ?? '0');

        // Invariants — verdict autoritaire du nœud (pas une re-dérivation côté UI)
        $invariants = $explorerData['invariants'] ?? [];
        $a6Left = floatval($invariants['a6_left'] ?? '0');
        $a6Right = floatval($invariants['a6_right'] ?? '0');
        $a5Ok = $invariants['a5_ok'] ?? null;
        $a6Ok = $invariants['a6_ok'] ?? null;
        $invariantsOk = ($a6Ok !== null) ? $a6Ok : true;

        // Network (MN/operators)
        $network = $explorerData['network'] ?? [];
        $mnTotal = $network['masternodes'] ?? 0;
        $mnActive = $network['mn_enabled'] ?? 0;
        $operatorCount = $network['operators'] ?? 0;

        // Finality
        $finality = $explorerData['finality'] ?? [];
        $finalityLag = $finality['lag'] ?? 0;
        $finalityStatus = $finality['status'] ?? 'unknown';
        $lastFinalized = $finality['height'] ?? 0;

        // Blockchain
        $blockchain = $explorerData['blockchain'] ?? [];
        $blocks = $blockchain['blocks'] ?? 0;
        $difficulty = $blockchain['difficulty'] ?? 0;

        // Peers
        $peers = $explorerData['peers'] ?? [];
        $connections = $peers['connections'] ?? 0;

        // Mempool
        $mempool = $explorerData['mempool'] ?? [];
        $mempoolSize = $mempool['size'] ?? 0;
        $mempoolBytes = $mempool['bytes'] ?? 0;

        // BTC SPV
        $btcspv = $explorerData['btcspv'] ?? [];
        $btcspvTip = $btcspv['tip_height'] ?? 0;
        $btcspvInitialized = $btcspv['initialized'] ?? false;

        return [
            'blocks' => $blocks,
            'difficulty' => $difficulty,
            'chain' => 'privnet',  // From schema or hardcoded for testnet
            'connections' => $connections,
            'version' => '',  // Not in getexplorerdata (minor)
            'protocolversion' => 0,
            'hashrate' => 0,  // Not relevant for DMM
            'masternodes_active' => $mnActive,
            'masternodes_total' => $mnTotal,
            'operators_count' => $operatorCount,
            'mempool_size' => $mempoolSize,
            'mempool_bytes' => $mempoolBytes,
            'r_percent' => 0,
            // ========== M0 SUPPLY ==========
            'm0_total' => $m0TotalSupply,
            'm0_circulating' => $m0Circulating,
            'm0_mn_collateral' => $mnCollateral,
            'm0_shield' => $m0Shielded,
            'fees_recycled' => $feesRecycled,
            // ========== SETTLEMENT LAYER (BP30) ==========
            'm0_vaulted_active' => $m0VaultedActive,
            'm0_savingspool' => 0,  // Deprecated
            'm1_supply' => $m1Supply,
            'm2_locked' => 0,  // Future
            // ========== YIELD & TREASURY ==========
            'yield_vault' => 0,
            'treasury' => 0,
            // ========== INVARIANTS (autoritaire) ==========
            'invariants_ok' => $invariantsOk,
            'a5_ok' => $a5Ok,
            'a6_ok' => $a6Ok,
            'state_available' => true,
            'schema_version' => 'explorer.v1',
            'a6_left' => $a6Left,
            'a6_right' => $a6Right,
            // ========== FINALITY ==========
            'finality_lag' => $finalityLag,
            'finality_status' => $finalityStatus,
            'last_finalized' => $lastFinalized,
            'last_finality_delay_ms' => 0,
            'avg_finality_delay_ms' => 0,
            // ========== BTC SPV ==========
            'btcspv_tip' => $btcspvTip,
            'btcspv_initialized' => $btcspvInitialized,
        ];
    }

    /**
     * Get BTC SPV info (headers sync status)
     * Uses getbtcheadersstatus for complete bridge info
     */
    public static function getBtcSpvInfo()
    {
        $rpc = self::getRpc();
        $result = [
            // btcspv (local headers from BTC)
            'spv_tip_height' => 0,
            'spv_tip_hash' => '',
            'spv_synced' => false,
            // btcheadersdb (consensus on BATHRON chain)
            'chain_tip_height' => 0,
            'chain_tip_hash' => '',
            'header_count' => 0,
            // Bridge status
            'headers_ahead' => 0,
            'can_publish' => false,
            'min_supported_height' => 0,
            'spv_ready' => false,
            'network' => 'signet',
            'db_initialized' => false,
        ];

        try {
            // Get full status from getbtcheadersstatus (primary source)
            $status = $rpc->getbtcheadersstatus();
            if (is_array($status)) {
                $result['db_initialized'] = $status['db_initialized'] ?? false;
                $result['chain_tip_height'] = $status['tip_height'] ?? 0;
                $result['chain_tip_hash'] = $status['tip_hash'] ?? '';
                $result['header_count'] = $status['header_count'] ?? 0;
                $result['spv_tip_height'] = $status['spv_tip_height'] ?? 0;
                $result['headers_ahead'] = $status['headers_ahead'] ?? 0;
                $result['can_publish'] = $status['can_publish'] ?? false;
            }

            // Get sync status for SPV readiness and network
            $sync = $rpc->getbtcsyncstatus();
            if (is_array($sync)) {
                $result['spv_synced'] = $sync['synced'] ?? false;
                $result['spv_tip_hash'] = substr($sync['tip_hash'] ?? '', 0, 16);
                $result['spv_ready'] = $sync['spv_ready'] ?? false;
                $result['network'] = $sync['network'] ?? 'signet';
                $result['min_supported_height'] = $sync['min_supported_height'] ?? 0;
            }
        } catch (Exception $e) {
            // SPV not available
        }

        return $result;
    }

    /**
     * Get full BTC info for BTC tab (headers, burns, scan status)
     */
    public static function getBTCFullInfo()
    {
        $rpc = self::getRpc();
        $result = [
            'headers' => null,
            'sync' => null,
            'burn_stats' => null,
            'scan_status' => null,
            'burn_status' => null,
            'burns_pending' => [],
            'burns_final' => [],
            'burns_all' => [],
        ];

        try {
            // Headers status (consensus chain)
            $result['headers'] = $rpc->getbtcheadersstatus();
        } catch (Exception $e) {}

        try {
            // SPV sync status (local)
            $result['sync'] = $rpc->getbtcsyncstatus();
        } catch (Exception $e) {}

        try {
            // Burn statistics
            $result['burn_stats'] = $rpc->getbtcburnstats();
        } catch (Exception $e) {}

        try {
            // Scan status
            $result['scan_status'] = $rpc->getburnscanstatus();
        } catch (Exception $e) {}

        try {
            // Overall burn status
            $result['burn_status'] = $rpc->getburnstatus();
        } catch (Exception $e) {}

        try {
            // List all burn claims (request "all" filter with high count)
            $burns = $rpc->listburnclaims("all", 1000, 0);
            if (is_array($burns)) {
                $result['burns_all'] = $burns;
                foreach ($burns as $burn) {
                    $status = $burn['status'] ?? $burn['db_status'] ?? '';
                    if ($status === 'pending' || $status === 'mempool') {
                        $result['burns_pending'][] = $burn;
                    } else {
                        $result['burns_final'][] = $burn;
                    }
                }
            }
        } catch (Exception $e) {}

        return $result;
    }

    /**
     * Get BTC burn stats
     *
     * NOTE: burnclaimdb does NOT track genesis burns (they are minted via TX_MINT_M0BTC
     * in block 1 without going through submitburnclaim). So burn_count from RPC is 0.
     * We count genesis burns from the JSON file instead.
     * btc_burned_sats from settlement is always correct (A5 invariant).
     */
    public static function getBurnStats()
    {
        $rpc = self::getRpc();
        $result = [
            'total_burns' => 0,
            'total_pending' => 0,
            'btc_transferred' => 0,
            'btc_pending' => 0,
        ];

        // Source of truth for amounts: getexplorerdata (uses settlement M0_total)
        // A5 invariant: btc_burned_sats == M0_total (always exact)
        try {
            $data = $rpc->getexplorerdata();
            if (is_array($data) && isset($data['burns'])) {
                $burns = $data['burns'];
                // burn_count from burnclaimdb is 0 for genesis burns - we'll fix below
                $result['total_burns'] = $burns['burn_count'] ?? 0;
                $result['total_pending'] = $burns['pending_count'] ?? 0;
                $result['btc_transferred'] = intval($burns['btc_burned_sats'] ?? 0);
                $result['btc_pending'] = intval($burns['btc_pending_sats'] ?? 0);
            }
        } catch (Exception $e) {
            // RPC not available - return zeros
        }

        // NOTE: burnclaimdb now tracks genesis burns (EnsureGenesisBurnsInDB at startup)
        // No need to add them from JSON anymore

        return $result;
    }

    /**
     * Get list of genesis burns from genesis_burns.json
     * Reads directly from local file for accurate display
     */
    public static function getGenesisBurnsList()
    {
        $burns = [];

        // Try to read from genesis_burns.json (multiple locations)
        // NOTE: genesis_burns_spv.json removed - daemon-only flow uses burnclaimdb
        $paths = [
            '/home/ubuntu/explorer/genesis_burns.json',             // Explorer dir (deployed)
            '/home/ubuntu/.bathron/testnet5/genesis_burns.json',    // Daemon datadir
            '/home/ubuntu/genesis_burns.json',                      // Server deployment
            __DIR__ . '/genesis_burns.json',                        // Same dir as explorer
            __DIR__ . '/../../contrib/testnet/genesis_burns.json',
            '/home/ubuntu/BATHRON/contrib/testnet/genesis_burns.json',
        ];

        foreach ($paths as $path) {
            if (file_exists($path)) {
                $content = file_get_contents($path);
                $data = json_decode($content, true);
                if ($data && isset($data['burns'])) {
                    $burns = $data['burns'];
                    break;
                }
            }
        }

        // Calculate totals
        $totalSats = 0;
        foreach ($burns as &$burn) {
            $totalSats += $burn['burned_sats'] ?? 0;
            // Add BTC amount for display
            $burn['burned_btc'] = ($burn['burned_sats'] ?? 0) / 100000000;
        }

        return [
            'burns' => $burns,
            'count' => count($burns),
            'total_sats' => $totalSats,
            'total_btc' => $totalSats / 100000000,
        ];
    }

    // [legacy DAO/grant/DOMC accessors removed 2026-06-30 — no callers; governance/yield/treasury dropped from model]

    /**
     * Read the persistent finality-track state (produced->finalized delays),
     * written by finality-tracker.service. Pure file read, no RPC.
     */
    public static function getFinalityTrack()
    {
        $path = '/home/ubuntu/explorer-state/finality.json';
        $default = ['lag' => 0, 'status' => 'unknown', 'tip' => 0, 'updated' => 0, 'blocks' => []];
        if (is_readable($path)) {
            $j = json_decode(file_get_contents($path), true);
            if (is_array($j)) return array_merge($default, $j);
        }
        return $default;
    }

    /**
     * DMM sortition fairness per operator (from listoperators): blocks produced,
     * actual vs expected production share, deviation. Map keyed by operatorPubKey.
     */
    public static function getSortition()
    {
        $rpc = self::getRpc();
        $map = [];
        try {
            $r = @$rpc->listoperators();
            if (is_array($r) && !empty($r['operators'])) {
                foreach ($r['operators'] as $o) {
                    $pk = $o['operatorPubKey'] ?? '';
                    if ($pk === '') continue;
                    $map[$pk] = [
                        'blocksProduced' => (int)($o['blocksProduced'] ?? 0),
                        'sharePercent'   => $o['sharePercent'] ?? 0,
                        'expectedShare'  => $o['expectedShare'] ?? 0,
                        'deviation'      => $o['deviation'] ?? '',
                    ];
                }
            }
        } catch (Exception $e) {
            // RPC indisponible — la table opérateurs retombe sur blocksProduced local
        }
        return $map;
    }

    /**
     * Production stats PAR masternode individuel (listmnstats) : blocs produits,
     * taux de production (% du réseau), taux attendu. Map clé = proTxHash.
     */
    public static function getMnStats()
    {
        $rpc = self::getRpc();
        $map = [];
        try {
            $r = @$rpc->listmnstats();
            if (is_array($r)) {
                foreach ($r as $m) {
                    $h = $m['proTxHash'] ?? '';
                    if ($h === '') continue;
                    $map[$h] = [
                        'blocksProduced' => (int)($m['blocksProduced'] ?? 0),
                        'productionRate' => (float)($m['productionRate'] ?? 0),
                        'expectedRate'   => (float)($m['expectedRate'] ?? 0),
                    ];
                }
            }
        } catch (Exception $e) {
            // RPC indisponible
        }
        return $map;
    }

    /**
     * Participation à la FINALITÉ par opérateur (getfinalityparticipation) sur les
     * N derniers blocs. Donnée ATOMIQUE : lue du store de finalité consensus du nœud
     * (les mêmes enregistrements que les gardes anti-reorg), pas une heuristique.
     * Map clé = operatorPubKey (hex) → signed / window / rate / last_signed_height.
     * La finalité est 1 voix par OPÉRATEUR (un opérateur multi-MN signe via un seul
     * MN par bloc) → la participation s'affiche par opérateur, jamais par MN.
     */
    public static function getFinalityParticipation($nblocks = 32)
    {
        $rpc = self::getRpc();
        $out = ['window' => 0, 'blocks_with_finality' => 0, 'operators' => []];
        try {
            $r = @$rpc->getfinalityparticipation($nblocks);
            if (is_array($r)) {
                $out['window'] = (int)($r['window'] ?? 0);
                $out['blocks_with_finality'] = (int)($r['blocks_with_finality'] ?? 0);
                foreach (($r['operators'] ?? []) as $o) {
                    $key = $o['operator'] ?? '';
                    if ($key === '') continue;
                    $out['operators'][$key] = [
                        'signed' => (int)($o['signed'] ?? 0),
                        'rate' => (float)($o['rate'] ?? 0),
                        'last_signed_height' => (int)($o['last_signed_height'] ?? 0),
                        'mn_count' => (int)($o['mn_count'] ?? 0),
                    ];
                }
            }
        } catch (Exception $e) {
            // RPC indisponible (vieux daemon) — la colonne affichera n/a, pas de fake
        }
        return $out;
    }

    /**
     * Get rotation check for fairness
     */
    public static function getRotationCheck()
    {
        $rpc = self::getRpc();
        try {
            $rotation = $rpc->checkrotation();
            if (is_array($rotation)) {
                return $rotation;
            }
        } catch (Exception $e) {
            // RPC not available
        }
        return [
            'fairness_score' => 0,
            'status' => 'unknown',
        ];
    }

    public static function getBlockList($offset = null, $count = BLOCKS_PER_LIST)
    {
        $rpc = self::getRpc();
        $info = $rpc->getblockchaininfo();
        if (!is_array($info)) {
            throw new Exception("RPC connection failed - cannot get blockchain info");
        }
        $height = $info['blocks'] ?? 0;

        $start = $offset === null ? $height : min($offset, $height);
        $blocks = [];

        for ($i = $start; $i >= 0 && count($blocks) < $count; $i--) {
            $hash = $rpc->getblockhash($i);
            if (!$hash) continue;
            $block = $rpc->getblock($hash);
            if (!is_array($block)) continue;

            $txCount = count($block['tx'] ?? []);
            $totalOut = 0;

            foreach (($block['tx'] ?? []) as $txid) {
                $tx = $rpc->getrawtransaction($txid, 1);
                if ($tx && is_array($tx)) {
                    foreach (($tx['vout'] ?? []) as $vout) {
                        $totalOut += $vout['value'] ?? 0;
                    }
                }
            }

            $blocks[] = [
                'height' => $block['height'],
                'hash' => $block['hash'],
                'time' => $block['time'],
                'txcount' => $txCount,
                'size' => $block['size'],
                'total_out' => $totalOut,
            ];
        }

        return ['blocks' => $blocks, 'height' => $height, 'start' => $start];
    }

    public static function getBlock($hash)
    {
        $rpc = self::getRpc();
        // Use verbosity=2 to get full transaction data
        $block = $rpc->getblock($hash, 2);
        if (!$block) return null;

        $transactions = [];
        foreach ($block['tx'] as $tx) {
            // With verbosity=2, tx is already an object with full data
            $outputs = [];
            $inputs = [];
            $totalOut = 0;
            $totalIn = 0;
            $isCoinbase = isset($tx['vin'][0]['coinbase']);

            // Process inputs
            foreach ($tx['vin'] as $vin) {
                if (isset($vin['coinbase'])) {
                    $inputs[] = ['coinbase' => $vin['coinbase']];
                } else {
                    $inputs[] = [
                        'txid' => $vin['txid'] ?? '',
                        'vout' => $vin['vout'] ?? 0,
                    ];
                }
            }

            // Process outputs - asset type comes from RPC (BP30)
            foreach ($tx['vout'] as $vout) {
                $value = $vout['value'] ?? 0;
                $address = $vout['scriptPubKey']['addresses'][0] ?? ($vout['scriptPubKey']['type'] ?? 'unknown');
                $scriptType = $vout['scriptPubKey']['type'] ?? 'unknown';
                $asset = $vout['asset'] ?? 'M0';  // RPC now returns asset type
                $outputs[] = [
                    'n' => $vout['n'],
                    'value' => $value,
                    'address' => $address,
                    'type' => $scriptType,
                    'asset' => $asset,
                    'asset_class' => getAssetClass($asset),
                ];
                $totalOut += $value;
            }

            $transactions[] = [
                'txid' => $tx['txid'],
                'size' => $tx['size'] ?? 0,
                'type' => $tx['type'] ?? 0,
                'type_name' => $tx['tx_type_name'] ?? null,
                'tx_flow' => $tx['tx_flow'] ?? null,
                'inputs' => $inputs,
                'outputs' => $outputs,
                'total' => $totalOut,
                'coinbase' => $isCoinbase,
            ];
        }

        return [
            'height' => $block['height'],
            'hash' => $block['hash'],
            'prevhash' => $block['previousblockhash'] ?? null,
            'nexthash' => $block['nextblockhash'] ?? null,
            'time' => $block['time'],
            'size' => $block['size'],
            'merkleroot' => $block['merkleroot'],
            'nonce' => $block['nonce'],
            'bits' => $block['bits'],
            'difficulty' => $block['difficulty'],
            'confirmations' => $block['confirmations'],
            'transactions' => $transactions,
        ];
    }

    /**
     * Get address information by scanning recent blocks
     * Since we don't have addressindex, we scan the blockchain
     */
    public static function getAddress($address, $maxBlocks = 100)
    {
        $rpc = self::getRpc();

        // Validate address first
        $valid = $rpc->validateaddress($address);
        if (!$valid || !($valid['isvalid'] ?? false)) {
            return null;
        }

        $info = $rpc->getblockchaininfo();
        $height = $info['blocks'];

        $transactions = [];
        $totalReceived = 0;
        $totalSent = 0;

        // Scan recent blocks for transactions involving this address
        $startBlock = max(0, $height - $maxBlocks);
        for ($i = $height; $i >= $startBlock && count($transactions) < 50; $i--) {
            $hash = $rpc->getblockhash($i);
            $block = $rpc->getblock($hash, 2); // verbosity 2 for full tx

            if (!$block || !isset($block['tx'])) continue;

            foreach ($block['tx'] as $tx) {
                $found = false;
                $txReceived = 0;
                $txSent = 0;

                // Check outputs (received)
                foreach ($tx['vout'] as $vout) {
                    $outAddr = $vout['scriptPubKey']['addresses'][0] ?? '';
                    if ($outAddr === $address) {
                        $found = true;
                        $txReceived += $vout['value'];
                        $totalReceived += $vout['value'];
                    }
                }

                // Check inputs (sent) - need to look up previous tx
                foreach ($tx['vin'] as $vin) {
                    if (isset($vin['txid'])) {
                        $prevTx = $rpc->getrawtransaction($vin['txid'], 1);
                        if ($prevTx && isset($prevTx['vout'][$vin['vout']])) {
                            $prevOut = $prevTx['vout'][$vin['vout']];
                            $inAddr = $prevOut['scriptPubKey']['addresses'][0] ?? '';
                            if ($inAddr === $address) {
                                $found = true;
                                $txSent += $prevOut['value'];
                                $totalSent += $prevOut['value'];
                            }
                        }
                    }
                }

                if ($found) {
                    $transactions[] = [
                        'txid' => $tx['txid'],
                        'height' => $block['height'],
                        'time' => $block['time'],
                        'received' => $txReceived,
                        'sent' => $txSent,
                        'net' => $txReceived - $txSent,
                    ];
                }
            }
        }

        return [
            'address' => $address,
            'isvalid' => true,
            'transactions' => $transactions,
            'total_received' => $totalReceived,
            'total_sent' => $totalSent,
            'balance' => $totalReceived - $totalSent,
            'tx_count' => count($transactions),
            'blocks_scanned' => min($maxBlocks, $height),
        ];
    }

    public static function getTransaction($txid)
    {
        $rpc = self::getRpc();
        $tx = $rpc->getrawtransaction($txid, 1);
        if (!$tx) return null;

        // Get block info if confirmed
        $blockInfo = null;
        if (isset($tx['blockhash'])) {
            $block = $rpc->getblock($tx['blockhash']);
            $blockInfo = [
                'hash' => $block['hash'],
                'height' => $block['height'],
                'time' => $block['time'],
            ];
        }

        // Process inputs
        $inputs = [];
        $totalIn = 0;
        $isCoinbase = false;

        foreach ($tx['vin'] as $vin) {
            if (isset($vin['coinbase'])) {
                $isCoinbase = true;
                $inputs[] = [
                    'coinbase' => $vin['coinbase'],
                    'sequence' => $vin['sequence'],
                ];
            } else {
                // Get the previous transaction to find the value
                $prevTx = $rpc->getrawtransaction($vin['txid'], 1);
                $prevOut = $prevTx['vout'][$vin['vout']] ?? null;
                $value = $prevOut['value'] ?? 0;
                $address = $prevOut['scriptPubKey']['addresses'][0] ?? 'unknown';
                $totalIn += $value;

                $inputs[] = [
                    'txid' => $vin['txid'],
                    'vout' => $vin['vout'],
                    'address' => $address,
                    'value' => $value,
                ];
            }
        }

        // Process outputs
        $outputs = [];
        $totalOut = 0;

        foreach ($tx['vout'] as $vout) {
            $address = $vout['scriptPubKey']['addresses'][0] ?? ($vout['scriptPubKey']['type'] ?? 'unknown');
            $asset = $vout['asset'] ?? 'M0';
            $outputs[] = [
                'n' => $vout['n'],
                'value' => $vout['value'],
                'address' => $address,
                'type' => $vout['scriptPubKey']['type'] ?? 'unknown',
                'asset' => $asset,
                'asset_class' => getAssetClass($asset),
            ];
            $totalOut += $vout['value'];
        }

        // Calculate fee (only for non-coinbase)
        $fee = $isCoinbase ? 0 : ($totalIn - $totalOut);

        return [
            'txid' => $tx['txid'],
            'size' => $tx['size'] ?? 0,
            'vsize' => $tx['vsize'] ?? $tx['size'] ?? 0,
            'version' => $tx['version'],
            'type' => $tx['type'] ?? 0,
            'locktime' => $tx['locktime'],
            'blockhash' => $tx['blockhash'] ?? null,
            'confirmations' => $tx['confirmations'] ?? 0,
            'time' => $tx['time'] ?? null,
            'blockinfo' => $blockInfo,
            'coinbase' => $isCoinbase,
            'inputs' => $inputs,
            'outputs' => $outputs,
            'total_in' => $totalIn,
            'total_out' => $totalOut,
            'fee' => $fee,
        ];
    }

    public static function getMasternodeList()
    {
        $rpc = self::getRpc();
        $mnlist = $rpc->protx_list();
        $blockchainInfo = $rpc->getblockchaininfo();
        $currentHeight = $blockchainInfo['blocks'] ?? 0;

        if (!is_array($mnlist)) {
            return [];
        }

        $masternodes = [];
        foreach ($mnlist as $mn) {
            $state = $mn['dmnstate'] ?? [];
            $meta = $mn['metaInfo'] ?? [];
            $collateral = $mn['collateralHash'] ?? '';
            $collateralIndex = $mn['collateralIndex'] ?? 0;

            // Status based on PoSeBanHeight
            $banHeight = $state['PoSeBanHeight'] ?? -1;
            $posePenalty = $state['PoSePenalty'] ?? 0;

            // Determine status
            if ($banHeight != -1) {
                $status = 'POSE_BANNED';
            } elseif ($posePenalty > 0) {
                $status = 'POSE_PENALTY';
            } else {
                $status = 'ENABLED';
            }

            // Calculate uptime from last_outbound_success
            $lastSuccess = $meta['last_outbound_success'] ?? 0;
            $lastSuccessElapsed = $meta['last_outbound_success_elapsed'] ?? 0;

            // If elapsed is huge (>1 year), node was never seen online
            $isOnline = ($lastSuccessElapsed < 600); // Consider online if seen in last 10 min

            // Registered height
            $registeredHeight = $state['registeredHeight'] ?? 0;

            // Calculate score (higher = better priority for next payment)
            // Score based on: blocks since last paid (more = higher score)
            $lastPaidHeight = $state['lastPaidHeight'] ?? 0;
            $blocksSinceLastPaid = ($lastPaidHeight > 0) ? ($currentHeight - $lastPaidHeight) : $currentHeight;
            $score = $blocksSinceLastPaid;

            // Reduce score if banned or has penalty
            if ($status === 'POSE_BANNED') {
                $score = -1;
            } elseif ($status === 'POSE_PENALTY') {
                $score = $score - ($posePenalty * 10);
            }

            $masternodes[] = [
                'proTxHash' => $mn['proTxHash'] ?? '',
                'collateralHash' => $collateral,
                'collateralIndex' => $collateralIndex,
                'collateralAddress' => $mn['collateralAddress'] ?? '',
                'operatorPubKey' => $state['operatorPubKey'] ?? '',
                'votingAddress' => $state['votingAddress'] ?? '',
                'payoutAddress' => $state['payoutAddress'] ?? '',
                'ownerAddress' => $state['ownerAddress'] ?? '',
                'service' => $state['service'] ?? '',
                'status' => $status,
                'poseBanHeight' => $banHeight,
                'posePenalty' => $posePenalty,
                'lastPaidHeight' => $lastPaidHeight,
                'registeredHeight' => $registeredHeight,
                'isOnline' => $isOnline,
                'lastSeenElapsed' => $lastSuccessElapsed,
                'score' => $score,
            ];
        }

        // Sort by score (highest first = next to be paid)
        usort($masternodes, function($a, $b) {
            return $b['score'] - $a['score'];
        });

        return $masternodes;
    }

    /**
     * Get operators list - Groups MNs by operator public key
     * This is the v4.0 Operator-Centric view
     * Includes score, badges, and proposals stats from operator_score RPC
     */
    public static function getOperatorList()
    {
        $rpc = self::getRpc();
        $mnlist = $rpc->protx_list();
        $blockchainInfo = $rpc->getblockchaininfo();
        $currentHeight = $blockchainInfo['blocks'] ?? 0;

        if (!is_array($mnlist)) {
            return [];
        }

        // Group MNs by operator public key
        $operatorMap = [];

        foreach ($mnlist as $mn) {
            $state = $mn['dmnstate'] ?? [];
            $meta = $mn['metaInfo'] ?? [];
            $operatorPubKey = $state['operatorPubKey'] ?? '';

            if (empty($operatorPubKey)) continue;

            // Initialize operator entry if not exists
            if (!isset($operatorMap[$operatorPubKey])) {
                $operatorMap[$operatorPubKey] = [
                    'operatorPubKey' => $operatorPubKey,
                    'masternodes' => [],
                    'totalMNs' => 0,
                    'activeMNs' => 0,
                    'bannedMNs' => 0,
                    'onlineMNs' => 0,
                    'totalScore' => 0,
                    'oldestRegistration' => PHP_INT_MAX,
                    'services' => [],
                    // v4.0 Score/Badge/Proposal fields (populated later)
                    'badges' => [],
                    'grantsPublished' => 0,
                    'grantsAccepted' => 0,
                    'domcVotes' => 0,
                    'grantVotes' => 0,
                    'blocksProduced' => 0,
                ];
            }

            // Status based on PoSeBanHeight
            $banHeight = $state['PoSeBanHeight'] ?? -1;
            $posePenalty = $state['PoSePenalty'] ?? 0;

            if ($banHeight != -1) {
                $status = 'POSE_BANNED';
                $operatorMap[$operatorPubKey]['bannedMNs']++;
            } elseif ($posePenalty > 0) {
                $status = 'POSE_PENALTY';
                $operatorMap[$operatorPubKey]['activeMNs']++;
            } else {
                $status = 'ENABLED';
                $operatorMap[$operatorPubKey]['activeMNs']++;
            }

            // Liveness : la joignabilité réseau n'est pas mesurable ici (Seed opère TOUS les MN,
            // donc aucune connexion sortante vers eux → last_outbound_success inutilisable).
            // On utilise le statut PoSe du consensus : sain = non banni ET sans pénalité.
            $isOnline = ($banHeight == -1 && $posePenalty == 0);
            if ($isOnline) {
                $operatorMap[$operatorPubKey]['onlineMNs']++;
            }

            // Registration height
            $registeredHeight = $state['registeredHeight'] ?? 0;
            if ($registeredHeight > 0 && $registeredHeight < $operatorMap[$operatorPubKey]['oldestRegistration']) {
                $operatorMap[$operatorPubKey]['oldestRegistration'] = $registeredHeight;
            }

            // Score
            $lastPaidHeight = $state['lastPaidHeight'] ?? 0;
            $blocksSinceLastPaid = ($lastPaidHeight > 0) ? ($currentHeight - $lastPaidHeight) : $currentHeight;
            $score = $blocksSinceLastPaid;
            if ($status === 'POSE_BANNED') {
                $score = -1;
            } elseif ($status === 'POSE_PENALTY') {
                $score = $score - ($posePenalty * 10);
            }
            $operatorMap[$operatorPubKey]['totalScore'] += max(0, $score);

            // Service IP
            $service = $state['service'] ?? '';
            if ($service && !in_array($service, $operatorMap[$operatorPubKey]['services'])) {
                $operatorMap[$operatorPubKey]['services'][] = $service;
            }

            // Add MN to operator
            $operatorMap[$operatorPubKey]['masternodes'][] = [
                'proTxHash' => $mn['proTxHash'] ?? '',
                'collateralHash' => $mn['collateralHash'] ?? '',
                'collateralIndex' => $mn['collateralIndex'] ?? 0,
                'service' => $service,
                'status' => $status,
                'isOnline' => $isOnline,
                'registeredHeight' => $registeredHeight,
                'lastPaidHeight' => $lastPaidHeight,
                'score' => $score,
            ];

            $operatorMap[$operatorPubKey]['totalMNs']++;
        }

        // Convert to array and sort by total MNs (descending)
        $operators = array_values($operatorMap);
        usort($operators, function($a, $b) {
            // First by active MNs, then by total score
            if ($b['activeMNs'] != $a['activeMNs']) {
                return $b['activeMNs'] - $a['activeMNs'];
            }
            return $b['totalScore'] - $a['totalScore'];
        });

        // Fix oldestRegistration for genesis MNs and fetch detailed score
        foreach ($operators as &$op) {
            if ($op['oldestRegistration'] == PHP_INT_MAX) {
                $op['oldestRegistration'] = 0; // Genesis
            }
            // Calculate anciennete (days since registration)
            $blocksSinceReg = $currentHeight - $op['oldestRegistration'];
            $op['ancienneteDays'] = floor($blocksSinceReg / 1440); // ~1440 blocks per day

            // Badges via getoperatorinfo (l'ancien RPC operator_score a été supprimé du nœud)
            try {
                $info = $rpc->getoperatorinfo($op['operatorPubKey']);
                if (is_array($info)) {
                    $op['badges']          = $info['badges'] ?? [];
                    $op['badgeIcons']      = $info['badgeIcons'] ?? [];
                    $op['blocksProduced']  = $info['blocksProduced'] ?? $op['blocksProduced'];
                    $op['reputationScore'] = $info['reputationScore'] ?? 0;
                    $op['alias']           = $info['alias'] ?? '';
                }
            } catch (Exception $e) {
                // RPC indisponible ou opérateur introuvable — pas de badges
            }
        }

        return $operators;
    }
}

// DEX API endpoints removed - DEX moved to separate SDK demo site

// ============ ROUTING ============
// Search query from ?q= parameter only (not fallback to QUERY_STRING to avoid tab pollution)
$query = isset($_GET['q']) ? trim($_GET['q']) : '';
$query = substr($query, 0, 64);
$tab = $_GET['tab'] ?? '';

$page = 'dashboard';
$data = [];

// Helper function to detect if query looks like an address
function isAddress($q) {
    // BATHRON testnet addresses start with x or y (pubkey) or 8 (script), mainnet with D or S
    // Shield addresses start with ptestsapling (testnet) or ps (mainnet)
    if (strlen($q) >= 26 && strlen($q) <= 35) {
        return preg_match('/^[xyYD8S][a-km-zA-HJ-NP-Z1-9]+$/', $q);
    }
    if (strlen($q) > 60 && strpos($q, 'ptestsapling') === 0) {
        return true; // Testnet shield address
    }
    if (strlen($q) > 60 && strpos($q, 'ps') === 0) {
        return true; // Mainnet shield address
    }
    return false;
}

try {
    // Handle tab navigation
    if ($tab === 'blocks' || $query === 'blocks') {
        // Blocks list page
        $page = 'blocks';
        $offset = isset($_GET['offset']) ? (int)$_GET['offset'] : null;
        $data = BATHRONExplorer::getBlockList($offset);
        $data['network'] = BATHRONExplorer::getNetworkInfo();
    } elseif ($tab === 'operators' || $query === 'operators') {
        // Operators page (v4.0 Operator-Centric view)
        $page = 'operators';
        $data['operators'] = BATHRONExplorer::getOperatorList();
        $data['network'] = BATHRONExplorer::getNetworkInfo();
        $data['rotation'] = BATHRONExplorer::getRotationCheck();
    } elseif ($tab === 'masternodes' || $query === 'masternodes') {
        // Masternodes page (individual MNs)
        $page = 'masternodes';
        $data['masternodes'] = BATHRONExplorer::getMasternodeList();
        $data['network'] = BATHRONExplorer::getNetworkInfo();
    } elseif ($tab === 'join' || $query === 'join') {
        $page = 'join';
        $data['network'] = BATHRONExplorer::getNetworkInfo();
    } elseif ($tab === 'btc' || $query === 'btc') {
        // BTC page (SPV bridge, burns, headers)
        $page = 'btc';
        $data['btc'] = BATHRONExplorer::getBTCFullInfo();
        // Burns come from listburnclaims RPC (in btc['burns_final'])
        $data['network'] = BATHRONExplorer::getNetworkInfo();
    } elseif (strlen($query) == 64) {
        // Try transaction first, then block
        $tx = BATHRONExplorer::getTransaction($query);
        if ($tx) {
            $page = 'tx';
            $data = $tx;
        } else {
            $block = BATHRONExplorer::getBlock($query);
            if ($block) {
                $page = 'block';
                $data = $block;
            }
        }
    } elseif (isAddress($query)) {
        // Address query
        $addr = BATHRONExplorer::getAddress($query);
        if ($addr) {
            $page = 'address';
            $data = $addr;
        } else {
            $data['error'] = 'Invalid address: ' . htmlspecialchars($query);
        }
    } elseif (is_numeric($query) && $query > 0) {
        // Block height query - show block list from that height
        $page = 'blocks';
        $data = BATHRONExplorer::getBlockList((int)$query);
        $data['network'] = BATHRONExplorer::getNetworkInfo();
    } else {
        // Default: Dashboard
        $page = 'dashboard';
        $data['network'] = BATHRONExplorer::getNetworkInfo();
        $data['btcspv'] = BATHRONExplorer::getBtcSpvInfo();
        $data['burns'] = BATHRONExplorer::getBurnStats();
        // Burns come from RPC (burnclaimdb), no file reading
        // Get recent blocks for dashboard
        $blockData = BATHRONExplorer::getBlockList(null, 5);
        $data['recent_blocks'] = $blockData['blocks'];
    }
} catch (Exception $e) {
    $data['error'] = $e->getMessage();
}

// ============ HTML OUTPUT ============
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= COIN_NAME ?> <?= NETWORK ?> Explorer</title>
    <link rel="icon" type="image/png" href="favicon.png">
    <?php if ($page === 'dashboard'): ?>
    <meta http-equiv="refresh" content="<?= REFRESH_TIME ?>">
    <?php endif; ?>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --border: #30363d;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --accent: #7c3aed;
            --accent-light: #a78bfa;
            --success: #3fb950;
            --warning: #d29922;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        /* Header */
        header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            padding: 15px 0;
            margin-bottom: 30px;
        }

        header .container {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            font-size: 24px;
            font-weight: bold;
            color: var(--accent-light);
            text-decoration: none;
        }

        .logo span {
            color: var(--text-secondary);
            font-weight: normal;
            font-size: 14px;
            margin-left: 10px;
            padding: 3px 8px;
            background: var(--bg-tertiary);
            border-radius: 4px;
        }

        /* Search Container (centered below header) */
        .search-container {
            max-width: 700px;
            margin: 0 auto 20px auto;
            padding: 0 20px;
        }

        .search-box {
            display: flex;
            gap: 10px;
            width: 100%;
        }

        .search-box input {
            flex: 1;
            padding: 12px 18px;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 14px;
        }

        .search-box input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(124, 58, 237, 0.2);
        }

        .search-box input::placeholder {
            color: var(--text-secondary);
        }

        .search-box button {
            padding: 12px 24px;
            background: var(--accent);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 500;
            transition: background 0.2s;
        }

        .search-box button:hover {
            background: var(--accent-light);
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }

        .stat-card .label {
            color: var(--text-secondary);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 5px;
        }

        .stat-card .value {
            font-size: 24px;
            font-weight: bold;
            color: var(--text-primary);
        }

        .stat-card .value.accent {
            color: var(--accent-light);
        }

        /* Tables */
        .card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 20px;
        }

        .card-header {
            padding: 15px 20px;
            border-bottom: 1px solid var(--border);
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            padding: 12px 20px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        th {
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 500;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        tr:hover {
            background: var(--bg-tertiary);
        }

        tr:last-child td {
            border-bottom: none;
        }

        a {
            color: var(--accent-light);
            text-decoration: none;
        }

        a:hover {
            text-decoration: underline;
        }

        .hash {
            font-family: 'SFMono-Regular', Consolas, monospace;
            font-size: 13px;
        }

        .truncate {
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        /* Block Details */
        .detail-grid {
            display: grid;
            grid-template-columns: 180px 1fr;
            gap: 1px;
            background: var(--border);
        }

        .detail-grid > div {
            padding: 12px 20px;
            background: var(--bg-secondary);
        }

        .detail-grid .label {
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 500;
        }

        .detail-grid .value {
            word-break: break-all;
            font-family: 'SFMono-Regular', Consolas, monospace;
            font-size: 13px;
        }

        /* Pagination */
        .pagination {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-top: 20px;
        }

        .pagination a, .pagination span {
            padding: 10px 20px;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text-primary);
        }

        .pagination a:hover {
            background: var(--bg-tertiary);
            text-decoration: none;
        }

        .pagination span {
            color: var(--text-secondary);
        }

        /* TX Badge */
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 500;
        }

        .badge-coinbase {
            background: var(--success);
            color: white;
        }

        .badge-tx {
            background: var(--accent);
            color: white;
        }

        /* TX Type Badges (BP30) */
        .badge-standard {
            background: #6b7280;
            color: white;
        }

        .badge-proreg {
            background: #3b82f6;
            color: white;
        }

        .badge-proupserv, .badge-proupreg, .badge-prouprev {
            background: #6366f1;
            color: white;
        }

        .badge-lock {
            background: #10b981;
            color: white;
        }

        .badge-unlock {
            background: #f59e0b;
            color: white;
        }

        .badge-transfer {
            background: #8b5cf6;
            color: white;
        }

        .badge-save {
            background: #06b6d4;
            color: white;
        }

        .badge-unsave {
            background: #ec4899;
            color: white;
        }

        .badge-unknown {
            background: #374151;
            color: white;
        }

        /* Asset Type Indicators (M0/M1/Vault) */
        .asset-badge {
            display: inline-block;
            padding: 1px 6px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 600;
            margin-left: 5px;
        }

        .asset-m0 {
            background: rgba(59, 130, 246, 0.2);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }

        .asset-m1 {
            background: rgba(139, 92, 246, 0.2);
            color: #a78bfa;
            border: 1px solid rgba(139, 92, 246, 0.3);
        }

        .asset-vault {
            background: rgba(16, 185, 129, 0.2);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        /* TX Flow indicator */
        .tx-flow {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 500;
            margin-left: 8px;
        }

        .tx-flow-lock {
            background: rgba(16, 185, 129, 0.15);
            color: #10b981;
        }

        .tx-flow-unlock {
            background: rgba(245, 158, 11, 0.15);
            color: #f59e0b;
        }

        .tx-flow-transfer {
            background: rgba(139, 92, 246, 0.15);
            color: #8b5cf6;
        }

        /* Navigation Tabs */
        .nav-tabs {
            display: flex;
            gap: 5px;
        }

        .nav-tab {
            padding: 8px 16px;
            border-radius: 6px;
            color: var(--text-secondary);
            text-decoration: none;
            font-weight: 500;
            transition: all 0.2s;
        }

        .nav-tab:hover {
            background: var(--bg-tertiary);
            color: var(--text-primary);
            text-decoration: none;
        }

        .nav-tab.active {
            background: var(--accent);
            color: white;
        }

        /* Status badges */
        .status-enabled {
            color: var(--success);
            font-weight: 500;
        }

        .status-penalty {
            color: var(--warning);
            font-weight: 500;
        }

        .status-banned {
            color: #f85149;
            font-weight: 500;
        }

        .badge-online {
            background: var(--success);
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 500;
        }

        .badge-offline {
            background: var(--text-secondary);
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 500;
        }

        /* Sortable table */
        th.sortable {
            cursor: pointer;
            user-select: none;
        }

        th.sortable:hover {
            background: var(--bg-secondary);
        }

        th.sortable::after {
            content: ' ⇅';
            opacity: 0.3;
        }

        th.sortable.sort-asc::after {
            content: ' ↑';
            opacity: 1;
        }

        th.sortable.sort-desc::after {
            content: ' ↓';
            opacity: 1;
        }

        /* Footer */
        footer {
            margin-top: 50px;
            padding: 20px 0;
            border-top: 1px solid var(--border);
            text-align: center;
            color: var(--text-secondary);
            font-size: 14px;
        }

        /* ============ BP30 CANONICAL DASHBOARD ============ */

        /* Pyramid - Total Supply */
        .bp30-pyramid {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            border: 2px solid var(--accent);
            border-radius: 12px;
            padding: 30px;
            text-align: center;
            margin-bottom: 25px;
            position: relative;
            overflow: hidden;
        }

        .bp30-pyramid::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--accent), var(--success), var(--accent));
        }

        .bp30-pyramid .pyramid-label {
            color: var(--accent-light);
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 10px;
        }

        .bp30-pyramid .pyramid-value {
            font-size: 42px;
            font-weight: 700;
            color: var(--text-primary);
            font-family: 'SFMono-Regular', Consolas, monospace;
        }

        .bp30-pyramid .pyramid-unit {
            color: var(--accent-light);
            font-size: 20px;
            margin-left: 8px;
        }

        .bp30-pyramid .pyramid-status {
            margin-top: 12px;
            font-size: 13px;
            color: var(--success);
            font-weight: 500;
        }

        /* Monetary Table - 3 Columns */
        .bp30-monetary-table {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 0;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 25px;
        }

        .bp30-column {
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
        }

        .bp30-column:last-child {
            border-right: none;
        }

        .bp30-column-header {
            background: var(--bg-tertiary);
            padding: 15px 20px;
            text-align: center;
            border-bottom: 1px solid var(--border);
        }

        .bp30-column-header .title {
            font-size: 14px;
            font-weight: 700;
            color: var(--text-primary);
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .bp30-column-header .subtitle {
            font-size: 11px;
            color: var(--text-secondary);
            margin-top: 3px;
        }

        /* Column colors */
        .bp30-column.btc .bp30-column-header { border-top: 3px solid #f7931a; }
        .bp30-column.m0 .bp30-column-header { border-top: 3px solid #10b981; }
        .bp30-column.m1 .bp30-column-header { border-top: 3px solid #8b5cf6; }

        .bp30-column-body {
            padding: 15px 20px;
            flex: 1;
        }

        .bp30-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px dashed var(--border);
        }

        .bp30-item:last-child {
            border-bottom: none;
        }

        a.bp30-item:hover {
            background: var(--bg-hover, rgba(255,255,255,0.05));
            border-radius: 4px;
            margin: 0 -8px;
            padding: 10px 8px;
        }

        .bp30-item .item-label {
            font-size: 12px;
            color: var(--text-secondary);
            font-family: 'SFMono-Regular', Consolas, monospace;
        }

        .bp30-item .item-value {
            font-size: 14px;
            font-weight: 600;
            color: var(--text-primary);
            font-family: 'SFMono-Regular', Consolas, monospace;
        }

        .bp30-item.outside-invariant {
            opacity: 0.6;
            font-style: italic;
        }

        .bp30-item.outside-invariant .item-label::after {
            content: ' *';
            color: var(--text-secondary);
        }

        .bp30-separator {
            border-top: 2px solid var(--border);
            margin: 10px 0;
        }

        .bp30-column-total {
            background: var(--bg-tertiary);
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-top: 2px solid var(--border);
        }

        .bp30-column-total .total-label {
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-secondary);
        }

        .bp30-column-total .total-value {
            font-size: 16px;
            font-weight: 700;
            font-family: 'SFMono-Regular', Consolas, monospace;
        }

        .bp30-column.m0 .total-value { color: #10b981; }
        .bp30-column.btc .total-value { color: #f7931a; }
        .bp30-column.m1 .total-value { color: #8b5cf6; }

        /* Invariant A6 Box */
        .bp30-invariant {
            background: var(--bg-secondary);
            border: 2px solid var(--success);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
            text-align: center;
        }

        .bp30-invariant.broken {
            border-color: #f85149;
        }

        .bp30-invariant .invariant-header {
            font-size: 14px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 15px;
        }

        .bp30-invariant .invariant-header .icon {
            font-size: 18px;
            margin-right: 8px;
        }

        .bp30-invariant .invariant-equation {
            font-family: 'SFMono-Regular', Consolas, monospace;
            font-size: 15px;
            color: var(--text-secondary);
            margin-bottom: 12px;
            padding: 12px;
            background: var(--bg-tertiary);
            border-radius: 8px;
        }

        .bp30-invariant .invariant-values {
            font-family: 'SFMono-Regular', Consolas, monospace;
            font-size: 16px;
            color: var(--text-primary);
            margin-bottom: 8px;
        }

        .bp30-invariant .invariant-sum {
            font-family: 'SFMono-Regular', Consolas, monospace;
            font-size: 20px;
            font-weight: 700;
            margin-bottom: 15px;
        }

        .bp30-invariant .invariant-sum .left { color: #10b981; }
        .bp30-invariant .invariant-sum .equals { color: var(--success); margin: 0 15px; }
        .bp30-invariant .invariant-sum .right { color: #8b5cf6; }

        .bp30-invariant.broken .invariant-sum .equals { color: #f85149; }

        .bp30-invariant .invariant-status {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 20px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 600;
        }

        .bp30-invariant .invariant-status.ok {
            background: rgba(16, 185, 129, 0.15);
            color: var(--success);
        }

        .bp30-invariant .invariant-status.broken {
            background: rgba(248, 81, 73, 0.15);
            color: #f85149;
        }

        /* Axioms Table */
        .bp30-axioms {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 25px;
        }

        .bp30-axioms .axioms-header {
            background: var(--bg-tertiary);
            padding: 12px 20px;
            font-size: 13px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: 1px solid var(--border);
        }

        .bp30-axiom-row {
            display: grid;
            grid-template-columns: 50px 1fr 60px;
            padding: 10px 20px;
            border-bottom: 1px solid var(--border);
            font-size: 13px;
            align-items: center;
        }

        .bp30-axiom-row:last-child {
            border-bottom: none;
        }

        .bp30-axiom-row:hover {
            background: var(--bg-tertiary);
        }

        .bp30-axiom-row .axiom-id {
            font-weight: 700;
            color: var(--accent-light);
        }

        .bp30-axiom-row .axiom-text {
            font-family: 'SFMono-Regular', Consolas, monospace;
            color: var(--text-secondary);
        }

        .bp30-axiom-row .axiom-status {
            text-align: center;
            color: var(--success);
            font-size: 16px;
        }

        .bp30-axiom-row.highlight {
            background: rgba(16, 185, 129, 0.08);
        }

        .bp30-axiom-row.highlight .axiom-id {
            color: var(--success);
        }

        /* Yield Panel */
        .bp30-yield {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 25px;
        }

        .bp30-yield .yield-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .bp30-yield .yield-title {
            font-size: 13px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .bp30-yield .yield-note {
            font-size: 11px;
            color: var(--warning);
            background: rgba(245, 158, 11, 0.1);
            padding: 4px 10px;
            border-radius: 4px;
        }

        .bp30-yield .yield-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
        }

        .bp30-yield .yield-item {
            text-align: center;
        }

        .bp30-yield .yield-item .value {
            font-size: 22px;
            font-weight: 700;
            color: var(--text-primary);
            font-family: 'SFMono-Regular', Consolas, monospace;
        }

        .bp30-yield .yield-item .label {
            font-size: 11px;
            color: var(--text-secondary);
            margin-top: 5px;
        }

        /* ========== BTC SPV BRIDGE PANEL ========== */
        .btc-bridge-panel .btc-bridge-flow {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0;
            margin: 20px 0;
            padding: 15px;
            background: var(--bg-primary);
            border-radius: 10px;
        }

        .btc-bridge-panel .bridge-block {
            background: var(--bg-secondary);
            border: 2px solid var(--border);
            border-radius: 10px;
            padding: 15px 25px;
            text-align: center;
            min-width: 160px;
            position: relative;
        }

        .btc-bridge-panel .bridge-block.btc-source {
            border-color: #f7931a;
            background: linear-gradient(135deg, rgba(247, 147, 26, 0.05) 0%, transparent 100%);
        }

        .btc-bridge-panel .bridge-block.bathron-chain {
            border-color: #10b981;
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.05) 0%, transparent 100%);
        }

        .btc-bridge-panel .bridge-block-header {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            margin-bottom: 8px;
        }

        .btc-bridge-panel .bridge-icon {
            font-size: 14px;
        }

        .btc-bridge-panel .bridge-label {
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
        }

        .btc-bridge-panel .bridge-value {
            font-size: 24px;
            font-weight: 700;
            color: var(--text-primary);
            font-family: 'SFMono-Regular', Consolas, monospace;
        }

        .btc-bridge-panel .bridge-sublabel {
            font-size: 10px;
            color: var(--text-muted);
            margin-top: 4px;
        }

        .btc-bridge-panel .bridge-status {
            font-size: 11px;
            font-weight: 500;
            margin-top: 8px;
            padding: 3px 8px;
            border-radius: 4px;
        }

        .btc-bridge-panel .status-ok {
            color: var(--success);
            background: rgba(16, 185, 129, 0.1);
        }

        .btc-bridge-panel .status-warn {
            color: var(--warning);
            background: rgba(245, 158, 11, 0.1);
        }

        .btc-bridge-panel .status-err {
            color: var(--danger);
            background: rgba(239, 68, 68, 0.1);
        }

        /* Bridge Arrow */
        .btc-bridge-panel .bridge-arrow {
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 0 15px;
            position: relative;
        }

        .btc-bridge-panel .arrow-line {
            width: 40px;
            height: 2px;
            background: linear-gradient(90deg, #f7931a, #10b981);
        }

        .btc-bridge-panel .arrow-head {
            color: #10b981;
            font-size: 12px;
            margin-left: 2px;
            position: absolute;
            right: 8px;
            top: 50%;
            transform: translateY(-50%);
        }

        .btc-bridge-panel .arrow-delta {
            font-size: 10px;
            font-weight: 600;
            color: var(--warning);
            background: rgba(245, 158, 11, 0.15);
            padding: 2px 6px;
            border-radius: 3px;
            margin-top: 6px;
        }

        /* Bridge Status Bar */
        .btc-bridge-panel .bridge-status-bar {
            display: flex;
            justify-content: space-around;
            padding: 12px 0;
            border-top: 1px solid var(--border);
            margin-top: 15px;
        }

        .btc-bridge-panel .status-item {
            text-align: center;
        }

        .btc-bridge-panel .status-label {
            display: block;
            font-size: 10px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }

        .btc-bridge-panel .status-value {
            font-size: 13px;
            font-weight: 600;
            font-family: 'SFMono-Regular', Consolas, monospace;
        }

        .btc-bridge-panel .val-ok { color: var(--success); }
        .btc-bridge-panel .val-warn { color: var(--warning); }
        .btc-bridge-panel .val-err { color: var(--danger); }
        .btc-bridge-panel .val-neutral { color: var(--text-secondary); }

        /* Mobile responsive */
        @media (max-width: 600px) {
            .btc-bridge-panel .btc-bridge-flow {
                flex-direction: column;
                gap: 10px;
            }
            .btc-bridge-panel .bridge-arrow {
                transform: rotate(90deg);
                padding: 10px 0;
            }
            .btc-bridge-panel .bridge-status-bar {
                flex-wrap: wrap;
                gap: 15px;
            }
        }

        /* Quick Stats Row */
        .bp30-quick-stats {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
            margin-bottom: 25px;
        }

        .bp30-quick-stat {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 15px;
            text-align: center;
        }

        .bp30-quick-stat .label {
            font-size: 11px;
            color: var(--text-secondary);
            text-transform: uppercase;
            margin-bottom: 5px;
        }

        .bp30-quick-stat .value {
            font-size: 18px;
            font-weight: 700;
            color: var(--text-primary);
        }

        .bp30-quick-stat .value.accent {
            color: var(--accent-light);
        }

        /* Responsive */
        @media (max-width: 768px) {
            header .container {
                flex-direction: column;
                gap: 15px;
            }

            .search-box input {
                width: 250px;
            }

            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .detail-grid {
                grid-template-columns: 1fr;
            }

            .bp30-monetary-table {
                grid-template-columns: 1fr;
            }

            .bp30-column {
                border-right: none;
                border-bottom: 1px solid var(--border);
            }

            .bp30-column:last-child {
                border-bottom: none;
            }

            .bp30-quick-stats {
                grid-template-columns: repeat(2, 1fr);
            }

            .bp30-yield .yield-grid {
                grid-template-columns: 1fr;
                gap: 15px;
            }

            .bp30-axiom-row {
                grid-template-columns: 40px 1fr 40px;
                font-size: 11px;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <a href="./" class="logo">
                BATHRON <span><?= NETWORK ?></span>
            </a>
            <nav class="nav-tabs">
                <a href="./" class="nav-tab <?= $page === 'dashboard' ? 'active' : '' ?>">Dashboard</a>
                <a href="?tab=btc" class="nav-tab <?= $page === 'btc' ? 'active' : '' ?>">BTC</a>
                <a href="?tab=blocks" class="nav-tab <?= $page === 'blocks' ? 'active' : '' ?>">Blocks</a>
                <a href="?tab=operators" class="nav-tab <?= $page === 'operators' ? 'active' : '' ?>">Operators</a>
                <a href="?tab=masternodes" class="nav-tab <?= $page === 'masternodes' ? 'active' : '' ?>">Nodes</a>
                <a href="?tab=join" class="nav-tab <?= $page === 'join' ? 'active' : '' ?>" style="color: var(--accent);">Join</a>
                <a href="https://dex.example/" class="nav-tab" target="_blank" style="color: var(--accent);">DEX ↗</a>
            </nav>
        </div>
    </header>

    <!-- Search Bar (centered below header) -->
    <div class="search-container">
        <form class="search-box" method="get">
            <input type="text" name="q" placeholder="Search block hash, height, transaction, or address..." value="<?= htmlspecialchars($query) ?>">
            <button type="submit">Search</button>
        </form>
    </div>

    <main class="container">
        <?php if (isset($data['error'])): ?>
            <div class="card">
                <div class="card-header">Error</div>
                <div style="padding: 20px; color: #f85149;">
                    <?= htmlspecialchars($data['error']) ?>
                </div>
            </div>
        <?php elseif ($page === 'dashboard'): ?>
            <!-- ============ BP30 CANONICAL DASHBOARD ============ -->
            <?php
            // Calculate derived values for BP30 dashboard
            $m0Total = $data['network']['m0_total'];
            $m0VaultedActive = $data['network']['m0_vaulted_active'];
            $m0MnCollateral = $data['network']['m0_mn_collateral'];
            $m0Shield = $data['network']['m0_shield'];
            $m1Supply = $data['network']['m1_supply'];
            $invariantsOk = $data['network']['invariants_ok'];
            $stateAvailable = $data['network']['state_available'];
            $feesRecycled = $data['network']['fees_recycled'] ?? 0;

            // M0_FREE — valeur AUTORITAIRE du nœud (getexplorerdata supply.m0_free →
            // m0_circulating). Pas de re-dérivation UI : dupliquer la formule ici
            // créait un risque de drift silencieux si le modèle daemon évolue.
            $m0Free = $data['network']['m0_circulating'];
            ?>

            <!-- 1️⃣ PYRAMID - TOTAL SUPPLY -->
            <div class="bp30-pyramid">
                <div class="pyramid-label">Total Supply (M0)</div>
                <div class="pyramid-value">
                    <?= formatSats($m0Total, false) ?><span class="pyramid-unit">M0</span>
                </div>
                <div class="pyramid-status">CONSERVED (Consensus Enforced)</div>
            </div>

            <!-- Quick Stats Row -->
            <div class="bp30-quick-stats">
                <div class="bp30-quick-stat">
                    <div class="label">Block</div>
                    <div class="value accent"><?= number_format($data['network']['blocks']) ?></div>
                </div>
                <div class="bp30-quick-stat">
                    <div class="label">Finality</div>
                    <div class="value" style="color: <?= $data['network']['finality_status'] === 'healthy' ? 'var(--success)' : 'var(--warning)' ?>;">
                        <?= strtoupper($data['network']['finality_status']) ?>
                    </div>
                </div>
                <div class="bp30-quick-stat">
                    <div class="label" title="MNs valides / enregistrées dans la liste déterministe (état consensus — PAS une mesure de vivacité : une MN silencieuse reste 'valide' tant qu'elle n'est pas PoSe-ban)">MNs (reg.)</div>
                    <div class="value"><?= $data['network']['masternodes_active'] ?>/<?= $data['network']['masternodes_total'] ?></div>
                </div>
                <div class="bp30-quick-stat">
                    <div class="label">Operators</div>
                    <div class="value"><?= $data['network']['operators_count'] ?></div>
                </div>
                <?php $dashFinPart = BATHRONExplorer::getFinalityParticipation(32); ?>
                <div class="bp30-quick-stat">
                    <div class="label" title="Opérateurs ayant signé la finalité dans les 32 derniers blocs finalisés — la mesure de VIVACITÉ réelle (source : store de finalité consensus)">Signers (32 blk)</div>
                    <div class="value">
                        <?php if (($dashFinPart['blocks_with_finality'] ?? 0) > 0):
                            $liveSigners = 0;
                            foreach ($dashFinPart['operators'] as $opk => $st) { if ($st['signed'] > 0) $liveSigners++; }
                        ?>
                            <?= $liveSigners ?>/<?= count($dashFinPart['operators']) ?>
                        <?php else: ?>
                            <span style="color: var(--text-secondary);">n/a</span>
                        <?php endif; ?>
                    </div>
                </div>
                <div class="bp30-quick-stat">
                    <div class="label">Mempool</div>
                    <div class="value"><?= $data['network']['mempool_size'] ?> tx</div>
                </div>
            </div>

            <!-- ⚡ FINALITY (délai mesuré par le nœud en ms via getfinalitystatus + quorum) -->
            <?php
            $ft = BATHRONExplorer::getFinalityTrack();
            $ftBlocks = $ft['blocks'] ?? [];
            $ftDelays = array_map(fn($b) => (int)($b['delay_ms'] ?? 0), $ftBlocks);
            $ftN = count($ftDelays);
            $ftMax = $ftN ? max($ftDelays) : 0;
            $ftAvgNode = (int)($ft['avg_delay_ms'] ?? 0);   // moyenne autoritaire du nœud
            $ftLastNode = (int)($ft['last_delay_ms'] ?? 0);
            $qSize = (int)($ft['quorum_size'] ?? 0);
            $qThreshold = (int)($ft['quorum_threshold'] ?? 0);
            $ftStatusColor = ($ft['status'] === 'healthy') ? 'var(--success)' : 'var(--warning)';
            $fmtMs = fn($ms) => $ms >= 1000 ? round($ms / 1000, 2) . 's' : ((int)$ms) . 'ms';
            ?>
            <div class="card" style="margin-bottom: 25px;">
                <div class="card-header">
                    <span>⚡ Finality — produced → finalized</span>
                    <span style="font-weight: normal; font-size: 13px; color: var(--text-secondary);">
                        lag <span style="color: <?= $ft['lag'] > 0 ? 'var(--warning)' : 'var(--success)' ?>; font-weight: 600;"><?= (int)$ft['lag'] ?></span>
                        · <span style="color: <?= $ftStatusColor ?>;"><?= strtoupper(htmlspecialchars($ft['status'])) ?></span>
                        <?php if ($qSize > 0): ?> · quorum <span style="color: var(--accent-light); font-weight: 600;"><?= $qThreshold ?>/<?= $qSize ?></span><?php endif; ?>
                    </span>
                </div>
                <div style="padding: 18px 20px;">
                    <!-- agrégats : le nœud mesure le délai en ms (getfinalitystatus) -->
                    <div style="display: flex; gap: 28px; margin-bottom: 18px; flex-wrap: wrap;">
                        <div>
                            <div style="font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px;">Délai moyen <span style="text-transform: none;">(nœud)</span></div>
                            <div style="font-size: 24px; font-weight: 700; color: var(--success);"><?= $fmtMs($ftAvgNode) ?></div>
                        </div>
                        <div>
                            <div style="font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px;">Dernier</div>
                            <div style="font-size: 24px; font-weight: 700;"><?= $fmtMs($ftLastNode) ?></div>
                        </div>
                        <div>
                            <div style="font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px;">Max observé</div>
                            <div style="font-size: 24px; font-weight: 700; color: <?= $ftMax > 1000 ? 'var(--warning)' : 'var(--text-primary)' ?>;"><?= $ftN ? $fmtMs($ftMax) : '—' ?></div>
                        </div>
                        <div>
                            <div style="font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px;">Échantillons</div>
                            <div style="font-size: 24px; font-weight: 700; color: var(--text-secondary);"><?= $ftN ?></div>
                        </div>
                    </div>
                    <?php if ($ftN === 0): ?>
                        <div style="color: var(--text-secondary); font-size: 13px;">
                            Lane en cours de collecte… (un échantillon par bloc finalisé). Les agrégats ci-dessus viennent directement du nœud.
                        </div>
                    <?php else: ?>
                        <!-- lane visuelle : derniers blocs finalisés (délai en ms) -->
                        <div style="display: flex; gap: 4px; align-items: flex-end; overflow-x: auto; padding-bottom: 6px;">
                            <?php foreach (array_slice($ftBlocks, -28) as $b):
                                $d = (int)($b['delay_ms'] ?? 0);
                                $col = $d <= 300 ? 'var(--success)' : ($d <= 1000 ? 'var(--warning)' : 'var(--danger, #f85149)');
                                $barH = min(64, 8 + (int)($d / 20));
                                $prod = $b['producer'] ?? '';
                                $prodShort = $prod !== '' ? substr($prod, 0, 10) . '…' : '?';
                            ?>
                                <div style="min-width: 32px; text-align: center; flex-shrink: 0;"
                                     title="bloc #<?= (int)$b['h'] ?> · producteur <?= htmlspecialchars($prodShort) ?> · finalisé en <?= $d ?>ms">
                                    <div style="height: <?= $barH ?>px; background: <?= $col ?>; border-radius: 3px 3px 0 0;"></div>
                                    <div style="font-size: 9px; color: var(--text-secondary); margin-top: 3px;"><?= $d ?></div>
                                    <div style="font-size: 8px; color: var(--text-muted, var(--text-secondary));">#<?= (int)$b['h'] ?></div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                        <div style="font-size: 11px; color: var(--text-secondary); margin-top: 8px;">
                            Délai (ms) = production → finalisation, mesuré par le nœud (<code>getfinalitystatus</code>)<?php if ($qSize > 0): ?> · quorum <?= $qThreshold ?>/<?= $qSize ?> opérateurs<?php endif; ?> · survole une barre pour le producteur du bloc.
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- 2️⃣ MONETARY TABLE - 3 COLUMNS -->
            <?php
            // Use RPC data ONLY (burnclaimdb is the single source of truth)
            // A5: btc_burned_sats == M0_total by construction
            $btcTransferred = $data['burns']['btc_transferred'] ?? 0;
            $txBurnCount = $data['burns']['total_burns'] ?? 0;
            ?>
            <div class="bp30-monetary-table">
                <!-- BTC Column -->
                <div class="bp30-column btc">
                    <div class="bp30-column-header">
                        <div class="title">Total BTC</div>
                        <div class="subtitle">Transferred</div>
                    </div>
                    <div class="bp30-column-body">
                        <a href="?tab=btc" class="bp30-item" style="text-decoration: none; color: inherit;">
                            <span class="item-label">BTC_BURNED_SATS</span>
                            <span class="item-value"><?= formatSats($btcTransferred, false) ?></span>
                        </a>
                        <a href="?tab=btc" class="bp30-item" style="text-decoration: none; color: inherit;">
                            <span class="item-label">TX_BURN_COUNT</span>
                            <span class="item-value"><?= $txBurnCount ?></span>
                        </a>
                        <div style="flex: 1;"></div>
                        <a href="?tab=btc" style="font-size: 11px; color: var(--text-secondary); padding: 10px 0; text-decoration: none; display: block;">
                            BTC burned on Bitcoin chain →
                        </a>
                    </div>
                    <div class="bp30-column-total">
                        <span class="total-label">Total (sats)</span>
                        <span class="total-value"><?= formatSats($btcTransferred, false) ?></span>
                    </div>
                </div>

                <!-- M0 Column -->
                <div class="bp30-column m0">
                    <div class="bp30-column-header">
                        <div class="title">Total M0</div>
                        <div class="subtitle">Base Money</div>
                    </div>
                    <div class="bp30-column-body">
                        <div class="bp30-item">
                            <span class="item-label">M0_FREE</span>
                            <span class="item-value"><?= formatSats($m0Free, false) ?></span>
                        </div>
                        <div class="bp30-item">
                            <span class="item-label">M0_VAULTED</span>
                            <span class="item-value"><?= formatSats($m0VaultedActive, false) ?></span>
                        </div>
                        <div class="bp30-separator"></div>
                        <div class="bp30-item">
                            <span class="item-label">M0_MN_COLLATERAL</span>
                            <span class="item-value"><?= formatSats($m0MnCollateral, false) ?></span>
                        </div>
                        <div class="bp30-item outside-invariant">
                            <span class="item-label">M0_SHIELDED</span>
                            <span class="item-value"><?= formatSats($m0Shield, false) ?></span>
                        </div>
                    </div>
                    <div class="bp30-column-total">
                        <span class="total-label">Total</span>
                        <span class="total-value"><?= formatSats($m0Total, false) ?></span>
                    </div>
                </div>

                <!-- M1 Column -->
                <div class="bp30-column m1">
                    <div class="bp30-column-header">
                        <div class="title">Total M1</div>
                        <div class="subtitle">Receipt Tokens</div>
                    </div>
                    <div class="bp30-column-body">
                        <div class="bp30-item" style="visibility: hidden;">
                            <span class="item-label">&nbsp;</span>
                            <span class="item-value">&nbsp;</span>
                        </div>
                        <div class="bp30-item">
                            <span class="item-label">M1_SUPPLY</span>
                            <span class="item-value"><?= formatSats($m1Supply, false) ?></span>
                        </div>
                        <div style="flex: 1;"></div>
                        <div style="font-size: 11px; color: var(--text-secondary); padding: 10px 0;">
                            Transferable claim on vaulted M0
                        </div>
                    </div>
                    <div class="bp30-column-total">
                        <span class="total-label">Total</span>
                        <span class="total-value"><?= formatSats($m1Supply, false) ?></span>
                    </div>
                </div>
            </div>

            <!-- 3️⃣ BTC HEADERS PANEL -->
            <?php
            $btcspv = $data['btcspv'] ?? [];
            $spvTipHeight = $btcspv['spv_tip_height'] ?? 0;
            $chainTipHeight = $btcspv['chain_tip_height'] ?? 0;
            $headersAhead = $btcspv['headers_ahead'] ?? 0;
            $canPublish = $btcspv['can_publish'] ?? false;
            $spvSynced = $btcspv['spv_synced'] ?? false;
            $spvReady = $btcspv['spv_ready'] ?? false;
            $minHeight = $btcspv['min_supported_height'] ?? 0;
            $network = $btcspv['network'] ?? 'signet';
            $dbInit = $btcspv['db_initialized'] ?? false;
            ?>
            <div class="bp30-yield btc-bridge-panel">
                <div class="yield-header">
                    <span class="yield-title">₿ BTC Headers</span>
                    <span class="yield-note"><?= $network ?></span>
                </div>

                <!-- Bridge Flow: BTC SPV → BATHRON Chain -->
                <div class="btc-bridge-flow">
                    <!-- Block 1: BTC SPV (headers from BTC network) -->
                    <div class="bridge-block btc-source">
                        <div class="bridge-block-header">
                            <span class="bridge-icon">₿</span>
                            <span class="bridge-label">BTC SPV</span>
                        </div>
                        <div class="bridge-value"><?= number_format($spvTipHeight) ?></div>
                        <div class="bridge-sublabel">Latest BTC Header</div>
                        <div class="bridge-status <?= $spvSynced ? 'status-ok' : 'status-warn' ?>">
                            <?= $spvSynced ? '● Synced' : '○ Syncing' ?>
                        </div>
                    </div>

                    <!-- Arrow 1 -->
                    <div class="bridge-arrow">
                        <span class="arrow-line"></span>
                        <span class="arrow-head">▶</span>
                        <?php if ($headersAhead > 0): ?>
                        <span class="arrow-delta">+<?= $headersAhead ?></span>
                        <?php endif; ?>
                    </div>

                    <!-- Block 2: btcheadersdb (consensus on BATHRON) -->
                    <div class="bridge-block bathron-chain">
                        <div class="bridge-block-header">
                            <span class="bridge-icon">⛓</span>
                            <span class="bridge-label">BATHRON Chain</span>
                        </div>
                        <div class="bridge-value"><?= number_format($chainTipHeight) ?></div>
                        <div class="bridge-sublabel">Headers on-chain</div>
                        <div class="bridge-status <?= $dbInit ? 'status-ok' : 'status-err' ?>">
                            <?= $dbInit ? '● Consensus' : '○ Not init' ?>
                        </div>
                    </div>
                </div>

                <!-- Bridge Status Bar -->
                <div class="bridge-status-bar">
                    <div class="status-item">
                        <span class="status-label">Sync</span>
                        <span class="status-value <?= ($headersAhead == 0) ? 'val-ok' : 'val-warn' ?>">
                            <?= ($headersAhead == 0) ? 'Synced' : $headersAhead . ' behind' ?>
                        </span>
                    </div>
                    <div class="status-item">
                        <span class="status-label">Autoclaim M0</span>
                        <span class="status-value <?= $spvReady ? 'val-ok' : 'val-err' ?>">
                            <?= $spvReady ? 'Active' : 'Inactive' ?>
                        </span>
                    </div>
                </div>
            </div>

            <!-- 4️⃣ INVARIANT A5 - MONETARY CONSERVATION -->
            <?php $a5Ok = $data['network']['a5_ok'] ?? ($btcTransferred > 0 && $btcTransferred == $m0Total); ?>
            <div class="bp30-invariant <?= $a5Ok ? '' : 'broken' ?>">
                <div class="invariant-header">
                    <span class="icon">&#9878;</span>INVARIANT A5 — MONETARY CONSERVATION
                </div>
                <div class="invariant-equation">
                    BTC_BURNED = M0_TOTAL (all M0 from BTC burns only)
                </div>
                <div class="invariant-sum">
                    <span class="left"><?= formatSats($btcTransferred, false) ?></span>
                    <span class="equals"><?= $a5Ok ? '=' : '&ne;' ?></span>
                    <span class="right"><?= formatSats($m0Total, false) ?></span>
                </div>
                <?php if (!$a5Ok && $feesRecycled > 0): ?>
                <div style="font-size: 11px; color: var(--text-secondary); padding: 4px 0;">
                    Delta: <?= formatSats(abs($m0Total - $btcTransferred), false) ?> sats (fees recycled in coinbase)
                </div>
                <?php endif; ?>
                <div class="invariant-status <?= $a5Ok ? 'ok' : 'broken' ?>">
                    <?= $a5Ok ? '&#10004; VERIFIED' : '&#10006; MISMATCH' ?>
                </div>
            </div>

            <!-- 6️⃣ INVARIANT A6 - SETTLEMENT BACKING -->
            <?php $a6Ok = $data['network']['a6_ok'] ?? ($m0VaultedActive == $m1Supply); ?>
            <div class="bp30-invariant <?= $a6Ok ? '' : 'broken' ?>">
                <div class="invariant-header">
                    <span class="icon">&#9878;</span>INVARIANT A6 — SETTLEMENT BACKING
                </div>
                <div class="invariant-equation">
                    M0_VAULTED = M1_SUPPLY
                </div>
                <div class="invariant-sum">
                    <span class="left"><?= formatSats($m0VaultedActive, false) ?></span>
                    <span class="equals"><?= $a6Ok ? '=' : '!=' ?></span>
                    <span class="right"><?= formatSats($m1Supply, false) ?></span>
                </div>
                <div class="invariant-status <?= $a6Ok ? 'ok' : 'broken' ?>">
                    <?= $a6Ok ? '&#10004; VERIFIED' : '&#10006; BROKEN' ?>
                </div>
            </div>

            <!-- Recent Blocks Preview -->
            <div class="card">
                <div class="card-header">
                    <span>Recent Blocks</span>
                    <a href="?tab=blocks" style="font-weight: normal; font-size: 14px;">View all &rarr;</a>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Height</th>
                            <th>Hash</th>
                            <th>Time</th>
                            <th>Txs</th>
                            <th>Size</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($data['recent_blocks'] as $block): ?>
                        <tr>
                            <td><a href="?q=<?= $block['hash'] ?>"><?= number_format($block['height']) ?></a></td>
                            <td class="hash truncate"><a href="?q=<?= $block['hash'] ?>"><?= substr($block['hash'], 0, 16) ?>...</a></td>
                            <td><?= date('H:i:s', $block['time']) ?></td>
                            <td><?= $block['txcount'] ?></td>
                            <td><?= number_format($block['size']) ?> B</td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

        <?php elseif ($page === 'blocks'): ?>
            <!-- BLOCKS LIST -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="label">Block Height</div>
                    <div class="value accent"><?= number_format($data['network']['blocks']) ?></div>
                </div>
                <div class="stat-card">
                    <div class="label">Last Finalized</div>
                    <div class="value"><?= number_format($data['network']['last_finalized']) ?></div>
                </div>
                <div class="stat-card">
                    <div class="label">Finality Status</div>
                    <div class="value" style="color: <?= $data['network']['finality_status'] === 'healthy' ? 'var(--success)' : 'var(--warning)' ?>;">
                        <?= strtoupper($data['network']['finality_status']) ?>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <span>Blocks</span>
                    <span style="color: var(--text-secondary); font-weight: normal; font-size: 14px;">
                        Auto-refresh: <?= REFRESH_TIME ?>s
                    </span>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Height</th>
                            <th>Hash</th>
                            <th>Time</th>
                            <th>Txs</th>
                            <th>Size</th>
                            <th>Value</th>
                            <th>Final</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($data['blocks'] as $block): ?>
                        <tr>
                            <td><a href="?q=<?= $block['hash'] ?>"><?= number_format($block['height']) ?></a></td>
                            <td class="hash truncate"><a href="?q=<?= $block['hash'] ?>"><?= substr($block['hash'], 0, 16) ?>...</a></td>
                            <td><?= date('Y-m-d H:i:s', $block['time']) ?></td>
                            <td><?= $block['txcount'] ?></td>
                            <td><?= number_format($block['size']) ?> B</td>
                            <td><?= formatSats($block['total_out']) ?></td>
                            <td style="color: <?= $block['height'] <= $data['network']['last_finalized'] ? 'var(--success)' : 'var(--text-secondary)' ?>;">
                                <?= $block['height'] <= $data['network']['last_finalized'] ? '✓' : '' ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            <div class="pagination">
                <?php if ($data['start'] < $data['height']): ?>
                    <a href="?tab=blocks&offset=<?= min($data['start'] + BLOCKS_PER_LIST, $data['height']) ?>">&larr; Newer</a>
                <?php else: ?>
                    <span>&larr; Newer</span>
                <?php endif; ?>

                <span>Block <?= number_format($data['start']) ?></span>

                <?php if ($data['start'] - BLOCKS_PER_LIST >= 0): ?>
                    <a href="?tab=blocks&offset=<?= $data['start'] - BLOCKS_PER_LIST ?>">Older &rarr;</a>
                <?php else: ?>
                    <span>Older &rarr;</span>
                <?php endif; ?>
            </div>

        <?php elseif ($page === 'block'): ?>
            <!-- Block Details -->
            <div class="card">
                <div class="card-header">Block #<?= number_format($data['height']) ?></div>
                <div class="detail-grid">
                    <div class="label">Hash</div>
                    <div class="value"><?= $data['hash'] ?></div>

                    <div class="label">Confirmations</div>
                    <div class="value"><?= number_format($data['confirmations']) ?></div>

                    <div class="label">Timestamp</div>
                    <div class="value"><?= date('Y-m-d H:i:s', $data['time']) ?> UTC</div>

                    <div class="label">Size</div>
                    <div class="value"><?= number_format($data['size']) ?> bytes</div>

                    <div class="label">Difficulty</div>
                    <div class="value"><?= $data['difficulty'] ?></div>

                    <div class="label">Merkle Root</div>
                    <div class="value"><?= $data['merkleroot'] ?></div>

                    <div class="label">Nonce</div>
                    <div class="value"><?= $data['nonce'] ?></div>

                    <div class="label">Bits</div>
                    <div class="value"><?= $data['bits'] ?></div>

                    <?php if ($data['prevhash']): ?>
                    <div class="label">Previous Block</div>
                    <div class="value"><a href="?<?= $data['prevhash'] ?>"><?= $data['prevhash'] ?></a></div>
                    <?php endif; ?>

                    <?php if ($data['nexthash']): ?>
                    <div class="label">Next Block</div>
                    <div class="value"><a href="?<?= $data['nexthash'] ?>"><?= $data['nexthash'] ?></a></div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Transactions -->
            <div class="card">
                <div class="card-header">Transactions (<?= count($data['transactions']) ?>)</div>
                <?php foreach ($data['transactions'] as $tx): ?>
                <div style="border-bottom: 1px solid var(--border); padding: 15px 20px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <div>
                            <a href="?<?= $tx['txid'] ?>" class="hash" style="font-size: 14px;"><?= $tx['txid'] ?></a>
                            <span style="margin-left: 10px;"><?= getTxTypeBadge($tx['type'] ?? 0, $tx['coinbase']) ?></span>
                            <?php if (!empty($tx['tx_flow'])): ?>
                                <span class="tx-flow tx-flow-<?= strtolower(str_replace('TX_', '', $tx['type_name'] ?? 'standard')) ?>"><?= $tx['tx_flow'] ?></span>
                            <?php endif; ?>
                        </div>
                        <div style="color: var(--text-secondary); font-size: 13px;">
                            <?= formatSats($tx['total']) ?>
                        </div>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr auto 1fr; gap: 10px; font-size: 13px;">
                        <!-- Inputs -->
                        <div>
                            <?php foreach ($tx['inputs'] as $input): ?>
                                <?php if (isset($input['coinbase'])): ?>
                                    <div style="padding: 5px; background: var(--bg-tertiary); border-radius: 4px; margin-bottom: 5px;">
                                        <span class="badge badge-coinbase">Coinbase</span>
                                    </div>
                                <?php else: ?>
                                    <div style="padding: 5px; background: var(--bg-tertiary); border-radius: 4px; margin-bottom: 5px;">
                                        <div class="hash truncate" style="max-width: 250px;"><?= substr($input['txid'], 0, 16) ?>...:<?= $input['vout'] ?></div>
                                    </div>
                                <?php endif; ?>
                            <?php endforeach; ?>
                        </div>
                        <!-- Arrow -->
                        <div style="display: flex; align-items: center; color: var(--accent-light); font-size: 20px;">
                            &rarr;
                        </div>
                        <!-- Outputs with asset badges -->
                        <div>
                            <?php foreach ($tx['outputs'] as $output): ?>
                                <div style="padding: 5px; background: var(--bg-tertiary); border-radius: 4px; margin-bottom: 5px; display: flex; justify-content: space-between; align-items: center;">
                                    <div style="display: flex; align-items: center;">
                                        <?php if (isAddress($output['address'])): ?>
                                            <a href="?<?= $output['address'] ?>" class="hash truncate" style="max-width: 160px;"><?= $output['address'] ?></a>
                                        <?php else: ?>
                                            <span class="hash truncate" style="max-width: 160px;"><?= $output['address'] ?></span>
                                        <?php endif; ?>
                                    </div>
                                    <div style="display: flex; align-items: center; gap: 8px;">
                                        <span style="color: var(--success);"><?= formatSats($output['value'], false) ?></span>
                                        <span class="asset-badge <?= $output['asset_class'] ?? 'asset-m0' ?>"><?= $output['asset'] ?? 'M0' ?></span>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>

            <div class="pagination">
                <a href="./">&larr; Back to blocks</a>
            </div>

        <?php elseif ($page === 'tx'): ?>
            <!-- Transaction Details -->
            <div class="card">
                <div class="card-header">
                    Transaction Details
                    <?= getTxTypeBadge($data['type'] ?? 0, $data['coinbase']) ?>
                </div>
                <div class="detail-grid">
                    <div class="label">TxID</div>
                    <div class="value"><?= $data['txid'] ?></div>

                    <div class="label">Status</div>
                    <div class="value">
                        <?php if ($data['confirmations'] > 0): ?>
                            <span style="color: var(--success);">Confirmed</span> (<?= number_format($data['confirmations']) ?> confirmations)
                        <?php else: ?>
                            <span style="color: var(--warning);">Unconfirmed</span>
                        <?php endif; ?>
                    </div>

                    <?php if ($data['blockinfo']): ?>
                    <div class="label">Block</div>
                    <div class="value">
                        <a href="?<?= $data['blockinfo']['hash'] ?>">#<?= number_format($data['blockinfo']['height']) ?></a>
                        (<?= date('Y-m-d H:i:s', $data['blockinfo']['time']) ?> UTC)
                    </div>
                    <?php endif; ?>

                    <div class="label">Size</div>
                    <div class="value"><?= number_format($data['size']) ?> bytes</div>

                    <div class="label">Type</div>
                    <div class="value">
                        <?= getTxTypeBadge($data['type'] ?? 0, $data['coinbase']) ?>
                        <span style="color: var(--text-secondary); margin-left: 10px; font-family: inherit;">
                            <?php $typeInfo = getTxTypeInfo($data['type'] ?? 0); ?>
                            <?= htmlspecialchars($typeInfo['desc']) ?>
                        </span>
                    </div>

                    <?php if (!$data['coinbase']): ?>
                    <div class="label">Fee</div>
                    <div class="value"><?= formatSats($data['fee'], false) ?> <?= COIN_TICKER ?></div>
                    <?php endif; ?>

                    <div class="label">Version</div>
                    <div class="value"><?= $data['version'] ?></div>

                    <div class="label">Lock Time</div>
                    <div class="value"><?= $data['locktime'] ?></div>
                </div>
            </div>

            <!-- Inputs & Outputs -->
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <!-- Inputs -->
                <div class="card">
                    <div class="card-header">Inputs (<?= count($data['inputs']) ?>)</div>
                    <table>
                        <thead>
                            <tr>
                                <th>From</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($data['inputs'] as $input): ?>
                            <tr>
                                <?php if (isset($input['coinbase'])): ?>
                                <td class="hash" colspan="2">
                                    <span class="badge badge-coinbase">Coinbase</span>
                                    <span style="color: var(--text-secondary); font-size: 12px; margin-left: 10px;">
                                        <?= substr($input['coinbase'], 0, 40) ?>...
                                    </span>
                                </td>
                                <?php else: ?>
                                <td>
                                    <div class="hash truncate" style="max-width: 180px;">
                                        <?php if (isAddress($input['address'])): ?>
                                            <a href="?<?= $input['address'] ?>"><?= $input['address'] ?></a>
                                        <?php else: ?>
                                            <?= $input['address'] ?>
                                        <?php endif; ?>
                                    </div>
                                    <div style="font-size: 11px; color: var(--text-secondary);">
                                        <a href="?<?= $input['txid'] ?>"><?= substr($input['txid'], 0, 16) ?>...</a>:<?= $input['vout'] ?>
                                    </div>
                                </td>
                                <td><?= formatSats($input['value'], false) ?> <?= COIN_TICKER ?></td>
                                <?php endif; ?>
                            </tr>
                            <?php endforeach; ?>
                            <?php if (!$data['coinbase']): ?>
                            <tr style="background: var(--bg-tertiary);">
                                <td><strong>Total</strong></td>
                                <td><strong><?= formatSats($data['total_in'], false) ?> <?= COIN_TICKER ?></strong></td>
                            </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>

                <!-- Outputs -->
                <div class="card">
                    <div class="card-header">Outputs (<?= count($data['outputs']) ?>)</div>
                    <table>
                        <thead>
                            <tr>
                                <th>To</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($data['outputs'] as $output): ?>
                            <tr>
                                <td>
                                    <div class="hash truncate" style="max-width: 180px;">
                                        <?php if (isAddress($output['address'])): ?>
                                            <a href="?<?= $output['address'] ?>"><?= $output['address'] ?></a>
                                        <?php else: ?>
                                            <?= $output['address'] ?>
                                        <?php endif; ?>
                                    </div>
                                    <div style="font-size: 11px; color: var(--text-secondary);">
                                        #<?= $output['n'] ?> (<?= $output['type'] ?>)
                                    </div>
                                </td>
                                <td style="text-align: right;">
                                    <?= formatSats($output['value'], false) ?>
                                    <span class="asset-badge <?= $output['asset_class'] ?? 'asset-m0' ?>"><?= $output['asset'] ?? 'M0' ?></span>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                            <tr style="background: var(--bg-tertiary);">
                                <td><strong>Total</strong></td>
                                <td><strong><?= formatSats($data['total_out'], false) ?> <?= COIN_TICKER ?></strong></td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="pagination">
                <?php if ($data['blockinfo']): ?>
                    <a href="?<?= $data['blockinfo']['hash'] ?>">&larr; Back to Block #<?= $data['blockinfo']['height'] ?></a>
                <?php endif; ?>
                <a href="./">&larr; Back to blocks</a>
            </div>

        <?php elseif ($page === 'address'): ?>
            <!-- Address Details -->
            <div class="card">
                <div class="card-header">Address Details</div>
                <div class="detail-grid">
                    <div class="label">Address</div>
                    <div class="value"><?= htmlspecialchars($data['address']) ?></div>

                    <div class="label">Balance (last <?= $data['blocks_scanned'] ?> blocks)</div>
                    <div class="value" style="color: var(--success);"><?= formatSats($data['balance'], false) ?> <?= COIN_TICKER ?></div>

                    <div class="label">Total Received</div>
                    <div class="value"><?= formatSats($data['total_received'], false) ?> <?= COIN_TICKER ?></div>

                    <div class="label">Total Sent</div>
                    <div class="value"><?= formatSats($data['total_sent'], false) ?> <?= COIN_TICKER ?></div>

                    <div class="label">Transactions</div>
                    <div class="value"><?= $data['tx_count'] ?></div>
                </div>
            </div>

            <!-- Transaction History -->
            <div class="card">
                <div class="card-header">
                    Recent Transactions (<?= count($data['transactions']) ?>)
                    <span style="color: var(--text-secondary); font-weight: normal; font-size: 12px;">
                        Scanned last <?= $data['blocks_scanned'] ?> blocks
                    </span>
                </div>
                <?php if (empty($data['transactions'])): ?>
                    <div style="padding: 20px; color: var(--text-secondary);">
                        No transactions found in the last <?= $data['blocks_scanned'] ?> blocks.
                    </div>
                <?php else: ?>
                    <table>
                        <thead>
                            <tr>
                                <th>Transaction</th>
                                <th>Block</th>
                                <th>Time</th>
                                <th>Received</th>
                                <th>Sent</th>
                                <th>Net</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($data['transactions'] as $tx): ?>
                            <tr>
                                <td class="hash truncate" style="max-width: 150px;">
                                    <a href="?<?= $tx['txid'] ?>"><?= substr($tx['txid'], 0, 16) ?>...</a>
                                </td>
                                <td><?= number_format($tx['height']) ?></td>
                                <td><?= date('Y-m-d H:i', $tx['time']) ?></td>
                                <td style="color: var(--success);">
                                    <?php if ($tx['received'] > 0): ?>
                                        +<?= formatSats($tx['received'], false) ?>
                                    <?php else: ?>
                                        -
                                    <?php endif; ?>
                                </td>
                                <td style="color: #f85149;">
                                    <?php if ($tx['sent'] > 0): ?>
                                        -<?= formatSats($tx['sent'], false) ?>
                                    <?php else: ?>
                                        -
                                    <?php endif; ?>
                                </td>
                                <td style="color: <?= $tx['net'] >= 0 ? 'var(--success)' : '#f85149' ?>;">
                                    <?= $tx['net'] >= 0 ? '+' : '' ?><?= formatSats($tx['net'], false) ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

            <div class="pagination">
                <a href="./">&larr; Back to blocks</a>
            </div>

        <?php elseif ($page === 'operators'): ?>
            <!-- Operators Stats -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="label">Total Operators</div>
                    <div class="value accent"><?= count($data['operators']) ?></div>
                </div>
                <div class="stat-card">
                    <div class="label" title="MNs valides (non PoSe-ban) dans la liste déterministe — état d'enregistrement, pas vivacité (cf. colonne Finality)">Valid MNs (reg.)</div>
                    <div class="value"><?= $data['network']['masternodes_active'] ?></div>
                </div>
                <div class="stat-card">
                    <div class="label">Total MNs</div>
                    <div class="value"><?= $data['network']['masternodes_total'] ?></div>
                </div>
                <div class="stat-card">
                    <div class="label">Block Height</div>
                    <div class="value"><?= number_format($data['network']['blocks']) ?></div>
                </div>
            </div>

            <!-- ⟳ ROTATION DES PRODUCTEURS (DMM) -->
            <?php
            $ftR = BATHRONExplorer::getFinalityTrack();
            $ftRBlocks = $ftR['blocks'] ?? [];
            $palette = ['#7c3aed', '#10b981', '#f7931a', '#3b82f6', '#ec4899', '#eab308', '#14b8a6', '#ef4444'];
            $opColors = []; $opCounts = []; $ci = 0;
            foreach ($ftRBlocks as $b) {
                $p = $b['producer'] ?? '';
                if ($p === '') continue;
                if (!isset($opColors[$p])) { $opColors[$p] = $palette[$ci % count($palette)]; $ci++; }
                $opCounts[$p] = ($opCounts[$p] ?? 0) + 1;
            }
            $totalP = array_sum($opCounts);
            $qN = (int)($ftR['quorum_size'] ?? 0);
            $qT = (int)($ftR['quorum_threshold'] ?? 0);
            ?>
            <div class="card" style="margin-bottom: 20px;">
                <div class="card-header">
                    <span>⟳ Rotation des producteurs (DMM)</span>
                    <span style="font-weight: normal; font-size: 12px; color: var(--text-secondary);">chaque couleur = un opérateur · producteur tiré par bloc (DMM)</span>
                </div>
                <div style="padding: 18px 20px;">
                    <?php if ($totalP === 0): ?>
                        <div style="color: var(--text-secondary); font-size: 13px;">Collecte en cours… (un échantillon par bloc finalisé).</div>
                    <?php else: ?>
                        <!-- bande : 1 case = 1 bloc, couleur = producteur -->
                        <div style="display: flex; gap: 3px; flex-wrap: wrap; margin-bottom: 16px;">
                            <?php foreach (array_slice($ftRBlocks, -60) as $b):
                                $p = $b['producer'] ?? '';
                                $c = $p !== '' ? $opColors[$p] : 'var(--bg-tertiary)';
                            ?>
                                <div title="bloc #<?= (int)$b['h'] ?> · <?= htmlspecialchars(substr($p, 0, 14)) ?>…" style="width: 14px; height: 26px; background: <?= $c ?>; border-radius: 2px;"></div>
                            <?php endforeach; ?>
                        </div>
                        <!-- légende : opérateur, couleur, part produite -->
                        <div style="display: flex; gap: 20px; flex-wrap: wrap; align-items: center;">
                            <?php arsort($opCounts); foreach ($opCounts as $p => $cnt):
                                $pct = round($cnt * 100 / $totalP);
                            ?>
                                <div style="display: flex; align-items: center; gap: 7px; font-size: 12px;">
                                    <span style="width: 12px; height: 12px; border-radius: 3px; background: <?= $opColors[$p] ?>; display: inline-block;"></span>
                                    <span class="hash" title="<?= htmlspecialchars($p) ?>"><?= htmlspecialchars(substr($p, 0, 10)) ?>…</span>
                                    <span style="color: var(--text-secondary);"><?= $cnt ?> blocs · <?= $pct ?>%</span>
                                </div>
                            <?php endforeach; ?>
                        </div>
                        <div style="font-size: 11px; color: var(--text-secondary); margin-top: 14px; border-top: 1px solid var(--border); padding-top: 12px;">
                            <strong>Production (DMM)</strong> = producteur tiré par bloc → tourne entre opérateurs ci-dessus.
                            <strong>Finalité (VRF)</strong> = comité de finalité sélectionné par sortition VRF<?php if ($qN > 0): ?>, seuil <?= $qT ?>/<?= $qN ?><?php endif; ?> ; à cette échelle les 4 opérateurs sont tous sélectionnés (comité cible ≫ nb d'opérateurs) → la rotation du comité n'apparaîtra qu'avec plus d'opérateurs.
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Operator List -->
            <div class="card">
                <div class="card-header">
                    <span>Operator List (v4.0 Operator-Centric)</span>
                    <span style="color: var(--text-secondary); font-weight: normal; font-size: 14px;">
                        <?= count($data['operators']) ?> operators managing <?= $data['network']['masternodes_total'] ?> MNs
                    </span>
                </div>
                <?php if (empty($data['operators'])): ?>
                    <div style="padding: 20px; color: var(--text-secondary);">
                        No operators registered.
                    </div>
                <?php else: ?>
                    <table id="op-table">
                        <thead>
                            <tr>
                                <th class="sortable" data-sort="rank">#</th>
                                <th>Operator Key</th>
                                <th class="sortable sort-desc" data-sort="mns">MNs</th>
                                <th class="sortable" data-sort="online">Online</th>
                                <th>Badges</th>
                                <th class="sortable" data-sort="blocks">Production (DMM)</th>
                                <th class="sortable" data-sort="anciennete">Ancienneté</th>
                                <th class="sortable" data-sort="points">Points</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php $sortition = BATHRONExplorer::getSortition(); ?>
                            <?php $i = 1; foreach ($data['operators'] as $op): ?>
                            <?php $so = $sortition[$op['operatorPubKey']] ?? null; ?>
                            <tr data-rank="<?= $i ?>" data-mns="<?= $op['activeMNs'] ?>" data-online="<?= $op['onlineMNs'] ?>" data-blocks="<?= $so['blocksProduced'] ?? ($op['blocksProduced'] ?? 0) ?>" data-anciennete="<?= $op['ancienneteDays'] ?>" data-points="<?= round($op['reputationScore'] ?? 0) ?>">
                                <td><?= $i++ ?></td>
                                <td class="hash truncate" style="max-width: 140px;" title="<?= $op['operatorPubKey'] ?>">
                                    <?= substr($op['operatorPubKey'], 0, 12) ?>...<?= substr($op['operatorPubKey'], -6) ?>
                                </td>
                                <td style="text-align: center;">
                                    <span style="color: var(--success); font-weight: 600;"><?= $op['activeMNs'] ?></span>
                                    <?php if ($op['bannedMNs'] > 0): ?>
                                        <span style="color: #f85149; font-size: 10px;">+<?= $op['bannedMNs'] ?>ban</span>
                                    <?php endif; ?>
                                </td>
                                <td style="text-align: center;">
                                    <?php if ($op['onlineMNs'] == $op['activeMNs'] && $op['onlineMNs'] > 0): ?>
                                        <span class="badge-online"><?= $op['onlineMNs'] ?>/<?= $op['activeMNs'] ?></span>
                                    <?php elseif ($op['onlineMNs'] > 0): ?>
                                        <span style="color: var(--warning);"><?= $op['onlineMNs'] ?>/<?= $op['activeMNs'] ?></span>
                                    <?php else: ?>
                                        <span class="badge-offline">0/<?= $op['activeMNs'] ?></span>
                                    <?php endif; ?>
                                </td>
                                <td style="font-size: 10px;">
                                    <?php if (!empty($op['badges'])): ?>
                                        <?php
                                        $badgeLabels = [
                                            'genesis_operator' => 'Genesis',
                                            'multi_mn'         => 'Multi-MN',
                                            'solo_operator'    => 'Solo',
                                            'top_producer'     => 'Top producer',
                                            'reliable'         => 'Fiable',
                                        ];
                                        $icons = $op['badgeIcons'] ?? [];
                                        foreach ($op['badges'] as $bi => $badge):
                                            $label = $badgeLabels[$badge] ?? ucwords(str_replace('_', ' ', $badge));
                                            $icon = $icons[$bi] ?? '';
                                        ?>
                                            <span title="<?= htmlspecialchars($badge) ?>" style="display:inline-flex;align-items:center;gap:3px;background:var(--bg-tertiary);border:1px solid var(--border);color:var(--text-primary);border-radius:4px;padding:2px 6px;margin:1px;font-size:11px;white-space:nowrap;"><?= $icon !== '' ? $icon . ' ' : '' ?><?= htmlspecialchars($label) ?></span>
                                        <?php endforeach; ?>
                                    <?php else: ?>
                                        <span style="color: var(--text-secondary);">-</span>
                                    <?php endif; ?>
                                </td>
                                <td style="text-align: center; font-size: 12px;">
                                    <?php if ($so !== null): ?>
                                        <span style="color: var(--accent-light); font-weight: 600;" title="Blocs produits (DMM)"><?= number_format($so['blocksProduced']) ?></span>
                                        <?php
                                            $devNum = floatval(str_replace(['%', '+', ' '], '', (string)$so['deviation']));
                                            $devCol = abs($devNum) <= 20 ? 'var(--success)' : (abs($devNum) <= 50 ? 'var(--warning)' : 'var(--danger, #f85149)');
                                        ?>
                                        <div style="font-size: 10px; color: var(--text-secondary); margin-top: 2px;" title="Part de production réelle / attendue · déviation (équité de production DMM)">
                                            <?= (int)$so['sharePercent'] ?>% / <?= (int)$so['expectedShare'] ?>%
                                            <?php if ($so['deviation'] !== ''): ?>
                                                <span style="color: <?= $devCol ?>; font-weight: 600;"><?= htmlspecialchars((string)$so['deviation']) ?></span>
                                            <?php endif; ?>
                                        </div>
                                    <?php else: ?>
                                        <span style="color: var(--text-secondary);"><?= number_format($op['blocksProduced'] ?? 0) ?></span>
                                    <?php endif; ?>
                                </td>
                                <td style="font-size: 12px;">
                                    <?php if ($op['ancienneteDays'] > 0): ?>
                                        <?= $op['ancienneteDays'] ?>j
                                    <?php else: ?>
                                        <span style="color: var(--text-secondary);">Genesis</span>
                                    <?php endif; ?>
                                </td>
                                <td style="text-align: center;">
                                    <?php $rep = round($op['reputationScore'] ?? 0); ?>
                                    <?php if ($rep > 0): ?>
                                        <span style="color: var(--accent-light); font-weight: 600;" title="Score de réputation 0-100 (voir légende en bas)"><?= $rep ?></span><span style="color: var(--text-secondary); font-size: 10px;"> pts</span>
                                    <?php else: ?>
                                        <span style="color: var(--text-secondary);">-</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

            <!-- Note about operator-centric model -->
            <div class="card" style="margin-top: 20px;">
                <div class="card-header">About Operator-Centric Model</div>
                <div style="padding: 20px; color: var(--text-secondary); font-size: 14px; line-height: 1.8;">
                    <p><strong>Identity = Operator Public Key</strong></p>
                    <p>In BATHRON, operators are the unit of consensus participation:</p>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li><strong>1 Operator = 1 Finality Signature</strong> - regardless of how many MNs they manage</li>
                        <li><strong>DMM Production</strong> - block producers are drawn per block by the DMM scheduler (random rotation)</li>
                        <li><strong>VRF Finality</strong> - a VRF-sorted operator committee finalizes; one signature covers all an operator's MNs</li>
                        <li><strong>Multi-MN Daemon</strong> - run multiple MNs on a single server</li>
                    </ul>
                </div>
            </div>

            <!-- 🏅 LÉGENDE BADGES & RÉPUTATION -->
            <div class="card" style="margin-top: 20px;">
                <div class="card-header">🏅 Légende — badges & réputation</div>
                <div style="padding: 18px 20px;">
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 10px 24px; font-size: 13px;">
                        <div><span style="font-size: 15px;">🏆</span> <strong>Genesis</strong> — enregistré au bloc ≤ 100</div>
                        <div><span style="font-size: 15px;">⚡</span> <strong>Multi-MN</strong> — gère 2+ masternodes</div>
                        <div><span style="font-size: 15px;">⚡⚡</span> <strong>Multi-MN ×5</strong> — gère 5+ masternodes</div>
                        <div><span style="font-size: 15px;">⚡⚡⚡</span> <strong>Multi-MN ×10</strong> — gère 10+ masternodes</div>
                        <div><span style="font-size: 15px;">✓</span> <strong>Perfect uptime</strong> — production ≥ 99% de l'attendu</div>
                        <div><span style="font-size: 15px;">📈</span> <strong>High producer</strong> — production > 105% de l'attendu</div>
                        <div><span style="font-size: 15px;">🎖️</span> <strong>Veteran</strong> — actif depuis 1000+ blocs</div>
                        <div><span style="font-size: 15px;">🐋</span> <strong>Whale</strong> — collatéral ≥ 50 000 BATHRON</div>
                    </div>
                    <div style="margin-top: 16px; border-top: 1px solid var(--border); padding-top: 14px; font-size: 12px; color: var(--text-secondary); line-height: 1.7;">
                        <strong style="color: var(--text-primary);">Réputation (0–100 pts)</strong> = uptime/production <strong>40%</strong> + nombre de MN <strong>20%</strong> (plafond 5) + ancienneté <strong>20%</strong> (plafond 1000 blocs) + badges <strong>20%</strong> (plafond 4 badges).
                        Indicateur calculé par le nœud (`getoperatorinfo`) — informatif, <em>pas</em> un paramètre de consensus.
                    </div>
                </div>
            </div>

        <?php elseif ($page === 'masternodes'): ?>
            <!-- MASTERNODES LIST (Individual MNs) -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="label" title="MNs valides (non PoSe-ban) dans la liste déterministe — état d'enregistrement, pas vivacité (cf. colonne Finality)">Valid MNs (reg.)</div>
                    <div class="value accent"><?= $data['network']['masternodes_active'] ?></div>
                </div>
                <div class="stat-card">
                    <div class="label">Total MNs</div>
                    <div class="value"><?= $data['network']['masternodes_total'] ?></div>
                </div>
                <div class="stat-card">
                    <div class="label">Total Collateral</div>
                    <div class="value"><?= formatSats($data['network']['m0_mn_collateral']) ?></div>
                </div>
                <div class="stat-card">
                    <div class="label">Block Height</div>
                    <div class="value"><?= number_format($data['network']['blocks']) ?></div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <span>Masternode List</span>
                    <span style="color: var(--text-secondary); font-weight: normal; font-size: 14px;">
                        Individual masternodes (see <a href="?tab=operators">Operators</a> for grouped view)
                    </span>
                </div>
                <?php if (empty($data['masternodes'])): ?>
                    <div style="padding: 20px; color: var(--text-secondary); font-size: 14px; line-height: 1.7;">
                        <strong>Aucun masternode pour l'instant.</strong><br>
                        Les masternodes s'enregistrent au bootstrap (<code>protx_register_batch</code>) quelques blocs après le genesis.
                        Si la chaîne vient d'être (ré)initialisée, ils apparaîtront sous peu — rafraîchis dans quelques secondes.
                        <?php if (($data['network']['blocks'] ?? 0) > 0): ?>
                            <br><span style="color: var(--text-muted, var(--text-secondary));">Hauteur courante : <?= number_format($data['network']['blocks']) ?>.</span>
                        <?php endif; ?>
                    </div>
                <?php else: ?>
                    <table id="mn-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Collateral</th>
                                <th>Operator</th>
                                <th>Service IP</th>
                                <th>Status</th>
                                <th>Production (DMM)</th>
                                <th title="Signatures de finalité de l'OPÉRATEUR de ce MN sur les 32 derniers blocs (1 voix par opérateur — un opérateur multi-MN signe via un seul MN). Source : store de finalité consensus du nœud.">Finality (32 blk)</th>
                                <th>Last produced</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php $mnStats = BATHRONExplorer::getMnStats(); ?>
                            <?php $finPart = BATHRONExplorer::getFinalityParticipation(32); ?>
                            <?php $i = 1; foreach ($data['masternodes'] as $mn): ?>
                            <tr>
                                <td><?= $i++ ?></td>
                                <td class="hash truncate" style="max-width: 120px;" title="<?= $mn['collateralAddress'] ?>">
                                    <a href="?q=<?= $mn['collateralAddress'] ?>"><?= substr($mn['collateralAddress'], 0, 12) ?>...</a>
                                </td>
                                <td class="hash truncate" style="max-width: 100px;" title="<?= $mn['operatorPubKey'] ?>">
                                    <?= substr($mn['operatorPubKey'], 0, 10) ?>...
                                </td>
                                <td style="font-size: 12px;"><?= htmlspecialchars($mn['service']) ?></td>
                                <td>
                                    <?php if ($mn['status'] === 'ENABLED'): ?>
                                        <span class="status-enabled"><?= $mn['status'] ?></span>
                                    <?php elseif ($mn['status'] === 'POSE_PENALTY'): ?>
                                        <span class="status-penalty"><?= $mn['status'] ?></span>
                                    <?php else: ?>
                                        <span class="status-banned"><?= $mn['status'] ?></span>
                                    <?php endif; ?>
                                </td>
                                <td style="text-align: center; font-size: 12px;">
                                    <?php $ms = $mnStats[$mn['proTxHash']] ?? null; ?>
                                    <?php if ($ms): ?>
                                        <span style="color: var(--accent-light); font-weight: 600;" title="Blocs produits par ce MN"><?= number_format($ms['blocksProduced']) ?></span>
                                        <div style="font-size: 10px; color: var(--text-secondary); margin-top: 2px;" title="Part de production réelle / attendue sur le réseau (équité de production DMM)">
                                            <?= round($ms['productionRate'], 1) ?>% <span style="color: var(--text-muted, var(--text-secondary));">/ <?= round($ms['expectedRate'], 1) ?>%</span>
                                        </div>
                                    <?php else: ?>
                                        <span style="color: var(--text-secondary);">—</span>
                                    <?php endif; ?>
                                </td>
                                <td style="text-align: center; font-size: 12px;">
                                    <?php
                                    $fp = $finPart['operators'][$mn['operatorPubKey']] ?? null;
                                    $fpTotal = $finPart['blocks_with_finality'] ?? 0;
                                    ?>
                                    <?php if ($fp !== null && $fpTotal > 0): ?>
                                        <?php
                                        $pct = (int)round($fp['rate'] * 100);
                                        $color = $pct >= 90 ? 'var(--success, #4caf50)' : ($pct >= 50 ? 'var(--warning, #ff9800)' : 'var(--danger, #f44336)');
                                        ?>
                                        <span style="color: <?= $color ?>; font-weight: 600;" title="Signé <?= $fp['signed'] ?> des <?= $fpTotal ?> derniers blocs finalisés (opérateur)"><?= $fp['signed'] ?>/<?= $fpTotal ?></span>
                                        <div style="font-size: 10px; color: var(--text-secondary); margin-top: 2px;">
                                            <?= $pct ?>%<?php if ($fp['signed'] === 0 && $fp['last_signed_height'] === 0): ?> <span title="Jamais signé dans la fenêtre — MN pas encore éligible (confirmedHash) ou opérateur muet">silencieux</span><?php endif; ?>
                                        </div>
                                    <?php else: ?>
                                        <span style="color: var(--text-secondary);" title="Donnée indisponible (RPC getfinalityparticipation absent ou aucun bloc finalisé dans la fenêtre)">n/a</span>
                                    <?php endif; ?>
                                </td>
                                <td style="font-size: 12px;">
                                    <?php if ($mn['lastPaidHeight'] > 0): ?>
                                        Block <?= number_format($mn['lastPaidHeight']) ?>
                                    <?php else: ?>
                                        <span style="color: var(--text-secondary);">Never</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

        <?php elseif ($page === 'btc'): ?>
            <!-- BTC BRIDGE / SPV - FULL PAGE -->
            <?php
            $btc = $data['btc'] ?? [];

            // Headers info
            $headers = $btc['headers'] ?? [];
            $chainTip = $headers['tip_height'] ?? 0;
            $headerCount = $headers['header_count'] ?? 0;
            $dbInit = $headers['db_initialized'] ?? false;
            $headersAhead = $headers['headers_ahead'] ?? 0;
            $canPublish = $headers['can_publish'] ?? false;

            // Sync info
            $sync = $btc['sync'] ?? [];
            $spvTip = $sync['tip_height'] ?? 0;
            $spvSynced = $sync['synced'] ?? false;
            $spvNetwork = $sync['network'] ?? 'signet';

            // Burn stats (from burnclaimdb - single source of truth)
            $burnStats = $btc['burn_stats'] ?? [];
            $m0btcSupply = $burnStats['m0btc_supply'] ?? 0;
            $totalFinal = $burnStats['total_final'] ?? 0;
            $totalPending = $burnStats['total_pending'] ?? 0;

            // Scan status
            $scanStatus = $btc['scan_status'] ?? [];
            $scanEnabled = $scanStatus['enabled'] ?? false;
            $lastScanned = $scanStatus['last_scanned_height'] ?? 0;

            // Burn claims (from listburnclaims RPC)
            $burnsPending = $btc['burns_pending'] ?? [];
            $burnsFinal = $btc['burns_final'] ?? [];
            ?>

            <!-- SPV Bridge Status -->
            <div class="card">
                <div class="card-header">
                    <span>BTC SPV</span>
                    <span style="color: <?= $dbInit ? 'var(--success)' : 'var(--warning)' ?>; font-weight: normal; font-size: 14px;">
                        <?= $dbInit ? 'INITIALIZED' : 'NOT READY' ?>
                    </span>
                </div>
                <div style="padding: 20px;">
                    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px;">
                        <div style="padding: 15px; background: var(--bg-tertiary); border-radius: 8px;">
                            <div style="font-size: 11px; color: var(--text-secondary); text-transform: uppercase;">Chain BTC Headers</div>
                            <div style="font-size: 20px; font-weight: bold; color: var(--accent);"><?= number_format($chainTip) ?></div>
                            <div style="font-size: 11px; color: var(--text-secondary);">Consensus tip</div>
                        </div>
                        <div style="padding: 15px; background: var(--bg-tertiary); border-radius: 8px;">
                            <div style="font-size: 11px; color: var(--text-secondary); text-transform: uppercase;">Chain SPV Publish</div>
                            <div style="font-size: 20px; font-weight: bold; color: var(--text-primary);"><?= number_format($spvTip) ?></div>
                            <div style="font-size: 11px; color: var(--text-secondary);"><?= $headersAhead > 0 ? "+{$headersAhead} to publish" : "synced" ?></div>
                        </div>
                        <?php
                            // M0_TOTAL from settlement = all BTC burned (A5 invariant)
                            // Value is already in SATS (1 BTC sat = 1 M0 sat)
                            $m0TotalSats = (int)($data['network']['m0_total'] ?? 0);
                            $m0TotalBTC = $m0TotalSats / 100000000;
                        ?>
                        <div style="padding: 15px; background: var(--bg-tertiary); border-radius: 8px;">
                            <div style="font-size: 11px; color: var(--text-secondary); text-transform: uppercase;">Total Burned (BTC)</div>
                            <div style="font-size: 20px; font-weight: bold; color: var(--accent);"><?= rtrim(rtrim(number_format($m0TotalBTC, 8), '0'), '.') ?> BTC</div>
                            <div style="font-size: 11px; color: var(--text-secondary);"><?= number_format($m0TotalSats) ?> sats</div>
                        </div>
                        <div style="padding: 15px; background: var(--bg-tertiary); border-radius: 8px;">
                            <div style="font-size: 11px; color: var(--text-secondary); text-transform: uppercase;">Daemons</div>
                            <div style="font-size: 14px; font-weight: bold; margin-top: 5px;">
                                <span style="color: var(--success);">Auto Publish SPV:</span> <span style="color: var(--success);">ON</span>
                            </div>
                            <div style="font-size: 14px; font-weight: bold;">
                                <span style="color: var(--success);">Auto Claim:</span> <span style="color: var(--success);">ON</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Pending Burns -->
            <?php if (!empty($burnsPending)): ?>
            <div class="card" style="margin-top: 20px; border: 1px solid var(--warning);">
                <div class="card-header" style="background: rgba(245, 158, 11, 0.1);">
                    <span style="color: var(--warning);">Pending Burn Claims</span>
                    <span style="color: var(--text-secondary); font-weight: normal; font-size: 14px;">
                        <?= count($burnsPending) ?> awaiting confirmation
                    </span>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>BTC TXID</th>
                            <th>Amount</th>
                            <th>Destination</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($burnsPending as $burn): ?>
                        <tr>
                            <td>
                                <a href="https://mempool.space/signet/tx/<?= htmlspecialchars($burn['btc_txid'] ?? '') ?>"
                                   target="_blank" style="color: var(--accent); font-family: monospace; font-size: 12px;">
                                    <?= substr($burn['btc_txid'] ?? '', 0, 16) ?>...
                                </a>
                            </td>
                            <td style="font-family: monospace;"><?= number_format($burn['amount_sats'] ?? $burn['burned_sats'] ?? 0) ?> sats</td>
                            <td style="font-family: monospace; font-size: 12px;"><?= substr($burn['bathron_dest'] ?? $burn['destination'] ?? '', 0, 16) ?>...</td>
                            <td><span style="color: var(--warning); font-weight: bold;"><?= strtoupper($burn['status'] ?? 'PENDING') ?></span></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?php endif; ?>

            <!-- Detected Burns (Live from BTC Signet) -->
            <?php
            // Fetch detected burns from mempool.space API
            $detectedBurns = [];
            $burnAddress = 'tb1qdc6qh88lkdaf3899gnntk7q293ufq8flkvmnsa59zx3sv9a05qwsdh5h09';
            $btcTipHeight = $chainTip; // From btcheadersdb
            $bathronHeight = $data['network']['blocks'] ?? 0;

            // Load genesis burns list
            $genesisBurns = BathronExplorer::getGenesisBurnsList();

            // Build set of genesis burn txids (these are FINAL - minted at block 1)
            $genesisTxids = [];
            foreach ($genesisBurns['burns'] ?? [] as $gb) {
                $genesisTxids[$gb['btc_txid']] = true;
            }

            // Fetch detected burns from mempool.space (curl + force IPv4: sortie IPv6 du VPS cassée
            // vers mempool.space). Cache fichier 30s : ne tape pas l'API à chaque rendu (auto-refresh 30s),
            // garde l'onglet réactif même si mempool ralentit, et sert le dernier cache si mempool tombe.
            $mempoolData = false;
            $cacheFile   = sys_get_temp_dir() . '/bathron_mempool_burns.json';
            $cacheTtl    = 30;
            if (is_readable($cacheFile) && (time() - filemtime($cacheFile)) < $cacheTtl) {
                $mempoolData = file_get_contents($cacheFile);
            }
            if ($mempoolData === false && function_exists('curl_init')) {
                $ch = curl_init("https://mempool.space/signet/api/address/{$burnAddress}/txs");
                curl_setopt_array($ch, [
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_CONNECTTIMEOUT => 4,
                    CURLOPT_TIMEOUT        => 6,
                    CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4,
                    CURLOPT_USERAGENT      => 'BATHRON-Explorer',
                ]);
                $resp = curl_exec($ch);
                if ($resp !== false && (int)curl_getinfo($ch, CURLINFO_HTTP_CODE) === 200) {
                    $mempoolData = $resp;
                    @file_put_contents($cacheFile, $resp, LOCK_EX);
                } elseif (is_readable($cacheFile)) {
                    // mempool KO → dernier cache même périmé (dégradation gracieuse)
                    $mempoolData = file_get_contents($cacheFile);
                }
                curl_close($ch);
            }
            if ($mempoolData) {
                $txs = json_decode($mempoolData, true) ?: [];
                foreach ($txs as $tx) {
                    $confirmed = $tx['status']['confirmed'] ?? false;
                    $txHeight = $tx['status']['block_height'] ?? 0;
                    $btcConfs = $confirmed && $btcTipHeight > 0 ? max(0, $btcTipHeight - $txHeight + 1) : 0;

                    // Find burn amount and OP_RETURN data
                    $burnAmount = 0;
                    $destHash160 = '';
                    foreach ($tx['vout'] ?? [] as $vout) {
                        if (($vout['scriptpubkey_address'] ?? '') === $burnAddress) {
                            $burnAmount = $vout['value'] ?? 0;
                        }
                        // Check for OP_RETURN with BATHRON prefix
                        $asm = $vout['scriptpubkey_asm'] ?? '';
                        if (strpos($asm, 'OP_RETURN') !== false && strpos($asm, '42415448524f4e') !== false) {
                            // Extract hash160 (last 20 bytes = 40 hex chars)
                            preg_match('/42415448524f4e01..([a-f0-9]{40})$/i', $vout['scriptpubkey'] ?? '', $m);
                            $destHash160 = $m[1] ?? '';
                        }
                    }

                    // Check burnclaimdb first (real claim_height), then genesis fallback
                    $isFinal = false;
                    $bathronConfs = 0;
                    $bathronClaimHeight = 0;

                    // Check burnclaimdb (FINAL burns)
                    foreach ($burnsFinal as $fb) {
                        if (($fb['btc_txid'] ?? '') === $tx['txid']) {
                            $isFinal = true;
                            $bathronConfs = 20; // Already final (K_FINALITY_TESTNET)
                            $bathronClaimHeight = $fb['claim_height'] ?? $fb['finalized_height'] ?? 0;
                            break;
                        }
                    }
                    // Check pending burns
                    if (!$isFinal) {
                        foreach ($burnsPending as $pb) {
                            if (($pb['btc_txid'] ?? '') === $tx['txid']) {
                                $bathronClaimHeight = $pb['claim_height'] ?? 0;
                                $bathronConfs = $bathronClaimHeight > 0 ? max(0, $bathronHeight - $bathronClaimHeight) : 0;
                                break;
                            }
                        }
                    }
                    // Fallback: genesis burn not yet in burnclaimdb
                    if (!$isFinal && $bathronClaimHeight === 0 && isset($genesisTxids[$tx['txid']])) {
                        $isFinal = true;
                        $bathronConfs = $bathronHeight;
                        $bathronClaimHeight = 2; // Genesis claims are at block 2 (block 1 = headers-only)
                    }

                    $detectedBurns[] = [
                        'txid' => $tx['txid'],
                        'height' => $txHeight,
                        'amount' => $burnAmount,
                        'dest_hash160' => $destHash160,
                        'btc_confs' => $btcConfs,
                        'bathron_confs' => $bathronConfs,
                        'bathron_height' => $bathronClaimHeight,
                        'is_final' => $isFinal,
                        'confirmed' => $confirmed
                    ];
                }
            }
            ?>
            <div class="card" style="margin-top: 20px;">
                <div class="card-header">
                    <span>Detected Burns (Live)</span>
                    <span style="color: var(--text-secondary); font-weight: normal; font-size: 14px;">
                        <?= count($detectedBurns) ?> burns on BTC Signet
                    </span>
                </div>
                <?php if (empty($detectedBurns)): ?>
                    <div style="padding: 20px; color: var(--text-secondary);">
                        No burns detected. Scanning burn address...
                    </div>
                <?php else: ?>
                    <table>
                        <thead>
                            <tr>
                                <th>BTC TXID</th>
                                <th>Amount</th>
                                <th>BTC Height</th>
                                <th>BTC Confs</th>
                                <th>BATHRON Height</th>
                                <th>BATHRON Confs</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($detectedBurns as $burn):
                                $btcOk = $burn['btc_confs'] >= 6;
                                $bathronOk = $burn['bathron_confs'] >= 20; // K_FINALITY_TESTNET
                                $status = 'PENDING';
                                $statusColor = 'var(--warning)';
                                if ($burn['is_final']) {
                                    $status = 'FINAL';
                                    $statusColor = 'var(--success)';
                                } elseif (!$burn['confirmed']) {
                                    $status = 'MEMPOOL';
                                    $statusColor = 'var(--text-secondary)';
                                } elseif ($btcOk && $burn['bathron_confs'] >= 20) {
                                    $status = 'FINAL';
                                    $statusColor = 'var(--success)';
                                } elseif ($btcOk && $burn['bathron_confs'] > 0) {
                                    $status = 'CONFIRMING';
                                    $statusColor = 'var(--accent)';
                                } elseif ($btcOk) {
                                    $status = 'CLAIMABLE';
                                    $statusColor = 'var(--success)';
                                }
                            ?>
                            <tr style="<?= !$burn['confirmed'] ? 'opacity: 0.6;' : '' ?>">
                                <td>
                                    <a href="https://mempool.space/signet/tx/<?= htmlspecialchars($burn['txid']) ?>"
                                       target="_blank" style="color: var(--accent); font-family: monospace; font-size: 12px;">
                                        <?= substr($burn['txid'], 0, 12) ?>...<?= substr($burn['txid'], -6) ?>
                                    </a>
                                </td>
                                <td style="text-align: right; font-family: monospace; padding-right: 15px;">
                                    <?php if ($burn['amount'] >= 1000000): ?>
                                        <?= rtrim(rtrim(number_format($burn['amount'] / 100000000, 8), '0'), '.') ?> BTC
                                    <?php else: ?>
                                        <?= number_format($burn['amount']) ?> sats
                                    <?php endif; ?>
                                </td>
                                <td style="text-align: center; font-family: monospace;">
                                    <?= $burn['height'] > 0 ? number_format($burn['height']) : '-' ?>
                                </td>
                                <td style="text-align: center;">
                                    <?php if ($btcOk): ?>
                                        <span style="color: var(--success); font-weight: bold;">✓ 6+</span>
                                    <?php else: ?>
                                        <span style="color: var(--warning); font-weight: bold;"><?= $burn['btc_confs'] ?>/6</span>
                                    <?php endif; ?>
                                </td>
                                <td style="text-align: center; font-family: monospace;">
                                    <?php if ($burn['bathron_height'] > 0): ?>
                                        <a href="?q=<?= $burn['bathron_height'] ?>" style="color: var(--accent);">
                                            <?= number_format($burn['bathron_height']) ?>
                                        </a>
                                    <?php else: ?>
                                        <span style="color: var(--text-secondary);">-</span>
                                    <?php endif; ?>
                                </td>
                                <td style="text-align: center;">
                                    <?php if ($bathronOk): ?>
                                        <span style="color: var(--success); font-weight: bold;">✓ 20+</span>
                                    <?php else: ?>
                                        <span style="color: var(--text-secondary); font-weight: bold;"><?= $burn['bathron_confs'] ?>/20</span>
                                    <?php endif; ?>
                                </td>
                                <td style="text-align: center;">
                                    <span style="color: <?= $statusColor ?>; font-weight: bold; font-size: 11px;">
                                        <?= $status ?>
                                    </span>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

            <!-- About Section -->
            <div class="card" style="margin-top: 20px;">
                <div class="card-header">How BTC Burns Work</div>
                <div style="padding: 20px; color: var(--text-secondary); font-size: 14px; line-height: 1.8;">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                        <div>
                            <p style="color: var(--text-primary); font-weight: bold; margin-bottom: 10px;">Burn Process</p>
                            <ol style="margin-left: 20px;">
                                <li>Send BTC to unspendable P2WSH address</li>
                                <li>Include OP_RETURN with destination</li>
                                <li>Wait for 6 confirmations on Signet</li>
                                <li>SPV proof validates burn on BATHRON</li>
                                <li>M0BTC minted 1:1 to destination</li>
                            </ol>
                        </div>
                        <div>
                            <p style="color: var(--text-primary); font-weight: bold; margin-bottom: 10px;">Technical Details</p>
                            <ul style="margin-left: 20px;">
                                <li><strong>Script:</strong> P2WSH(OP_FALSE)</li>
                                <li><strong>OP_RETURN:</strong> BATHRON|01|NET|HASH160</li>
                                <li><strong>SPV:</strong> Merkle proof verification</li>
                                <li><strong>No custody:</strong> BTC destroyed forever</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

        <?php elseif ($page === 'join'): ?>
            <!-- JOIN PAGE -->
            <?php
            $burnAddr = 'tb1qdc6qh88lkdaf3899gnntk7q293ufq8flkvmnsa59zx3sv9a05qwsdh5h09';
            $joinAddr = isset($_GET['addr']) ? trim($_GET['addr']) : '';
            $joinHash160 = '';
            $joinMetadata = '';
            $joinError = '';

            if ($joinAddr !== '') {
                // Validate and convert BATHRON address to hash160
                $result = trim(shell_exec("python3 -c \"
import hashlib, sys
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58decode(s):
    n = 0
    for c in s:
        if c not in ALPHABET: raise ValueError('bad char')
        n = n * 58 + ALPHABET.index(c)
    return bytes.fromhex('%050x' % n)
try:
    d = b58decode('$joinAddr')
    payload, cksum = d[:-4], d[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != cksum:
        print('ERROR:bad checksum')
    else:
        print(payload[1:].hex())
except: print('ERROR:invalid address')
\" 2>/dev/null"));

                if (str_starts_with($result, 'ERROR:') || strlen($result) !== 40) {
                    $joinError = 'Invalid BATHRON address';
                } else {
                    $joinHash160 = $result;
                    $joinMetadata = '42415448524f4e' . '01' . '54' . $joinHash160;
                }
            }
            ?>

            <div class="card">
                <div class="card-header">Join BATHRON — Burn BTC to mint M0</div>
                <div style="padding: 30px;">
                    <p style="color: var(--text-secondary); margin-bottom: 25px; line-height: 1.6;">
                        Burn BTC on Signet to receive M0BTC on BATHRON testnet. 1 satoshi burned = 1 M0 minted.<br>
                        The burn is <strong>irreversible</strong> — BTC is sent to a provably unspendable address.
                    </p>

                    <!-- Step 1: Enter address -->
                    <form method="get" style="margin-bottom: 30px;">
                        <input type="hidden" name="tab" value="join">
                        <div style="display: flex; gap: 10px; align-items: center;">
                            <label style="color: var(--text-primary); white-space: nowrap; font-weight: bold;">Your BATHRON address:</label>
                            <input type="text" name="addr" value="<?= htmlspecialchars($joinAddr) ?>"
                                placeholder="yJYD2bfYYBe6qAojSzMKX949H7QoQifNAo"
                                style="flex: 1; padding: 10px 14px; background: var(--bg-primary); border: 1px solid var(--border); color: var(--text-primary); border-radius: 6px; font-family: monospace; font-size: 14px;">
                            <button type="submit" style="padding: 10px 24px; background: var(--accent); color: #fff; border: none; border-radius: 6px; cursor: pointer; font-weight: bold;">Generate</button>
                        </div>
                        <?php if ($joinError): ?>
                            <p style="color: #ef4444; margin-top: 10px;"><?= htmlspecialchars($joinError) ?></p>
                        <?php endif; ?>
                    </form>

                    <?php if ($joinMetadata): ?>
                    <!-- Step 2: Show burn details -->
                    <div style="background: var(--bg-primary); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px;">
                        <p style="color: var(--accent); font-weight: bold; margin-bottom: 15px; font-size: 16px;">Your burn details</p>

                        <div style="display: grid; gap: 12px;">
                            <div>
                                <span style="color: var(--text-secondary); font-size: 12px;">BURN ADDRESS (send BTC here)</span>
                                <div style="font-family: monospace; font-size: 13px; color: var(--text-primary); word-break: break-all; background: var(--bg-secondary); padding: 8px 12px; border-radius: 4px; margin-top: 4px; cursor: pointer;" onclick="navigator.clipboard.writeText('<?= $burnAddr ?>')" title="Click to copy"><?= $burnAddr ?></div>
                            </div>
                            <div>
                                <span style="color: var(--text-secondary); font-size: 12px;">OP_RETURN METADATA (include in your TX)</span>
                                <div style="font-family: monospace; font-size: 13px; color: var(--text-primary); word-break: break-all; background: var(--bg-secondary); padding: 8px 12px; border-radius: 4px; margin-top: 4px; cursor: pointer;" onclick="navigator.clipboard.writeText('<?= $joinMetadata ?>')" title="Click to copy"><?= $joinMetadata ?></div>
                            </div>
                            <div>
                                <span style="color: var(--text-secondary); font-size: 12px;">DESTINATION (M0 will be minted here)</span>
                                <div style="font-family: monospace; font-size: 13px; color: var(--text-primary); background: var(--bg-secondary); padding: 8px 12px; border-radius: 4px; margin-top: 4px;"><?= htmlspecialchars($joinAddr) ?></div>
                            </div>
                        </div>
                    </div>

                    <!-- Step 3: bitcoin-cli command -->
                    <div style="background: var(--bg-primary); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px;">
                        <p style="color: var(--accent); font-weight: bold; margin-bottom: 15px;">Quick command (bitcoin-cli)</p>
                        <pre style="background: #0d1117; color: #c9d1d9; padding: 16px; border-radius: 6px; overflow-x: auto; font-size: 13px; line-height: 1.6; margin: 0;"># Create burn TX (replace AMOUNT with BTC amount, e.g. 0.0001)
bitcoin-cli -signet createrawtransaction "[]" \
  "{\"data\":\"<?= $joinMetadata ?>\",\"<?= $burnAddr ?>\":AMOUNT}"

# Then fund, sign, and broadcast:
bitcoin-cli -signet fundrawtransaction "RAW_TX"
bitcoin-cli -signet signrawtransactionwithwallet "FUNDED_TX"
bitcoin-cli -signet sendrawtransaction "SIGNED_TX"</pre>
                    </div>

                    <!-- Step 4: Or use the script -->
                    <div style="background: var(--bg-primary); border: 1px solid var(--border); border-radius: 8px; padding: 20px;">
                        <p style="color: var(--accent); font-weight: bold; margin-bottom: 15px;">Or use the automated script</p>
                        <pre style="background: #0d1117; color: #c9d1d9; padding: 16px; border-radius: 6px; overflow-x: auto; font-size: 13px; line-height: 1.6; margin: 0;"># One command — handles everything automatically
./burn_signet.sh <?= htmlspecialchars($joinAddr) ?> 10000</pre>
                        <p style="color: var(--text-secondary); font-size: 13px; margin-top: 10px;">
                            Get it: <a href="https://github.com/AdonisPhusis/bathron-node-tools" target="_blank" style="color: var(--accent);">github.com/AdonisPhusis/bathron-node-tools</a>
                        </p>
                    </div>
                    <?php endif; ?>

                    <!-- Info section -->
                    <div style="margin-top: 25px; padding-top: 20px; border-top: 1px solid var(--border);">
                        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; color: var(--text-secondary); font-size: 13px;">
                            <div>
                                <p style="color: var(--text-primary); font-weight: bold; margin-bottom: 8px;">What happens</p>
                                <ol style="margin-left: 16px; line-height: 1.8;">
                                    <li>You send BTC to the burn address</li>
                                    <li>Wait 6 confirmations (~1 hour)</li>
                                    <li>Burn is auto-detected by the network</li>
                                    <li>M0BTC minted 1:1 to your address</li>
                                </ol>
                            </div>
                            <div>
                                <p style="color: var(--text-primary); font-weight: bold; margin-bottom: 8px;">Requirements</p>
                                <ul style="margin-left: 16px; line-height: 1.8;">
                                    <li>Min burn: <strong>1,000 sats</strong></li>
                                    <li>Network: BTC <strong>Signet</strong></li>
                                    <li>Conversion: <strong>1:1</strong> (1 sat = 1 M0)</li>
                                    <li>Fee: <strong>0</strong> (claim is free)</li>
                                </ul>
                            </div>
                            <div>
                                <p style="color: var(--text-primary); font-weight: bold; margin-bottom: 8px;">Get Signet BTC</p>
                                <ul style="margin-left: 16px; line-height: 1.8;">
                                    <li><a href="https://signetfaucet.com" target="_blank" style="color: var(--accent);">signetfaucet.com</a></li>
                                    <li><a href="https://alt.signetfaucet.com" target="_blank" style="color: var(--accent);">alt.signetfaucet.com</a></li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

        <?php endif; ?>
    </main>

    <footer>
        <div class="container">
            <?= COIN_NAME ?> Explorer | Powered by BATHRON Core
        </div>
    </footer>

    <?php if ($page === 'operators'): ?>
    <script>
    // Sortable table for operators
    document.addEventListener('DOMContentLoaded', function() {
        const table = document.getElementById('op-table');
        if (!table) return;

        const headers = table.querySelectorAll('th.sortable');
        const tbody = table.querySelector('tbody');

        headers.forEach(header => {
            header.addEventListener('click', function() {
                const sortKey = this.dataset.sort;
                const isAsc = this.classList.contains('sort-asc');

                // Remove sort classes from all headers
                headers.forEach(h => h.classList.remove('sort-asc', 'sort-desc'));

                // Toggle sort direction
                this.classList.add(isAsc ? 'sort-desc' : 'sort-asc');

                // Sort rows
                const rows = Array.from(tbody.querySelectorAll('tr'));
                rows.sort((a, b) => {
                    let aVal = a.dataset[sortKey];
                    let bVal = b.dataset[sortKey];

                    // Numeric sort for these columns
                    if (['rank', 'mns', 'online', 'anciennete', 'score'].includes(sortKey)) {
                        aVal = parseFloat(aVal) || 0;
                        bVal = parseFloat(bVal) || 0;
                        return isAsc ? bVal - aVal : aVal - bVal;
                    }

                    // String sort
                    return isAsc ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
                });

                // Re-append rows in new order
                rows.forEach(row => tbody.appendChild(row));
            });
        });
    });
    </script>
    <?php endif; ?>

</body>
</html>
