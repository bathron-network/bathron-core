<?php
/*
    finality_tracker.php — enregistre le délai de finalité MESURÉ PAR LE NŒUD
    (getfinalitystatus.last_finality_delay_ms, en ms) + le producteur de chaque
    bloc (getquorum.producer_operator), dans un état JSON lu par l'explorer.
    Tourne en boucle sous finality-tracker.service (Restart=always).
    NB : remplace l'ancienne mesure poll-3s (grossière, ~secondes) — le nœud
    mesure le vrai délai production→finalisation en millisecondes.
*/
// RPC credentials are NEVER stored in this file. Same EnvironmentFile as the
// explorer web UI (systemd loads it too via finality-tracker.service).
// Fail-closed: no config -> wait and retry, never a default password.
const RPC_CONFIG_FILE = '/etc/bathron/explorer-rpc.env';

function rpc_config() {
    if (!is_readable(RPC_CONFIG_FILE)) return false;
    $vals = [];
    foreach (file(RPC_CONFIG_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        $eq = strpos($line, '=');
        if ($eq === false) continue;
        $k = trim(substr($line, 0, $eq));
        $v = trim(substr($line, $eq + 1));
        if (strlen($v) >= 2 && ($v[0] === '"' || $v[0] === "'") && substr($v, -1) === $v[0]) {
            $v = substr($v, 1, -1);
        }
        $vals[$k] = $v;
    }
    if (($vals['BATHRON_RPC_USER'] ?? '') === '' || ($vals['BATHRON_RPC_PASS'] ?? '') === '') {
        return false;
    }
    return [
        'user' => $vals['BATHRON_RPC_USER'],
        'pass' => $vals['BATHRON_RPC_PASS'],
        'host' => $vals['BATHRON_RPC_HOST'] ?? '127.0.0.1',
        'port' => (int)($vals['BATHRON_RPC_PORT'] ?? 27175),
        'state_file' => $vals['BATHRON_STATE_FILE'] ?? '',
    ];
}
define('STATE', (function () {
    // Same env file as the RPC config; generic fallback next to the install dir.
    $cfg = rpc_config();
    if ($cfg !== false && ($cfg['state_file'] ?? '') !== '') return $cfg['state_file'];
    return __DIR__ . '/explorer-state/finality.json';
})());
const MAX_SAMPLES = 60;
const POLL_SEC = 3;

function rpc($method, $params = []) {
    $cfg = $GLOBALS['rpc_cfg'] ?? false;
    if ($cfg === false) return null;
    $payload = json_encode(['jsonrpc' => '1.0', 'id' => 'ftrack', 'method' => $method, 'params' => $params]);
    $ch = curl_init('http://' . $cfg['host'] . ':' . $cfg['port'] . '/');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_USERPWD        => $cfg['user'] . ':' . $cfg['pass'],
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT        => 8,
    ]);
    $r = curl_exec($ch);
    curl_close($ch);
    if ($r === false) return null;
    $j = json_decode($r, true);
    return $j['result'] ?? null;
}

function defaultState() {
    return [
        'updated' => 0, 'lag' => 0, 'status' => 'unknown', 'tip' => 0,
        'quorum_size' => 0, 'quorum_threshold' => 0,
        'avg_delay_ms' => 0, 'last_delay_ms' => 0, 'producer' => '',
        'last_height' => 0, 'blocks' => [],
    ];
}

function loadState() {
    if (is_readable(STATE)) {
        $j = json_decode(file_get_contents(STATE), true);
        if (is_array($j)) return array_merge(defaultState(), $j);
    }
    return defaultState();
}

function saveState($s) {
    $tmp = STATE . '.tmp';
    file_put_contents($tmp, json_encode($s), LOCK_EX);
    rename($tmp, STATE);  // remplacement atomique
}

@mkdir(dirname(STATE), 0755, true);

// Fail-closed startup: no config -> wait for it, never fall back to defaults.
$GLOBALS['rpc_cfg'] = rpc_config();
while ($GLOBALS['rpc_cfg'] === false) {
    fwrite(STDERR, "finality_tracker: RPC config unavailable (" . RPC_CONFIG_FILE . "), retrying in 30s\n");
    sleep(30);
    $GLOBALS['rpc_cfg'] = rpc_config();
}

$state = loadState();
$lastH = (int)($state['last_height'] ?? 0);

while (true) {
    $now = time();
    $fs = rpc('getfinalitystatus');
    if (is_array($fs) && isset($fs['last_finalized_height'])) {
        $Hf = (int)$fs['last_finalized_height'];
        $state['lag']             = (int)($fs['finality_lag'] ?? 0);
        $state['status']          = $fs['status'] ?? 'unknown';
        $state['tip']             = (int)($fs['tip_height'] ?? $Hf);
        $state['quorum_size']     = (int)($fs['quorum_size'] ?? 0);
        $state['quorum_threshold']= (int)($fs['quorum_threshold'] ?? 0);
        $state['avg_delay_ms']    = (int)round($fs['avg_finality_delay_ms'] ?? 0);
        $state['last_delay_ms']   = (int)round($fs['last_finality_delay_ms'] ?? 0);

        // Reset/genesis : si la finalité RECULE, l'ancienne chaîne n'existe plus → purge.
        if ($lastH > 0 && $Hf < $lastH) {
            $lastH = $Hf;
            $state['blocks'] = [];
        }
        if ($lastH === 0) {
            $lastH = $Hf;  // démarrage à froid : on mesure le neuf
        }

        if ($Hf > $lastH) {
            $avg  = $state['avg_delay_ms'];
            $last = $state['last_delay_ms'];
            for ($h = $lastH + 1; $h <= $Hf; $h++) {
                $producer = '';
                $q = rpc('getquorum', [(int)$h]);
                if (is_array($q)) $producer = $q['producer_operator'] ?? '';
                // le délai ms précis n'est connu que pour le dernier finalisé ; les
                // sauts intermédiaires (rares, lag≈0) prennent la moyenne du nœud.
                $delayMs = ($h === $Hf) ? $last : $avg;
                $state['blocks'][] = ['h' => $h, 'delay_ms' => (int)$delayMs, 'producer' => $producer];
            }
            $lastH = $Hf;
            if (count($state['blocks']) > MAX_SAMPLES) {
                $state['blocks'] = array_slice($state['blocks'], -MAX_SAMPLES);
            }
        }
        if (!empty($state['blocks'])) {
            $state['producer'] = end($state['blocks'])['producer'];
        }
        $state['last_height'] = $lastH;
        $state['updated'] = $now;
        saveState($state);
    }
    sleep(POLL_SEC);
}
