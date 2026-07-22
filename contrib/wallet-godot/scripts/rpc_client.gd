extends Node
## BATHRON RPC Client - Thin client for bathrond daemon
## NO wallet.dat, NO private keys - just RPC calls

signal connected
signal disconnected
signal error(message: String)
signal balance_updated(m0: float, m1: float)

const HTTP_POOL_SIZE := 8  # Allow 8 concurrent requests

var _http_pool: Array[HTTPRequest] = []
var _host: String = "127.0.0.1"
var _port: int = 27175
var _auth: String = ""
var _request_id: int = 0
var _pending_callbacks: Dictionary = {}
var _http_to_request: Dictionary = {}  # Map HTTPRequest -> request_id

func _ready() -> void:
	# Create pool of HTTPRequest nodes for concurrent requests
	for i in range(HTTP_POOL_SIZE):
		var http := HTTPRequest.new()
		http.name = "HTTP_%d" % i
		add_child(http)
		http.request_completed.connect(_on_request_completed.bind(http))
		_http_pool.append(http)

	# Try to load cookie auth automatically (deferred so signals are connected first)
	call_deferred("_load_cookie_auth")

func _load_cookie_auth() -> void:
	## Load .cookie file for automatic authentication (localhost only)
	var cookie_paths := [
		OS.get_environment("HOME") + "/.bathron/.cookie",
		OS.get_environment("HOME") + "/.bathron/testnet5/.cookie",
	]

	for path in cookie_paths:
		if FileAccess.file_exists(path):
			var file := FileAccess.open(path, FileAccess.READ)
			if file:
				var content := file.get_as_text().strip_edges()
				if ":" in content:
					_auth = Marshalls.utf8_to_base64(content)
					print("[RPC] Cookie auth loaded from: ", path)
					connected.emit()
					return

	print("[RPC] No cookie found, manual auth required")

func configure(host: String, port: int, user: String = "", password: String = "") -> void:
	_host = host
	_port = port
	if user != "" and password != "":
		_auth = Marshalls.utf8_to_base64(user + ":" + password)

func _get_available_http() -> HTTPRequest:
	## Get an available HTTPRequest from the pool
	for http in _http_pool:
		if http.get_http_client_status() == HTTPClient.STATUS_DISCONNECTED:
			return http
	# All busy - return first one (will queue)
	return _http_pool[0]

func _call_rpc(method: String, params: Array = [], callback: Callable = Callable()) -> void:
	_request_id += 1
	var request_id := _request_id

	var body := {
		"jsonrpc": "2.0",
		"id": request_id,
		"method": method,
		"params": params
	}

	var headers := [
		"Content-Type: application/json",
	]
	if _auth != "":
		headers.append("Authorization: Basic " + _auth)

	var url := "http://%s:%d/" % [_host, _port]
	var json_body := JSON.stringify(body)

	if callback.is_valid():
		_pending_callbacks[request_id] = callback

	var http := _get_available_http()
	_http_to_request[http] = request_id

	var err := http.request(url, headers, HTTPClient.METHOD_POST, json_body)
	if err != OK:
		error.emit("HTTP request failed: " + str(err))

func _on_request_completed(result: int, response_code: int, headers: PackedStringArray, body: PackedByteArray, http: HTTPRequest) -> void:
	# Clean up the http-to-request mapping
	_http_to_request.erase(http)

	if result != HTTPRequest.RESULT_SUCCESS:
		error.emit("Connection failed")
		disconnected.emit()
		return

	if response_code == 401:
		error.emit("Authentication failed")
		return

	var json := JSON.new()
	var parse_result := json.parse(body.get_string_from_utf8())
	if parse_result != OK:
		error.emit("Invalid JSON response")
		return

	var response: Dictionary = json.data
	var request_id: int = response.get("id", 0)

	if response.has("error") and response["error"] != null:
		error.emit(str(response["error"].get("message", "Unknown error")))
		return

	if _pending_callbacks.has(request_id):
		var callback: Callable = _pending_callbacks[request_id]
		_pending_callbacks.erase(request_id)
		if callback.is_valid():
			callback.call(response.get("result"))

# ============================================================================
# PUBLIC API - Settlement Layer RPCs
# ============================================================================

func get_balance(callback: Callable) -> void:
	## Get M0 balance
	_call_rpc("getbalance", [], callback)

func get_wallet_state(callback: Callable) -> void:
	## Get wallet state (M0 + M1 balances)
	_call_rpc("getwalletstate", [true], callback)

func get_state(callback: Callable) -> void:
	## Get global settlement state
	_call_rpc("getstate", [], callback)

func list_receipts(callback: Callable) -> void:
	## List M1 receipts
	_call_rpc("listreceipts", [], callback)

func lock(amount: float, callback: Callable) -> void:
	## Lock M0 -> M1
	_call_rpc("lock", [amount], callback)

func unlock(amount_or_outpoint: Variant, callback: Callable) -> void:
	## Unlock M1 -> M0
	_call_rpc("unlock", [amount_or_outpoint], callback)

func transfer_m1(outpoint: String, address: String, callback: Callable) -> void:
	## Transfer M1 to another address
	_call_rpc("transfer_m1", [outpoint, address], callback)

func wallet_passphrase(passphrase: String, timeout: int, callback: Callable) -> void:
	## Unlock wallet for signing (passphrase NEVER stored!)
	_call_rpc("walletpassphrase", [passphrase, timeout], callback)

func wallet_lock(callback: Callable) -> void:
	## Lock wallet immediately
	_call_rpc("walletlock", [], callback)

func get_block_count(callback: Callable) -> void:
	## Get current block height
	_call_rpc("getblockcount", [], callback)

func get_connection_count(callback: Callable) -> void:
	## Get peer count
	_call_rpc("getconnectioncount", [], callback)

func get_blockchain_info(callback: Callable) -> void:
	## Get blockchain sync info (blocks, headers, progress)
	_call_rpc("getblockchaininfo", [], callback)

func get_new_address(callback: Callable, label: String = "") -> void:
	## Generate new receive address
	_call_rpc("getnewaddress", [label], callback)

func get_addresses_by_label(callback: Callable, label: String = "") -> void:
	## Get existing addresses by label
	_call_rpc("getaddressesbylabel", [label], callback)
