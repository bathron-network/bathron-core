extends Control
## Main Wallet UI Controller
## Thin client - NO sensitive data stored

@onready var status_label: Label = %Status
@onready var m0_value: Label = %M0Value
@onready var m1_value: Label = %M1Value
@onready var amount_input: LineEdit = %AmountInput
@onready var lock_btn: Button = %LockBtn
@onready var unlock_btn: Button = %UnlockBtn
@onready var receipts_list: ItemList = %ReceiptsList
@onready var block_height: Label = %BlockHeight
@onready var peers_label: Label = %Peers
@onready var sync_label: Label = %SyncStatus
@onready var receive_addr: LineEdit = %ReceiveAddress
@onready var copy_btn: Button = %CopyBtn
@onready var passphrase_dialog: AcceptDialog = %PassphraseDialog
@onready var passphrase_input: LineEdit = %PassphraseInput

var _pending_action: String = ""
var _receipts: Array = []
var _receive_address: String = ""

func _ready() -> void:
	# Connect RPC signals
	RPC.connected.connect(_on_connected)
	RPC.disconnected.connect(_on_disconnected)
	RPC.error.connect(_on_error)

	# Connect UI signals
	lock_btn.pressed.connect(_on_lock_pressed)
	unlock_btn.pressed.connect(_on_unlock_pressed)
	copy_btn.pressed.connect(_on_copy_pressed)
	passphrase_dialog.confirmed.connect(_on_passphrase_confirmed)
	$RefreshTimer.timeout.connect(_refresh_data)

	# Initial state
	_set_buttons_enabled(false)
	status_label.text = "Connecting..."
	status_label.add_theme_color_override("font_color", Color.YELLOW)
	sync_label.text = "Sync: --"
	receive_addr.text = "Loading..."

func _on_connected() -> void:
	status_label.text = "Connected"
	status_label.add_theme_color_override("font_color", Color.GREEN)
	_set_buttons_enabled(true)
	_refresh_data()
	_get_receive_address()

func _on_disconnected() -> void:
	status_label.text = "Disconnected"
	status_label.add_theme_color_override("font_color", Color.RED)
	_set_buttons_enabled(false)

func _on_error(message: String) -> void:
	status_label.text = "Error"
	status_label.add_theme_color_override("font_color", Color.RED)
	print("[ERROR] ", message)
	# Show error in a non-blocking way
	if "unlock" in message.to_lower() or "passphrase" in message.to_lower():
		_show_passphrase_dialog()

func _set_buttons_enabled(enabled: bool) -> void:
	lock_btn.disabled = not enabled
	unlock_btn.disabled = not enabled
	amount_input.editable = enabled

func _refresh_data() -> void:
	RPC.get_wallet_state(_on_wallet_state)
	RPC.get_blockchain_info(_on_blockchain_info)
	RPC.get_connection_count(_on_connection_count)
	RPC.list_receipts(_on_receipts)

func _on_wallet_state(result: Variant) -> void:
	if result == null:
		return

	if result is Dictionary:
		var m0 := 0.0
		var m1 := 0.0

		# BP30 format: m0.balance, m1.total
		if result.has("m0") and result["m0"] is Dictionary:
			m0 = float(result["m0"].get("balance", 0))
		if result.has("m1") and result["m1"] is Dictionary:
			m1 = float(result["m1"].get("total", 0))

		m0_value.text = "%.8f" % m0
		m1_value.text = "%.8f" % m1

func _on_blockchain_info(result: Variant) -> void:
	if result == null:
		return
	if result is Dictionary:
		var blocks: int = result.get("blocks", 0)
		var headers: int = result.get("headers", 0)
		var progress: float = result.get("verificationprogress", 0.0)

		block_height.text = "Block: %d" % blocks

		if headers > blocks:
			var pct := (float(blocks) / float(headers)) * 100.0 if headers > 0 else 0.0
			sync_label.text = "Sync: %d/%d (%.1f%%)" % [blocks, headers, pct]
			sync_label.add_theme_color_override("font_color", Color.YELLOW)
		else:
			sync_label.text = "Sync: OK"
			sync_label.add_theme_color_override("font_color", Color.GREEN)

func _on_connection_count(result: Variant) -> void:
	if result != null:
		var count := int(result)
		peers_label.text = "Peers: %d" % count
		if count == 0:
			peers_label.add_theme_color_override("font_color", Color.RED)
		else:
			peers_label.add_theme_color_override("font_color", Color.GREEN)

func _on_receipts(result: Variant) -> void:
	if result == null:
		return

	_receipts.clear()
	receipts_list.clear()

	if result is Array:
		for receipt in result:
			if receipt is Dictionary:
				_receipts.append(receipt)
				var outpoint: String = receipt.get("outpoint", "?")
				var amount: float = float(receipt.get("amount", 0))
				var short_outpoint := outpoint.substr(0, 16) + "..."
				receipts_list.add_item("%.8f M1 - %s" % [amount, short_outpoint])

# ============================================================================
# LOCK / UNLOCK ACTIONS
# ============================================================================

func _on_lock_pressed() -> void:
	var amount_text := amount_input.text.strip_edges()
	if amount_text.is_empty():
		status_label.text = "Enter amount"
		return

	var amount := float(amount_text)
	if amount <= 0:
		status_label.text = "Invalid amount"
		return

	_pending_action = "lock"
	status_label.text = "Locking..."
	RPC.lock(amount, _on_lock_result)

func _on_lock_result(result: Variant) -> void:
	if result == null:
		return

	if result is Dictionary and result.has("txid"):
		var txid: String = result["txid"]
		status_label.text = "Locked! TX: " + txid.substr(0, 16) + "..."
		status_label.add_theme_color_override("font_color", Color.GREEN)
		_refresh_data()
	else:
		status_label.text = "Lock failed"
		status_label.add_theme_color_override("font_color", Color.RED)

func _on_unlock_pressed() -> void:
	var amount_text := amount_input.text.strip_edges()
	if amount_text.is_empty():
		status_label.text = "Enter amount"
		return

	var amount := float(amount_text)
	if amount <= 0:
		status_label.text = "Invalid amount"
		return

	_pending_action = "unlock"
	status_label.text = "Unlocking..."
	RPC.unlock(amount, _on_unlock_result)

func _on_unlock_result(result: Variant) -> void:
	if result == null:
		return

	if result is Dictionary and result.has("txid"):
		var txid: String = result["txid"]
		status_label.text = "Unlocked! TX: " + txid.substr(0, 16) + "..."
		status_label.add_theme_color_override("font_color", Color.GREEN)
		_refresh_data()
	else:
		status_label.text = "Unlock failed"
		status_label.add_theme_color_override("font_color", Color.RED)

# ============================================================================
# RECEIVE ADDRESS
# ============================================================================

func _get_receive_address() -> void:
	## Get or create a receive address
	if _receive_address != "":
		receive_addr.text = _receive_address
		return
	RPC.get_new_address(_on_receive_address, "wallet_receive")

func _on_receive_address(result: Variant) -> void:
	if result != null and result is String:
		_receive_address = result
		receive_addr.text = result

func _on_copy_pressed() -> void:
	if _receive_address != "":
		DisplayServer.clipboard_set(_receive_address)
		status_label.text = "Address copied!"
		status_label.add_theme_color_override("font_color", Color.GREEN)

# ============================================================================
# PASSPHRASE DIALOG (for encrypted wallets)
# ============================================================================

func _show_passphrase_dialog() -> void:
	passphrase_input.text = ""
	passphrase_dialog.popup_centered()

func _on_passphrase_confirmed() -> void:
	var passphrase := passphrase_input.text
	passphrase_input.text = ""  # Clear immediately!

	if passphrase.is_empty():
		return

	status_label.text = "Unlocking wallet..."
	RPC.wallet_passphrase(passphrase, 300, _on_wallet_unlocked)

func _on_wallet_unlocked(result: Variant) -> void:
	if result == null:
		status_label.text = "Wallet unlocked (5 min)"
		status_label.add_theme_color_override("font_color", Color.GREEN)

		# Retry pending action
		if _pending_action == "lock":
			_on_lock_pressed()
		elif _pending_action == "unlock":
			_on_unlock_pressed()

		_pending_action = ""
