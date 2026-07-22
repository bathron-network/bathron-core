extends Node
## Configuration Manager - Stores ONLY non-sensitive settings
## NO passwords, NO private keys, NO passphrases

const CONFIG_PATH := "user://settings.cfg"

var _config := ConfigFile.new()

# RPC Settings (non-sensitive)
var rpc_host: String = "127.0.0.1"
var rpc_port: int = 27175
var rpc_use_cookie: bool = true

# UI Settings
var theme: String = "dark"
var language: String = "en"
var refresh_interval: float = 10.0

func _ready() -> void:
	load_config()

func load_config() -> void:
	var err := _config.load(CONFIG_PATH)
	if err == OK:
		rpc_host = _config.get_value("rpc", "host", "127.0.0.1")
		rpc_port = _config.get_value("rpc", "port", 27175)
		rpc_use_cookie = _config.get_value("rpc", "use_cookie", true)
		theme = _config.get_value("ui", "theme", "dark")
		language = _config.get_value("ui", "language", "en")
		refresh_interval = _config.get_value("ui", "refresh_interval", 10.0)
		print("[Config] Loaded from: ", CONFIG_PATH)
	else:
		print("[Config] No config file, using defaults")
		save_config()

func save_config() -> void:
	_config.set_value("rpc", "host", rpc_host)
	_config.set_value("rpc", "port", rpc_port)
	_config.set_value("rpc", "use_cookie", rpc_use_cookie)
	_config.set_value("ui", "theme", theme)
	_config.set_value("ui", "language", language)
	_config.set_value("ui", "refresh_interval", refresh_interval)
	_config.save(CONFIG_PATH)
	print("[Config] Saved to: ", CONFIG_PATH)
