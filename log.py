import binaryninja as bn
import frida

LOGGER = bn.log.Logger(0, "Frinja")

log = LOGGER.log
debug = LOGGER.log_debug
info = LOGGER.log_info
warn = LOGGER.log_warn
error = LOGGER.log_error
alert = LOGGER.log_alert

def frida_logger(msg: frida.core.ScriptMessage, data: dict):
	debug(msg)
	if msg["type"] == "error":
		if msg["stack"]:
			error(msg["stack"])

		error("\n".join(msg["description"].split("\\n")))
		return

	if msg["payload"]:
		info(msg["payload"])
