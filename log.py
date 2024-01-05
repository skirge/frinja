from typing import Callable
import binaryninja as bn

LOGGER = bn.log.Logger(0, "Frinja")

log = LOGGER.log
debug = LOGGER.log_debug
info = LOGGER.log_info
warn = LOGGER.log_warn
error = LOGGER.log_error
alert = LOGGER.log_alert

def alert_on_error(func: Callable):
	def wrapper(*args, **kwargs):
		try:
			return func(*args, **kwargs)
		except Exception as e:
			error(e)
			alert(f"Frinja: {e}")
	return wrapper
