from typing import Callable, Optional
import binaryninja as bn

LOGGER = bn.log.Logger(0, "Frinja")

log = LOGGER.log
debug = LOGGER.log_debug
info = LOGGER.log_info
warn = LOGGER.log_warn
error = LOGGER.log_error
alert = LOGGER.log_alert

def alert_on_error_cb(exception: Optional[Callable] = None, finalizer: Optional[Callable] = None):
	def wrapper(func: Callable):
		def inner(*args, **kwargs):
			try:
				return func(*args, **kwargs)
			except Exception as e:
				error(e)
				alert(f"Frinja: {e}")

				if exception:
					exception(e)
			finally:
				if finalizer:
					finalizer()

		return inner
	return wrapper

def alert_on_error(func: Callable):
	return alert_on_error_cb()(func)
