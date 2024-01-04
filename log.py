import binaryninja as bn

LOGGER = bn.log.Logger(0, "Frinja")

log = LOGGER.log
debug = LOGGER.log_debug
info = LOGGER.log_info
warn = LOGGER.log_warn
error = LOGGER.log_error
alert = LOGGER.log_alert
