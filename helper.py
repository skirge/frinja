from typing import Callable, Optional
import binaryninja as bn
import frida

from .log import *
from .settings import HOOK_TAG_TYPE, HOOK_TAG_TYPE_ICON, SETTINGS

def get_functions_by_tag(bv: bn.BinaryView, tag: str):
	if not bv.get_tag_type(HOOK_TAG_TYPE):
		bv.create_tag_type(HOOK_TAG_TYPE, HOOK_TAG_TYPE_ICON)

	return [f for f in bv.functions if f.get_function_tags(False, tag)]

def needs_settings(func: Callable):
	def wrapper(bv: bn.BinaryView, *args, **kwargs):
		SETTINGS.restore(bv)
		func(bv, *args, **kwargs)
	return wrapper

def message_handler(func: Callable):
	def wrapper(*args, **kwargs):
		def inner(msg: frida.core.ScriptMessage, data: Optional[bytes]):
			# TODO: What to do with the data?
			if msg["type"] == "error":
				if msg["stack"]:
					error(msg["stack"])

				error("\n".join(msg["description"].split("\\n")))
				return

			func(msg["payload"], data, *args, **kwargs)
		return inner
	return wrapper
