import binaryninja as bn

from .frida_launcher import FridaLauncher
from .log import *
from .settings import HOOK_TAG_TYPE, HOOK_TAG_TYPE_ICON, Settings

def mark_hooked(bv: bn.BinaryView, func: bn.Function):
	# NOTE: Maybe rely on id instead of name?
	if not bv.get_tag_type(HOOK_TAG_TYPE):
		bv.create_tag_type(HOOK_TAG_TYPE, HOOK_TAG_TYPE_ICON)

	if not func.get_function_tags(False, HOOK_TAG_TYPE):
		func.add_tag(HOOK_TAG_TYPE, "Hook function calls", None)

def _get_functions_by_tag(bv: bn.BinaryView, tag: str):
	if not bv.get_tag_type(HOOK_TAG_TYPE):
		bv.create_tag_type(HOOK_TAG_TYPE, HOOK_TAG_TYPE_ICON)

	return [f for f in bv.functions if f.get_function_tags(False, tag)]

def frida_start(settings: Settings):
	def func(bv: bn.BinaryView):
		settings.restore(bv)
		info("Launching frinja with hooker script")
		targets = _get_functions_by_tag(bv, HOOK_TAG_TYPE)
		frida_launcher = FridaLauncher.from_template(settings, "hooker.js.j2", frida_logger, bv=bv, targets=targets)
		frida_launcher.start()

	return func
