from typing import Callable, Optional
from threading import Thread
import binaryninja as bn
import frida

from .frida_launcher import FridaLauncher, jinja
from .log import *
from .settings import HOOK_TAG_TYPE, HOOK_TAG_TYPE_ICON, Settings

def _get_functions_by_tag(bv: bn.BinaryView, tag: str):
	if not bv.get_tag_type(HOOK_TAG_TYPE):
		bv.create_tag_type(HOOK_TAG_TYPE, HOOK_TAG_TYPE_ICON)

	return [f for f in bv.functions if f.get_function_tags(False, tag)]

def needs_settings(func: Callable):
	def wrapper(settings: Settings):
		def inner(bv: bn.BinaryView, *args, **kwargs):
			settings.restore(bv)
			func(settings, bv, *args, **kwargs)
		return inner
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

@alert_on_error
def show_help(bv: bn.BinaryView):
	bv.show_markdown_report("Frinja Help", open(bn.user_plugin_path() + "/frinja/README.md").read())

@alert_on_error
def mark_hooked(bv: bn.BinaryView, func: bn.Function):
	# NOTE: Maybe rely on id instead of name?
	if not bv.get_tag_type(HOOK_TAG_TYPE):
		bv.create_tag_type(HOOK_TAG_TYPE, HOOK_TAG_TYPE_ICON)

	if not func.get_function_tags(False, HOOK_TAG_TYPE):
		func.add_tag(HOOK_TAG_TYPE, "Hook function calls", None)

# Frida Start
@needs_settings
def frida_start(settings: Settings, bv: bn.BinaryView):
	info("Launching hooker script")
	targets = _get_functions_by_tag(bv, HOOK_TAG_TYPE)
	frida_launcher = FridaLauncher.from_template(settings, "hooker.js.j2", on_frida_start(), bv=bv, targets=targets)
	frida_launcher.start()

@message_handler
def on_frida_start(msg: str, data: Optional[bytes]):
	print(msg)
	info(msg)

# Function Inspector
@alert_on_error
@needs_settings
def function_inspector(settings: Settings, bv: bn.BinaryView, func: bn.Function):
	info(f"Launching function inspector for {func.name}@{func.start}")
	frida_launcher = FridaLauncher.from_template(settings, "function_inspector.js.j2", on_function_inspector(bv, func), bv=bv, func=func)
	frida_launcher.start()

@message_handler
def on_function_inspector(msg: str, data: Optional[bytes], bv: bn.BinaryView, func: bn.Function):
	addr = bv.start + int(msg, 16)
	block = func.get_basic_block_at(addr)
	debug(f"Highlighting block {block}")
	block.set_auto_highlight(bn.HighlightStandardColor.CyanHighlightColor)

# Function Dumper
@alert_on_error
@needs_settings
def function_dumper(settings: Settings, bv: bn.BinaryView, func: bn.Function):
	dump_data = []
	info(f"Launching function dumper for {func.name}@{func.start}")
	frida_launcher = FridaLauncher.from_template(settings, "function_dumper.js.j2", on_function_dumper(bv, func, dump_data), bv=bv, func=func)
	frida_launcher.start()

	def reporter():
		frida_launcher.join()
		info("Dumping complete - generating report")
		template = jinja.get_template("function_dumper_report.md.j2")
		report = template.render(bv=bv, func=func, data=dump_data)
		bv.show_markdown_report(f"{func.name} Dump", report)

	t = Thread(target=reporter)
	t.daemon = True
	t.start()


@message_handler
def on_function_dumper(msg: dict, data: Optional[bytes], bv: bn.BinaryView, func: bn.Function, dump_data: list):
	if "return" in msg:
		msg["return"] = int(msg["return"], 16)
	dump_data.append(msg)
