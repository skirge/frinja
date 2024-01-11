from html import escape
from typing import Any, Optional
import binaryninja as bn

from .frida_launcher import FridaLauncher, jinja
from .log import *
from .console import CONSOLE
from .settings import HOOK_TAG_TYPE, HOOK_TAG_TYPE_ICON
from .helper import get_functions_by_tag, needs_settings, message_handler

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
	else:
		func.remove_user_function_tags_of_type(HOOK_TAG_TYPE)

# Frida Start
@needs_settings
def frida_start(bv: bn.BinaryView):
	info("Launching hooker script")
	# int is immutable so we have to use dict/list
	state = { "depth": 0 }
	targets = get_functions_by_tag(bv, HOOK_TAG_TYPE)
	frida_launcher = FridaLauncher.from_template(bv, "hooker.js.j2", targets=targets)
	frida_launcher.on_message_send = [on_frida_start(state)]
	frida_launcher.start()

@message_handler
def on_frida_start(msg: Any, data: Optional[bytes], state: dict):
	if not isinstance(msg, dict) or "event" not in msg.keys() or msg["event"] not in ("call", "return"):
		CONSOLE.handle_message(msg)
		return

	indent = "║ " * state["depth"]
	# TODO: Per-thread color
	if msg["event"] == "call":
		args = ", ".join([f"{k}={v}" for k, v in msg["args"].items()])
		CONSOLE.output.appendHtml(escape(f"{indent}╔ {msg['function']}@{hex(msg['address'])}({args})"))
		state["depth"] += 1
	elif msg["event"] == "return":
		state["depth"] -= 1
		indent = indent[:-2]
		CONSOLE.output.appendHtml(escape(f"{indent}╚ {msg['function']}@{hex(msg['address'])}(...) « {msg['retval']}"))

	if state["depth"] <= 0:
		state["depth"] = 0

# Function Inspector
@alert_on_error
@needs_settings
def function_inspector(bv: bn.BinaryView, func: bn.Function):
	info(f"Launching function inspector for {func.name}@{func.start}")
	frida_launcher = FridaLauncher.from_template(bv, "function_inspector.js.j2", func=func)
	frida_launcher.on_message_send = [on_function_inspector(bv, func)]
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
def function_dumper(bv: bn.BinaryView, func: bn.Function):
	dump_data = []
	info(f"Launching function dumper for {func.name}@{func.start}")

	def reporter():
		info("Dumping complete - generating report")
		template = jinja.get_template("function_dumper_report.md.j2")
		report = template.render(bv=bv, func=func, data=dump_data)
		bv.show_markdown_report(f"{func.name} Dump", report)

	frida_launcher = FridaLauncher.from_template(bv, "function_dumper.js.j2", func=func)
	frida_launcher.on_message_send = [on_function_dumper(bv, func, dump_data)]
	frida_launcher.on_end.append(reporter)
	frida_launcher.start()


@message_handler
def on_function_dumper(msg: dict, data: Optional[bytes], bv: bn.BinaryView, func: bn.Function, dump_data: list):
	if "return" in msg:
		msg["return"] = int(msg["return"], 16)
	dump_data.append(msg)

# Devi
@alert_on_error
@needs_settings
def devi(bv: bn.BinaryView, func: bn.Function):
	dump_data = {
		"callList": [],
		"modules": None,
	}
	info(f"Launching devi analysis for {func.name}@{func.start}")

	def reporter():
		frida_launcher.join()
		info("Analysis complete - calling devi plugin")

		import murx_devi_binja

		# Disable the load_virtual_calls function that shows the load dialog
		class DeviMuted(murx_devi_binja.binja_devi):
			def load_virtual_calls(self):
				pass

		devi = DeviMuted(bv)
		devi.devirtualize_calls(dump_data["calls"], dump_data["modules"])

	frida_launcher = FridaLauncher.from_template(bv, "devi.js.j2", on_devi(bv, func, dump_data), func=func)
	frida_launcher.on_message_send = [on_devi(bv, func, dump_data)]
	frida_launcher.on_end.append(reporter)
	frida_launcher.start()

@message_handler
def on_devi(msg: dict, data: Optional[bytes], bv: bn.BinaryView, func: bn.Function, dump_data: dict):
	if "callList" in msg.keys():
		dump_data["callList"].extend(msg["callList"])
	elif "moduleMap" in msg.keys():
		dump_data["modules"] = msg["moduleMap"]

# Log Sniffer
@needs_settings
def log_sniffer(bv: bn.BinaryView):
	info("Launching log sniffer")
	frida_launcher = FridaLauncher.from_template(bv, "log_sniffer.js.j2")
	frida_launcher.start()
