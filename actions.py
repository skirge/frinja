from typing import Callable, Optional
from threading import Thread
import binaryninja as bn
import frida

from .console import CONSOLE

from .frida_launcher import FridaLauncher, jinja
from .log import *
from .settings import HOOK_TAG_TYPE, HOOK_TAG_TYPE_ICON, SETTINGS

def _get_functions_by_tag(bv: bn.BinaryView, tag: str):
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
def frida_start(bv: bn.BinaryView):
	info("Launching hooker script")
	targets = _get_functions_by_tag(bv, HOOK_TAG_TYPE)
	frida_launcher = FridaLauncher.from_template(bv, "hooker.js.j2", targets=targets)
	# frida_launcher.on_start.connect(lambda: CONSOLE.session_start(settings, bv))
	# frida_launcher.on_end.connect(CONSOLE.session_end)
	# frida_launcher.on_message.connect(CONSOLE.on_message)
	# frida_launcher.input_signal(CONSOLE.eval_signal)
	frida_launcher.run()

@message_handler
def on_frida_start(msg: str, data: Optional[bytes]):
	print(msg)
	info(msg)

# Function Inspector
@alert_on_error
@needs_settings
def function_inspector(bv: bn.BinaryView, func: bn.Function):
	info(f"Launching function inspector for {func.name}@{func.start}")
	frida_launcher = FridaLauncher.from_template(bv, "function_inspector.js.j2", on_function_inspector(bv, func), func=func)
	frida_launcher.run()

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
	frida_launcher = FridaLauncher.from_template(bv, "function_dumper.js.j2", on_function_dumper(bv, func, dump_data), func=func)
	frida_launcher.run()

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

# Devi
@alert_on_error
@needs_settings
def devi(bv: bn.BinaryView, func: bn.Function):
	dump_data = {
		"callList": [],
		"modules": None,
	}
	info(f"Launching devi analysis for {func.name}@{func.start}")
	frida_launcher = FridaLauncher.from_template(bv, "devi.js.j2", on_devi(bv, func, dump_data), func=func)
	frida_launcher.run()

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


	t = Thread(target=reporter)
	t.daemon = True
	t.run()


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
	frida_launcher = FridaLauncher.from_template(bv, "log_sniffer.js.j2", on_log_sniffer())
	frida_launcher.run()

@message_handler
def on_log_sniffer(msg: str, data: Optional[bytes]):
	info(msg)
