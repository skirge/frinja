from html import escape
from typing import Any, Optional
import binaryninja as bn
from binaryninja.highlight import HighlightColor
import frida

from .frida_launcher import FridaLauncher, jinja, FRIDA_RELOADER
from .log import *
#from .console import CONSOLE
from .settings import HOOK_TAG_TYPE, HOOK_TAG_TYPE_ICON
from .helper import get_functions_by_tag, needs_settings, message_handler, PLUGIN_PATH

@alert_on_error
def show_help(bv: bn.BinaryView):
	bv.show_markdown_report("Frinja Help", open(PLUGIN_PATH / "README.md").read())

def mark_hooked(bv: bn.BinaryView, func: bn.Function):
	global FRIDA_RELOADER

	# NOTE: Maybe rely on id instead of name?
	if not bv.get_tag_type(HOOK_TAG_TYPE):
		state = bv.begin_undo_actions()
		bv.create_tag_type(HOOK_TAG_TYPE, HOOK_TAG_TYPE_ICON)
		bv.commit_undo_actions(state)

	if not func.get_function_tags(False, HOOK_TAG_TYPE):
		func.add_tag(HOOK_TAG_TYPE, "Hook function calls", None)
	else:
		func.remove_user_function_tags_of_type(HOOK_TAG_TYPE)

	try:
		FRIDA_RELOADER()
	except frida.InvalidOperationError:
		FRIDA_RELOADER = lambda: None

# Frida Start
@needs_settings
def frida_start(bv: bn.BinaryView):
	global FRIDA_RELOADER

	info("Launching hooker script")
	# int is immutable so we have to use dict/list
	state = { "depth": 0 }
	targets = get_functions_by_tag(bv, HOOK_TAG_TYPE)

	frida_launcher = FridaLauncher.from_template(bv, "hooker.js.j2", targets=targets)
	frida_launcher.on_message_send = [on_frida_start(state)]
	frida_launcher.start()

	FRIDA_RELOADER = lambda: frida_launcher.replace_script_from_template("hooker.js.j2", targets=get_functions_by_tag(bv, HOOK_TAG_TYPE))

@message_handler
def on_frida_start(msg: Any, data: Optional[bytes], state: dict):
	if not isinstance(msg, dict) or "event" not in msg.keys() or msg["event"] not in ("call", "return"):
		#CONSOLE.handle_message(msg)
		print(msg)
		return

	for k, v in msg.items():
		if isinstance(v, str):
			msg[k] = escape(v)

	link = f'<a href="function:{hex(msg["address"])}">{msg["function"]}</a>'
	indent = "║ " * state["depth"]
	# TODO: Per-thread color
	if msg["event"] == "call":
		args = ", ".join([f"{k}={v}" for k, v in msg["args"].items()])
		#CONSOLE.output.appendHtml(f"{indent}╔ {link}({args})")
		print(f"{indent}╔ {link}({args})")
		state["depth"] += 1
	elif msg["event"] == "return":
		state["depth"] -= 1
		indent = indent[:-2]
		retval = msg["retval"]

		if "new_retval" in msg.keys():
			retval = f'<span style="text-decoration: line-through">{retval}</span> ~> <b>{msg["new_retval"]}</b>'

		#CONSOLE.output.appendHtml(f"{indent}╚ {link}(...) « {retval}")
		print(f"{indent}╚ {link}(...) « {retval}")

	if state["depth"] <= 0:
		state["depth"] = 0

# Function Inspector
@alert_on_error
@needs_settings
def function_inspector(bv: bn.BinaryView, func: bn.Function):
	info(f"Launching function inspector for {func.name}@{hex(func.start)}")
	frida_launcher = FridaLauncher.from_template(bv, "function_inspector.js.j2", func=func)
	frida_launcher.on_message_send = [on_function_inspector(bv, func)]
	frida_launcher.start()

colors = [
	[252,176,69],
	[252,144,60],
	[252,117,53],
	[253,61,38],
	[253,29,29],
	[231,34,56],
	[221,36,68],
	[202,41,92],
	[185,45,113],
	[158,52,147],
	[131,58,180],
]

@message_handler
def on_function_inspector(msg: Any, data: Optional[bytes], bv: bn.BinaryView, func: bn.Function):
	global colors
	if not isinstance(msg, dict) or "addr" not in msg.keys() or "count" not in msg.keys():
		#CONSOLE.handle_message(msg)
		print(msg)
		return
	addr = bv.start + int(msg["addr"], 16)
	debug(f"Highlighting block @ {hex(addr)}")

	c = msg["count"]
	color = [0,0,0]
	if c>0 and c < 10:
		color=colors[0]
		info(f"DoS: <10 executions @ {hex(addr)}")
	elif c>=10 and c < 50:
		color=colors[1]
		info(f"DoS: +10 executions @ {hex(addr)}")
	elif c>=50 and c < 100:
		color=colors[2]
		info(f"DoS: +50 executions @ {hex(addr)}")
	elif c>=100 and c < 500:
		color=colors[3]
		info(f"DoS: +100 executions @ {hex(addr)}")
	elif c>=500 and c < 1000:
		color=colors[4]
		bv.set_comment_at(addr, "+500 executions")
		info(f"DoS: +500 executions @ {hex(addr)}")
	elif c>=1000 and c<10000:
		color=colors[5]
		bv.set_comment_at(addr, "+1k executions")
		info(f"DoS: +1000 executions @ {hex(addr)}")
	elif c>=10000 and c<100000:
		color=colors[6]
		bv.set_comment_at(addr, "+10k executions")
		info(f"DoS: +10000 executions @ {hex(addr)}")
	elif c>=100000 and c<1000000:
		color=colors[7]
		bv.set_comment_at(addr, "+100k executions")
		info(f"DoS: +100k executions @ {hex(addr)}")
	elif c>=1000000 and c<10000000:
		color=colors[8]
		bv.set_comment_at(addr, "+1M executions")
		info(f"DoS: +1M executions @ {hex(addr)}")
	elif c>=10000000:
		color=colors[9]
		bv.set_comment_at(addr, "+10M executions")
		info(f"DoS: +10M executions @ {hex(addr)}")
	blocks = bv.get_basic_blocks_at(addr)
	for block in blocks:
		block.set_auto_highlight(bn.HighlightColor(red=color[0],green=color[1], blue=color[2]))
		block.function.set_auto_instr_highlight(addr,bn.HighlightColor(red=color[0],green=color[1],blue=color[2]))


# Function Dumper
@alert_on_error
@needs_settings
def function_dumper(bv: bn.BinaryView, func: bn.Function):
	dump_data = []
	info(f"Launching function dumper for {func.name}@{hex(func.start)}")

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
	if "return" in msg.keys():
		msg["return"] = int(msg["return"], 16)
	dump_data.append(msg)

# File Dumper
@alert_on_error
@needs_settings
def file_dumper(bv: bn.BinaryView, func: bn.Function):
	dump_data = []
	file_path = bn.interaction.get_text_line_input("File name (substring)","File name to monitor")
	if file_path is None:
		return
	file_path = file_path.decode()

	info(f"Launching file dumper for {file_path}")

	def reporter():
		info("Dumping complete - generating report")
		template = jinja.get_template("file_dumper_report.md.j2")
		report = template.render(bv=bv, func=func, data=dump_data, file_path=file_path)
		bv.show_markdown_report(f"File {file_path} dump", report)

	frida_launcher = FridaLauncher.from_template(bv, "file_dumper.js.j2", func=func, file_path=file_path)
	frida_launcher.on_message_send = [on_function_dumper(bv, func, dump_data)]
	frida_launcher.on_end.append(reporter)
	frida_launcher.start()


@message_handler
def on_function_dumper(msg: dict, data: Optional[bytes], bv: bn.BinaryView, func: bn.Function, dump_data: list):
	if "return" in msg.keys():
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
	info(f"Launching devi analysis for {func.name}@{hex(func.start)}")

	frida_launcher = FridaLauncher.from_template(bv, "devi.js.j2", func=func)
	frida_launcher.on_message_send = [on_devi(bv, func, dump_data)]
	frida_launcher.start()

@message_handler
def on_devi(msg: dict, data: Optional[bytes], bv: bn.BinaryView, func: bn.Function, dump_data: dict):
	#print(msg)
	if "callList" in msg.keys():
		dump_data["callList"].extend(msg["callList"])
	elif "moduleMap" in msg.keys():
		dump_data["modules"] = msg["moduleMap"]
	elif "deviFinished" in msg.keys():
		info("Analysis complete - calling devi plugin")

		import devi as bndevi

		# Disable the load_virtual_calls function that shows the load dialog
		class DeviMuted(bndevi.binja_devi):
			def load_virtual_calls(self):
				pass

		state = bv.begin_undo_actions()
		devi = DeviMuted(bv)
		devi.devirtualize_calls(dump_data["callList"], dump_data["modules"])
		dump_data["callList"] = []
		info("devi plugin done")
		bv.commit_undo_actions(state)

# Log Sniffer
@needs_settings
def log_sniffer(bv: bn.BinaryView):
	info("Launching log sniffer")
	frida_launcher = FridaLauncher.from_template(bv, "log_sniffer.js.j2")
	frida_launcher.start()