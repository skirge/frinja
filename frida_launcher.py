import time
from typing import List, Optional
import frida
import binaryninja as bn

from .console import CONSOLE
from .settings import ExecutionAction, SETTINGS
from .log import *
from .helper import PLUGIN_PATH
from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_PATH = PLUGIN_PATH / "templates"
FRIDA_RELOADER: Callable[[], None] = lambda: None

jinja = Environment(
	loader=FileSystemLoader(TEMPLATES_PATH),
	autoescape=select_autoescape()
)


class FridaLauncher(bn.BackgroundTaskThread):
	bv: bn.BinaryView
	script_source: str

	on_log: List[Callable[[str, str], None]]
	on_destroyed: List[Callable[[], None]]
	on_detached: List[Callable[[str], None]]
	on_start: List[Callable[[Callable[[str], str]], None]]
	on_end: List[Callable[[], None]]
	on_message: List[Callable[[frida.core.ScriptMessage, Optional[bytes]], None]]
	on_message_send: List[Callable[[frida.core.ScriptPayloadMessage, Optional[bytes]], None]]
	on_message_error: List[Callable[[frida.core.ScriptErrorMessage], None]]

	session: Optional[frida.core.Session]
	script: Optional[frida.core.Script]
	evaluate: Optional[Callable[[str], str]]

	def __init__(self, bv: bn.BinaryView, script: str):
		global FRIDA_RELOADER
		super().__init__("Frinja initializing", True)

		FRIDA_RELOADER = lambda: None
		self.script_source = script
		self.bv = bv
		self.script = None
		self.session = None
		self.evaluate = None
		SETTINGS.restore(bv)

		self.on_log = [CONSOLE.handle_log]
		self.on_destroyed = []
		self.on_detached = []
		self.on_start = [CONSOLE.session_start]
		self.on_end = [CONSOLE.session_end]
		self.on_message = []
		self.on_message_send = [lambda msg, _: CONSOLE.handle_message(msg)]
		self.on_message_error = [CONSOLE.handle_error]

	@staticmethod
	def from_template(bv: bn.BinaryView, template_name: str, **kwargs):
		template = jinja.get_template(template_name)
		script = template.render(settings=SETTINGS, bv=bv, **kwargs)
		return FridaLauncher(bv, script)

	def replace_script_from_template(self, template_name: str, **kwargs):
		template = jinja.get_template(template_name)
		script = template.render(settings=SETTINGS, bv=self.bv, **kwargs)
		return self.replace_script(script)

	def replace_script(self, script: str) -> bool:
		if self.session is None:
			return False

		if self.script is None:
			info("Loading script")
			self.progress = "Loading script"
		else:
			info("Reloading script")
			self.progress = "Reloading script"
			self.script.unload()

			bn.execute_on_main_thread(lambda: CONSOLE.output.appendHtml("<br/>=== Script reloaded ===<br/>"))

		# Print the script (very useful for debugging)
		debug("\n".join([f"{n + 1}: {l}" for n, l in enumerate(script.split("\n"))]))

		# Create the script with the repl code injected
		repl_script = open(TEMPLATES_PATH / "repl.js").read()
		self.script = self.session.create_script(repl_script + "\n\n" + script)

		# Intialize the callback handlers
		def on_destroyed():
			for f in self.on_destroyed:
				bn.execute_on_main_thread(f)
			# self.cancel()

		def on_message(msg: frida.core.ScriptMessage, data: Optional[bytes]):
			for f in self.on_message:
				bn.execute_on_main_thread(lambda: f(msg, data))

			if msg["type"] == "error":
				for f in self.on_message_error:
					bn.execute_on_main_thread(lambda: f(msg))
			elif msg["type"] == "send":
				for f in self.on_message_send:
					bn.execute_on_main_thread(lambda: f(msg, data))

		def on_log(level: str, text: str):
			for f in self.on_log:
				bn.execute_on_main_thread(lambda: f(level, text))

		self.script.set_log_handler(on_log)
		self.script.on("destroyed", on_destroyed)
		self.script.on("message", on_message)
		self.script.load()
		self.evaluate = self.script.exports_sync.evaluate # RPC export defined in repl.js

		self.progress = "Frinja running..."

	def run(self):
		if SETTINGS.device is None:
			alert("Please select a device from the settings")

		# Prepare the callback handlers
		def on_detached(reason):
			info("Detached from process")
			for f in self.on_detached:
				bn.execute_on_main_thread(lambda: f(reason))
			self.cancel()

		# Add the session & script finalizer
		def finish_script():
			if SETTINGS.exec_action != ExecutionAction.SPAWN:
				self.script.unload()
				self.session.detach()
			else:
				try:
					SETTINGS.device.kill(pid)
					info("Process killed")
				except frida.ProcessNotFoundError:
					info("Process already finished")
		self.on_end.append(finish_script)

		# Find (or create) the process
		pid = 0
		if SETTINGS.exec_action == ExecutionAction.SPAWN:
			# TODO: Allow tinkering with the env, stdio and cwd
			pid = SETTINGS.device.spawn(SETTINGS.file_target, SETTINGS.cmdline.split(" "))
			info(f"Spawned {SETTINGS.file_target} with arguments `{SETTINGS.cmdline}` that got PID {pid}")
		elif SETTINGS.exec_action == ExecutionAction.ATTACH_NAME:
			pid = SETTINGS.attach_name
		elif SETTINGS.exec_action == ExecutionAction.ATTACH_PID:
			pid = SETTINGS.attach_pid
		else:
			alert("Frinja: Unknown execution action")
		info(f"Attaching to {pid}")

		# Initialize the frida session
		self.session = SETTINGS.device.attach(pid)
		self.session.on("detached", on_detached)

		# Load the script
		self.replace_script(self.script_source)

		# Resume the process and connect to the REPL
		if SETTINGS.exec_action == ExecutionAction.SPAWN:
			SETTINGS.device.resume(pid)

		for f in self.on_start:
			bn.execute_on_main_thread(lambda: f(self.evaluate, self.cancel))

		while True:
			if self.cancelled or self.finished:
				break
			time.sleep(1)

	def _finalizer(self):
		# global FRIDA_RELOADER
		self.progress = "Frinja cleaning up"

		# FRIDA_RELOADER = lambda: None
		bn.execute_on_main_thread(lambda: CONSOLE.output.appendHtml("<br/>=== Script finished ===<br/>"))
		for f in self.on_end:
			bn.execute_on_main_thread(f)

		# SETTINGS.store(self.bv)

	def finish(self):
		self._finalizer()
		super().finish()
