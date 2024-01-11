import time
from typing import Any, List, Mapping, Optional, Tuple, Union
import frida
import binaryninja as bn

from .console import CONSOLE
from .settings import ExecutionAction, SETTINGS
from .log import *
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
from PySide6.QtCore import SignalInstance

TEMPLATES_PATH = Path(bn.user_plugin_path()) / "frinja" / "templates"

mgr = bn.RepositoryManager()
for repo in mgr.repositories:
	if any([x.path == "dzervas_frinja" and x.installed for x in repo.plugins]):
		TEMPLATES_PATH = Path(repo.full_path) / "dzervas_frinja" / "templates"
		break

jinja = Environment(
	loader=FileSystemLoader(TEMPLATES_PATH),
	autoescape=select_autoescape()
)


class FridaLauncher(bn.BackgroundTaskThread):
	bv: bn.BinaryView
	script: str

	on_log: List[Callable[[str, str], None]]
	on_destroyed: List[Callable[[], None]]
	on_detached: List[Callable[[str], None]]
	on_start: List[Callable[[Callable[[str], str]], None]]
	on_end: List[Callable[[], None]]
	on_message: List[Callable[[frida.core.ScriptMessage, Optional[bytes]], None]]
	on_message_send: List[Callable[[frida.core.ScriptPayloadMessage], None]]
	on_message_error: List[Callable[[frida.core.ScriptErrorMessage], None]]

	def __init__(self, bv: bn.BinaryView, script: str):
		super().__init__("Frinja initializing", True)

		self.script = script
		self.bv = bv
		SETTINGS.restore(bv)

		self.on_log = [CONSOLE.handle_log]
		self.on_destroyed = []
		self.on_detached = []
		self.on_start = [CONSOLE.session_start]
		self.on_end = [CONSOLE.session_end]
		self.on_message = [CONSOLE.handle_message]
		self.on_message_send = []
		self.on_message_error = []

	@staticmethod
	def from_template(bv: bn.BinaryView, template_name: str, **kwargs):
		template = jinja.get_template(template_name)
		script = template.render(settings=SETTINGS, bv=bv, **kwargs)

		print("\n".join([f"{i + 1}: {l}" for i, l in enumerate(script.split("\n"))]))

		return FridaLauncher(bv, script)

	def run(self):
		if SETTINGS.device is None:
			alert("Please select a device from the settings")

		# Prepare the callback handlers
		def on_detached(reason):
			for f in self.on_detached:
				bn.execute_on_main_thread(lambda: f(reason))
			self.cancel()

		def on_destroyed():
			for f in self.on_destroyed:
				bn.execute_on_main_thread(f)
			self.cancel()

		def on_message(msg: frida.core.ScriptMessage, data: Optional[bytes]):
			for f in self.on_message:
				bn.execute_on_main_thread(lambda: f(msg, data))

			if msg["type"] == "error":
				for f in self.on_message_error:
					bn.execute_on_main_thread(lambda: f(msg))
			elif msg["type"] == "send":
				for f in self.on_message_send:
					bn.execute_on_main_thread(lambda: f(msg))

		def on_log(level: str, text: str):
			for f in self.on_log:
				bn.execute_on_main_thread(lambda: f(level, text))

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
		session = SETTINGS.device.attach(pid)
		session.on("detached", on_detached)

		# Load the script
		script = session.create_script(self.script + "\n\n" + open(TEMPLATES_PATH / "repl.js").read())
		script.set_log_handler(on_log)
		script.on("destroyed", on_destroyed)
		script.on("message", on_message)
		info("Loading script")
		script.load()

		# Add the session & script finalizer
		def finish_script():
			if SETTINGS.exec_action != ExecutionAction.SPAWN:
				script.unload()
				session.detach()
			else:
				try:
					SETTINGS.device.kill(pid)
					info("Process killed")
				except frida.ProcessNotFoundError:
					info("Process already finished")
		self.on_end.append(finish_script)

		# Resume the process and connect to the REPL
		if SETTINGS.exec_action == ExecutionAction.SPAWN:
			SETTINGS.device.resume(pid)

		self.progress = "Frinja running..."
		evaluate = script.exports_sync.evaluate # RPC export defined in repl.js

		for f in self.on_start:
			bn.execute_on_main_thread(lambda: f(evaluate))

		while True:
			if self.cancelled or self.finished:
				break
			time.sleep(1)

	def _finalizer(self):
		self.progress = "Frinja cleaning up"
		for f in self.on_end:
			bn.execute_on_main_thread(f)

		SETTINGS.store(self.bv)

	def finish(self):
		self._finalizer()
		super().finish()
