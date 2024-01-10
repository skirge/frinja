import time
from typing import Any, Mapping, Optional, Tuple, Union
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

class FridaLauncher(bn.BackgroundTask):
	bv: bn.BinaryView
	script: str

	on_log: SignalInstance
	# on_destroyed: SignalInstance
	# on_detached: SignalInstance
	on_start: Optional[SignalInstance]
	on_end: Optional[SignalInstance]
	on_message: Optional[SignalInstance]
	on_message_send: Optional[SignalInstance]
	on_message_error: Optional[SignalInstance]
	_evaluate: Optional[Callable[[str], str]]

	def __init__(self, bv: bn.BinaryView, script: str):
		super().__init__("Frinja initializing", True)

		self.script = script
		self.bv = bv
		SETTINGS.restore(bv)

		self.on_log = None
		self.on_start = None
		self.on_end = None
		self.on_message = None
		self.on_message_send = None
		self.on_message_error = None
		self._evaluate = None

	def finalizer(self):
		SETTINGS.store(self.bv)

	def cancel(self):
		warn("Cancelled")
		super().cancel()

	def finish(self):
		warn("Finished")
		super().finish()

	@staticmethod
	def from_template(bv: bn.BinaryView, template_name: str, **kwargs):
		template = jinja.get_template(template_name)
		script = template.render(settings=SETTINGS, bv=bv, **kwargs)

		print("\n".join([f"{i + 1}: {l}" for i, l in enumerate(script.split("\n"))]))

		return FridaLauncher(bv, script)

	def input_signal(self, signal: SignalInstance):
		signal.connect(self.on_input)

	def on_input(self, text: str):
		if self._evaluate:
			self._evaluate(text)

	# @alert_on_error
	def run(self):
		if SETTINGS.device is None:
			alert("Please select a device from the settings")

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

		def on_detached(reason):
			info(f"Script detached: {reason}")
			# self.on_end.emit()
			CONSOLE.session_end()
			self.finish()

		def on_destroyed():
			info("Script destroyed")
			# self.on_end.emit()
			CONSOLE.session_end()
			self.finish()

		def on_message(msg: frida.core.ScriptMessage, data: Optional[bytes]):
			# self.on_message.emit(msg)
			info(f"Message received: {msg} {data}")

			# if msg["type"] == "error":
				# error(msg["stack"])
				# self.on_message_error.emit(msg)
			# elif msg["type"] == "send":
				# CONSOLE.handle_result(msg["payload"])
				# self.on_message_send.emit(msg)

		info(f"Attaching to {pid}")

		session = SETTINGS.device.attach(pid)
		session.on("detached", on_detached)

		script = session.create_script(self.script + "\n\n" + open(TEMPLATES_PATH / "repl.js").read())
		# script.set_log_handler(lambda level, text: self.on_log.emit(level, text))
		script.set_log_handler(CONSOLE.handle_log)

		script.on("destroyed", on_destroyed)
		script.on("message", on_message)

		info("Loading script")
		script.load()

		if SETTINGS.exec_action == ExecutionAction.SPAWN:
			SETTINGS.device.resume(pid)

		self.progress = "Frinja running..."
		# self.on_start.emit()
		self._evaluate = script.exports_sync.evaluate
		CONSOLE.session_start(self._evaluate)

		# while True:
		# 	if self.cancelled or self.finished:
		# 		break
		# 	time.sleep(1)

		# self.on_end.emit()

		# if SETTINGS.exec_action != ExecutionAction.SPAWN:
		# 	script.unload()
		# 	session.detach()
		# 	return

		# try:
		# 	SETTINGS.device.kill(pid)
		# 	info("Process killed")
		# except frida.ProcessNotFoundError:
		# 	info("Process already finished")
