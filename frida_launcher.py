import time
from typing import Any, Mapping, Optional, Tuple, Union
import frida
import binaryninja as bn
from .console import CONSOLE
from .settings import ExecutionAction, Settings
from .log import *
from jinja2 import Environment, FileSystemLoader, select_autoescape
jinja = Environment(
	loader=FileSystemLoader(bn.user_plugin_path() + "/frinja/templates"),
	autoescape=select_autoescape()
)

class FridaLauncher(bn.BackgroundTaskThread):
	script: str
	settings: Settings
	callback: Optional[frida.core.ScriptMessageCallback]

	def __init__(self, settings: Settings, script: str, callback: Optional[frida.core.ScriptMessageCallback] = None):
		super().__init__("Frinja initializing", True)
		self.script = script
		self.settings = settings
		self.callback = callback

	@staticmethod
	def from_template(settings: Settings, template: str, callback: Optional[frida.core.ScriptMessageCallback] = None, **kwargs):
		template = jinja.get_template(template)
		script = template.render(**kwargs)
		print("\n".join([f"{i + 1}: {l}" for i, l in enumerate(script.split("\n"))]))
		return FridaLauncher(settings, script, callback=callback)

	@alert_on_error
	def run(self):
		if self.settings.device is None:
			alert("Please select a device from the settings")

		pid = 0
		if self.settings.exec_action == ExecutionAction.SPAWN:
			# TODO: Allow tinkering with the env, stdio and cwd
			pid = self.settings.device.spawn(self.settings.file_target, self.settings.cmdline.split(" "))
			info(f"Spawned {self.settings.file_target} with arguments `{self.settings.cmdline}` that got PID {pid}")
		elif self.settings.exec_action == ExecutionAction.ATTACH_NAME:
			pid = self.settings.attach_name
		elif self.settings.exec_action == ExecutionAction.ATTACH_PID:
			pid = self.settings.attach_pid
		else:
			alert("Frinja: Unknown execution action")

		def on_detached(reason):
			CONSOLE.session_end()
			info(f"Script detached: {reason}")
			self.finish()

		def on_destroyed():
			CONSOLE.session_end()
			info("Script destroyed")
			self.finish()

		def on_message(msg, data):
			debug(f"Message received: {msg} {data}")
			if self.callback:
				self.callback(msg, data)

		info(f"Attaching to {pid}")

		session = self.settings.device.attach(pid)
		session.on("detached", on_detached)

		script = session.create_script(self.script + "\n\n" + open(bn.user_plugin_path() + "/frinja/templates/repl.js").read())
		script.set_log_handler(CONSOLE.handle_log)

		script.on("destroyed", on_destroyed)
		script.on("message", on_message)

		info("Loading script")
		debug(self.script)
		script.load()

		if self.settings.exec_action == ExecutionAction.SPAWN:
			self.settings.device.resume(pid)

		self.progress = "Frinja running..."
		CONSOLE.session_start(script.exports_sync.evaluate)

		while True:
			if self.cancelled or self.finished:
				break
			time.sleep(1)

		if not self.settings.exec_action == ExecutionAction.SPAWN:
			return

		try:
			self.settings.device.kill(pid)
			info("Process killed")
		except frida.ProcessNotFoundError:
			info("Process already finished")
