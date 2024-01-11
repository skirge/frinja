from threading import Thread
import binaryninjaui as ui
import json

import frida

# from .frida_launcher import FridaLauncher
from .log import *
from .settings import SETTINGS, Settings
from html import escape
from typing import Any, Callable, Mapping, Optional, Tuple, Union
from PySide6.QtWidgets import QVBoxLayout, QTextBrowser, QLineEdit, QLabel, QHBoxLayout
from PySide6.QtGui import QTextCursor
from PySide6.QtCore import Qt, Signal, SignalInstance

# Got from https://github.com/frida/frida-tools/blob/main/frida_tools/repl.py#L1188
def hexdump(src, length: int = 16) -> str:
	FILTER = "".join([(len(repr(chr(x))) == 3) and chr(x) or "." for x in range(256)])
	lines = []
	for c in range(0, len(src), length):
		chars = src[c : c + length]
		hex = " ".join(["%02x" % x for x in iter(chars)])
		printable = "".join(["%s" % ((x <= 127 and FILTER[x]) or ".") for x in iter(chars)])
		lines.append("%04x  %-*s  %s\n" % (c, length * 3, hex, printable))
	return "".join(lines).rstrip("\n")


class HistoryLineEdit(QLineEdit):
	def __init__(self, parent=None):
		super().__init__(parent)
		self.history = []
		self.history_pos = -1

	def keyPressEvent(self, event):
		if event.key() == Qt.Key.Key_Up:
			if self.history_pos < len(self.history) - 1:
				self.history_pos += 1
				self.setText(self.history[self.history_pos])
		elif event.key() == Qt.Key.Key_Down:
			if self.history_pos > 0:
				self.history_pos -= 1
				self.setText(self.history[self.history_pos])
			else:
				self.history_pos = -1
				self.clear()
		else:
			super().keyPressEvent(event)

	def loadHistory(self):
		self.history = SETTINGS.console_history
		self.history_pos = -1

	def addToHistory(self, command):
		try:
			self.history.remove(command)
		except ValueError:
			pass

		self.history_pos = -1
		self.history.insert(0, command)

		if len(self.history) > 4096:
			self.history = self.history[:4096]

		SETTINGS.console_history = self.history


class FridaConsoleWidget(ui.GlobalAreaWidget):
	_evaluate: Optional[Callable[[str], Union[bytes, Mapping[Any, Any], Tuple[str, bytes]]]] = None
	input: HistoryLineEdit
	output: QTextBrowser

	settings: Settings
	bv: bn.BinaryView

	def __init__(self):
		super().__init__("Frida Console")

		layout = QVBoxLayout()

		self.output = QTextBrowser(self)
		layout.addWidget(self.output)

		def appendHtml(self: QTextBrowser, html: str):
			if not isinstance(html, str):
				alert(f"appendHtml called with non-string argument: {str(html)}")
				return

			self.moveCursor(QTextCursor.End)
			self.insertHtml("<br/>" + html)
			self.moveCursor(QTextCursor.End)
		setattr(self.output, "appendHtml", appendHtml.__get__(self.output, QTextBrowser))

		hbox = QHBoxLayout()
		hbox.addWidget(QLabel(">"))

		self.input = HistoryLineEdit(self)
		self.input.returnPressed.connect(self.on_input_handler)
		hbox.addWidget(self.input)

		layout.addLayout(hbox)
		self.setLayout(layout)

		self.session_end()

	@alert_on_error
	def on_input_handler(self):
		if not self._evaluate:
			self.output.appendHtml("Internal Error: No evaluate function set")
			return

		text = self.input.text()
		self.input.addToHistory(text)
		self.input.clear()
		self.output.appendHtml(f"> {text}")

		result = self._evaluate(text)
		self.handle_result(result)
		@alert_on_error
		def eval_bg():
			result = self._evaluate(text)
			bn.execute_on_main_thread_and_wait(lambda: self.handle_result(result))

		Thread(target=eval_bg).start()

	def session_start(self, evaluate: Callable[[str], Union[bytes, Mapping[Any, Any], Tuple[str, bytes]]]):
		if not evaluate:
			alert("Frinja: No evaluate function set for console on session start")
			return

		self._evaluate = evaluate
		self.input.clear()
		self.input.loadHistory()
		self.input.setReadOnly(False)
		self.input.setFocus()

		self.output.appendHtml("Frida Client v" + str(frida.__version__))
		self.output.appendHtml("Frida Client v" + evaluate("Frida.version")[1])

	def session_end(self):
		self.input.setReadOnly(True)
		self.input.setText("Please use the `Start Hooker` command to start a session")
		self._evaluate = None
		self.input.history = []

	def handle_result(self, result: Union[bytes, Mapping[Any, Any], Tuple[str, bytes]]):
		if result[0] == "error":
			error = result[1]
			line = f'<span style="color: red;"><b>{escape(error["name"])}</b></span>: {escape(error["message"])}'

			if "stack" in error.keys():
				message_len = len(error["message"].split("\n"))
				# trim_amount = 6 if self._runtime == "v8" else 7
				trimmed_stack = error["stack"].split("\n")[message_len:-6]
				if len(trimmed_stack) > 0:
					output += "\n" + "\n".join(trimmed_stack)

			self.output.appendHtml(line)
			return

		if isinstance(result, bytes):
			self.output.appendHtml(escape(hexdump(result)))
		elif isinstance(result, dict):
			warn(f"dict instance {str(result)}")
		elif result[0] in ("function", "undefined", "null"):
			self.output.appendHtml(escape(result[0]))
		else:
			self.output.appendHtml(escape(json.dumps(result[1], sort_keys=True, indent=4, separators=(",", ": "))))

	def handle_log(self, level: str, text: str):
		line = text

		if level == "debug":
			line = f'<span style="color: gray;"><b>[d]</b></span> <i>{escape(text)}</i>'
		elif level == "info":
			line = f'<span style="color: blue;"><b>[+]</b></span> {escape(text)}'
		elif level == "warning":
			line = f'<span style="color: yellow;"><b>[!]</b></span> {escape(text)}'
		elif level == "error":
			line = f'<span style="color: red;"><b>[x]</b> {escape(text)}</span>'

		self.output.appendHtml(line)

	def handle_message(self, msg: frida.core.ScriptMessage, data: Optional[bytes]):
		print("handle", msg)
		if msg["type"] == "error":
			self.output.appendHtml(f"<span style='color: red;'><b>{escape(msg['description'])}</b></span>")
			if msg["stack"]:
				self.output.appendHtml("<span style='color: red;>" + "<br/>".join(escape(msg["description"]).split("\\n")) + "</span>")

			return

		self.output.appendHtml(escape("< " + msg["payload"]))


CONSOLE = FridaConsoleWidget()
