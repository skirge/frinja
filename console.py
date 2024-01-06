import binaryninjaui as ui
import json

import frida
from .log import *
from typing import Any, Callable, Mapping, Optional, Tuple, Union
from PySide6.QtWidgets import QVBoxLayout, QTextBrowser, QLineEdit, QLabel, QHBoxLayout
from PySide6.QtGui import QTextCursor

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


class FridaConsoleWidget(ui.GlobalAreaWidget):
	_evaluate: Optional[Callable[[str], Union[bytes, Mapping[Any, Any], Tuple[str, bytes]]]] = None

	def __init__(self, name):
		super().__init__(name)

		layout = QVBoxLayout()

		self.output = QTextBrowser(self)
		layout.addWidget(self.output)

		def appendHtml(self: QTextBrowser, html: str):
			self.moveCursor(QTextCursor.End)
			self.insertHtml("<br/>" + html)
			self.moveCursor(QTextCursor.End)
		setattr(self.output, "appendHtml", appendHtml.__get__(self.output, QTextBrowser))

		hbox = QHBoxLayout()
		hbox.addWidget(QLabel(">"))

		self.input = QLineEdit(self)
		self.input.returnPressed.connect(self.on_input)
		hbox.addWidget(self.input)

		layout.addLayout(hbox)

		self.setLayout(layout)
		self.session_end()

	@alert_on_error
	def on_input(self):
		if not self._evaluate:
			self.output.appendHtml("Internal Error: No evaluate function set")
			return

		text = self.input.text()
		self.input.clear()
		self.output.appendHtml(f"> {text}")

		result = self._evaluate(text)
		self.handle_result(result)

	def session_start(self, evaluate: Callable[[str], Union[bytes, Mapping[Any, Any], Tuple[str, bytes]]]):
		if not evaluate:
			alert("Frinja: No evaluate function set for console on session start")
			return

		self._evaluate = evaluate
		self.input.clear()
		self.input.setReadOnly(False)
		self.input.setFocus()

		self.output.appendHtml("Frida Client v" + str(frida.__version__))
		self.output.appendHtml("Frida Server v" + self._evaluate("Frida.version")[1])

	def session_end(self):
		self.input.setReadOnly(True)
		self.input.setText("Please use the `Start Hooker` command to start a session")
		self._evaluate = None

	def handle_result(self, result: Union[bytes, Mapping[Any, Any], Tuple[str, bytes]]):
		if result[0] == "error":
			error = result[1]
			line = f'<span style="color: red;"><b>{error["name"]}</b></span>: {error["message"]}'

			if "stack" in error.keys():
				message_len = len(error["message"].split("\n"))
				# trim_amount = 6 if self._runtime == "v8" else 7
				trimmed_stack = error["stack"].split("\n")[message_len:-6]
				if len(trimmed_stack) > 0:
					output += "\n" + "\n".join(trimmed_stack)

			self.output.appendHtml(line)
			return

		if isinstance(result, bytes):
			self.output.appendHtml(hexdump(result))
		elif isinstance(result, dict):
			warn(f"dict instance {str(result)}")
		elif result[0] in ("function", "undefined", "null"):
			self.output.appendHtml(result[0])
		else:
			self.output.appendHtml(json.dumps(result[1], sort_keys=True, indent=4, separators=(",", ": ")))

	def handle_log(self, level: str, text: str):
		line = text

		if level == "debug":
			line = f'<span style="color: gray;">[d]</span> <i>{text}</i>'
		elif level == "info":
			line = f'<span style="color: blue;">[i]</span> {text}'
		elif level == "warn":
			line = f'<span style="color: yellow;">[!]</span> {text}'
		elif level == "error":
			line = f'<span style="color: red;"><b>[x]</b> {text}</span>'

		self.output.appendHtml(line)


CONSOLE = FridaConsoleWidget("Frida Console")
