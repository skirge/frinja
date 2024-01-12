import binaryninja as bn
import binaryninjaui as ui
import Vector35_snippets as snippets
from PySide6.QtWidgets import QDialog
from PySide6.QtCore import QFileInfo
from PySide6.QtGui import QKeySequence
import os

from .log import *

def newFileDialog(cls):
	name_ui = bn.TextLineField("Snippet Name:")
	type_ui = bn.ChoiceField("Snippet Type:", ["Python", "Frinja"])
	form = [
		name_ui,
		type_ui,
	]

	ok = bn.get_form_input(form, "New Snippet")
	snippetName = name_ui.result.strip()

	if type_ui.result == 0 and not snippetName.endswith(".py"):
		snippetName += ".py"
	elif type_ui.result == 1 and not snippetName.endswith(".js.j2"):
		snippetName += ".js.j2"

	if ok and snippetName:
		index = cls.tree.selectionModel().currentIndex()
		selection = cls.files.filePath(index)
		if QFileInfo(selection).isDir():
			path = os.path.join(selection, snippetName)
		else:
			path = os.path.join(snippets.snippetPath, snippetName)
			cls.readOnly(False)
		open(path, "w").close()
		cls.tree.setCurrentIndex(cls.files.index(path))
		debug("Snippets: Snippet %s created." % snippetName)

_includeWalk = snippets.includeWalk
def includeWalk(dir, includeExt):
	result = []
	result.extend(_includeWalk(dir, includeExt))
	result.extend(_includeWalk(dir, ".js.j2"))
	result.extend(_includeWalk(dir, ".js"))
	return result

def loadSnippetFromFile(snippetPath):
	try:
		with snippets.codecs.open(snippetPath, 'r', 'utf-8') as snippetFile:
			snippetText = snippetFile.readlines()
	except:
		return ("", "", "")

	if (len(snippetText) < 3):
		return ("", "", "")

	description = snippetText[0].strip()
	keySequence = snippetText[1].strip()

	comment = "#"
	if snippetPath.endswith(".js.j2"):
		comment = "{#"
	elif snippetPath.endswith(".js"):
		comment = "//"

	if not description.startswith(comment) or not keySequence.startswith(comment):
		return ("", "", "")

	description = description[len(comment):].strip()
	keySequence = keySequence[len(comment):].strip()

	if snippetPath.endswith(".js.j2"):
		# Remove the closing `#}`
		description = description[:-2].strip()
		keySequence = keySequence[:-2].strip()

	qKeySequence = QKeySequence(keySequence)
	if qKeySequence.isEmpty():
		qKeySequence = None
	return (description,
			qKeySequence,
			''.join(snippetText[2:])
	)

_actionFromSnippet = snippets.actionFromSnippet
def actionFromSnippet(snippetPath, description):
	if not snippetPath.endswith(".js.j2") and not snippetPath.endswith(".js"):
		return _actionFromSnippet(snippetPath, description)

	if description:
		return _actionFromSnippet(snippetPath, "[Frinja] " + description)

	return _actionFromSnippet(snippetPath, "[Frinja] " + os.path.basename(snippetPath).rstrip(".js.j2").rstrip(".js"))

_executeSnippet = snippets.executeSnippet
def executeSnippet(code, description):
	if not description.startswith("Snippets\\[Frinja] "):
		return _executeSnippet(code, description)

	class SnippetTask():
		def __init__(self, code, snippetGlobals, context, snippetName="Executing frinja snippet"):
			self.code = code
			self.snippetGlobals = snippetGlobals
			self.context = context
			self.snippetName = snippetName

		def start(self):
			from .frida_launcher import FridaLauncher, jinja
			script = jinja.from_string(self.code).render(self.snippetGlobals)

			info(f"Executing frinja snippet {self.snippetName}")
			debug(script)

			launcher = FridaLauncher(self.snippetGlobals["bv"], script)
			return launcher.start()

	_SnippetTask = snippets.SnippetTask
	snippets.SnippetTask = SnippetTask
	_executeSnippet(code[6:], description)
	snippets.SnippetTask = _SnippetTask

def show(cls: snippets.Snippets):
	QDialog.show(cls)

	# Allow frinja snippets to be edited/selected
	nameFilters = cls.files.nameFilters()
	nameFilters.append("*.js.j2")
	cls.files.setNameFilters(nameFilters)

	# Add correct syntax highlighting
	def loadSnippet():
		if cls.edit.highlighter is None:
			return snippets.Snippets.loadSnippet(cls)

		from pygments.lexers import get_lexer_by_name
		if cls.currentFile.endswith(".js.j2"):
			cls.edit.highlighter.lexer = get_lexer_by_name("javascript+jinja")
			cls.edit.setPlaceholderText("jinja2 javascript code")
		elif cls.currentFile.endswith(".js"):
			cls.edit.highlighter.lexer = get_lexer_by_name("javascript")
			cls.edit.setPlaceholderText("javascript code")
		elif cls.currentFile.endswith(".py"):
			cls.edit.highlighter.lexer = get_lexer_by_name("python")
			cls.edit.setPlaceholderText("python code")

		snippets.Snippets.loadSnippet(cls)
	cls.loadSnippet = loadSnippet

	# Save scripts correctly - with proper comments
	def save():
		if not cls.snippetName.text().endswith(".js.j2") and not cls.snippetName.text().endswith(".js"):
			return snippets.Snippets.save(cls)

		if os.path.basename(cls.currentFile) != cls.snippetName:
			os.unlink(cls.currentFile)
			cls.currentFile = os.path.join(os.path.dirname(cls.currentFile), cls.snippetName.text())

		debug(f"Snippets: Saving frinja script {cls.currentFile}")

		comment = "// {0}\n"
		if cls.currentFile.endswith(".js.j2"):
			comment = "{{# {0} #}}\n"

		outputSnippet = snippets.codecs.open(cls.currentFile, "w", "utf-8")
		outputSnippet.write(comment.format(cls.snippetDescription.text()))
		outputSnippet.write(comment.format(cls.keySequenceEdit.keySequence().toString()))
		outputSnippet.write(cls.edit.toPlainText())
		outputSnippet.close()
	cls.save = save

snippets.Snippets.show = show
# Allows the creation of frinja snippets
snippets.Snippets.newFileDialog = newFileDialog
# Allows frinja scripts to be registered, loaded, etc.
snippets.includeWalk = includeWalk
# Parse scripts correctly
snippets.loadSnippetFromFile = loadSnippetFromFile
# Give a distinct name to frinja snippets
snippets.actionFromSnippet = actionFromSnippet
# Execute frinja snippets
snippets.executeSnippet = executeSnippet

snippets.Snippets.registerAllSnippets()
