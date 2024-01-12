import binaryninja as bn
import binaryninjaui as ui
import Vector35_snippets as snippets
from PySide6.QtWidgets import QDialog
from PySide6.QtCore import QFileInfo
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

# def includeWalk(dir, includeExt):
	# return snippets.includeWalk(dir, includeExt).extend(snippets.includeWalk(dir, ".js.j2"))

def show(cls: snippets.Snippets):
	QDialog.show(cls)

	# Allow frinja snippets to be edited/selected
	nameFilters = cls.files.nameFilters()
	nameFilters.append("*.js.j2")
	cls.files.setNameFilters(nameFilters)

	# Don't nag during file save
	# cls.snippetName.text().endswith = lambda self, x: True if x == ".js.j2" else str.endswith(self, x)

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

snippets.Snippets.show = show
# Allows the creation of frinja snippets
snippets.Snippets.newFileDialog = newFileDialog
