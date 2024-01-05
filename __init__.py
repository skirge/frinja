'''
binrida.py - Stalk,dump and instrumentation with Frida

Copyright (c) 2019 Andrea Ferraris

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
'''
import binaryninja as bn
from .settings import Settings
from .actions import *

settings = Settings()
bn.PluginCommand.register("Frinja\Settings", "Set up Frinja to your liking", settings.show)
bn.PluginCommand.register_for_function("Frinja\Hook Function", "Mark function for hooking during run", mark_hooked)
bn.PluginCommand.register("Frinja\Run Hooker", "Start frida with the given settings and the hooker script", frida_start(settings))
bn.PluginCommand.register_for_function("Frinja\Inspect Function Paths", "Highlight the code paths that the functions takes", function_inspector(settings))
bn.PluginCommand.register_for_function("Frinja\Dump Function Context", "Create a report of all the function calls and returns", function_dumper(settings))
