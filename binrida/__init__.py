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
import psutil
import frida
from .FridaHandler import FridaHandler
from .output import *
from jinja2 import Environment, FileSystemLoader, select_autoescape
env = Environment(
    loader=FileSystemLoader(bn.user_plugin_path() + "/BinRida/templates"),
    autoescape=select_autoescape()
)

SETTINGS = {}

def SettingsGUI(bv,action=None,extra_settings=None):
    ## Frida devices enumeration
    devices     = frida.enumerate_devices()
    f_dev       = bn.ChoiceField('Device\t', [a.id for a in devices], SETTINGS['dev_id'] if 'dev_id' in SETTINGS.keys() else None)
    ## TODO:: TCP GUI
    f_appName   = bn.TextLineField('Application\t', SETTINGS['name'] if 'name' in SETTINGS.keys() else None)
    cmdLine     = bn.TextLineField('Command line\t', SETTINGS['cmd'] if 'cmd' in SETTINGS.keys() else None)
    spawn       = bn.ChoiceField('Execution mode\t', ['Spawn a new process', 'Attacch to PID'], SETTINGS['spawn'] if 'spawn' in SETTINGS.keys() else None)
    pid         = []

    ## I don't know if it is usefull or it is a problem... for example, remote attach
    for i in psutil.process_iter(attrs=['pid','name']):
        pid.append(i.info['name'] + ' (' + str(i.info['pid']) + ')')

    f_pid       = bn.ChoiceField('PID\t', pid, SETTINGS['pid'] if 'pid' in SETTINGS.keys() else None)
    form        = [bn.LabelField('Frida general settings'), bn.SeparatorField(),f_dev,f_appName,cmdLine,spawn,f_pid]
    if extra_settings != None:
        form += [bn.SeparatorField(), bn.LabelField(action)] + extra_settings
    ret = bn.interaction.get_form_input(form, 'BinRida')

    ## Global settings
    if ret:
        SETTINGS['dev'] = devices[f_dev.result]
        SETTINGS['dev_id'] = f_dev.result
        SETTINGS['name'] = f_appName.result.strip()
        SETTINGS['pid'] = int(pid[f_pid.result].split('(')[1][:-1])
        #  0 for spawn, 1 else
        SETTINGS['spawn'] = spawn.result
        SETTINGS['cmd'] = cmdLine.result

    return ret,SETTINGS

def start_stalking(bv,addr = None):
    colors = [bn.HighlightStandardColor.BlueHighlightColor, bn.HighlightStandardColor.CyanHighlightColor, 	bn.HighlightStandardColor.GreenHighlightColor,bn.HighlightStandardColor.MagentaHighlightColor, bn.HighlightStandardColor.OrangeHighlightColor, bn.HighlightStandardColor.RedHighlightColor, bn.HighlightStandardColor.WhiteHighlightColor,bn.HighlightStandardColor.YellowHighlightColor]
    f_colors = bn.ChoiceField('Highlight color\t',[ a.name for a in colors])
    extra_settings = [f_colors]
    ret,settings = SettingsGUI(bv,'Stalker',extra_settings)

    if not ret:
        return

    execute = bv.file.original_filename
    if settings['name'] != "":
        execute = settings['name']

    bn.log.log_info("Start '" + execute + ' ' + settings['cmd'] + "' on " + settings['dev'].id + ' device ')
    data = {}

    ## Set the device
    data['device'] = settings['dev']

    ## Command to spawn
    data['execute'] = [execute]
    if settings['cmd'] != "":
        for i in settings['cmd'].split(' '):
            data['execute'].append(i)

    ## Spawning
    spawn = True
    if settings['spawn'] == 1:
        data['pid'] = settings['pid']
        spawn = False

    ## Preparing block
    data['maps'] = []
    data['blocks'] = []
    data['functions'] = bv.functions if addr == None else [addr]

    stalker = FridaHandler(data, bv.file.original_filename, spawn, 'stalk')
    stalker.start()

    bn.show_message_box('Frida running', 'Press OK button to terminate.')

    stalker.cancel()
    stalker.join()

    colorize(data, colors[f_colors.result], bv)

def start_dump(bv, funct):
    extra_settings = []
    for i in funct.parameter_vars:
        f = bn.LabelField("'" + i.name + "'")
        extra_settings.append(f)

    extra_settings.append(bn.MultilineTextField('Dumping data. v_args[NAME] is printed in report'))
    ret,settings = SettingsGUI(bv,'Dump function contents',extra_settings)
    if not ret:
        return

    execute = bv.file.original_filename
    if settings['name'] != "":
        execute = settings['name']

    bn.log.log_info("Start '" + execute + ' ' + settings['cmd'] + "' on " + settings['dev'].id + ' device ')
    data = {}

    ## Set the device
    data['device'] = settings['dev']

    ## Command to spawn
    data['execute'] = [execute]
    if settings['cmd'] != "":
        for i in settings['cmd'].split(' '):
            data['execute'].append(i)

    ## Spawning
    spawn = True
    if settings['spawn'] == 1:
        data['pid'] = settings['pid']
        spawn = False

    ## Preparing block
    data['dump'] = []
    data['maps'] = []
    data['functions'] = funct
    data['arguments'] = extra_settings[-1].result

    stalker = FridaHandler(data,bv.file.original_filename,spawn,'dump')
    stalker.start()

    bn.show_message_box('Frida running','Press OK button to terminate.')

    stalker.cancel()
    stalker.join()

    CreateMarkdownReport(bv, funct, data)

def start_instrumentation(bv,address):
    ## TODO: Check the instrumented instruction. Frida has problem with some instruction
    f = bv.get_functions_containing(address)
    f_function = bn.LabelField('Container function\t' + f[0].name)
    f_funct = bn.LabelField('Instrumented instruction\t' + bv.get_disassembly(address))
    f_script = bn.MultilineTextField("Frida script\t")

    extra_settings = [f_function, f_funct, f_script]
    ret,settings = SettingsGUI(bv, 'Instrumentation', extra_settings)

    if not ret:
        return

    execute = bv.file.original_filename
    if settings['name'] != "":
        execute = settings['name']

    bn.log.log_info("Start '" + execute + ' ' + settings['cmd'] + "' on " + settings['dev'].id + ' device ')
    data = {}

    ## Set the device
    data['device'] = settings['dev']

    ## Command to spawn
    data['execute'] = [execute]
    if settings['cmd'] != "":
        for i in settings['cmd'].split(' '):
            data['execute'].append(i)

    ## Spawning
    spawn = True
    if settings['spawn'] == 1:
        data['pid'] = settings['pid']
        spawn = False

    ## Stalker data
    data['maps'] = []
    data['functions'] = [f[0].start, address]
    data['script'] = f_script.result

    stalker = FridaHandler(data, bv.file.original_filename, spawn, 'instr')
    stalker.start()

    bn.show_message_box('Frida running', 'Press OK button to terminate.')

    stalker.cancel()
    stalker.join()

LOG_SCRIPT = ""
LOG_TAG_TYPE = "BinRida Instrumented"
def mark_log(bv: bn.BinaryView, func: bn.Function):
    if not bv.get_tag_type(LOG_TAG_TYPE):
        bv.create_tag_type(LOG_TAG_TYPE, "📜")

    if not func.get_function_tags(True, LOG_TAG_TYPE):
        func.add_tag(LOG_TAG_TYPE, "Log function calls", None)
        bn.log.log_info(f"Function {func.name} marked for logging", "BinRida")

def _get_functions_by_tag(bv, tag):
    return [f for f in bv.functions if f.get_function_tags(True, tag)]

def start_frida(bv: bn.BinaryView):
    ret, settings = SettingsGUI(bv, 'Instrumentation', [])

    log_targets = _get_functions_by_tag(bv, LOG_TAG_TYPE)
    bn.log.log_info(f"Logging the following functions: " + ",".join([f.name for f in log_targets]), "BinRida")
    template = env.get_template("logger.js.j2")
    script = template.render(targets=log_targets, bv=bv)

    data = {}
    data["script"] = script
    data["maps"] = []

    ## Set the device
    data['device'] = settings['dev']

    execute = bv.file.original_filename
    if settings['name'] != "":
        execute = settings['name']

    ## Command to spawn
    data['execute'] = [execute]
    if settings['cmd'] != "":
        for i in settings['cmd'].split(' '):
            data['execute'].append(i)

    ## Spawning
    spawn = True
    if settings['spawn'] == 1:
        data['pid'] = settings['pid']
        spawn = False

    stalker = FridaHandler(data, bv.file.original_filename, spawn, 'script')
    stalker.start()

    bn.show_message_box('Frida running','Press OK button to terminate.')

    stalker.cancel()
    stalker.join()
