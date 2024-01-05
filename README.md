# Frinja

Author: **Dimitris Zervas**

Frida plugin for binary ninja.

A set of jinja-enabled frida scripts using the context of binary ninja's static analysis.

This is a continuation of the [BinRida](https://github.com/c3r34lk1ll3r/BinRida) plugin by @[c3r34lk1ll3r](https://github.com/c3r34lk1ll3r).

## Usage

First of all you'll need to go to `Plugins > Frinja > Settings` to set up the frida
connection and the application to be instrumented.

Afterwards you can use any available commands - the `Hook Function` and `Run Hooker`
commands are explained [below](#hooker)

### Dump Function Context

It hooks and gathers all calls and returns of the focused function and generates
a markdown report with the following information:

- Callee address
- Thread ID
- Arguments (tries to dereference pointers, read strings and numbers)
- Return value
- Register values

### Inspect Function Paths

A code coverage tracer for the focused function that highlights the executed basic blocks

## Hooker

The main show of this plugin is the `Run Hooker` command. It allows you to trace
and tamper with the execution of the application.

After a function is marked with the `Hook Function` command (or any function with
the `Frinja Hooked` tag) all its calls and returns will get logged in the log pane.

There's also the ability to add pre and post hooks to the function as well as altering
the return value.

To do so a function comment should be added in the following format:

```text
@prehook: <prehook js code>
@posthook: <posthook js code>
@ret: <return value>
```

The return value can be any kind of valid javascript expression

## License

This plugin is released under a MIT license.
