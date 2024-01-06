// From https://github.com/frida/frida-tools/blob/main/frida_tools/repl.py
rpc.exports = {
	evaluate(expression) {
		try {
			const result = eval(expression);
			if (result instanceof ArrayBuffer) {
				return result;
			} else {
				const type = (result === null) ? 'null' : typeof result;
				return [type, result];
			}
		} catch (e) {
			return ['error', {
				name: e.name,
				message: e.message,
				stack: e.stack
			}];
		}
	},
}

// Object.defineProperty(rpc, 'exports', {
// 	get() {
// 		return rpcExports;
// 	},
// 	set(value) {
// 		for (const [k, v] of Object.entries(value)) {
// 			rpcExports[k] = v;
// 		}
// 	}
// });
