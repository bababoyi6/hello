import { registerHooks } from 'node:module';

export function connect() {
  throw new Error('Use a synthetic TCP socket or workerd');
}

registerHooks({
  resolve(specifier, context, next) {
    return specifier === 'cloudflare:sockets' ? { url: import.meta.url, shortCircuit: true } : next(specifier, context);
  },
});
