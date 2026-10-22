'use strict';
const http = require('node:http');
const https = require('node:https');
const security = require('./security/server.cjs');
function patch(transport) {
  const original = transport.createServer;
  transport.createServer = function (...args) {
    const last = args.length - 1;
    if (typeof args[last] !== 'function') throw Error('Server harus menggunakan handler request native Node.js');
    const handler = args[last];
    args[last] = (req, res) => security.route(req, res, () => handler(req, res));
    return original.apply(this, args);
  };
}
patch(http);
patch(https);
require('./server.js');
