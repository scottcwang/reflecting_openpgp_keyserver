'use strict';

var express_app = require('./app');

// Constants
const PORT = 3000;
const HOST = '0.0.0.0';

express_app.listen(PORT, HOST);
console.log(`Running on http://${HOST}:${PORT}`);
