'use strict';

require('dotenv').config();

var express_app = require('./app');

express_app.listen(process.env.PORT, process.env.HOST);
console.log(`Running on http://${process.env.HOST}:${process.env.PORT}`);
