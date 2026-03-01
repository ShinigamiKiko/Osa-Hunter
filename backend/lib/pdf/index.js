'use strict';

const { buildLibReportHtml } = require('./buildLib');
const { buildImgReportHtml } = require('./buildImg');
const { buildDepReportHtml } = require('./buildDep');

module.exports = { buildLibReportHtml, buildImgReportHtml, buildDepReportHtml };
