'use strict';
const { buildLibReportHtml  } = require('./buildLib');
const { buildImgReportHtml  } = require('./buildImg');
const { buildDepReportHtml  } = require('./buildDep');
const { buildOsReportHtml   } = require('./buildOs');
const { buildSastReportHtml } = require('./buildSast');

module.exports = { buildLibReportHtml, buildImgReportHtml, buildDepReportHtml, buildOsReportHtml, buildSastReportHtml };
