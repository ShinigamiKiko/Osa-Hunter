'use strict';

const { IMAGE_RE } = require('./constants');

function validateImage(image) {
  return typeof image === 'string' && image.length > 0 && image.length < 512 && IMAGE_RE.test(image);
}

module.exports = { validateImage };
