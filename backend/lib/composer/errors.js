'use strict';

class HttpError extends Error {
  constructor(statusCode, msg, details) {
    super(msg);
    this.statusCode = statusCode;
    this.details = details;
  }
}

function classifyComposerError(pkg, constraint, errMsg) {
  const msg = String(errMsg || '');

  if (/could not find (a matching|any) package|no matching package found|package .* not found/i.test(msg)) {
    return new HttpError(404, `Пакет «${pkg}» не найден в Packagist (или версия недоступна).`);
  }

  if (/affected by security advisories|block-insecure|security advisories/i.test(msg)) {
    return new HttpError(
      409,
      `Composer заблокировал разрешение зависимостей для «${pkg}@${constraint}» из-за security advisories (Packagist audit).`,
      { kind: 'security_advisories' }
    );
  }

  if (/requires php|requires ext-|composer-runtime-api|php extension/i.test(msg)) {
    return new HttpError(
      409,
      `Не удалось разрешить «${pkg}@${constraint}»: platform requirements (версия PHP / ext-*).`,
      { kind: 'platform_requirements' }
    );
  }

  if (/Your requirements could not be resolved|conflict|cannot be resolved to an installable set/i.test(msg)) {
    return new HttpError(
      409,
      `Не удалось разрешить зависимости для «${pkg}@${constraint}»: конфликт ограничений зависимостей.`,
      { kind: 'dependency_conflict' }
    );
  }

  if (/Could not parse version constraint|Invalid version string/i.test(msg)) {
    return new HttpError(
      400,
      `Неверный constraint версии для «${pkg}»: «${constraint}». Используй, например, "3.0.0", "^3.0", "~3.0", "*" или "dev-main".`,
      { kind: 'bad_constraint' }
    );
  }

  return new HttpError(502, `Composer scan failed for «${pkg}@${constraint}».`);
}

module.exports = { HttpError, classifyComposerError };
