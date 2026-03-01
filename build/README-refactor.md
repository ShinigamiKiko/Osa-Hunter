# Refactor notes (no logic changes)

## What changed
- Frontend JS: renamed files to clearer "ui-*" names.
- Dependency Scan UI (`dep-scan.js`) split into multiple smaller files under `frontend/public/js/dependency-scan/`.
- Backend route files renamed to `*.route.js` (only filenames/import paths changed; API endpoints unchanged).
- CSS: added SCSS source split into partials under `frontend/public/css/scss/`.
  - `public/css/main.css` kept as-is so the UI is unchanged.

## Frontend script order
The `index.html` keeps the same execution order; only filenames changed.

## SCSS
`css/scss/main.scss` is the source-of-truth layout to be compiled into `css/main.css`.
