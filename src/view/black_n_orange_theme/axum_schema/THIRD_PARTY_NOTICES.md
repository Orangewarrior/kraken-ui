# Third-party and local UI helper notes

This ZIP does not vendor NPM packages or CDN assets.

The table pagination/search code is a local vanilla-JS helper named `KwDataTable` in `static/app.js`. It implements a DataTables-style JSON contract (`draw`, `recordsTotal`, `recordsFiltered`, `data`) so the backend can later be switched to the official DataTables library if desired.

The local helper code is distributed under the same BSD-3-Clause license as this template package.

Official DataTables 1.10+ is MIT licensed, but its official runtime code is not bundled in this ZIP.
PrismJS is MIT licensed, but its official runtime code is not bundled in this ZIP; the evidence highlighter here is a small local implementation.
