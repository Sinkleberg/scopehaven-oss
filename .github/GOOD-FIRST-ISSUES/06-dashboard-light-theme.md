# Dashboard: move the literal colours into the `--sh-*` custom properties so a light theme becomes possible

The dashboard is dark only. `public/dashboard/dashboard.css` sets `color-scheme: dark` on `.sh-dashboard`, `public/index.html` declares `<meta name="color-scheme" content="dark">`, and nothing reads `prefers-color-scheme`. The stylesheet declares ten `--sh-*` custom properties, uses eight of them, and carries 136 literal hex colours outside them: the sidebar `.sh-nav-item` text (`#a4acb8`), `.sh-button` (`#1b1f25` on `#404750`), `.sh-help` (`#99a6b9`), the table header `th` (`#8998ad`), the focus ring (`#b8cce6`) and so on. A user on a light desktop gets a dark page, and nobody can offer a second theme without editing every rule.

Lift the literal colours into named custom properties on `.sh-dashboard`, keeping today's dark values as the defaults so nothing changes visually, then add one `@media (prefers-color-scheme: light)` block that overrides the properties with a light palette whose text-on-background pairs meet WCAG AA (4.5:1 for body text, 3:1 for the `.sh-tag` borders and the `:focus-visible` outline). `.sh-pass`, `.sh-fail` and `.sh-inconclusive` already carry a text label, so they stay distinguishable by more than hue in both themes; keep that. Change the `color-scheme` meta in `public/index.html` to `light dark`. No new dependency and no build step; the stylesheet stays one file, and the offline preview under `design/dashboard/` is where to look at both themes.

## Pointers

- `public/dashboard/dashboard.css`: the `.sh-dashboard` rule with the custom properties, and every rule after it.
- `public/index.html`: the `color-scheme` and `theme-color` metas.
- `public/dashboard/dashboard.mjs`: the status classes (`sh-pass`, `sh-fail`, `sh-inconclusive`, `sh-error`, `sh-not_applicable`) the tags use.
- `design/dashboard/preview.html` and `design/dashboard/preview-server.mjs`: the offline preview with sample data, for checking both themes in a browser.

## Acceptance

The dark theme's computed colours are unchanged, the light theme passes AA on every text pair the stylesheet defines, and no literal hex colour remains outside a custom-property declaration.

## Test

`test/dashboard-theme.test.mjs` (new): reads the stylesheet, asserts every `#` colour literal sits inside a `--sh-...:` declaration, and computes the WCAG contrast ratio of the declared text and background pairs for both palettes.

## Labels

`good first issue`, `dashboard`

## Effort

3 to 4 hours.
