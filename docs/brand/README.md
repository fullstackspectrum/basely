# Basely brand assets

Basely follows the [Full-Stack-Spectrum](https://fullstackspectrum.com) design system.

- `basely-icon.svg`: the mark on a 64×64 `#0a0d12` tile (radius 14), for avatars and app icons. The HTML report inlines it as its tab icon (`_FAVICON_SVG` in `basely/html.py`) and draws the tile-less mark in its header (`basely/assets/report.html`); keep all three in sync.
- `basely-mark.svg`: the mark alone, for dark grounds only (its layers are filled `#0a0d12`).
- `readme-banner.png`: 2560×640, shown at 1280×320 at the top of the README.
- `github-social-preview.png`: 1280×640, uploaded under the repository's Settings → Social preview.
- `src/brand.html` and `src/render.sh`: the source for both PNGs. Edit the HTML, then run `./docs/brand/src/render.sh` (needs Google Chrome).

The mark is Layered Core with the red core replaced by an upward chevron over a base line: a better base. Blue and yellow layers sit behind a `#eef1f6` outline, cool at the back, hot at the front. The glyph is a 3-unit `#ff4d5e` stroke with round caps and joins, matching GitPulse's pulse line and Sbomly's ± sign.

In the banner's comparison, the image in use today carries the red node and the pick takes the brand blue.

The wordmark is written Basely in prose and headings, and `basely` in mono contexts (the command, eyebrows).
