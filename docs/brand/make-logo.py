#!/usr/bin/env python3
"""Regenerates the GateLight brand SVGs (pure paths, no font needed):  python3 docs/brand/make-logo.py <out-dir>"""
import sys, os
out = sys.argv[1]
os.makedirs(out, exist_ok=True)

CY, IND, GRN, AMB1, AMB2 = '#22d3ee', '#818cf8', '#34d399', '#fde68a', '#f59e0b'

def defs(prefix=''):
    p = prefix
    return f'''<defs>
    <linearGradient id="{p}arch" gradientUnits="userSpaceOnUse" x1="26" y1="22" x2="102" y2="106"><stop offset="0" stop-color="{CY}"/><stop offset="1" stop-color="#6366f1"/></linearGradient>
    <linearGradient id="{p}hub" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fcd34d"/><stop offset="1" stop-color="{AMB2}"/></linearGradient>
  </defs>'''

def mark(p=''):
    """The gate (arch), a lit core in its opening, one input fanning out to three servers. 128x128 box."""
    return f'''<g>
    <path d="M26 106V62a38 38 0 0 1 76 0v44" fill="none" stroke="url(#{p}arch)" stroke-width="12" stroke-linejoin="round"/>
    <circle cx="64" cy="58" r="19" fill="none" stroke="{AMB2}" stroke-opacity=".3" stroke-width="3"/>
    <circle cx="64" cy="58" r="11" fill="url(#{p}hub)"/>
    <path d="M64 70V80M46 92V80H82V92M64 80V92" fill="none" stroke="#8b9bb4" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
    <rect x="41" y="91" width="10" height="10" rx="2.5" fill="{CY}"/><rect x="59" y="91" width="10" height="10" rx="2.5" fill="{IND}"/><rect x="77" y="91" width="10" height="10" rx="2.5" fill="{GRN}"/>
  </g>'''

# ---- monoline geometric wordmark, baseline y=0, stroke 7, round caps ----
SW = 8
def glyphs(ink, dot):
    g = {}
    g['G'] = (52, f'<path d="M45.9 -44.7A26 26 0 1 0 52 -28H32" />')
    g['a'] = (38, '<circle cx="19" cy="-19" r="19"/><path d="M38 -38V0"/>')
    g['t'] = (28, '<path d="M14 -52V-14Q14 0 28 0M2 -38H28"/>')
    g['e'] = (38, '<path d="M0 -19H38A19 19 0 1 0 33.6 -6.8"/>')
    g['l'] = (0, '<path d="M0 -56V0"/>')
    g['L'] = (26, '<path d="M0 -56V0H26"/>')
    g['i'] = (0, f'<path d="M0 -38V0"/><circle cx="0" cy="-54" r="4.4" fill="{dot}" stroke="none"/>')
    g['g'] = (38, '<circle cx="19" cy="-19" r="19"/><path d="M38 -38V6Q38 22 19 22Q6 22 1 12"/>')
    g['h'] = (38, '<path d="M0 -56V0M0 -22Q0 -38 19 -38Q38 -38 38 -22V0"/>')
    return g

def wordmark(ink, dot, word='GateLight'):
    g = glyphs(ink, dot)
    x = 0; parts = []
    for ch in word:
        w, body = g[ch]
        parts.append(f'<g transform="translate({x + (SW/2 if ch in "li" else 0):.1f} 0)">{body}</g>')
        x += w + 17 + (0 if ch not in 'li' else 0)
    width = x - 17
    return f'<g fill="none" stroke="{ink}" stroke-width="{SW}" stroke-linecap="round" stroke-linejoin="round">{"".join(parts)}</g>', width

def lockup(ink, name):
    wm, ww = wordmark(ink, AMB2)
    # mark scaled to 0.92, wordmark baseline aligned with the arch feet
    s = .92; mw = 128 * s
    W = int(mw + 14 + ww + 24); H = 128 * s + 8
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H:.0f}" width="{W*1.3:.0f}" height="{H*1.3:.0f}" role="img" aria-label="GateLight">
  <title>GateLight</title>
  {defs()}
  <g transform="translate(0 4) scale({s})">{mark()}</g>
  <g transform="translate({mw + 14:.1f} {4 + 104*s - 1:.1f})">{wm}</g>
</svg>
'''
    open(f'{out}/{name}', 'w').write(svg)

lockup('#e8edf6', 'logo-dark.svg')    # for dark backgrounds
lockup('#0b1220', 'logo-light.svg')   # for light backgrounds

# standalone mark, transparent
open(f'{out}/mark.svg', 'w').write(f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128" role="img" aria-label="GateLight">
  <title>GateLight</title>
  {defs()}
  {mark()}
</svg>
''')

# app icon / favicon: mark on a dark rounded tile
open(f'{out}/logo.svg', 'w').write(f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" role="img" aria-label="GateLight">
  <title>GateLight</title>
  {defs()}
  <linearGradient id="tile" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#141f38"/><stop offset="1" stop-color="#080d18"/></linearGradient>
  <rect width="128" height="128" rx="30" fill="url(#tile)"/>
  <rect x=".75" y=".75" width="126.5" height="126.5" rx="29.5" fill="none" stroke="#ffffff" stroke-opacity=".08" stroke-width="1.5"/>
  <g transform="translate(12.8 8) scale(.8)">{mark()}</g>
</svg>
''')
print('ok')
