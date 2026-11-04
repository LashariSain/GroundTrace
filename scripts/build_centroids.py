"""Precompute country centroids for groundtrace/static/world.svg.

Writes static/centroids.json: {cc: [x, y]} in the SVG's own coordinates, the
centroid of each country's LARGEST polygon (so the US point sits in the
contiguous states, not between them and Alaska). The map's paths use only
relative `m` moves with implicit relative line-tos and `z`.
Run again only if world.svg changes.
"""
import json
import re
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "groundtrace" / "static"


def polygons(d: str) -> list[list[tuple[float, float]]]:
    tokens = re.findall(r"[mMzZ]|-?\d*\.?\d+(?:e-?\d+)?", d)
    polys, cur, x, y, start, i = [], [], 0.0, 0.0, (0.0, 0.0), 0
    while i < len(tokens):
        t = tokens[i]
        if t in "zZ":
            if cur:
                polys.append(cur)
            cur, (x, y) = [], start
            i += 1
        elif t in "mM":
            if cur:
                polys.append(cur)
            dx, dy = float(tokens[i + 1]), float(tokens[i + 2])
            x, y = (x + dx, y + dy) if t == "m" else (dx, dy)
            start, cur, i = (x, y), [(x, y)], i + 3
        else:  # implicit relative line-to
            x, y = x + float(t), y + float(tokens[i + 1])
            cur.append((x, y))
            i += 2
    if cur:
        polys.append(cur)
    return polys


def centroid(poly):
    a = cx = cy = 0.0
    for (x0, y0), (x1, y1) in zip(poly, poly[1:] + poly[:1]):
        k = x0 * y1 - x1 * y0
        a += k
        cx += (x0 + x1) * k
        cy += (y0 + y1) * k
    if abs(a) < 1e-9:
        return abs(a), sum(p[0] for p in poly) / len(poly), sum(p[1] for p in poly) / len(poly)
    return abs(a) / 2, cx / (3 * a), cy / (3 * a)


def main():
    svg = (STATIC / "world.svg").read_text(encoding="utf-8")
    out = {}
    for d, cc in re.findall(r'<path\s+d="([^"]+)"\s+aria-label="[^"]*"\s+id="([a-z]{2})"', svg):
        area, x, y = max((centroid(p) for p in polygons(d) if len(p) >= 3), default=(0, 0, 0))
        if area:
            out[cc.upper()] = [round(x, 1), round(y, 1)]
    (STATIC / "centroids.json").write_text(json.dumps(out, separators=(",", ":")), encoding="utf-8")
    print(f"{len(out)} centroids written")


if __name__ == "__main__":
    main()
