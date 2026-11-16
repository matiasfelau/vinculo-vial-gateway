#!/usr/bin/env python3
"""Convierte el reporte de LuaCov (`luacov.report.out`) a Cobertura XML.

diff-cover lee Cobertura, y LuaCov solo emite su formato propio. El formato del
reporte es el que escribe `luacov.reporter` (ver `ReporterBase` en LuaCov):

    ==============================================================================
    kong/plugins/token-offloading/handler.lua
    ==============================================================================
          local x = 1          <- sin conteo: la línea no es ejecutable
       3  local y = x + 1      <- ejecutable, corrió 3 veces
    *0    return nil           <- ejecutable, nunca corrió

El ancho de la columna de conteos es el mismo en todo el reporte, así que una
línea de código que casualmente empieza con un número no se confunde con una
línea con conteo: el prefijo de las no ejecutables siempre son espacios y su
ancho no coincide con el de una línea medida.

Uso:
    luacov_to_cobertura.py REPORTE.out SALIDA.xml [--markdown RESUMEN.md]
                           [--fail-under PORCENTAJE]

Con `--fail-under` el programa escribe igual todos los archivos de salida y
termina con código 1 si la cobertura total queda por debajo del porcentaje:
es el gate sobre el total del CI.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from xml.etree import ElementTree as ET

RULE = "=" * 78
# Conteo (`   12`) o línea ejecutable sin cubrir (`*0`, `**0`...), y el separador.
_MEASURED = re.compile(r"^( *\d+|\*+0) (.*)$")


@dataclass
class FileCoverage:
    name: str
    lines: dict[int, int] = field(default_factory=dict)

    @property
    def valid(self) -> int:
        return len(self.lines)

    @property
    def covered(self) -> int:
        return sum(1 for hits in self.lines.values() if hits > 0)

    @property
    def rate(self) -> float:
        return self.covered / self.valid if self.valid else 1.0


def _hits(prefix: str) -> int:
    prefix = prefix.strip()
    return 0 if prefix.startswith("*") else int(prefix)


def parse_report(text: str) -> list[FileCoverage]:
    """Devuelve la cobertura por archivo, en el orden del reporte."""
    raw = text.splitlines()

    # Primera pasada: partir en archivos y quedarse con las líneas candidatas.
    sections: list[tuple[str, list[tuple[int, str, str]]]] = []
    i = 0
    while i < len(raw):
        if raw[i] != RULE:
            i += 1
            continue
        if i + 1 < len(raw) and raw[i + 1] == "Summary":
            break
        name = raw[i + 1].strip() if i + 1 < len(raw) else ""
        i += 3  # regla, nombre, regla
        candidates: list[tuple[int, str, str]] = []
        line_nr = 0
        while i < len(raw) and raw[i] != RULE:
            line_nr += 1
            match = _MEASURED.match(raw[i])
            if match:
                candidates.append((line_nr, match.group(1), match.group(2)))
            i += 1
        # La última línea de la sección es el separador en blanco que agrega
        # LuaCov, no una línea del archivo: no cambia ningún número de línea
        # porque va al final.
        sections.append((name, candidates))

    # El ancho de la columna de conteos es único en todo el reporte: el más
    # frecuente entre las candidatas es el real. Las que no lo respetan son
    # líneas no ejecutables cuyo código empieza con un dígito.
    widths = Counter(len(prefix) for _, candidates in sections for _, prefix, _ in candidates)
    width = widths.most_common(1)[0][0] if widths else 0

    files = []
    for name, candidates in sections:
        coverage = FileCoverage(name=PurePosixPath(name.replace("\\", "/")).as_posix())
        for line_nr, prefix, _ in candidates:
            if len(prefix) == width:
                coverage.lines[line_nr] = _hits(prefix)
        files.append(coverage)
    return files


def to_cobertura(files: list[FileCoverage], timestamp: int = 0) -> ET.ElementTree:
    valid = sum(f.valid for f in files)
    covered = sum(f.covered for f in files)
    root = ET.Element(
        "coverage",
        {
            "line-rate": f"{covered / valid if valid else 1.0:.6f}",
            "branch-rate": "0",
            "lines-covered": str(covered),
            "lines-valid": str(valid),
            "branches-covered": "0",
            "branches-valid": "0",
            "complexity": "0",
            "version": "1",
            "timestamp": str(timestamp),
        },
    )
    ET.SubElement(ET.SubElement(root, "sources"), "source").text = "."
    packages = ET.SubElement(root, "packages")

    by_package: dict[str, list[FileCoverage]] = {}
    for coverage in files:
        package = str(PurePosixPath(coverage.name).parent).replace("/", ".")
        by_package.setdefault(package, []).append(coverage)

    for package_name, members in by_package.items():
        package = ET.SubElement(
            packages,
            "package",
            {
                "name": package_name,
                "line-rate": f"{sum(m.covered for m in members) / max(sum(m.valid for m in members), 1):.6f}",
                "branch-rate": "0",
                "complexity": "0",
            },
        )
        classes = ET.SubElement(package, "classes")
        for member in members:
            cls = ET.SubElement(
                classes,
                "class",
                {
                    "name": PurePosixPath(member.name).name,
                    "filename": member.name,
                    "line-rate": f"{member.rate:.6f}",
                    "branch-rate": "0",
                    "complexity": "0",
                },
            )
            ET.SubElement(cls, "methods")
            lines = ET.SubElement(cls, "lines")
            for number, hits in sorted(member.lines.items()):
                ET.SubElement(
                    lines, "line", {"number": str(number), "hits": str(hits), "branch": "false"}
                )
    ET.indent(root)
    return ET.ElementTree(root)


def total_percent(files: list[FileCoverage]) -> float:
    """Cobertura total en %, sobre todas las líneas ejecutables de todos los archivos."""
    valid = sum(f.valid for f in files)
    covered = sum(f.covered for f in files)
    return 100.0 * covered / valid if valid else 100.0


def markdown_summary(files: list[FileCoverage]) -> str:
    valid = sum(f.valid for f in files)
    covered = sum(f.covered for f in files)
    total = total_percent(files)
    rows = [
        f"**Cobertura total (plugins Lua): {total:.2f} %** ({covered} de {valid} líneas)",
        "",
        "| Archivo | Cubiertas | Ejecutables | % |",
        "|---|---:|---:|---:|",
    ]
    for f in sorted(files, key=lambda f: (f.rate, f.name)):
        rows.append(f"| `{f.name}` | {f.covered} | {f.valid} | {100 * f.rate:.1f} |")
    return "\n".join(rows) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report")
    parser.add_argument("output")
    parser.add_argument("--markdown", help="además escribe un resumen en Markdown")
    parser.add_argument(
        "--fail-under",
        type=float,
        metavar="PORCENTAJE",
        help="termina con código 1 si la cobertura total es menor a este porcentaje",
    )
    args = parser.parse_args(argv)
    # El resumen lleva tildes: en consolas que no son UTF-8 (Windows) no debe romper.
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

    with open(args.report, encoding="utf-8") as fh:
        files = parse_report(fh.read())
    if not files:
        print("El reporte de LuaCov no tiene ningún archivo medido.", file=sys.stderr)
        return 1

    to_cobertura(files).write(args.output, encoding="utf-8", xml_declaration=True)
    summary = markdown_summary(files)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(summary)
    print(summary)

    if args.fail_under is not None:
        total = total_percent(files)
        if total < args.fail_under:
            print(
                f"La cobertura total ({total:.2f} %) es menor al mínimo exigido "
                f"({args.fail_under:g} %).",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
