"""Pruebas del convertidor LuaCov -> Cobertura.

Los reportes de ejemplo respetan el formato que escribe `luacov.reporter`: una
columna de conteos de ancho fijo, `*0` para las líneas ejecutables sin cubrir y
espacios para las que no son ejecutables.
"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).parent))
import luacov_to_cobertura as conv  # noqa: E402

RULE = "=" * 78

# Ancho de la columna = 4: `  12`, `   1`, `***0`. Ver `_count_format` en LuaCov.
REPORT = "\n".join(
    [
        RULE,
        "kong/lib/vv/errors.lua",
        RULE,
        "     local M = {}",  # no ejecutable
        "   1 local x = 1",  # ejecutable, 1 vez
        "  12 M.f = function() end",  # ejecutable, 12 veces
        "",  # línea en blanco
        "***0 return nil",  # ejecutable sin cubrir
        "     1 es un comentario que empieza con un número",  # no ejecutable
        "",  # separador de LuaCov
        RULE,
        "kong/plugins/token-offloading/handler.lua",
        RULE,
        "***0 local y = 2",
        "***0 return y",
        "",
        RULE,
        "Summary",
        RULE,
        "",
        "File                                       Hits Missed Coverage",
        "kong/lib/vv/errors.lua                        2      1  66.67%",
        "",
    ]
)


class ParseReportTest(unittest.TestCase):
    def setUp(self):
        self.files = {f.name: f for f in conv.parse_report(REPORT)}

    def test_lists_every_file_and_stops_at_summary(self):
        self.assertEqual(
            list(self.files),
            ["kong/lib/vv/errors.lua", "kong/plugins/token-offloading/handler.lua"],
        )

    def test_hits_and_misses_are_keyed_by_source_line_number(self):
        lines = self.files["kong/lib/vv/errors.lua"].lines
        self.assertEqual(lines[2], 1)
        self.assertEqual(lines[3], 12)
        self.assertEqual(lines[5], 0)

    def test_non_executable_lines_are_not_counted(self):
        lines = self.files["kong/lib/vv/errors.lua"].lines
        # 1: sin conteo, 4: en blanco, 6: comentario cuyo texto empieza con un dígito
        self.assertEqual(sorted(lines), [2, 3, 5])

    def test_file_with_no_hits_is_fully_uncovered(self):
        untested = self.files["kong/plugins/token-offloading/handler.lua"]
        self.assertEqual((untested.covered, untested.valid), (0, 2))
        self.assertEqual(untested.rate, 0.0)

    def test_rate_of_file_without_executable_lines_is_one(self):
        self.assertEqual(conv.FileCoverage("vacio.lua").rate, 1.0)

    def test_empty_report_has_no_files(self):
        self.assertEqual(conv.parse_report(""), [])

    def test_windows_separators_are_normalized(self):
        report = "\n".join([RULE, "kong\\lib\\vv\\errors.lua", RULE, "  1 x = 1", ""])
        self.assertEqual(conv.parse_report(report)[0].name, "kong/lib/vv/errors.lua")


class CoberturaTest(unittest.TestCase):
    def setUp(self):
        files = conv.parse_report(REPORT)
        self.root = conv.to_cobertura(files).getroot()

    def test_totals_match_the_measured_lines(self):
        # errors.lua: 3 ejecutables, 2 cubiertas. handler.lua: 2 ejecutables, 0 cubiertas.
        self.assertEqual(self.root.get("lines-valid"), "5")
        self.assertEqual(self.root.get("lines-covered"), "2")
        self.assertEqual(self.root.get("line-rate"), "0.400000")

    def test_classes_carry_repo_relative_filenames_for_diff_cover(self):
        filenames = [c.get("filename") for c in self.root.iter("class")]
        self.assertEqual(
            filenames,
            ["kong/lib/vv/errors.lua", "kong/plugins/token-offloading/handler.lua"],
        )

    def test_uncovered_line_is_reported_with_zero_hits(self):
        handler = next(c for c in self.root.iter("class") if c.get("name") == "handler.lua")
        hits = {ln.get("number"): ln.get("hits") for ln in handler.iter("line")}
        self.assertEqual(hits, {"1": "0", "2": "0"})

    def test_packages_follow_the_directory(self):
        names = [p.get("name") for p in self.root.iter("package")]
        self.assertEqual(names, ["kong.lib.vv", "kong.plugins.token-offloading"])

    def test_report_without_executable_lines_is_fully_covered(self):
        root = conv.to_cobertura([]).getroot()
        self.assertEqual(root.get("line-rate"), "1.000000")


class MarkdownTest(unittest.TestCase):
    def test_summary_shows_total_and_worst_files_first(self):
        text = conv.markdown_summary(conv.parse_report(REPORT))
        self.assertIn("**Cobertura total (plugins Lua): 40.00 %** (2 de 5 líneas)", text)
        self.assertLess(
            text.index("token-offloading/handler.lua"), text.index("kong/lib/vv/errors.lua")
        )


class CliTest(unittest.TestCase):
    def run_cli(self, report_text, *extra_args):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "in.out").write_text(report_text, encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).parent / "luacov_to_cobertura.py"),
                str(tmp / "in.out"),
                str(tmp / "cobertura.xml"),
                "--markdown",
                str(tmp / "resumen.md"),
                *extra_args,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return result, tmp

    def test_writes_valid_xml_and_markdown(self):
        result, tmp = self.run_cli(REPORT)
        self.assertEqual(result.returncode, 0, result.stderr)
        root = ET.fromstring((tmp / "cobertura.xml").read_text(encoding="utf-8"))
        self.assertEqual(root.tag, "coverage")
        self.assertEqual(root.get("lines-valid"), "5")
        self.assertIn("Cobertura total", (tmp / "resumen.md").read_text(encoding="utf-8"))

    def test_fails_when_the_report_has_no_files(self):
        result, tmp = self.run_cli("")
        self.assertEqual(result.returncode, 1)
        self.assertFalse((tmp / "cobertura.xml").exists())

    # REPORT cubre 2 de 5 líneas ejecutables: 40,00 % en total.
    def test_fail_under_fails_below_the_threshold_but_still_writes_the_reports(self):
        result, tmp = self.run_cli(REPORT, "--fail-under", "85")
        self.assertEqual(result.returncode, 1)
        self.assertIn("40.00 %", result.stderr)
        self.assertIn("85 %", result.stderr)
        self.assertTrue((tmp / "cobertura.xml").exists())
        self.assertIn("Cobertura total", (tmp / "resumen.md").read_text(encoding="utf-8"))

    def test_fail_under_accepts_a_total_exactly_at_the_threshold(self):
        result, _ = self.run_cli(REPORT, "--fail-under", "40")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_fail_under_accepts_a_total_above_the_threshold(self):
        result, _ = self.run_cli(REPORT, "--fail-under", "39.99")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_without_fail_under_a_low_total_does_not_fail(self):
        result, _ = self.run_cli(REPORT)
        self.assertEqual(result.returncode, 0, result.stderr)


class TotalPercentTest(unittest.TestCase):
    def test_is_computed_over_all_executable_lines_not_averaged_per_file(self):
        # errors.lua: 2 de 3; handler.lua: 0 de 2 -> 2 de 5, no el promedio de 66,7 y 0.
        self.assertAlmostEqual(conv.total_percent(conv.parse_report(REPORT)), 40.0)

    def test_without_measured_lines_it_is_fully_covered(self):
        self.assertEqual(conv.total_percent([]), 100.0)


if __name__ == "__main__":
    unittest.main()
