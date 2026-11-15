#!/bin/sh
# Corre la suite de Busted midiendo cobertura con LuaCov y deja en `coverage/`
# el reporte de texto de LuaCov. Se ejecuta dentro de la imagen de test; el CI
# monta `coverage/` como volumen para recuperarlo (ver .github/workflows/tests.yml).
#
# El código de salida es el de Busted: un spec rojo falla el job aunque el
# reporte se haya generado igual.
cd /app || exit 1
mkdir -p coverage

VV_COVERAGE=1 busted spec/
status=$?

resty -e 'pcall(require, "luarocks.loader"); require("luacov.runner").run_report(".luacov")' || exit 1

exit "$status"
