# ─────────────────────────────────────────────────────────────────────────────
# vinculo-vial-gateway
#
# Una sola etapa: los plugins son Lua interpretado por el propio OpenResty de
# Kong, no hay nada que compilar ni que copiar a una imagen mínima. Multi-stage
# acá sólo agregaría ruido.
# ─────────────────────────────────────────────────────────────────────────────
FROM kong:3.7

USER root

# `gettext-base` aporta envsubst, con el que el entrypoint resuelve la config
# declarativa; `curl` es para el healthcheck contra el Status API (:8100).
# Se instalan y se necesitan en runtime (no sólo en build), así que no hay
# ganancia de tamaño en separarlos en una etapa aparte.
RUN apt-get update \
 && apt-get install -y --no-install-recommends gettext-base curl \
 && rm -rf /var/lib/apt/lists/*

# Plugins custom. La ruta refleja el nombre del módulo:
# /opt/kong/kong/plugins/<nombre>/handler.lua → kong.plugins.<nombre>.handler
COPY kong/plugins/ /opt/kong/kong/plugins/

# Módulos compartidos entre plugins (`vv.*`), fuera del namespace de Kong.
COPY kong/lib/ /opt/kong/

# Configuración de la instancia y plantilla declarativa. El `.template` se
# renderiza en cada arranque contra las variables de entorno.
COPY kong/kong.conf /etc/kong/kong.conf
COPY kong/kong.yml /etc/kong/kong.yml.template
COPY docker/entrypoint.sh /usr/local/bin/vv-entrypoint.sh

RUN chmod +x /usr/local/bin/vv-entrypoint.sh

# `;;` conserva el path por defecto de Lua, para que sigan resolviéndose los
# módulos propios de Kong.
ENV KONG_LUA_PACKAGE_PATH="/opt/kong/?.lua;;"

USER kong

# Proxy (único punto de entrada público) y Status API (sólo lectura, healthcheck).
# La Admin API queda apagada por config (admin_listen = off en kong.conf): no
# se expone ningún puerto para ella.
EXPOSE 8000 8100

# El entrypoint propio renderiza la config y delega en el de la imagen oficial.
ENTRYPOINT ["/usr/local/bin/vv-entrypoint.sh"]
CMD ["kong", "docker-start"]
