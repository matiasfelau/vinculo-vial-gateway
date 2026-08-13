# vinculo-vial-gateway

API Gateway de la plataforma **Vínculo Vial**, construido sobre **Kong 3.7 en modo
DB-less**. Es el único punto de entrada público: enruta el tráfico hacia los
servicios internos y concentra la seguridad perimetral.

Para US-01 (Registro) expone `POST /api/v1/auth/signup` hacia
`vinculo-vial-identity` y valida el **Mock App Attestation**
(`X-App-Attestation`) antes de permitir tráfico hacia la red interna. El body
nunca se inspecciona ni se modifica: viaja cifrado extremo a extremo (HPKE).

## Estado

| Capacidad | Estado |
|---|---|
| Bootstrap DB-less + logging + Admin API | ✅ |
| Ruteo declarativo a `identity-service` | ⏳ |
| Rate limiting global | ⏳ |
| Plugin `app-attestation` (Lua) | ⏳ |
| Token offloading (`X-User-Hash`) | ⏳ |
| Imagen Docker + compose | ⏳ |

## Estructura

```
kong/
  kong.conf     # configuración de la instancia (DB-less, listeners, logging)
  kong.yml      # configuración declarativa (Services, Routes, Plugins) — plantilla
spec/           # tests Busted de los plugins Lua
```

## Configuración

Copiar `.env.example` a `.env` y completar. `.env` no se versiona.

## Convenciones

- Rama base `dev`; una rama `feature/<slug>` por feature, PR + squash merge.
- Los detalles de arquitectura y el contrato compartido entre componentes están
  en [CLAUDE.md](CLAUDE.md).
