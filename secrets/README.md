# secrets/

Credenciales que se montan en el contenedor. **Nada de acá se versiona**
(salvo este README): ver `.gitignore`.

## `google-service-account.json`

JSON del service account de Google Cloud con acceso a la Play Integrity API.
El Gateway lo usa para autenticarse contra `decodeIntegrityToken`.

Para obtenerlo:

1. En Google Cloud Console, sobre el proyecto vinculado a Play Console, habilitar
   la **Play Integrity API**.
2. Crear un service account y descargar su clave en formato JSON.
3. En Play Console → *Configuración* → *Integridad de la app*, vincular ese
   proyecto de Cloud.
4. Guardar el archivo acá como `google-service-account.json`.

`docker-compose.yml` monta este directorio en `/etc/vinculo-vial` de sólo
lectura, y `GOOGLE_SERVICE_ACCOUNT_PATH` apunta al archivo.

Con `ATTESTATION_SOURCE=mock` no hace falta.
