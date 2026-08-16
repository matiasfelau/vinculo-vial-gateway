local verdict_policy = require "kong.plugins.app-attestation.verdict"
local play = require "spec.helpers.playintegrity"

local NOW = 1735689600 -- 2025-01-01T00:00:00Z
local NONE = play.NONE

-- Espejo de los defaults del schema; en runtime los completa Kong.
local function config(overrides)
  local conf = {
    package_name = play.PACKAGE_NAME,
    accepted_app_verdicts = { "PLAY_RECOGNIZED" },
    accepted_device_verdicts = { "MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY" },
    accepted_licensing_verdicts = {},
    expected_certificate_digests = {},
    require_request_hash = false,
    max_age_seconds = 120,
    clock_skew_seconds = 30,
  }

  for key, value in pairs(overrides or {}) do
    conf[key] = value ~= NONE and value or nil
  end

  return conf
end

local function evaluate(verdict_overrides, conf_overrides, body_hash, now)
  return verdict_policy.evaluate(
    play.verdict(now or NOW, verdict_overrides),
    config(conf_overrides),
    body_hash,
    now or NOW
  )
end

describe("política de atestación", function()
  describe("veredicto aceptable", function()
    it("acepta una app reconocida en un dispositivo íntegro", function()
      assert.is_true(evaluate())
    end)

    it("acepta un dispositivo con integridad reforzada", function()
      -- Google devuelve los niveles acumulados; alcanza con que uno esté
      -- entre los aceptados.
      assert.is_true(evaluate({
        deviceIntegrity = {
          deviceRecognitionVerdict = {
            "MEETS_BASIC_INTEGRITY",
            "MEETS_DEVICE_INTEGRITY",
            "MEETS_STRONG_INTEGRITY",
          },
        },
      }))
    end)

    it("tolera desfasaje de reloj dentro de la ventana configurada", function()
      -- Emitido 20s en el futuro, con 30s de tolerancia.
      assert.is_true(evaluate({
        requestDetails = { timestampMillis = tostring((NOW + 20) * 1000) },
      }))
    end)
  end)

  describe("estructura del veredicto", function()
    it("rechaza algo que no es un veredicto", function()
      local ok, reason = verdict_policy.evaluate("no soy una tabla", config(), nil, NOW)
      assert.is_nil(ok)
      assert.equals("malformed_verdict", reason)
    end)

    it("rechaza un veredicto sin requestDetails", function()
      local ok, reason = evaluate({ requestDetails = NONE })
      assert.is_nil(ok)
      assert.equals("missing_request_details", reason)
    end)

    it("rechaza un veredicto sin appIntegrity", function()
      local ok, reason = evaluate({ appIntegrity = NONE })
      assert.is_nil(ok)
      assert.equals("missing_app_integrity", reason)
    end)

    it("rechaza un veredicto sin deviceIntegrity", function()
      local ok, reason = evaluate({ deviceIntegrity = NONE })
      assert.is_nil(ok)
      assert.equals("missing_device_integrity", reason)
    end)
  end)

  describe("identidad de la app", function()
    -- Google publica el package en dos lugares y no siempre puebla los dos:
    -- la Standard API puede omitir `requestDetails.requestPackageName`. El
    -- criterio es "todos los presentes coinciden y hay al menos uno".
    it("acepta cuando ambas ubicaciones traen el package correcto", function()
      assert.is_true(evaluate())
    end)

    it("acepta si falta requestPackageName pero appIntegrity coincide", function()
      -- Éste es el caso que rechazaba de más: un veredicto legítimo de la
      -- Standard API sin `requestDetails.requestPackageName`.
      assert.is_true(evaluate({
        requestDetails = { requestPackageName = NONE },
      }))
    end)

    it("acepta si falta appIntegrity.packageName pero requestDetails coincide", function()
      assert.is_true(evaluate({
        appIntegrity = { packageName = NONE },
      }))
    end)

    it("rechaza un token emitido para otra aplicación", function()
      local ok, reason, detail = evaluate({
        requestDetails = { requestPackageName = "com.otra.app" },
      })
      assert.is_nil(ok)
      assert.equals("package_mismatch", reason)
      -- El detalle es lo que hace diagnosticable el rechazo desde el log.
      assert.matches("requestDetails.requestPackageName", detail, 1, true)
      assert.matches("com.otra.app", detail, 1, true)
      assert.matches(play.PACKAGE_NAME, detail, 1, true)
    end)

    it("rechaza si appIntegrity.packageName no coincide, aunque falte el otro", function()
      local ok, reason, detail = evaluate({
        requestDetails = { requestPackageName = NONE },
        appIntegrity = { packageName = "com.otra.app" },
      })
      assert.is_nil(ok)
      assert.equals("package_mismatch", reason)
      assert.matches("appIntegrity.packageName", detail, 1, true)
    end)

    it("rechaza si ninguna de las dos ubicaciones trae el package", function()
      -- Sin identidad no hay nada que verificar: un token de cualquier otra
      -- app pasaría.
      local ok, reason = evaluate({
        requestDetails = { requestPackageName = NONE },
        appIntegrity = { packageName = NONE },
      })
      assert.is_nil(ok)
      assert.equals("package_name_absent", reason)
    end)

    it("no verifica el package si no se configuró ninguno", function()
      assert.is_true(evaluate({
        requestDetails = { requestPackageName = NONE },
        appIntegrity = { packageName = NONE },
      }, { package_name = NONE }))
    end)

    it("rechaza una app no reconocida por Play", function()
      -- Lo que devuelve Google para un APK que no distribuyó él: un build
      -- local firmado con el keystore de debug, por ejemplo.
      local ok, reason, detail = evaluate({
        appIntegrity = { appRecognitionVerdict = "UNRECOGNIZED_VERSION" },
      })
      assert.is_nil(ok)
      assert.equals("app_verdict_rejected", reason)
      assert.matches("UNRECOGNIZED_VERSION", detail, 1, true)
      assert.matches("PLAY_RECOGNIZED", detail, 1, true)
    end)

    it("rechaza una app que Google no llegó a evaluar", function()
      local ok, reason, detail = evaluate({
        appIntegrity = { appRecognitionVerdict = "UNEVALUATED" },
      })
      assert.is_nil(ok)
      assert.equals("app_verdict_rejected", reason)
      assert.matches("UNEVALUATED", detail, 1, true)
    end)

    it("permite aceptar builds no distribuidos por Play, para desarrollo", function()
      -- Aflojar esto desactiva de hecho la verificación de que la app sea la
      -- legítima; existe para poder iterar sin subir a Play en cada cambio.
      assert.is_true(evaluate(
        { appIntegrity = { appRecognitionVerdict = "UNRECOGNIZED_VERSION" } },
        { accepted_app_verdicts = { "PLAY_RECOGNIZED", "UNRECOGNIZED_VERSION" } }
      ))
    end)

    it("rechaza un certificado de firma distinto del esperado", function()
      local ok, reason = evaluate(nil, {
        expected_certificate_digests = { "otra-huella-distinta" },
      })
      assert.is_nil(ok)
      assert.equals("certificate_digest_rejected", reason)
    end)

    it("acepta si el certificado está entre los esperados", function()
      assert.is_true(evaluate(nil, {
        expected_certificate_digests = { "otra-huella", "6a6a1474b5cbbb2b1aa57e0bc3" },
      }))
    end)

    it("no verifica el certificado si no se configuró ninguno", function()
      assert.is_true(evaluate({
        appIntegrity = { certificateSha256Digest = { "cualquier-cosa" } },
      }))
    end)
  end)

  describe("integridad del dispositivo", function()
    it("rechaza un dispositivo que sólo pasa controles básicos", function()
      local ok, reason = evaluate({
        deviceIntegrity = { deviceRecognitionVerdict = { "MEETS_BASIC_INTEGRITY" } },
      })
      assert.is_nil(ok)
      assert.equals("device_verdict_rejected", reason)
    end)

    it("rechaza un emulador", function()
      local ok, reason = evaluate({
        deviceIntegrity = { deviceRecognitionVerdict = { "MEETS_VIRTUAL_INTEGRITY" } },
      })
      assert.is_nil(ok)
      assert.equals("device_verdict_rejected", reason)
    end)

    it("rechaza una lista vacía, que es como Google reporta un dispositivo comprometido", function()
      local ok, reason, detail = evaluate({
        deviceIntegrity = { deviceRecognitionVerdict = {} },
      })
      assert.is_nil(ok)
      assert.equals("device_verdict_rejected", reason)
      -- Una lista vacía tiene que distinguirse en el log de un veredicto con
      -- valores que no están entre los aceptados.
      assert.matches("recibido=[]", detail, 1, true)
    end)

    it("permite aflojar la política por configuración", function()
      assert.is_true(evaluate(
        { deviceIntegrity = { deviceRecognitionVerdict = { "MEETS_BASIC_INTEGRITY" } } },
        { accepted_device_verdicts = { "MEETS_BASIC_INTEGRITY" } }
      ))
    end)
  end)

  describe("frescura", function()
    it("rechaza una atestación más vieja que la ventana permitida", function()
      local ok, reason, detail = evaluate({
        requestDetails = { timestampMillis = tostring((NOW - 151) * 1000) },
      })
      assert.is_nil(ok)
      assert.equals("attestation_too_old", reason)
      -- El desfasaje en segundos distingue un reloj mal sincronizado en el
      -- Gateway (desvío constante) de una atestación realmente vieja.
      assert.matches("151", detail, 1, true)
    end)

    it("rechaza un timestamp en el futuro fuera de la tolerancia", function()
      local ok, reason = evaluate({
        requestDetails = { timestampMillis = tostring((NOW + 31) * 1000) },
      })
      assert.is_nil(ok)
      assert.equals("timestamp_in_future", reason)
    end)

    it("rechaza un veredicto sin timestamp", function()
      local ok, reason = evaluate({ requestDetails = { timestampMillis = NONE } })
      assert.is_nil(ok)
      assert.equals("missing_timestamp", reason)
    end)
  end)

  describe("ligadura con el body (requestHash)", function()
    local BODY_HASH = "1a2b3c4d5e6f"

    it("acepta cuando el hash del veredicto coincide con el del body", function()
      assert.is_true(evaluate(
        { requestDetails = { requestHash = BODY_HASH } },
        { require_request_hash = true },
        BODY_HASH
      ))
    end)

    it("rechaza una atestación válida reutilizada sobre otro body", function()
      local ok, reason, detail = evaluate(
        { requestDetails = { requestHash = BODY_HASH } },
        { require_request_hash = true, request_hash_encoding = "hex" },
        "hash-de-un-body-distinto"
      )
      assert.is_nil(ok)
      assert.equals("request_hash_mismatch", reason)
      -- Con los dos valores y el encoding en el log se distingue "la app
      -- hasheó otro payload" de "la app usa otro encoding".
      assert.matches(BODY_HASH, detail, 1, true)
      assert.matches("hash-de-un-body-distinto", detail, 1, true)
      assert.matches("hex", detail, 1, true)
    end)

    it("acepta `nonce` como alternativa, para el flujo clásico de Play", function()
      assert.is_true(evaluate(
        { requestDetails = { nonce = BODY_HASH } },
        { require_request_hash = true },
        BODY_HASH
      ))
    end)

    it("rechaza si el veredicto no trae ninguna ligadura", function()
      local ok, reason = evaluate(nil, { require_request_hash = true }, BODY_HASH)
      assert.is_nil(ok)
      assert.equals("missing_request_hash", reason)
    end)

    it("rechaza si no se pudo calcular el hash del body", function()
      local ok, reason = evaluate(
        { requestDetails = { requestHash = BODY_HASH } },
        { require_request_hash = true },
        nil
      )
      assert.is_nil(ok)
      assert.equals("body_hash_unavailable", reason)
    end)
  end)

  describe("licencia de Play", function()
    it("no la verifica por defecto, porque en sideload es UNLICENSED", function()
      assert.is_true(evaluate({
        accountDetails = { appLicensingVerdict = "UNLICENSED" },
      }))
    end)

    it("rechaza una copia no licenciada cuando se exige licencia", function()
      local ok, reason = evaluate(
        { accountDetails = { appLicensingVerdict = "UNLICENSED" } },
        { accepted_licensing_verdicts = { "LICENSED" } }
      )
      assert.is_nil(ok)
      assert.equals("licensing_verdict_rejected", reason)
    end)

    it("rechaza si falta accountDetails y se exige licencia", function()
      local ok, reason = evaluate(
        { accountDetails = NONE },
        { accepted_licensing_verdicts = { "LICENSED" } }
      )
      assert.is_nil(ok)
      assert.equals("missing_account_details", reason)
    end)
  end)
end)
