/*
  jardim — ESP-01S gate-trigger firmware, MQTT over TLS, TOTP

  Pulses GPIO0 HIGH for ~250ms (mimicking a press of the paired remote's
  button through the BC548 transistor) whenever a valid TOTP code arrives
  on the MQTT command topic. Wi-Fi is provisioned via WiFiManager's
  captive portal, same pattern as the previous working sketch.

  Security model (see README.md / LEIAME.md for the full rationale):
    - TLS (port 8883) so credentials and traffic aren't sent in the clear.
    - Dedicated MQTT credentials for this device (separate from the
      credentials your phone/PC app uses), restricted per-topic by the
      broker's own ACL (EMQX Cloud Authorization) — MQTT auth/ACL and
      TOTP are two independent layers, neither replaces the other.
    - TOTP (RFC 6238), validated here in firmware — the public page never
      embeds any secret; it only has a plain text field where a person
      types the 6-digit code their own authenticator app shows.
    - Each registered person/device has an independent secret (K) and an
      independent replay counter: the last accepted time-step is tracked
      per secret, so a captured-and-replayed code is rejected even inside
      the validity window.
    - Fail-closed on time: if NTP has never synced, or the last successful
      sync is older than NTP_STALE_MS, no TOTP code is accepted — a stale
      or absent clock never defaults to "valid".
    - A short cooldown after a successful trigger, plus a temporary
      lockout after too many consecutive invalid codes.
    - A grace window after each (re)subscribe to ignore a stray retained
      message.
*/

#include <ESP8266WiFi.h>
#include <WiFiManager.h>
#include <WiFiClientSecureBearSSL.h>
#include <PubSubClient.h>
#include <time.h>
#include <bearssl/bearssl.h>
#include <Ticker.h>

#include "secrets.h"   // MQTT_HOST/PORT/USER/PASSWORD, TOTP_SECRET_1..8, WM_AP_PASSWORD — gitignored
#include "root_ca.h"   // EMQX_ROOT_CA — public, safe to commit

// ---- Hardware ----
const int TRIGGER_PIN = 0;                  // GPIO0 -> 5.1k resistor -> BC548 base
const unsigned long PULSE_MS = 250;         // how long to hold the "button" down
const unsigned long COOLDOWN_MS = 4000;     // ignore repeat triggers within this window
const unsigned long IGNORE_AFTER_SUBSCRIBE_MS = 2500; // guard against a stray retained message

// ---- MQTT topics ----
const char *TOPIC_CMD = "jardim/cmd";
const char *TOPIC_STATUS = "jardim/status";

// ---- TOTP (RFC 6238) ----
const int MAX_TOTP_SECRETS = 8;              // array size, not "number of people" — ver conversa
const unsigned long TOTP_STEP_SECONDS = 30;  // tamanho padrao da janela de tempo
const unsigned int TOTP_CODE_BYTES = 8;      // bytes do digest expostos no codigo
const unsigned int TOTP_CODE_LEN = TOTP_CODE_BYTES * 2; // 16 caracteres hexadecimais (64 bits)
const int TOTP_WINDOW = 1;                   // aceita o passo atual, o anterior e o seguinte
const unsigned long NTP_STALE_MS = 48UL * 3600UL * 1000UL; // 48h sem sincronizar = falha segura
const int MAX_FAILED_ATTEMPTS = 5;           // tentativas invalidas consecutivas antes do bloqueio
const unsigned long LOCKOUT_MS = 60UL * 1000UL; // duracao do bloqueio temporario

// Slot vazio = string vazia (""). As entradas reais ficam em secrets.h.
const char *TOTP_SECRETS[MAX_TOTP_SECRETS] = {
  TOTP_SECRET_1, TOTP_SECRET_2, TOTP_SECRET_3, TOTP_SECRET_4,
  TOTP_SECRET_5, TOTP_SECRET_6, TOTP_SECRET_7, TOTP_SECRET_8,
};
uint64_t lastAcceptedStep[MAX_TOTP_SECRETS] = {0};

int consecutiveFailedAttempts = 0;
unsigned long lockoutUntilMillis = 0;

// Atualizado sempre que o relogio do sistema e ajustado (sincronizacao
// inicial ou qualquer resincronizacao periodica feita internamente pelo
// core do ESP8266) — e assim que detectamos um "sync de verdade", nao s
// que o relogio continua correndo sozinho desde o ultimo sync.
volatile unsigned long lastNtpSyncMillis = 0;
volatile bool ntpEverSynced = false;

void onNtpSync() {
  lastNtpSyncMillis = millis();
  ntpEverSynced = true;
}

bool ntpIsFresh() {
  if (!ntpEverSynced) return false;
  return (millis() - lastNtpSyncMillis) < NTP_STALE_MS;
}

// ---- LED azul embutido do ESP-01S ----
// Ligado ao GPIO2, em logica invertida (LOW acende, HIGH apaga). Serve
// como diagnostico visual sem precisar do monitor serial:
//   aceso fixo        -> Wi-Fi e MQTT ambos conectados (funcionamento normal)
//   1 piscada + pausa  -> sem Wi-Fi, ou Wi-Fi ok mas MQTT inacessivel
//   2 piscadas + pausa -> modo AP (WiFiManager), aguardando configuracao
const int LED_PIN = 2;
const unsigned long LED_BLINK_ON_MS = 150;
const unsigned long LED_BLINK_OFF_MS = 150;
const unsigned long LED_BLINK_PAUSE_MS = 700;
const unsigned long LED_PULSE_BLINK_MS = 25; // pisca rapido durante o acionamento do portao

void ledOn()  { digitalWrite(LED_PIN, LOW); }
void ledOff() { digitalWrite(LED_PIN, HIGH); }

// Maquina de estados do piscar, dirigida por Ticker (timer de hardware),
// nao por millis() no loop principal - assim ela continua animando
// mesmo durante chamadas bloqueantes como wifiManager.autoConnect() ou
// os delay() de retentativa em connectMQTT().
Ticker ledTicker;
int ledBlinkStep = 0;
int ledBlinkCount = 1; // 1 ou 2 piscadas por ciclo, conforme o modo atual
int currentLedMode = -1; // -1 = indefinido, 0 = aceso fixo, 1 ou 2 = piscando

void ledBlinkTick() {
  int totalSteps = ledBlinkCount * 2; // on+off para cada piscada do ciclo
  int stepInCycle = ledBlinkStep % (totalSteps + 1); // +1 = a pausa final
  if (stepInCycle < totalSteps) {
    if (stepInCycle % 2 == 0) {
      ledOn();
      ledTicker.once_ms(LED_BLINK_ON_MS, ledBlinkTick);
    } else {
      ledOff();
      ledTicker.once_ms(LED_BLINK_OFF_MS, ledBlinkTick);
    }
  } else {
    ledOff();
    ledTicker.once_ms(LED_BLINK_PAUSE_MS, ledBlinkTick);
  }
  ledBlinkStep++;
}

void startBlinking(int count) {
  ledBlinkCount = count;
  ledBlinkStep = 0;
  ledBlinkTick();
}

// Troca de modo do LED, mas so reinicia o padrao de piscar se o modo
// realmente mudou - evita reiniciar o ciclo a cada chamada repetida.
void setLedMode(int mode) {
  if (mode == currentLedMode) return;
  currentLedMode = mode;
  if (mode == 0) {
    ledTicker.detach();
    ledOn();
  } else {
    startBlinking(mode);
  }
}

BearSSL::WiFiClientSecure secureClient;
PubSubClient mqttClient(secureClient);

unsigned long lastTriggerMillis = 0;
unsigned long subscribedAtMillis = 0;
bool everSubscribed = false;

void pulseGate() {
  Serial.println(F("Acionando portao..."));

  // Pisca o LED rapidamente durante o pulso, como indicacao visual do
  // acionamento (sem depender do monitor serial). O intervalo e curto
  // e deterministico (PULSE_MS), entao o padrao normal do LED (Ticker)
  // e suspenso e substituido por um piscar manual so por essa janela,
  // e restaurado ao modo anterior no final.
  int previousLedMode = currentLedMode;
  ledTicker.detach();

  digitalWrite(TRIGGER_PIN, HIGH);
  unsigned long pulseStart = millis();
  bool ledState = false;
  while (millis() - pulseStart < PULSE_MS) {
    ledState = !ledState;
    if (ledState) ledOn(); else ledOff();
    delay(LED_PULSE_BLINK_MS);
  }
  digitalWrite(TRIGGER_PIN, LOW);

  currentLedMode = -1; // forca setLedMode a reaplicar o padrao, mesmo se for o mesmo numero
  setLedMode(previousLedMode);

  mqttClient.publish(TOPIC_STATUS, "acionado", false);
  Serial.println(F("Sinal enviado."));
}

// Decodifica uma string Base32 (RFC 4648, alfabeto A-Z2-7, sem distincao
// de maiusculas/minusculas, '=' de padding ignorado) em bytes crus.
// Retorna a quantidade de bytes escritos em 'out', ou 0 se a entrada for
// invalida ou maior do que 'outLen' permite.
size_t base32Decode(const char *input, uint8_t *out, size_t outLen) {
  uint32_t buffer = 0;
  int bitsLeft = 0;
  size_t count = 0;
  for (const char *p = input; *p; p++) {
    char c = *p;
    if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
    int8_t val;
    if (c >= 'A' && c <= 'Z') val = c - 'A';
    else if (c >= 'a' && c <= 'z') val = c - 'a';
    else if (c >= '2' && c <= '7') val = c - '2' + 26;
    else return 0; // caractere fora do alfabeto Base32

    buffer = (buffer << 5) | (uint32_t)val;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      if (count >= outLen) return 0; // buffer de saida pequeno demais
      out[count++] = (uint8_t)(buffer >> (bitsLeft - 8));
      bitsLeft -= 8;
    }
  }
  return count;
}

// Calcula o codigo TOTP para a chave e o passo de tempo (C) fornecidos,
// usando o HMAC-SHA1 que ja vem embutido no BearSSL (o mesmo usado para
// o TLS do MQTT) — nenhuma biblioteca nova. Em vez do truncamento
// decimal do RFC 4226/6238 (pensado para um numero que uma pessoa
// digita de cabeca), expoe diretamente os primeiros TOTP_CODE_BYTES
// bytes do digest como uma string hexadecimal de TOTP_CODE_LEN
// caracteres: o codigo nunca e visto nem digitado por uma pessoa, e um
// espaco de busca maior (64 bits) torna a forca bruta impraticavel mesmo
// em cenarios de reinicio do dispositivo, que zeram o bloqueio por
// tentativas. "out" deve ter pelo menos TOTP_CODE_LEN + 1 bytes.
void totpCode(const uint8_t *key, size_t keyLen, uint64_t step, char *out) {
  uint8_t msg[8];
  uint64_t stepCopy = step;
  for (int i = 7; i >= 0; i--) {
    msg[i] = (uint8_t)(stepCopy & 0xFF);
    stepCopy >>= 8;
  }

  br_hmac_key_context keyCtx;
  br_hmac_key_init(&keyCtx, &br_sha1_vtable, key, keyLen);

  br_hmac_context hmacCtx;
  br_hmac_init(&hmacCtx, &keyCtx, 0);
  br_hmac_update(&hmacCtx, msg, sizeof(msg));

  uint8_t hash[20]; // SHA-1 produz 20 bytes
  br_hmac_out(&hmacCtx, hash);

  static const char hexDigits[] = "0123456789abcdef";
  for (unsigned int i = 0; i < TOTP_CODE_BYTES; i++) {
    out[i * 2]     = hexDigits[(hash[i] >> 4) & 0x0F];
    out[i * 2 + 1] = hexDigits[hash[i] & 0x0F];
  }
  out[TOTP_CODE_LEN] = '\0';
}

// Verifica se o payload recebido (texto de TOTP_CODE_LEN caracteres
// hexadecimais) corresponde a um codigo TOTP valido e ainda nao usado de
// algum dos segredos cadastrados. Em caso de sucesso, atualiza o
// contador de replay daquele segredo especifico e retorna true.
bool totpMatches(const uint8_t *payload, unsigned int length) {
  if (length != TOTP_CODE_LEN) return false;

  char received[TOTP_CODE_LEN + 1];
  for (unsigned int i = 0; i < length; i++) {
    char c = (char)payload[i];
    bool isHexDigit = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    if (!isHexDigit) return false; // so aceita hexadecimal minusculo, igual ao gerado pela pagina
    received[i] = c;
  }
  received[TOTP_CODE_LEN] = '\0';

  uint64_t currentStep = (uint64_t)time(nullptr) / TOTP_STEP_SECONDS;
  char candidate[TOTP_CODE_LEN + 1];

  for (int i = 0; i < MAX_TOTP_SECRETS; i++) {
    if (TOTP_SECRETS[i][0] == '\0') continue; // slot vazio, pula

    uint8_t key[32];
    size_t keyLen = base32Decode(TOTP_SECRETS[i], key, sizeof(key));
    if (keyLen == 0) continue; // segredo mal formado, pula o slot

    for (int w = -TOTP_WINDOW; w <= TOTP_WINDOW; w++) {
      if (w < 0 && currentStep < (uint64_t)(-w)) continue; // evita underflow perto do boot
      uint64_t step = currentStep + w;
      if (step <= lastAcceptedStep[i]) continue; // esse passo ja foi usado - bloqueia replay
      totpCode(key, keyLen, step, candidate);
      if (strcmp(candidate, received) == 0) {
        lastAcceptedStep[i] = step;
        return true;
      }
    }
  }
  return false;
}

void mqttCallback(char *topic, byte *payload, unsigned int length) {
  if (strcmp(topic, TOPIC_CMD) != 0) return;

  if (!everSubscribed || (millis() - subscribedAtMillis < IGNORE_AFTER_SUBSCRIBE_MS)) {
    Serial.println(F("Ignorando mensagem logo apos subscribe (possivel retained)."));
    return;
  }

  if (millis() < lockoutUntilMillis) {
    Serial.println(F("Bloqueado temporariamente apos tentativas invalidas - comando ignorado."));
    return;
  }

  if (!ntpIsFresh()) {
    Serial.println(F("Hora nao sincronizada (ou sincronizacao antiga) - comando rejeitado (falha segura)."));
    return;
  }

  if (!totpMatches(payload, length)) {
    Serial.println(F("Codigo TOTP invalido - comando ignorado."));
    consecutiveFailedAttempts++;
    if (consecutiveFailedAttempts >= MAX_FAILED_ATTEMPTS) {
      lockoutUntilMillis = millis() + LOCKOUT_MS;
      consecutiveFailedAttempts = 0;
      Serial.println(F("Muitas tentativas invalidas - bloqueando temporariamente."));
    }
    return;
  }
  consecutiveFailedAttempts = 0;

  if (millis() - lastTriggerMillis < COOLDOWN_MS) {
    Serial.println(F("Comando ignorado (cooldown ativo)."));
    return;
  }

  lastTriggerMillis = millis();
  pulseGate();
}

String clientId() {
  return "esp01-portao-" + String(ESP.getChipId(), HEX);
}

void connectMQTT() {
  while (!mqttClient.connected()) {
    setLedMode(1);
    Serial.print(F("Conectando ao broker MQTT... "));
    String cid = clientId();
    if (mqttClient.connect(cid.c_str(), MQTT_USER, MQTT_PASSWORD)) {
      Serial.println(F("conectado."));
      mqttClient.subscribe(TOPIC_CMD, 1);
      subscribedAtMillis = millis();
      everSubscribed = true;
      mqttClient.publish(TOPIC_STATUS, "online", false);
    } else {
      Serial.print(F("falhou, rc="));
      Serial.print(mqttClient.state());
      Serial.println(F(" - tentando de novo em 3s"));
      delay(3000);
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(100);
  Serial.println(F("\nIniciando jardim..."));

  pinMode(TRIGGER_PIN, OUTPUT);
  digitalWrite(TRIGGER_PIN, LOW);

  pinMode(LED_PIN, OUTPUT);
  ledOff();

  WiFiManager wifiManager;
  // 2 piscadas enquanto o modo AP (configuracao) estiver ativo.
  wifiManager.setAPCallback([](WiFiManager *wm) { setLedMode(2); });
  // AP de configuracao protegida por senha, ao contrario do sketch
  // anterior (que usava um AP aberto) - evita que alguem nas proximidades
  // reconfigure o dispositivo durante o setup inicial.
  if (!wifiManager.autoConnect("PortaoWiFi-Setup", WM_AP_PASSWORD)) {
    Serial.println(F("Falha ao conectar ao Wi-Fi - reiniciando."));
    delay(1000);
    ESP.restart();
  }
  setLedMode(1); // Wi-Fi ok, ainda sem MQTT
  Serial.print(F("Wi-Fi conectado. IP: "));
  Serial.println(WiFi.localIP());

  // Sincroniza o relogio via NTP antes de qualquer conexao TLS: a
  // validacao do certificado real (root_ca.h) e o calculo do TOTP
  // dependem de o ESP8266 conhecer a hora atual, e o relogio interno
  // comeca zerado (~1970) a cada boot. settimeofday_cb registra quando
  // o relogio e de fato ajustado (agora e em qualquer resincronizacao
  // futura), para a checagem de "hora desatualizada" do TOTP.
  settimeofday_cb(onNtpSync);
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  Serial.print(F("Sincronizando hora via NTP"));
  time_t now = time(nullptr);
  while (now < 8 * 3600 * 2) {
    delay(500);
    Serial.print(F("."));
    now = time(nullptr);
  }
  Serial.println();
  Serial.print(F("Hora sincronizada: "));
  Serial.print(ctime(&now));

  // TLS: uma unica ancora de confianca (leve) em vez de um bundle
  // completo de CAs - ver include/root_ca.h para preencher com o
  // certificado real do seu broker.
  static BearSSL::X509List trustAnchor(EMQX_ROOT_CA);
  secureClient.setTrustAnchors(&trustAnchor);

  // Reduz o uso de RAM (importante nos ~80KB do ESP8266) se o broker
  // suportar negociacao de fragmento maximo (MFLN); cai para os buffers
  // padrao (maiores) se nao suportar.
  if (secureClient.probeMaxFragmentLength(MQTT_HOST, MQTT_PORT, 512)) {
    secureClient.setBufferSizes(512, 512);
    Serial.println(F("MFLN suportado: buffers TLS reduzidos."));
  } else {
    Serial.println(F("MFLN nao suportado pelo broker: usando buffers TLS padrao."));
  }

  mqttClient.setServer(MQTT_HOST, MQTT_PORT);
  mqttClient.setCallback(mqttCallback);

  connectMQTT();
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    setLedMode(1);
    Serial.println(F("Wi-Fi caiu, aguardando reconexao..."));
    delay(1000);
    return;
  }
  if (!mqttClient.connected()) {
    everSubscribed = false;
    connectMQTT();
  }
  setLedMode(0);
  mqttClient.loop();
}
