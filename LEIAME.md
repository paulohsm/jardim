# jardim

Sistema de acionamento remoto para um portão elétrico residencial,
controlado por uma página web pela internet e protegido por códigos
TOTP de uso único (no estilo RFC 6238), validados inteiramente no
firmware do dispositivo.

Página ativa: https://paulohsm.github.io/jardim/

## Como funciona

Um ESP-01S (ESP8266) é ligado, através de um adaptador USB CH340G já
existente e de um transistor BC548, aos contatos da placa do controle
remoto original do portão — assim ele consegue "apertar o botão"
eletronicamente sem substituir o controle original.

O ESP-01S permanece conectado a um broker MQTT (EMQX Cloud, com TLS) e
assina um tópico de comando. A página web estática em `docs/` conecta
ao mesmo broker via MQTT sobre WebSocket e publica um código de uso
único nesse tópico quando o botão "Acionar portão" é pressionado. O
firmware só aciona o relé do portão se esse código for um código TOTP
válido, ainda não usado, de um dos até 8 segredos cadastrados.

## Modelo de segurança

- Cada segredo autorizado (`K`) é um segredo TOTP padrão Base32 (o
  mesmo formato usado por qualquer aplicativo autenticador), gerado de
  forma independente para cada dispositivo/pessoa.
- Os segredos ficam apenas em `include/secrets.h` no firmware
  (ignorado pelo git, nunca commitado) e no `localStorage` do próprio
  navegador de cada pessoa autorizada, do lado da página — nunca no
  código publicado deste repositório.
- O código de uso único é derivado com HMAC-SHA1 sobre um intervalo de
  30 segundos, da mesma forma que o TOTP padrão funciona, mas em vez
  dos 6 dígitos decimais usuais, ele expõe 16 caracteres hexadecimais
  (64 bits) — o código nunca é digitado ou lido por uma pessoa, então
  não há motivo para mantê-lo curto.
- O firmware garante, independentemente da página:
  - **Proteção contra repetição (replay)**: cada intervalo de tempo
    aceito é registrado por segredo e nunca é aceito de novo.
  - **Falha segura em caso de relógio dessincronizado**: nenhum
    código é aceito se o dispositivo nunca sincronizou via NTP, ou se
    a última sincronização tem mais de 48h.
  - **Bloqueio temporário**: após 5 tentativas inválidas consecutivas,
    novas tentativas são ignoradas por 60 segundos.
- A credencial MQTT embutida no JavaScript público da página
  (`jardim-app`) é intencionalmente pública: ela é restrita, pela ACL
  do broker, a publicar apenas no tópico de comando — não pode assinar
  nada. A fronteira de segurança real é a verificação TOTP no
  firmware, não o sigilo dessa credencial.
- A credencial MQTT do próprio dispositivo (`jardim-esp`, com direito
  de assinatura) e todos os segredos TOTP ficam totalmente fora deste
  repositório.

## Hardware

- ESP-01S (ESP8266, 512KB de flash)
- Adaptador USB com chip WCH CH340G, ligado à placa do controle
  remoto original do portão
- Transistor BC548 como chave eletrônica entre o ESP-01S e os
  contatos do controle remoto original

## Configuração do firmware

1. Copie `include/secrets_example.h` para `include/secrets.h` (esse
   arquivo é ignorado pelo git e nunca deve ser commitado).
2. Preencha o host/porta TLS do EMQX Cloud e uma credencial MQTT
   dedicada para o dispositivo (`MQTT_USER`/`MQTT_PASSWORD`), criada
   em Authentication no broker.
3. Gere até 8 segredos TOTP Base32 independentes, um por
   dispositivo/pessoa que você queira autorizar, por exemplo:
   ```
   openssl rand 20 | python3 -c "import sys, base64; print(base64.b32encode(sys.stdin.buffer.read()).decode())"
   ```
   Deixe um slot como `""` se não precisar dele.
4. Defina uma `WM_AP_PASSWORD` para o hotspot de configuração do
   WiFiManager que aparece no primeiro boot (ou após um reset de
   Wi-Fi).
5. Compile e grave com o PlatformIO:
   ```
   pio run
   pio run -t upload
   ```

## Configuração do broker EMQX Cloud

Duas credenciais separadas, em Access Control → Authentication, com
ACLs em Access Control → Authorization:

- `jardim-esp` (usada pelo firmware): assinar `jardim/cmd`, publicar
  `jardim/status`.
- `jardim-app` (usada pela página web pública): publicar apenas
  `jardim/cmd` — sem permissão de assinatura em nada.
- Negar tudo como regra padrão/geral.

## Página web

`docs/index.html` é uma página estática (sem etapa de build) publicada
via GitHub Pages a partir da pasta `/docs` deste repositório. O host
MQTT e a credencial `jardim-app` estão fixos no código-fonte — veja
"Modelo de segurança" acima para entender por que isso não é um
problema.

Cada pessoa autorizada abre a página uma vez, cola seu próprio segredo
TOTP em Base32 no campo de configuração, e ele é salvo apenas no
`localStorage` daquele navegador. A partir daí, apertar o botão
calcula e envia um código novo automaticamente.

## Enviando para o GitHub

Se este repositório tiver commits locais que ainda não estão no GitHub:
```
git add -A
git commit -m "sua mensagem"
git push origin master
```
Isso exige acesso de rede a github.com no computador onde o comando for
executado.

## Publicando a página (GitHub Pages)

1. Envie (push) este repositório para o GitHub (se o próprio push
   falhar, veja "Enviando para o GitHub" abaixo).
2. No GitHub, acesse **Settings → Pages**.
3. Em "Build and deployment", escolha **Deploy from a branch**.
4. Selecione a branch **`master`** e a pasta **`/docs`**, depois
   clique em **Save**.
5. O GitHub publica a página em `https://<usuario>.github.io/<repositorio>/`
   — geralmente em um ou dois minutos. Para este repositório:
   https://paulohsm.github.io/jardim/

## Licença

Nenhuma licença foi escolhida ainda para este repositório.
