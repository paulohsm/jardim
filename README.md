# jardim

Remote-trigger system for a residential electric gate, controlled from a
web page over the internet and protected by TOTP (RFC 6238-style)
one-time codes validated entirely on the device firmware.

Live page: https://paulohsm.github.io/jardim/

## How it works

An ESP-01S (ESP8266) is wired, through an existing CH340G USB adapter and
a BC548 transistor, to the pads of the house's original gate remote
control board — so it can "press the button" electronically without
replacing the original remote.

The ESP-01S stays connected to an MQTT broker (EMQX Cloud, TLS) and
subscribes to a command topic. The static web page in `docs/` connects to
the same broker over MQTT-over-WebSocket and publishes a one-time code to
that topic when the "Acionar portão" button is pressed. The firmware only
pulses the gate relay if that code is a valid, unused, time-based code
for one of up to 8 registered secrets.

## Security model

- Each authorized secret (`K`) is a standard Base32 TOTP secret (the same
  format any authenticator app uses), generated independently per
  device/person.
- Secrets live only in `include/secrets.h` on the firmware side
  (gitignored, never committed) and in each authorized browser's own
  `localStorage` on the page side — never in this repository's published
  code.
- The one-time code is derived with HMAC-SHA1 over a 30-second time step,
  the same way standard TOTP works, but instead of the usual 6 decimal
  digits it exposes 16 hexadecimal characters (64 bits) — the code is
  never typed or read by a human, so there's no reason to keep it short.
- The firmware enforces, independently of the page:
  - **Replay protection**: each accepted time step is recorded per
    secret and never accepted again.
  - **Fail-closed on clock drift**: no code is accepted if the device
    has never synced over NTP, or the last sync is older than 48h.
  - **Lockout**: after 5 consecutive invalid attempts, new attempts are
    ignored for 60 seconds.
- The MQTT credential embedded in the public page's JavaScript
  (`jardim-app`) is intentionally public: it is restricted, via the
  broker's ACL, to publishing on the command topic only — it cannot
  subscribe to anything. The actual security boundary is the TOTP check
  in firmware, not the secrecy of that credential.
- The device's own MQTT credential (`jardim-esp`, with subscribe rights)
  and every TOTP secret stay out of this repository entirely.

## Hardware

- ESP-01S (ESP8266, 512KB flash)
- USB adapter with a WCH CH340G chip, wired into the gate's existing
  remote control board
- BC548 transistor as the electronic switch between the ESP-01S and the
  original remote's contacts

## Firmware setup

1. Copy `include/secrets_example.h` to `include/secrets.h` (this file is
   gitignored and must never be committed).
2. Fill in your EMQX Cloud TLS host/port and a dedicated MQTT credential
   for the device (`MQTT_USER`/`MQTT_PASSWORD`), created under the
   broker's Authentication settings.
3. Generate up to 8 independent Base32 TOTP secrets, one per
   device/person you want to authorize, e.g.:
   ```
   openssl rand 20 | python3 -c "import sys, base64; print(base64.b32encode(sys.stdin.buffer.read()).decode())"
   ```
   Leave a slot as `""` if you don't need it.
4. Set a `WM_AP_PASSWORD` for the WiFiManager setup hotspot that appears
   on first boot (or after a Wi-Fi reset).
5. Build and upload with PlatformIO:
   ```
   pio run
   pio run -t upload
   ```

## EMQX Cloud broker setup

Two separate credentials, under Access Control → Authentication, with
ACLs under Access Control → Authorization:

- `jardim-esp` (used by the firmware): subscribe `jardim/cmd`, publish
  `jardim/status`.
- `jardim-app` (used by the public web page): publish `jardim/cmd` only
  — no subscribe permission on anything.
- Deny-all as the default/catch-all rule.

## Web page

`docs/index.html` is a static page (no build step) published via GitHub
Pages from this repository's `/docs` folder. The MQTT host and the
`jardim-app` credential are hardcoded in its source — see "Security
model" above for why that's fine.

Each authorized person opens the page once, pastes their own Base32 TOTP
secret into the setup field, and it's saved only in that browser's own
`localStorage`. From then on, pressing the button computes and sends a
fresh code automatically.

## Pushing to GitHub

If this repository has local commits that aren't on GitHub yet:
```
git add -A
git commit -m "your message"
git push origin master
```
This needs network access to github.com from wherever you run it.

## Publishing the page (GitHub Pages)

1. Push this repository to GitHub (if the push itself fails, see
   "Pushing to GitHub" below).
2. On GitHub, go to **Settings → Pages**.
3. Under "Build and deployment", choose **Deploy from a branch**.
4. Pick branch **`master`** and folder **`/docs`**, then click **Save**.
5. GitHub publishes the page at `https://<user>.github.io/<repo>/` —
   usually within a minute or two. For this repository, that's
   https://paulohsm.github.io/jardim/

## License

No license has been chosen yet for this repository.
