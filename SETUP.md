# Setup

Requires Linux, Python 3.12+, `libsodium23`, JDK 17, Android SDK platform 35 and build-tools 35.0.0.

## 1. Build once

Run from this folder, using your own JDK and SDK paths.

```bash
export JDK_DIR=/your/jdk-17
export SDK_DIR="$HOME/Android/Sdk"
export YPSO_ADB="$SDK_DIR/platform-tools/adb"
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
python3 -m venv .venv-proxy
.venv-proxy/bin/python -m pip install -r requirements-proxy.txt
export YPSO_MITMDUMP="$PWD/.venv-proxy/bin/mitmdump"
export YPSO_MITM_CONFDIR="$PWD/private/mitmproxy"
umask 077
mkdir -p private
.venv/bin/python tools/build_bridge.py --jdk "$JDK_DIR" --sdk "$SDK_DIR" --out build/bridge-01 --keystore private/bridge.keystore
```

## 2. Set up the phone once

I tested mylife 2.6.1.001 on Android 16; the helpers expect English screens.

1. Install mylife from Google Play and PCAPdroid on the phone.
2. Finish mylife's normal sign-in and leave its Device management empty.
3. The pump must already be paired with the phone through the normal CamAPS setup.
4. Enable USB debugging, approve the computer, keep the phone unlocked and enable Bluetooth and mylife's Nearby/location permissions.
5. Create the proxy certificate, then stop mitmproxy:

```bash
.venv-proxy/bin/mitmdump --set confdir="$YPSO_MITM_CONFDIR" --listen-host 127.0.0.1 --listen-port 18521
```

6. Install `private/mitmproxy/mitmproxy-ca-cert.cer` as a user CA through Android Settings.
7. In PCAPdroid, select VPN mode, only `net.sinovo.mylife.app`, and SOCKS `127.0.0.1:18520`.
8. Keep server certificate checks enabled.

## 3. Run

1. Start the configured PCAPdroid capture and connect the phone by USB.

```bash
.venv/bin/python run.py
```

2. On the first run, enter the pump's exact paired name and Bluetooth address from Android Settings.
3. The name must be `YpsoPump_` followed by eight digits, including the underscore.
4. The script remembers them, reads firmware automatically and calls the existing authorization/status test.

`Authorization passed.` means the pump accepted the authorization and returned status the client could authenticate and decrypt.

## 4. Clean up

1. Stop PCAPdroid capture, deny mylife's Nearby permission, and remove only the device entry created by this test from mylife's Device management.
2. Stop mylife and restore its previous permissions and your previous VPN settings.
3. Open CamAPS and verify fresh pump information; stopping the proxy does not restore the previous keys.
4. If needed, follow CamAPS's displayed instructions and its [normal re-linking process](https://s3-eu-west-1.amazonaws.com/camdiab.user.manual/user_manual_fx_mmoll_commercial.pdf#page=33).