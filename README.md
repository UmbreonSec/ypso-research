# YpsoPump research

**DISCLAIMER: this is for RESEARCH ONLY, and should not be used on a real pump for medical purposes, as this might break your pump/settings, or cause any other unexpected consequences. I am NOT responsible for any damage/issues caused by the use of this repository.**

I used the official mylife app to get permission for my own app to communicate with the pump.

## How it works

1. A proxy replaced the app's public key with mine in its request to the manufacturer's server.
2. My client then used the server's reply to read and decrypt the pump's status.

No root or changes to the official app are needed.

## Notes

- The tests used one Android 16 phone, Linux and pump firmware V05.02.03.
- Saved keys worked after reconnecting and restarting the phone, and a fresh key replacement also worked.
- Some authorization attempts and returns to CamAPS failed, so reliable renewal and recovery remain unfinished.
- I did not test insulin delivery or waiting for a key to expire.

Follow [SETUP.md](SETUP.md) once, then run `.venv/bin/python run.py`.
