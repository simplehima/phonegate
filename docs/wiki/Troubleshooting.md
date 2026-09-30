# Troubleshooting

| Problem | What to do |
|---|---|
| The PC app says **"The PhoneGate service isn't running"** | Open *Services*, find **PhoneGate Agent** and start it. The watchdog also restarts it within 5 minutes. If it keeps stopping, run the setup again. |
| **SmartScreen** blocks the setup | The setup isn't code-signed yet. Check its SHA-256 against `SHA256SUMS.txt`, then choose *More info → Run anyway*. |
| **No request arrives on the phone** | Check that the phone has internet and that PhoneGate is allowed to show notifications. Also make sure battery optimisation isn't restricting it (Settings → Apps → PhoneGate → Battery → Unrestricted). Then open `https://<your relay>/healthz`; it should say `ok`. |
| The phone says the **number doesn't match** | Type the 2-digit number shown on the PC. Getting it wrong twice is treated as suspicious. |
| **Relay down or no internet** at the lock screen | Use **Offline approval** or a **recovery code**. See [Recovery and offline access](Recovery-and-offline-access.md). |
| The phone app **was reinstalled or the phone was reset** | Its keys are gone. Sign in with a recovery code, then pair again. |
| You **enrolled a new fingerprint** on the phone | Android invalidates the approval key when fingerprints change. Pair the PC again. |
| **"Stopped reporting"** alert | The PC may just be offline or have lost power. If not, check that PhoneGate is still installed and running. |
| Uninstall is refused | Protection is on. Turn it off in the PC app first. |
