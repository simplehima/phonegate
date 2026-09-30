# Recovery and offline access

PhoneGate is **fail-secure**: without an approval, the PC stays locked. So there are two ways in
that don't need the network.

## Offline approval (phone available, but no internet or the relay is down)

1. On the lock screen choose **Offline approval (no network)**. The PC shows a QR code.
2. On the phone, open **Offline code**, scan it, and confirm with your fingerprint.
3. On the PC, type the 10-digit code the phone shows, plus your password.

## Recovery codes (phone lost or dead)

On the lock screen choose **Use a recovery code**. Type your password and one of your 10 codes.

- Each code works **once**.
- After 5 wrong codes, entry is locked for a while, and each lockout is longer than the last.
- Your phone is told when a code was used.

Running low? In the PhoneGate app on the PC, turn protection off (you'll need a code or your
phone), generate a new set, and turn it back on.

## Last resort

Windows doesn't load third-party sign-in tiles in **Safe Mode**, so you can always sign in there
with just your password and uninstall PhoneGate. The tamper alarm reports Safe Mode starts to your
phone. See [Security model](Security-model.md).
