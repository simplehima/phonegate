# Installing the phone app

**Needs:** Android 11 or newer with a screen lock and a fingerprint or face unlock.

PhoneGate isn't on the Play Store. The Windows setup includes the app at
`C:\Program Files\PhoneGate\Android\PhoneGate.apk`, and every
[release](https://github.com/simplehima/phonegate/releases) has it too.

1. **Move the file to your phone** (pick one):
   - **USB cable**: choose *File transfer* on the phone and copy it to *Download*.
   - **Quick Share / Nearby Share**: right-click the APK → Share → your phone.
   - **Your own cloud drive**: upload it, then open it on the phone.
2. **Install**: open the file on the phone. When Android asks, allow *Install unknown apps* for
   your file manager (you can turn this off again afterwards). Tap **Install**.
3. **Check it's genuine**: in PhoneGate on the PC, open **Set up → Get the phone app**. It shows
   the APK's SHA-256 and its signing certificate; compare them with `SHA256SUMS.txt` from the
   release. If the PC app says the file *changed after installation*, don't install it.
4. Open PhoneGate on the phone and allow notifications. Sign-in requests arrive as notifications.

**Updates:** install the newer APK over the old one. Android accepts only updates signed with the
same key, which protects you from fake updates.

**One phone, several PCs:** a single phone can protect as many PCs as you like; pair each one
separately. Each PC is paired with exactly one phone.
