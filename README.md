# Biometric-EVM-Model-Software
Python program simulating Voting system except it uses fingerprint sensor of laptop to verify the user.

Misc maybe useful facts:
* The Python program uses Windows Biometric API.
* # The fingerprint registration should be done in Windows settings
* # The fingerprint slot refers to the position when a fingerprint is registered, so the first fingerprint registered on a laptop is slot 1, and subsequent fingerprints follow in order.
* This programs uses sqlite3 module of python. If you are using python 2.5 or above it is stardard inclusion else install it using PIP
* This program only works in Windows 10. I am trying to port it to Windows 11 but the new security features/inclusions in windows 11 is not helping.
