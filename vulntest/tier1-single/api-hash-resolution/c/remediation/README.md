# Remediation

API hash resolution is a malware obfuscation technique; not a
software vulnerability. The legitimate alternative is `LoadLibrary`
+ `GetProcAddress` with strings — which is what defenders expect.
Defender response: structural detection of the export-walk +
hash-compare loop is high-confidence malware indicator.
