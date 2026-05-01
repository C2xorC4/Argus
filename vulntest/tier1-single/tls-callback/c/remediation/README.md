# Remediation

TLS callbacks are a legitimate language feature — Visual C++
runtime initialiser, MFC startup, instrumented telemetry. Their
*presence* is not a vulnerability; their *use as malware
first-stage* is.

Defender response: treat TLS-directory presence in unsigned /
unfamiliar binaries as one signal among many; combine with imports
analysis, string analysis, and behavioural telemetry to confirm
malicious intent.
