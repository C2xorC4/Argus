# Remediation

APC injection is a malware technique; not a software vulnerability.
Defender response: structural detection of the QueueUserAPC +
alertable-wait pair plus cross-process variant identification
(`OpenThread` + `QueueUserAPC` against another process).
