# Remediation

Direct-syscall is a malware technique, not a software bug. The
"remediation" here is at the defender side: detect the technique
in inbound binaries and treat it as a strong evasion signal.

For software developers: do not roll syscall stubs in your own
code. Use the documented Win32 API. NTDLL syscall stubs are
internal contract and can change between Windows versions.
