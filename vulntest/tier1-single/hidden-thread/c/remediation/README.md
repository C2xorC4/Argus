# Remediation

Hidden-from-debugger threads are a malware anti-analysis technique;
not a software vulnerability. Defender response: ETW-based
syscall monitoring catches `NtSetInformationThread` with the
hide-from-debugger class.
