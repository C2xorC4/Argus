# Remediation

VEH/SEH are legitimate language features. Their use as covert-
execution slots is the malware concern; the language feature is not
the bug.

Software developers: prefer C++ exceptions or explicit error returns
over VEH for normal control-flow needs.
