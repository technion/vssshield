# VSSShield

A Rust project in the spirit of [Raccine](https://github.com/Neo23x0/Raccine)

## Operation

vssshield is intended to be installed as a debugger for high risk applications, notably vssadmin and wmic.

Using either deny or allow lists, it attempts to decide what looks like an attempt to delete shadow copies. In such cases it will not only prevent execution, it will kill the parent process, which hopefully is the malware being executed.
