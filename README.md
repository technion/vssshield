# VSSShield

A Rust project in the spirit of [Raccine](https://github.com/Neo23x0/Raccine)

## Operation

vssshield is intended to be installed as a debugger for high risk applications, notably vssadmin and wmic.

Using either deny or allow lists, it attempts to decide what looks like an attempt to delete shadow copies. In such cases it will not only prevent execution, it will kill the parent process, which hopefully is the malware being executed.

It needs to be said that this style of application serves as a mitigation, and should never be anticipated as providing any level of assurance against any particular event.

## Development

The unusual nature of this application means that some amount of panics are acceptable and potentially even more desirable than alternatives in the case of an error. Some unsafe was unavoidable, but this has been modelled on code direct from Rust's stdlib test suite.

Code is designed to compile against Rust Stable with no clippy errors.

## Installation

The included Powershell script `Install-vssshield.ps1` will automatically download and register the latest stable version for use.