XDiFF is an Extended Differential Fuzzing Framework built to find vulnerabilities. Its goal is to collect as much valuable data as possible and then to infer all potential vulnerabilities in the application/s. Vulnerabilities can either be found in isolated pieces of software or by comparing:
* different inputs
* different versions
* different implementations
* different operating systems' implementations

It is open source, written entirely in Python, and is able to fuzz multiple pieces of software and test cases in parallel. It can run on multiple OSs (Linux, Windows, OS X, and Freebsd). The fuzzer's main goal is to detect differential issues aided with the extended capabilities, but since will also trigger hangs and crashes is also capable of attaching a debugger to detect memory errors.

For more information please refer to the [guide](https://github.com/IOActive/XDiFF/wiki/What-is-XDiFF%3F) in the wiki.
