# What is XDiFF?
XDiFF is an Extended Differential Fuzzing Framework built to find vulnerabilities. Its goal is to collect as much valuable data as possible and then to infer all potential vulnerabilities in the application/s. Vulnerabilities can either be found in isolated pieces of software or by comparing:
* Different inputs
* Different versions
* Different implementations
* Different operating systems' implementations

It is an open source Python fuzzer able to test multiple pieces of software and inputs in parallel. It can run on multiple OSs (Linux, Windows, OS X, and Freebsd). The fuzzer's main goal is to detect differential issues aided with the extended capabilities, but since will also trigger hangs and crashes is also capable of attaching a debugger to detect memory errors.

## Quick guide
1. [Install](https://github.com/IOActive/XDiFF/wiki/Install) XDiFF on a VM
2. [The input](https://github.com/IOActive/XDiFF/wiki/The-input) of test cases that you will be using to feed the fuzzer.
3. [The software](https://github.com/IOActive/XDiFF/wiki/The-software) that you will fuzz
4. [The output](https://github.com/IOActive/XDiFF/wiki/The-output) of the test cases once processed and how to analyze them 
5. ...
6. Profit!

## Author
Fernando Arnaboldi - _Initial work_

## Acknowledgments
Thanks to Lucas Apa, Tao Sauvage, Scott Headington, Carlos Hollman, Cesar Cerrudo, Acid and Topo for their reviews and comments. Thanks to Arlekin for the logo.

## License
This project is licensed under the GNU general public license version 3.

## Logo
![XDiFF Logo](https://user-images.githubusercontent.com/12038478/33187082-ec625f3e-d06d-11e7-831a-08e11823a391.png)

