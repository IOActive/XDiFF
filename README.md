# What is XDiFF?
 XDiFF is an Extended Differential Fuzzing Framework built for finding 
 vulnerabilities in software. It collects as much data as possible from 
 different executions an then tries to infer different potential vulnerabilities 
 based on the different outputs obtained.
 The vulnerabilities can either be found in isolated pieces of software or by 
 comparing:
  * Different inputs
  * Different versions
  * Different implementations
  * Different operating systems' implementations

 The fuzzer uses Python and runs on multiple OSs (Linux, Windows, OS X, and 
 Freebsd). Its main goal is to detect issues based on diffential fuzzing aided 
 with the extended capabilities to increase coverage. Still, it will found
 common vulnerabilities based on hangs and crashes, allowing to attach a 
 memory debugger to the fuzzing sessions.

## Quick guide
Please follow the following steps:
1. [Install](https://github.com/IOActive/XDiFF/wiki/1.-Install) XDiFF
2. Define [the input](https://github.com/IOActive/XDiFF/wiki/2.-The-input)
3. Define [the software](https://github.com/IOActive/XDiFF/wiki/3.-The-software)
4. Run [the fuzzer](https://github.com/IOActive/XDiFF/wiki/4.-The-fuzzer)
5. Analyze [the output](https://github.com/IOActive/XDiFF/wiki/5.-The-output) 
6. ...
7. Profit!

## Disclaimer
The tool and the fuzzing process can be susceptible to code execution. 
Use it at your own risk always inside a VM. 

## Authors
- Fernando Arnaboldi - _Initial work_
- [cclauss](https://github.com/cclauss)

For contributions, please propose a [Changelog](https://github.com/IOActive/XDiFF/wiki/Changelog) entry in the pull-request comments.

## Acknowledgments
Thanks Lucas Apa, Tao Sauvage, Scott Headington, Carlos Hollman, Cesar Cerrudo, Federico Muttis, Topo for their feedback and Arlekin for the logo.

## License
This project is licensed under the GNU general public license version 3.

## Logo
![XDiFF Logo](https://user-images.githubusercontent.com/12038478/33187082-ec625f3e-d06d-11e7-831a-08e11823a391.png)
