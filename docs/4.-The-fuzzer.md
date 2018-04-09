## Fuzzing
The most basic execution requires defining which category and which database will be used:
```
./run.py -c shells -d shells.sqlite
```
The output should look like this:
![Basic execution](https://user-images.githubusercontent.com/12038478/33235137-ebf31cba-d210-11e7-9e39-d75e7a946ce5.png)

It includes a lot of debugging information, and the most important parts are marked. At the top is the execution, and at the bottom is the beginning of the execution along with the rate (you want this number to be as high as possible).

## Fuzzing using the input fuzzers

If you want to generate new test cases based on the currently defined test cases, you can use the input fuzzers that were installed as part of the install process.
```
./run.py -c shells -d shells.sqlite -z 0
```
Now the output should indicate now and then when new inputs are being generated
![Using the input fuzzers](https://user-images.githubusercontent.com/12038478/33235241-c786cbd6-d212-11e7-8f43-d470a6cdfff1.png)

## Additional fuzzing options:

There are three additional important optional settings to be mentioned:

- [*-t 100*]: The amount of threads to be executed in parallel.
- [*-T 10*]: The timeout per thread
- [*-v*]: Use valgrind to execute the software to be fuzzed.

The combination of threads and the timeout is something to be defined per category. Fuzzing a shell requires no time, while compiling and fuzzing a java program takes much more time. Pay attention at the output produced to see if the software is being properly executed (or is getting mostly killed because the timeout is too low).

---
# What's next?

You want to analyze [the output](https://github.com/IOActive/XDiFF/wiki/The-output)