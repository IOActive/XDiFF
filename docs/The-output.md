## Analyzing the output
The most basic form of analyzing the output is running:
```
./analyze.py -d shells.sqlite
```
A normal analysis output looks like this:
![Analyze the output](https://user-images.githubusercontent.com/12038478/33235297-3a2bbd44-d214-11e7-93b0-dbb223747f23.png)

### HTML
The previous execution creates by default an HTML file named ```shells.sqlite.html``` that for this session looks like this on a web browser:

![HTML](https://user-images.githubusercontent.com/12038478/33235323-cce95632-d214-11e7-95cd-df2c61ebc3c9.png)

### Text

Another possibility is to output the analysis as text when using the ```-t txt``` option:
![Text](https://user-images.githubusercontent.com/12038478/33235337-5205f744-d215-11e7-8270-1d82b5484573.png)

## The analytic functions
There are multiple analytic functions that can expose information from the database. The default function that gets executed is ```report```, which include 15 functions. Following is the whole list of function, and the ones in bold are already included as part of the ```report```:

- **```analyze_canary_file```**: Find canary filenames in the stdout or stderr, even though canary files were not part of the payload
- **```analyze_canary_token_code```**: Find canary tokens of code executed in the stdout or in the stderr
- **```analyze_canary_token_command```**: Find canary tokens of commands in the stdout or stderr
- **```analyze_canary_token_file```**: Find canary tokens of files in the stdout or in the stderr
- ```analyze_elapsed```: Analize which was the total time required for each piece of software
- ```analyze_file_disclosure_without_path```: Find the tmp_prefix in the stdout or stderr without the full path
- ```analyze_file_disclosure```: Find the tmp_prefix in the stdout or in the stderr
- ```analyze_killed_differences```: Find when one piece of software was killed AND another one was not killed for the same input
- **```analyze_output_messages```**: Analize which were the different output messages for each piece of software
- ```analyze_path_disclosure_without_file```: Find the tmp_dir in the stdout or stderr, even though the testcase did not have a temporary file
- ```analyze_path_disclosure```: Find the tmp_dir in the stdout or stderr
- **```analyze_remote_connection```**: Find remote connections made
- **```analyze_return_code_differences```**: Find when different return codes are received for the same input
- **```analyze_return_code_same_software_differences```**: Find when different return codes are received for the same software using different input forms
- **```analyze_return_code```**: Get the different return codes for each piece of software
- ```analyze_same_software```: Find when the same software produces different results when using different inputs 
- ```analyze_same_stdout```: Finds different testcases that produce the same standard output
- ```analyze_specific_return_code```: Find specific return codes
- **```analyze_stdout```**: Find when different pieces of software produces different results 
- ```analyze_top_elapsed_killed```: Find which killed tests cases required more time
- ```analyze_top_elapsed_not_killed```: Find which not killed tests cases required more time
- **```analyze_username_disclosure```**: Find when a specific username is disclosed in the stdout or in the stderr
- **```analyze_valgrind```**: Find Valgrind references in case it was used
- ```list_killed_results```: Print the killed fuzzing results
- **```list_results```**: Print the fuzzing results: valuable to see how the software worked with the testcases defined, without using any constrains
- **```list_software```**: Print the list of [active] software used with testcases from the database
- ```list_summary```: Print an quantitative information summary using all the analytic functions from this class

### Working with the analytic functions
Depending on what type of software you're fuzzing, it may be convenient to enable or disable certain functions. The best way is to modify the ```analyze.py``` script to expose the information that we need. 

For other scenarios, you may just want to expose the output of a single function. Let's suppose that you only care about the analytic function ```analyze_return_code``` to see how code behaves:
<pre>
./analyze.py -d shells.sqlite -m <b>analyze_return_code</b> -o txt
</pre>

The previous command produces the following output:
```
----------------------------------------------------------------------------------------
| Analyze Different Return Codes per Software - analyze_return_code (5 rows)           |
----------------------------------------------------------------------------------------
| Software        | Type     | OS                | Return Code      | Amount           |
----------------------------------------------------------------------------------------
| Bash            | CLI      | darwin            | 1                | 499              |
----------------------------------------------------------------------------------------
| Bash            | CLI      | darwin            | 2                | 76               |
----------------------------------------------------------------------------------------
| Ksh             | CLI      | darwin            | 0                | 73               |
----------------------------------------------------------------------------------------
| Ksh             | CLI      | darwin            | 1                | 495              |
----------------------------------------------------------------------------------------
| Ksh             | CLI      | darwin            | 3                | 7                |
----------------------------------------------------------------------------------------
```