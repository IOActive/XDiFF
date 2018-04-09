# Changelog
Changes are listed in time order: newer changes are at the top, older changes are at the bottom.

## Version: [1.2](https://github.com/IOActive/XDiFF/releases/tag/1.2)
- Changed main function names in the root directory
- Improved code, documentation, and (most of) the code is now tested. Tons of bugfixes.
- Added new analysis for error disclosure (analyze_error_disclosure) and path disclosure (analyze_path_disclosure_stderr)
- Added new compatibility class (classes.compat) to support Python 3
- Added risk value to the different analytic functions. Print functions based on their rating: ./xdiff_analyze.py -d db.sqlite -r 0/1/2/3
- Improved analysis of network connections to test browsers connections
- software.ini: added support to test non random filenames. Set on the second column: Filename = /etc/myfixedfilename
- Added -d for debug output
- Added new parameters in the settings.py class
 
#### Contributors:
- farnaboldi

## Version: [1.1.1](https://github.com/IOActive/XDiFF/releases/tag/1.1.1) (beta)
- Added support for Python 3 [[2]](https://github.com/IOActive/XDiFF/pull/2)

#### Contributors:
- cclauss

## Version: [1.1.0](https://github.com/IOActive/XDiFF/releases/tag/1.1.0)
- First public release for Blackhat Europe 2017

#### Contributors:
- farnaboldi
