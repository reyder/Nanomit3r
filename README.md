# Nanomiter

Nanomiter is an experimental project focused on showing a concept of implementing powerful anti-debugging system. Whole project consists of 3 stages:

  - Target disassembly
  - Building external library with debugger
  - Injecting library

This implementation targets macOS system only ! Other operating systems are not taken into consideration in future development.

# New Features!

  - You can specify what sections are analyzed in 1st stage

### Tech

Nanomiter uses a number of open source projects to work properly:

* [Capstone] - lightweight multi-platform, multi-architecture disassembly framework
* [argparse] - simple C++ header only command line argument parser

### Installation

TODO

### Development

Want to contribute? Great! .. but not yet !

#### Building for source
For development build:
```sh
$ xcodebuild -scheme DEBUG build
```
Make sure to install capstone library from brew and link it in the project.

### Todos

 - Add json output file for PART 1
 - Support multiple segments / sections in dissassembly
 - Add limits for nanomites
 - Randomization
 - Add support for calls

**Free Software, Hell Yeah!**

[//]: # (You should not be here)

   [Capstone]: <https://www.capstone-engine.org/>
   [argparse]: <https://github.com/jamolnng/argparse>

