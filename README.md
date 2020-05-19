# Nanomiter

Nanomiter is an experimental project focused on showing a concept of implementing powerful anti-debugging system. Whole project consists of 3 stages:

  - Target disassembly
  - Building external library with debugger
  - Injecting library

This implementation targets macOS system only ! Other operating systems are not taken into consideration in future development.

## New Features!

  - You can specify what sections are analyzed in 1st stage

## Development

Want to contribute? Great! .. but not yet !

## Building for source

For development build:
```sh
$ xcodebuild -target Nanomit3r -scheme Nanomit3r -configuration DEBUG build
```
Make sure to install capstone library from brew and link it in the project.

## Usage

First step is to analyze binary file that we want to nanomite. Example of the command:

```bash
/Users/korona/Nanomit3r -f /Users/korona/csr -s __text -g __TEXT -o /Users/korona/nanomite_data.json --output2 /Users/korona/csr_mod
```

In result we receive 2 files:
* JSON file with nanomite data
* Modified binary file with nanomites

Next step is to build external library. We need first copy `nanomite_data.json` file to Nanobreak folder in this project. Afterwards execute:

```bash
xcodebuild -target NanoBreak -scheme NanoBreak -configuration DEBUG build
```

Finally we have alle parts and we can execute our binary. You can use any injection method to attach dylib. For testing purposes you can try:

```bash
DYLD_INSERT_LIBRARIES=/Users/korona/libNanoBreak.dylib /Users/korona/csr_mod
```

Special script was created for automted building and execution. Bash version 4+ is required: `brew install bash` 
All builds will be stored in project folder.

```bash
./helper.sh
```

## Tech

Nanomiter uses a number of open source projects to work properly:

* [Capstone] - lightweight multi-platform, multi-architecture disassembly framework
* [argparse] - simple C++ header only command line argument parser
* [json.h] - simple single header solution to parsing JSON in C and C++.

## Todos

- [x] Add json output file for PART 1
- [ ] Support multiple segments / sections in dissassembly
- [ ] Add limits for nanomites
- [ ] Randomization
- [x] Add support for calls

**Free Software, Hell Yeah!**

[//]: # (You should not be here)

   [Capstone]: <https://www.capstone-engine.org/>
   [argparse]: <https://github.com/jamolnng/argparse>
   [json.h]: <https://github.com/sheredom/json.h>
