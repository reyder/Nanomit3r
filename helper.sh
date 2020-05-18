#!/usr/local/bin/bash

build_nanomiter() {
	echo "Starting building Nanomit3r in $1 mode..."

	[[ "$1" == "DEBUG" ]] && CONF="Debug" || CONF="Release"

	xcodebuild -target Nanomit3r -scheme Nanomit3r -derivedDataPath build -configuration $CONF build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO
}

build_debuger() {
	echo "Starting building NanoBreak in $1 mode..."

	[[ "$1" == "DEBUG" ]] && CONF="Debug" || CONF="Release"

	xcodebuild -target NanoBreak -scheme NanoBreak -derivedDataPath build_dylib -configuration $CONF build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO
}

enter_working_dir() {
	WORK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

	echo "Entering correct working directory: $WORK_DIR"
	cd $WORK_DIR
}

only_run_main() {
	WORK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

	WHICH_EXAMPLE="csr"
	read -e -i "$WHICH_EXAMPLE" -p "Select example binary [inject_dylib | csr | jtool2 | disarm]: " WHICH_EXAMPLE

	OUTPUT_BINARY="/tmp/${WHICH_EXAMPLE}_mod"

	if [[ ! -f "$OUTPUT_BINARY" ]]; then
		echo "$OUTPUT_BINARY does not exist"
		exit 0
	fi

	chmod +x "$OUTPUT_BINARY"

	WHICH_SCHEME="RELEASE"
	read -e -i "$WHICH_SCHEME" -p "Which scheme do you want to use [RELEASE/DEBUG] for Nanobreak DYLIB: " WHICH_SCHEME

	if [[ $WHICH_SCHEME == "RELEASE" ]]; then
		WHICH_SCHEME="Release"
	else
		WHICH_SCHEME="Debug"
	fi

	if [[ ! -f "build_dylib/Build/Products/$WHICH_SCHEME/libNanoBreak.dylib" ]]; then
		echo "Dylib does not exists"
		exit 0
	fi

	SURE="y"
	read -e -i "$SURE" -p "WARNING !!! You need to recompile DYLIB evry time you change example binary or parametrs [y/n]: " SURE

	if [[ $SURE != "y" ]]; then
		echo "No agree. exit"
		exit 0
	fi

	DYLD_INSERT_LIBRARIES=${WORK_DIR}/build_dylib/Build/Products/$WHICH_SCHEME/libNanoBreak.dylib "$OUTPUT_BINARY"
}

main() {
	enter_working_dir

	ONLY_RUN="y"
	read -e -i "$ONLY_RUN" -p "You already BUILD all you need and want to just RUN examples ? [y/n]: " ONLY_RUN

	if [[ $ONLY_RUN == "y" ]]; then
		only_run_main

		echo "Goodbay."
		exit 0
	fi


	WANT_BUILD_NANO_REL="y"
	WANT_BUILD_NANO_DGB="n"
	read -e -i "$WANT_BUILD_NANO_REL" -p "Do you want build Nanomit3r (RELEASE) [y/n]: " WANT_BUILD_NANO_REL
	read -e -i "$WANT_BUILD_NANO_DGB" -p "Do you want build Nanomit3r (DEBUG) [y/n]: " WANT_BUILD_NANO_DGB

	echo "Building Nanomi3r RELEASE in 3 2 1."
	[[ "$WANT_BUILD_NANO_REL" == "y" ]] && build_nanomiter RELEASE
	echo "Building Nanomi3r DEBUG in 3 2 1."
	[[ "$WANT_BUILD_NANO_DGB" == "y" ]] && build_nanomiter DEBUG

	chmod +x "build/Build/Products/Release/Nanomit3r"
	echo "All builds successed."

	WHICH_SCHEME="RELEASE"
	WHICH_EXAMPLE="csr"
	read -e -i "$WHICH_SCHEME" -p "Which scheme do you want to use [RELEASE/DEBUG] for Nanomit3r: " WHICH_SCHEME
	read -e -i "$WHICH_EXAMPLE" -p "Select example binary [inject_dylib | csr | jtool2 | disarm]: " WHICH_EXAMPLE

	OUTPUT_BINARY="/tmp/${WHICH_EXAMPLE}_mod"
	OUTPUT_JSON="/tmp/${WHICH_EXAMPLE}.json"

	read -e -i "$OUTPUT_BINARY" -p "Select path for output modyfied bainry file: " OUTPUT_BINARY
	read -e -i "$OUTPUT_JSON" -p "Select path for output JSON data file: " OUTPUT_JSON


	if [[ $WHICH_SCHEME == "RELEASE" ]]; then
		echo "Executing Nanomit3r RELEASE."
		build/Build/Products/Release/Nanomit3r -f Examples/"$WHICH_EXAMPLE" -s __text -g __TEXT -o "$OUTPUT_JSON" --output2 "$OUTPUT_BINARY"
	else
		echo "Executing Nanomit3r DEBUG."
		build/Build/Products/Debug/Nanomit3r -f Examples/"$WHICH_EXAMPLE" -s __text -g __TEXT -o "$OUTPUT_JSON" --output2 "$OUTPUT_BINARY"
	fi

	echo "Move data file to NanoBreak Target..."
	mv -f "$OUTPUT_JSON" "Nanobreak/ww.h"

	echo "All seems good so far. Let's try to compile debuger."

	WANT_BUILD_DBG_REL="y"
	WANT_BUILD_DBG_DGB="y"
	read -e -i "$WANT_BUILD_DBG_REL" -p "Do you want build DYLIB debuger (RELEASE) [y/n]: " WANT_BUILD_DBG_REL
	read -e -i "$WANT_BUILD_DBG_DGB" -p "Do you want build DYLIB debuger (DEBUG) [y/n]: " WANT_BUILD_DBG_DGB

	echo "Building NanoBreak RELEASE in 3 2 1."
	[[ "$WANT_BUILD_DBG_REL" == "y" ]] && build_debuger RELEASE
	echo "Building NanoBreak DEBUG in 3 2 1."
	[[ "$WANT_BUILD_DBG_DGB" == "y" ]] && build_debuger DEBUG

	echo "Incredible. That's it. "

}

main
