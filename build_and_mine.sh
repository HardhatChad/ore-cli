#!/bin/bash
#
echo ========================================================
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo ========================================================
cargo build --release
buildexitcode=$?
if [ $buildexitcode -gt 0 ]; then
	echo Build process reurned non zero exit code $buildexitcode so probably failed.
	exit $buildexitcode
fi

if [ ! -f ./ore ]; then
	echo Creating a link to the ore executable
	ln -s ./target/release/ore ./ore
fi

if [ $# -eq 0 ]; then
	echo Build succeeded. No miner has been started.
	exit $buildexitcode
fi

if [ $buildexitcode -eq 0 ]; then
	echo ========================================================
	echo Starting miner $1...
	echo ========================================================
	./miner.sh $1
fi
