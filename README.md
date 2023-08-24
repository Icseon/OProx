# OProx
This is a simple proxy that patches the process memory of a robot fighting game in realtime and runs a proxy alongside it. One click.

## How to compile:
`i686-w64-mingw32-gcc main.cpp -o dist/proxy.exe -m32 --verbose -lws2_32`

## Just want to run?
The `dist` folder contains `proxy.exe` - you can run that with `wine proxy.exe bots.dat`.
