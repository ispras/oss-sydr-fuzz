# Lua

[Lua][lua-homepage] is a powerful, efficient, lightweight, embeddable
scripting language. Lua is dynamically typed, runs by interpreting bytecode
with a register-based virtual machine, and has automatic memory management with
incremental garbage collection, making it ideal for configuration, scripting,
and rapid prototyping. Lua is designed, implemented, and maintained by a team
at PUC-Rio, the Pontifical Catholic University of Rio de Janeiro in Brazil.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-lua .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/lua` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-lua /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c luaL_loadstring.toml run

Corpus minimization (step is required for AFL++):

	sydr-fuzz -c luaL_loadstring.toml cmin

Collect and report coverage:

    # sydr-fuzz -c luaL_loadstring.toml cov-report

Building HTML report:

	$ sydr-fuzz -c luaL_loadstring.toml cov-show -- -format=html > index.html

## Hybrid Fuzzing with AFL++

    # sydr-fuzz -c luaL_loadstring-afl++.toml run

## Alternative Fuzz Targets

Lua project has 13 fuzz targets.

### lua_dump

    # sydr-fuzz -c lua_dump.toml run

### luaL_addgsub

    # sydr-fuzz -c luaL_addgsub.toml run

### luaL_buffaddr

    # sydr-fuzz -c luaL_buffaddr.toml run

### luaL_bufflen

    # sydr-fuzz -c luaL_bufflen.toml run

### luaL_buffsub

    # sydr-fuzz -c luaL_buffsub.toml run

### luaL_dostring

    # sydr-fuzz -c luaL_dostring.toml run

### luaL_gsub

    # sydr-fuzz -c luaL_gsub.toml run

### luaL_loadbuffer

    # sydr-fuzz -c luaL_loadbuffer.toml run

### luaL_loadbuffer_proto

    # sydr-fuzz -c luaL_loadbuffer_proto.toml run

### luaL_loadbufferx

    # sydr-fuzz -c luaL_loadbufferx.toml run

### luaL_loadstring

    # sydr-fuzz -c luaL_loadstring.toml run

### lua_load

    # sydr-fuzz -c lua_load.toml run

### luaL_traceback

    # sydr-fuzz -c luaL_traceback.toml run

### lua_stringtonumber

    # sydr-fuzz -c lua_stringtonumber.toml run

[lua-homepage]: https://www.lua.org/about.html
