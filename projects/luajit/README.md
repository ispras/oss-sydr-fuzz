# LuaJIT

[LuaJIT][luajit-homepage] is a Just-In-Time Compiler (JIT) for the Lua
programming language. Lua is a powerful, dynamic and light-weight programming
language. It may be embedded or used as a general-purpose, stand-alone
language.

## Build Docker

    # sudo docker build -t oss-sydr-fuzz-luajit .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/luajit` directory:

    # unzip sydr.zip

Run docker:

    # sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-luajit /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c luaL_loadstring.toml run

Corpus minimization (step is required for AFL++):

    # sydr-fuzz -c luaL_loadstring.toml cmin

Collect and report coverage:

    # sydr-fuzz -c luaL_loadstring.toml cov-report

Building HTML report:

    # sydr-fuzz -c luaL_loadstring.toml cov-show -- -format=html > index.html

## Hybrid Fuzzing with AFL++

    # sydr-fuzz -c luaL_loadstring-afl++.toml run

## Alternative Fuzz Targets

LuaJIT project has 7 fuzz targets.

### lua_dump

    # sydr-fuzz -c lua_dump.toml run

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

### luaL_traceback

    # sydr-fuzz -c luaL_traceback.toml run

[luajit-homepage]: http://luajit.org/
