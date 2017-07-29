# QUIC server and clients binaries

This repo has binary builds of `quic_client` and `quic_server` from Chromium's source for testing [quic-go](https://github.com/lucas-clemente/quic-go).

## How to build

Follow the instructions to checkout Chromium: [https://www.chromium.org/developers/how-tos/get-the-code](https://www.chromium.org/developers/how-tos/get-the-code)

Set the build configuration:
```sh
gn args out/Debug
```
and enter the following:
```
# Build arguments go here. Examples:
   is_component_build = false
   is_debug = true
# See "gn args <out_dir> --list" for available build arguments.
```

Build:
```sh
ninja -C out/Debug quic_client quic_server
```

Strip the binary:
```sh
strip out/Debug/quic_client out/Debug/quic_server
```
