#!/bin/sh
exec ./target/release/bf-jit mandelbrot.bf --no-jit > /dev/null
