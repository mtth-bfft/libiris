libiris
=======

![Build Status](https://github.com/mtth-bfft/libiris/actions/workflows/build_test.yml/badge.svg?branch=main)

libiris is a (work in progress) cross-platform sandboxing library.

Repository
==========

This repository contains:

* `broker`: the broker library which allows creating workers
* `worker`: the worker library loaded by workers when they start
* `policy`: a crate which allows specifying exactly what rights a worker has
* `ipc`: a crate which allows workers to send requests to their broker, and get resources in response
* `tests`: an integration test suite for all the crates above
