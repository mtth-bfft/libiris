libiris
=======

libiris is a (work in progress) cross-platform sandboxing library.

Repository
==========

This repository contains:

* `libiris`: the broker library which allows creating workers
* `libiris-worker`: the worker library loaded by workers when they start
* `libiris-policy`: a crate which allows specifying exactly what rights a worker has
* `libiris-ipc`: a crate which allows workers to send requests to their broker, and get resources in response
* `libiris-integration-tests`: a test suite for all the crates above
