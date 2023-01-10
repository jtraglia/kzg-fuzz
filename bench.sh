#!/bin/bash
set -euo pipefail

CC=clang go test -bench="Benchmark*" -test.benchtime=100x -test.benchmem=true