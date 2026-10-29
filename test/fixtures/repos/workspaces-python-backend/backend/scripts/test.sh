#!/usr/bin/env bash
set -e

coverage run -m pytest tests/
coverage report
