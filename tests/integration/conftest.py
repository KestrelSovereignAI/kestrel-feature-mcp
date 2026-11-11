"""Explicit input for the native browser-container ownership campaign."""


def pytest_addoption(parser):
    parser.addoption('--browser-build-receipt', help='Build receipt from tests/browser/run_native.py')
