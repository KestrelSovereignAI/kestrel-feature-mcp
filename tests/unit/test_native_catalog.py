"""Catalog validation cannot silently select a retired transport."""

import tomllib

import pytest

from kestrel_feature_mcp.registry import MCPRegistry


@pytest.mark.parametrize("field,value", [("transport", "sse"), ("transport", "unknown"),
                                         ("type", "unknown"), ("categories", ["unknown"])])
def test_invalid_catalog_entry_fails_explicitly(tmp_path, field, value):
    catalog = tmp_path / "catalog.toml"
    catalog.write_text(f"[servers.example]\n{field} = {value!r}\n")
    with pytest.raises(ValueError):
        MCPRegistry(catalog)


def test_missing_catalog_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        MCPRegistry(tmp_path / "missing.toml")


def test_malformed_catalog_is_an_error(tmp_path):
    catalog = tmp_path / "catalog.toml"
    catalog.write_text("[servers.broken\n")
    with pytest.raises(tomllib.TOMLDecodeError):
        MCPRegistry(catalog)
