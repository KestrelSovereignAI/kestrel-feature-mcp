"""Image routing, Docker requests and identity share implicit-tag semantics."""

import pytest

from kestrel_feature_mcp.images import normalize_image_ref
from kestrel_feature_mcp.manager import container_name_for_image


@pytest.mark.parametrize("reference,expected", [
    ("image", "image:latest"),
    ("acme/native", "acme/native:latest"),
    ("acme/native:v2", "acme/native:v2"),
    ("private.registry:5000/native", "private.registry:5000/native:latest"),
    ("acme/native@sha256:abcdef", "acme/native@sha256:abcdef"),
])
def test_docker_image_tag_semantics_are_idempotent(reference, expected):
    assert normalize_image_ref(reference) == expected
    assert normalize_image_ref(expected) == expected
    assert container_name_for_image(reference, "did:test:owner") == container_name_for_image(expected, "did:test:owner")


@pytest.mark.parametrize("reference", [None, "", 1, True, "  ", " acme/native", "acme/native "])
def test_invalid_image_reference_fails_before_resource_planning(reference):
    with pytest.raises(ValueError, match="image reference"):
        normalize_image_ref(reference)
    with pytest.raises(ValueError, match="image reference"):
        container_name_for_image(reference, "did:test:owner")
