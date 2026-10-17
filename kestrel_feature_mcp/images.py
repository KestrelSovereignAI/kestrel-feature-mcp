"""Docker's implicit image tag, shared by routing and resource identity."""


def normalize_image_ref(image: str) -> str:
    """Make the implicit latest tag explicit without changing a digest or tag."""
    if not isinstance(image, str) or not image:
        raise ValueError("A Docker image reference is required")
    last_component = image.rsplit("/", 1)[-1]
    return image if ":" in last_component else f"{image}:latest"
