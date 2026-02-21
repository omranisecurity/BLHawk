import validators

def url_validator(url) -> bool:
    """Return True if `url` looks like a valid URL."""
    return bool(validators.url(url))