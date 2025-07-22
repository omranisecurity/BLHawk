import validators

def url_validator(url):
    if validators.url(url):
        return True
    else:
        return False