from urllib.parse import urlparse


def normalize_url(url):
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed_url = urlparse(url)

    normalized_url = parsed_url.geturl()

    return normalized_url


def check_https(url):
    parsed_url = urlparse(url)

    return parsed_url.scheme == "https"