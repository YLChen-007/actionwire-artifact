import requests


def _post(body, timeout):
    return requests.post(
        "http://fixed-camofox.example/tabs",
        json=body,
        timeout=timeout,
    )
