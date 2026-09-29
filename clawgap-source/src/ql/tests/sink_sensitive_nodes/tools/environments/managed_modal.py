import requests


class ManagedModalEnvironment:
    def _request(self, method, path, *, json=None):
        return requests.request(
            method,
            f"{self._gateway_origin}{path}",
            json=json,
        )
