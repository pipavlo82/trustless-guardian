"""Fail-closed error type with stable, non-secret reason codes."""


class SecurityError(Exception):
    def __init__(self, code):
        if type(code) is not str or not code:
            raise TypeError("security error code must be a non-empty string")
        self.code = code
        super().__init__(code)
