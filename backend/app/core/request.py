from fastapi import Request


def client_ip(request: Request) -> str | None:
    """Return the client address resolved by Uvicorn's trusted-proxy middleware.

    Uvicorn is configured to trust only the Nginx container IP, and Nginx
    overwrites X-Forwarded-For with the socket peer rather than appending input.
    """
    return request.client.host if request.client else None
