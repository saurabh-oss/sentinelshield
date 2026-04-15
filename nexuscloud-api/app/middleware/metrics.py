import time
from starlette.middleware.base import BaseHTTPMiddleware
from prometheus_client import Counter, Histogram, Gauge

REQUEST_COUNT = Counter("nexuscloud_requests_total", "Total requests", ["method", "path", "status"])
REQUEST_LATENCY = Histogram("nexuscloud_request_duration_seconds", "Request latency", ["method", "path"])
ACTIVE_REQUESTS = Gauge("nexuscloud_active_requests", "Active requests")
AUTH_FAILURES = Counter("nexuscloud_auth_failures_total", "Auth failures", ["path", "client_ip"])
ERROR_COUNT = Counter("nexuscloud_errors_total", "Server errors", ["method", "path", "status"])

class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        ACTIVE_REQUESTS.inc()
        start = time.time()
        try:
            response = await call_next(request)
            duration = time.time() - start
            path = request.url.path
            method = request.method
            status = str(response.status_code)

            REQUEST_COUNT.labels(method=method, path=path, status=status).inc()
            REQUEST_LATENCY.labels(method=method, path=path).observe(duration)

            if response.status_code == 401:
                ip = request.client.host if request.client else "unknown"
                AUTH_FAILURES.labels(path=path, client_ip=ip).inc()
            if response.status_code >= 500:
                ERROR_COUNT.labels(method=method, path=path, status=status).inc()

            return response
        finally:
            ACTIVE_REQUESTS.dec()
