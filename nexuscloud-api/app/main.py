from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
from app.middleware.event_emitter import EventEmitterMiddleware
from app.middleware.metrics import MetricsMiddleware
from app.routers import auth, tenants, subscriptions, products, releases, data_ingestion, admin

app = FastAPI(
    title="NexusCloud Commerce Platform",
    description="Enterprise SaaS subscription commerce API — powering digital product delivery at scale.",
    version="2.15.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])
app.add_middleware(EventEmitterMiddleware)
app.add_middleware(MetricsMiddleware)

# Mount Prometheus metrics
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# Register routers
app.include_router(auth.router)
app.include_router(tenants.router)
app.include_router(subscriptions.router)
app.include_router(products.router)
app.include_router(releases.router)
app.include_router(data_ingestion.router)
app.include_router(admin.router)

@app.get("/health", tags=["System"])
def health_check():
    return {"status": "healthy", "service": "nexuscloud-commerce", "version": "2.15.0"}

@app.get("/", tags=["System"])
def root():
    return {
        "service": "NexusCloud Commerce Platform",
        "version": "2.15.0",
        "docs": "/docs",
        "health": "/health",
        "metrics": "/metrics",
    }
