from datetime import UTC, datetime

from app.core.database import Base
from fastapi import FastAPI
from fastapi.routing import APIRoute

from security.schemas.findings import ApplicationMap, ModelInfo, RouteInfo


class ApplicationMapperAgent:
    """Agent 1: Discovers and maps application routes, authorization requirements, and database entities."""

    def __init__(self, app: FastAPI | None = None):
        self.app = app

    def _extract_routes(self, routes, prefix: str = "") -> list[RouteInfo]:
        endpoints: list[RouteInfo] = []
        for route in routes:
            if isinstance(route, APIRoute):
                full_path = (prefix + route.path).rstrip("/") or "/"
                for method in route.methods:
                    if method in ("HEAD", "OPTIONS"):
                        continue

                    # Inspect dependencies for authorization requirements
                    dependencies = [
                        getattr(dep.call, "__name__", str(dep.call))
                        for dep in route.dependant.dependencies
                        if hasattr(dep, "call")
                    ]
                    auth_required = any(
                        "current_user" in name or "current_admin" in name
                        for name in dependencies
                    )
                    admin_only = any("current_admin" in name for name in dependencies)

                    # Extract route parameter names
                    params = [
                        param.name
                        for param in route.dependant.path_params + route.dependant.query_params
                    ]
                    if route.dependant.body_params:
                        params.extend([b.name for b in route.dependant.body_params])

                    endpoints.append(
                        RouteInfo(
                            path=full_path,
                            method=method,
                            handler_name=route.endpoint.__name__,
                            summary=route.summary or "",
                            auth_required=auth_required,
                            admin_only=admin_only,
                            parameters=params,
                            tags=route.tags or [],
                        )
                    )
            elif hasattr(route, "original_router"):
                ctx = getattr(route, "include_context", None)
                pfx = prefix + (getattr(ctx, "prefix", "") or "")
                endpoints.extend(self._extract_routes(route.original_router.routes, pfx))
            elif hasattr(route, "routes"):
                endpoints.extend(self._extract_routes(route.routes, prefix))
        return endpoints

    def scan(self, app: FastAPI | None = None) -> ApplicationMap:
        target_app = app or self.app
        if target_app is None:
            raise ValueError("FastAPI application instance must be provided to ApplicationMapperAgent.")

        endpoints: list[RouteInfo] = self._extract_routes(target_app.routes)

        # Discover registered SQLAlchemy models
        models: list[ModelInfo] = []
        for table_name, table in Base.metadata.tables.items():
            models.append(
                ModelInfo(
                    model_name=table_name.capitalize(),
                    table_name=table_name,
                    fields=[col.name for col in table.columns],
                )
            )

        return ApplicationMap(
            app_name=target_app.title,
            version=target_app.version,
            scanned_at=datetime.now(UTC),
            total_endpoints=len(endpoints),
            endpoints=endpoints,
            models=models,
            auth_flows={
                "strategy": "JWT Bearer Token with JTI fast-revocation and session-level risk tracking",
                "login_endpoint": "/api/v1/auth/login",
                "logout_endpoint": "/api/v1/auth/logout",
                "roles": ["customer", "admin"],
            },
        )
