"""FastAPI entrypoint for the Autonomous SOC Threat Defense Simulator."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.graph import router as graph_router
from app.api.simulation import router as simulation_router
from app.api.websockets import router as websockets_router
from app.core.config import settings
from app.core.deps import graph_service, manager, simulation_engine
from app.models.schemas import HealthRead

app = FastAPI(title=settings.app_name, version=settings.app_version)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(simulation_router, prefix=settings.api_v1_prefix)
app.include_router(graph_router, prefix=settings.api_v1_prefix)
app.include_router(websockets_router)


@app.get("/", response_model=HealthRead)
async def health() -> HealthRead:
    """Return process health and live simulation / graph / WebSocket stats."""
    return HealthRead(
        status="ok",
        service=settings.app_name,
        version=settings.app_version,
        simulation_state=simulation_engine.state.value,
        websocket_connections=len(manager.active_connections),
        graph_nodes=graph_service.graph.number_of_nodes(),
        graph_edges=graph_service.graph.number_of_edges(),
    )
