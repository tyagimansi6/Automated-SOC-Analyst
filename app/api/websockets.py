"""Live telemetry, alert, and graph WebSocket feed."""

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from app.core.deps import get_manager
from app.services.websocket import ConnectionManager

router = APIRouter(tags=["websockets"])


@router.websocket("/ws")
async def websocket_feed(
    websocket: WebSocket,
    manager: ConnectionManager = Depends(get_manager),
) -> None:
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
