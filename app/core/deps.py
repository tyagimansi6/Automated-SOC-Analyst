"""Process-wide service instances shared by API routers."""

from app.services.detection import AnomalyDetector
from app.services.graph_service import GraphService
from app.services.websocket import ConnectionManager, manager
from app.simulation.engine import SimulationEngine

graph_service = GraphService()
detector = AnomalyDetector()
simulation_engine = SimulationEngine(graph_service, detector, manager)


def get_graph_service() -> GraphService:
    return graph_service


def get_detector() -> AnomalyDetector:
    return detector


def get_manager() -> ConnectionManager:
    return manager


def get_simulation_engine() -> SimulationEngine:
    return simulation_engine
