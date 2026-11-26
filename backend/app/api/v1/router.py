"""Aggregated /api/v1 router."""

from __future__ import annotations

from fastapi import APIRouter

from backend.app.api.v1 import audit, auth, bench, detector, devices, health, keys, messaging, nodes, policy, resources, rotation_backup, simulation, users

api_v1_router = APIRouter()
api_v1_router.include_router(health.router)
api_v1_router.include_router(auth.router)
api_v1_router.include_router(users.router)
api_v1_router.include_router(devices.router)
api_v1_router.include_router(resources.router)
api_v1_router.include_router(rotation_backup.router)
api_v1_router.include_router(keys.router)
api_v1_router.include_router(nodes.router)
api_v1_router.include_router(policy.router)
api_v1_router.include_router(audit.router)
api_v1_router.include_router(detector.router)
api_v1_router.include_router(messaging.router)
api_v1_router.include_router(bench.router)
api_v1_router.include_router(simulation.router)
