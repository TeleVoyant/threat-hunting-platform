# api/routes/models.py — SECURED
from fastapi import APIRouter, Depends
from api.middleware import require_permission
from shared.security import User

router = APIRouter(prefix="/models", tags=["models"])


@router.post("/retrain")
async def retrain_model(
    user: User = Depends(require_permission("retrain_models")),
):
    """Only ADMIN role can retrain models."""
    # ... retrain logic ...
    return {"status": "retraining started", "triggered_by": user.username}


@router.get("/status")
async def model_status(
    user: User = Depends(require_permission("read_detections")),
):
    """VIEWER and above can check model status."""
    # ... return model info ...
