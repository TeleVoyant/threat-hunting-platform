# api/middleware.py
"""
FastAPI middleware for authentication, audit logging, rate limiting.
"""

from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, APIKeyHeader
from shared.security import AuthManager, User

security_bearer = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_current_user(
    request: Request,
    bearer=Depends(security_bearer),
    api_key=Depends(api_key_header),
) -> User:
    """
    Extract and validate user from JWT token or API key.
    Every API endpoint depends on this.
    """
    auth_manager: AuthManager = request.app.state.auth_manager

    # Try JWT first
    if bearer and bearer.credentials:
        user = auth_manager.verify_jwt(bearer.credentials)
        if user:
            return user

    # Fall back to API key
    if api_key:
        user = auth_manager.authenticate_api_key(api_key)
        if user:
            return user

    raise HTTPException(status_code=401, detail="Invalid or missing credentials")


def require_permission(permission: str):
    """Dependency that checks if current user has specific permission."""

    async def check(
        request: Request,
        user: User = Depends(get_current_user),
    ) -> User:
        auth_manager: AuthManager = request.app.state.auth_manager
        if not auth_manager.has_permission(user, permission):
            raise HTTPException(
                status_code=403,
                detail=f"Permission '{permission}' required. Your role: {user.role.value}",
            )
        return user

    return check
