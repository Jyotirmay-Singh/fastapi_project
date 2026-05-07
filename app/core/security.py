from datetime import datetime, timezone, timedelta
from typing import dict, Optional, Any
from jose import jwt, JWTError, ExpiredSignatureError
from app.core.config import settings

def create_token(data:dict, expire_minutes=30) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc)+timedelta(minutes=expire_minutes)
    to_encode.update({'exp':expire.timestamp()})
    return jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm = settings.JWT_ALGORITHM
    )

def verify_token(token: str) -> Optional[dict[str, Any]]:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except ExpiredSignatureError:
        print("Token has expired.")
        # In FastAPI, you might raise an HTTPException(status_code=401, detail="Token expired") here
        return None
    except JWTError:
        print("Token is invalid.")
        return None
    