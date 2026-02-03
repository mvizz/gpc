# main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt import PyJWKClient
from functools import lru_cache

app = FastAPI()
security = HTTPBearer()

# Azure AD Configuration - replace with your values
TENANT_ID = "your-tenant-id"
CLIENT_ID = "your-backend-api-client-id"  # The API's app registration client ID

# Azure AD endpoints
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
ISSUER = f"https://sts.windows.net/{TENANT_ID}/"
# Alternative issuer (v2.0 endpoint): f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"


@lru_cache()
def get_jwks_client():
    """Cache the JWKS client to avoid fetching keys on every request."""
    return PyJWKClient(JWKS_URL)


def validate_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Validate the Azure AD access token and return the decoded claims."""
    token = credentials.credentials
    
    try:
        # Get the signing key from Azure AD
        jwks_client = get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        
        # Decode and validate the token
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=CLIENT_ID,  # Validate the audience
            issuer=ISSUER,       # Validate the issuer
        )
        return payload
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidAudienceError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid audience"
        )
    except jwt.InvalidIssuerError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid issuer"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )


# Protected endpoint example
@app.get("/api/protected")
def protected_route(token_data: dict = Depends(validate_token)):
    return {
        "message": "You have access!",
        "user": token_data.get("preferred_username") or token_data.get("upn"),
        "name": token_data.get("name"),
    }


# Public endpoint (no auth required)
@app.get("/api/health")
def health_check():
    return {"status": "healthy"}






# Cell 1: Install dependencies
!pip install pyjwt[crypto] requests msal

# Cell 2: Test token validation function directly
import jwt
from jwt import PyJWKClient

TENANT_ID = "your-tenant-id"
CLIENT_ID = "your-backend-api-client-id"
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
ISSUER = f"https://sts.windows.net/{TENANT_ID}/"

def validate_token(token: str) -> dict:
    """Validate Azure AD token and return claims."""
    jwks_client = PyJWKClient(JWKS_URL)
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    
    payload = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=CLIENT_ID,
        issuer=ISSUER,
    )
    return payload

# Cell 3: Test with your token
access_token = "eyJ0eXAiOiJKV1Q..."  # Paste your token here

try:
    claims = validate_token(access_token)
    print("✅ Token is valid!")
    print(f"User: {claims.get('preferred_username') or claims.get('upn')}")
    print(f"Name: {claims.get('name')}")
    print(f"Expires: {claims.get('exp')}")
except Exception as e:
    print(f"❌ Token validation failed: {e}")
