from fastapi import FastAPI, APIRouter, UploadFile, File, Form, HTTPException, Depends, status, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
import shutil
import mimetypes
from bson import ObjectId
import httpx
import json

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Create uploads directory
UPLOADS_DIR = ROOT_DIR / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-secret-key-change-in-production")
ALGORITHM = os.environ.get("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Security
security = HTTPBearer()

# Create the main app without a prefix
app = FastAPI()

# Add CORS middleware FIRST (before any other middleware)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000", 
        "https://restroom-review-frontend-production.up.railway.app",
        "https://*.up.railway.app",
        "*"
    ],
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Add session middleware for OAuth
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# MongoDB connection (with graceful fallback)
client = None
db = None

try:
    mongo_url = os.environ.get('MONGO_URL')
    if mongo_url:
        client = AsyncIOMotorClient(mongo_url)
        db = client[os.environ.get('DB_NAME', 'bathroom_reviews')]
        print("✅ MongoDB connected successfully")
    else:
        print("⚠️ No MongoDB URL provided - database features disabled")
except Exception as e:
    client = None
    db = None
    print(f"⚠️ MongoDB connection failed: {e} - database features disabled")

# Database helper function
async def get_db():
    if db is None:
        raise HTTPException(
            status_code=503,
            detail="Database not available. Please configure MongoDB connection."
        )
    return db

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Authentication Models
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    profile_picture: Optional[str] = None
    is_verified: bool = False
    created_at: datetime
    updated_at: datetime

class Token(BaseModel):
    access_token: str
    token_type: str
    user: User

# Existing Bathroom Models (updated with categorical ratings)
class BathroomRatingCategories(BaseModel):
    sink: int = Field(ge=1, le=5)  # Sink cleanliness and functionality
    floor: int = Field(ge=1, le=5)  # Floor cleanliness and condition
    toilet: int = Field(ge=1, le=5)  # Toilet cleanliness and functionality
    smell: int = Field(ge=1, le=5)  # Odor/smell rating
    niceness: int = Field(ge=1, le=5)  # Overall ambiance and niceness

class BathroomRating(BaseModel):
    id: str
    user_id: str
    user_name: str
    image_url: str
    sink_rating: int
    floor_rating: int
    toilet_rating: int
    smell_rating: int
    niceness_rating: int
    overall_rating: float
    location: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    comments: Optional[str] = None
    timestamp: datetime

# Google OAuth Models
class GoogleTokenData(BaseModel):
    credential: str

# Helper functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    database = await get_db()  # This will raise 503 if DB not available
    
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = await database.users.find_one({"id": user_id})
    if user is None:
        raise credentials_exception
    return user

def serialize_user(user: dict) -> dict:
    """Convert MongoDB user document to serializable format"""
    if user is None:
        return None
    
    # Convert ObjectId to string if present
    if '_id' in user:
        del user['_id']
    
    # Ensure datetime objects are properly handled
    if 'created_at' in user and isinstance(user['created_at'], datetime):
        user['created_at'] = user['created_at'].isoformat()
    if 'updated_at' in user and isinstance(user['updated_at'], datetime):
        user['updated_at'] = user['updated_at'].isoformat()
    
    return user

def serialize_bathroom(bathroom: dict) -> dict:
    """Convert MongoDB bathroom document to serializable format"""
    if bathroom is None:
        return None
    
    # Convert ObjectId to string if present
    if '_id' in bathroom:
        del bathroom['_id']
    
    # Ensure datetime objects are properly handled
    if 'timestamp' in bathroom and isinstance(bathroom['timestamp'], datetime):
        bathroom['timestamp'] = bathroom['timestamp'].isoformat()
    
    return bathroom

# Authentication endpoints
@api_router.post("/auth/register", response_model=Token)
async def register(user_data: UserCreate):
    database = await get_db()
    
    # Check if user already exists
    existing_user = await database.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Hash password and create user
    hashed_password = hash_password(user_data.password)
    user_id = str(uuid.uuid4())
    
    new_user = {
        "id": user_id,
        "email": user_data.email,
        "full_name": user_data.full_name,
        "hashed_password": hashed_password,
        "profile_picture": None,
        "is_verified": False,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    await database.users.insert_one(new_user)
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_id}, expires_delta=access_token_expires
    )
    
    # Return token and user data (without password)
    user_response = serialize_user({k: v for k, v in new_user.items() if k != 'hashed_password'})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_response
    }

@api_router.post("/auth/login", response_model=Token)
async def login(user_data: UserLogin):
    database = await get_db()
    
    # Find user by email
    user = await database.users.find_one({"email": user_data.email})
    if not user or not verify_password(user_data.password, user['hashed_password']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['id']}, expires_delta=access_token_expires
    )
    
    # Return token and user data (without password)
    user_response = serialize_user({k: v for k, v in user.items() if k != 'hashed_password'})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_response
    }

@api_router.get("/auth/me", response_model=User)
async def get_current_user_profile(current_user: dict = Depends(get_current_user)):
    return serialize_user(current_user)

@api_router.post("/auth/google", response_model=Token)
async def google_login(token_data: GoogleTokenData):
    database = await get_db()
    
    try:
        # Verify the Google credential token
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://oauth2.googleapis.com/tokeninfo?id_token={token_data.credential}"
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid Google token"
                )
            
            google_data = response.json()
            
            # Extract user information from Google response
            email = google_data.get("email")
            name = google_data.get("name")
            picture = google_data.get("picture")
            
            if not email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email not provided by Google"
                )
            
            # Check if user already exists
            existing_user = await database.users.find_one({"email": email})
            
            if existing_user:
                # User exists, log them in
                user_id = existing_user['id']
                user_response = serialize_user({k: v for k, v in existing_user.items() if k != 'hashed_password'})
            else:
                # Create new user
                user_id = str(uuid.uuid4())
                new_user = {
                    "id": user_id,
                    "email": email,
                    "full_name": name or email.split('@')[0],
                    "profile_picture": picture,
                    "is_verified": True,  # Google accounts are pre-verified
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                }
                
                await database.users.insert_one(new_user)
                user_response = serialize_user(new_user)
            
            # Create access token
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": user_id}, expires_delta=access_token_expires
            )
            
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "user": user_response
            }
            
    except httpx.RequestError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify Google token"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication failed: {str(e)}"
        )

# Bathroom rating endpoints
@api_router.post("/bathrooms", response_model=dict)
async def upload_bathroom_rating(
    image: UploadFile = File(...),
    sink_rating: int = Form(...),
    floor_rating: int = Form(...),
    toilet_rating: int = Form(...),
    smell_rating: int = Form(...),
    niceness_rating: int = Form(...),
    location: str = Form(...),
    latitude: Optional[float] = Form(None),
    longitude: Optional[float] = Form(None),
    comments: Optional[str] = Form(None),
    current_user: dict = Depends(get_current_user)
):
    database = await get_db()
    
    # Validate image
    if not image.content_type or not image.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="File must be an image")
    
    # Validate ratings
    for rating_name, rating_value in [
        ("sink_rating", sink_rating),
        ("floor_rating", floor_rating), 
        ("toilet_rating", toilet_rating),
        ("smell_rating", smell_rating),
        ("niceness_rating", niceness_rating)
    ]:
        if not (1 <= rating_value <= 5):
            raise HTTPException(
                status_code=400, 
                detail=f"{rating_name} must be between 1 and 5"
            )
    
    # Generate unique filename
    file_extension = image.filename.split('.')[-1] if '.' in image.filename else 'jpg'
    unique_filename = f"{uuid.uuid4()}.{file_extension}"
    file_path = UPLOADS_DIR / unique_filename
    
    # Save image file
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save image: {str(e)}")
    
    # Calculate overall rating
    overall_rating = (sink_rating + floor_rating + toilet_rating + smell_rating + niceness_rating) / 5
    
    # Create bathroom rating document
    bathroom_id = str(uuid.uuid4())
    bathroom_data = {
        "id": bathroom_id,
        "user_id": current_user['id'],
        "user_name": current_user['full_name'],
        "image_url": f"/api/uploads/{unique_filename}",
        "sink_rating": sink_rating,
        "floor_rating": floor_rating,
        "toilet_rating": toilet_rating,
        "smell_rating": smell_rating,
        "niceness_rating": niceness_rating,
        "overall_rating": round(overall_rating, 1),
        "location": location,
        "latitude": latitude,
        "longitude": longitude,
        "comments": comments or "",
        "timestamp": datetime.utcnow()
    }
    
    # Insert into database
    await database.bathrooms.insert_one(bathroom_data)
    
    # Return the created bathroom data
    response_data = serialize_bathroom(bathroom_data)
    return {
        "success": True,
        "message": "Bathroom rating uploaded successfully",
        "bathroom": response_data
    }

@api_router.get("/bathrooms", response_model=List[BathroomRating])
async def get_all_bathrooms():
    database = await get_db()
    
    bathrooms = []
    async for bathroom in database.bathrooms.find().sort("timestamp", -1):
        bathrooms.append(serialize_bathroom(bathroom))
    return bathrooms

@api_router.get("/bathrooms/my", response_model=List[BathroomRating])
async def get_my_bathrooms(current_user: dict = Depends(get_current_user)):
    database = await get_db()
    
    bathrooms = []
    async for bathroom in database.bathrooms.find({"user_id": current_user['id']}).sort("timestamp", -1):
        bathrooms.append(serialize_bathroom(bathroom))
    return bathrooms

@api_router.get("/bathrooms/{bathroom_id}", response_model=BathroomRating)
async def get_bathroom(bathroom_id: str):
    database = await get_db()
    
    bathroom = await database.bathrooms.find_one({"id": bathroom_id})
    if not bathroom:
        raise HTTPException(status_code=404, detail="Bathroom not found")
    return serialize_bathroom(bathroom)

@api_router.delete("/bathrooms/{bathroom_id}")
async def delete_bathroom(bathroom_id: str, current_user: dict = Depends(get_current_user)):
    database = await get_db()
    
    bathroom = await database.bathrooms.find_one({"id": bathroom_id})
    if not bathroom:
        raise HTTPException(status_code=404, detail="Bathroom not found")
    
    # Check if user owns this bathroom rating
    if bathroom['user_id'] != current_user['id']:
        raise HTTPException(status_code=403, detail="Not authorized to delete this bathroom rating")
    
    # Delete the image file
    try:
        image_filename = bathroom['image_url'].split('/')[-1]
        image_path = UPLOADS_DIR / image_filename
        if image_path.exists():
            image_path.unlink()
    except Exception as e:
        print(f"Warning: Failed to delete image file: {e}")
    
    # Delete from database
    await database.bathrooms.delete_one({"id": bathroom_id})
    
    return {"success": True, "message": "Bathroom rating deleted successfully"}

# Static file serving for uploads
@api_router.get("/uploads/{filename}")
async def get_image(filename: str):
    file_path = UPLOADS_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Image not found")
    
    # Get the MIME type
    mime_type, _ = mimetypes.guess_type(str(file_path))
    if not mime_type:
        mime_type = 'application/octet-stream'
    
    return FileResponse(
        file_path,
        media_type=mime_type,
        headers={
            "Cache-Control": "public, max-age=31536000",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET",
            "Access-Control-Allow-Headers": "*"
        }
    )

# Include the router in the main app
app.include_router(api_router)

# Add CORS preflight handler
@app.options("/{full_path:path}")
async def preflight_handler(request: Request, full_path: str):
    return Response(
        content="",
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Credentials": "true"
        }
    )

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    if client:
        client.close()

# Health check endpoint
@app.get("/")
async def health_check():
    db_status = "connected" if db is not None else "not connected"
    return {
        "status": "healthy", 
        "message": "Loo Review API is running",
        "database": db_status
    }

# Health check for API prefix
@api_router.get("/")
async def api_health_check():
    db_status = "connected" if db is not None else "not connected"
    return {
        "status": "healthy", 
        "message": "Loo Review API is running",
        "database": db_status
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
