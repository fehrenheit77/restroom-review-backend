Action: cat /app/railway-deployment/main.py
Observation: from fastapi import FastAPI, HTTPException, Depends, File, UploadFile, Form, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import motor.motor_asyncio
import bcrypt
import jwt
import os
import uuid
import base64
from datetime import datetime, timedelta
import httpx
from pathlib import Path

# Environment variables
MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
DATABASE_NAME = os.environ.get('DATABASE_NAME', 'restroom_review')

# FastAPI app
app = FastAPI(title="Restroom Review API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://restroom-review-frontend-production.up.railway.app",
        "https://*.up.railway.app",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB client
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URL)
db = client[DATABASE_NAME]

# Collections
users_collection = db.users
bathrooms_collection = db.bathrooms
reports_collection = db.reports

# Create uploads directory and serve static files
os.makedirs("/app/railway-deployment/static/uploads", exist_ok=True)
app.mount("/static", StaticFiles(directory="/app/railway-deployment/static"), name="static")

# Security
security = HTTPBearer()

# Pydantic models
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

class GoogleAuthRequest(BaseModel):
    credential: str

class BathroomResponse(BaseModel):
    id: str
    user_id: Optional[str]
    user_name: Optional[str]
    image_url: str
    sink_rating: int
    floor_rating: int
    toilet_rating: int
    smell_rating: int
    niceness_rating: int
    overall_rating: float
    location: str
    latitude: Optional[float]
    longitude: Optional[float]
    comments: str
    timestamp: str

class TermsResponse(BaseModel):
    terms_text: str
    version: str
    last_updated: str

class ReportRequest(BaseModel):
    content_type: str  # "review" or "user"
    content_id: str
    reason: str
    description: Optional[str] = None

class ReportResponse(BaseModel):
    id: str
    reporter_id: str
    reporter_name: str
    content_type: str
    content_id: str
    reason: str
    description: Optional[str]
    status: str
    created_at: datetime

# Helper functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str) -> str:
    payload = {
        'sub': user_id,
        'exp': datetime.utcnow() + timedelta(minutes=30)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_jwt_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload.get('sub')
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

async def get_user_by_email(email: str):
    user_doc = await users_collection.find_one({"email": email})
    if user_doc:
        # If the user has a custom 'id' field, use it; otherwise, convert _id to string
        if "id" not in user_doc:
            user_doc["id"] = str(user_doc["_id"])
        return user_doc
    return None

async def get_user_by_id(user_id: str):
    try:
        user_doc = await users_collection.find_one({"id": user_id})
        if user_doc:
            return user_doc
        return None
    except:
        return None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        user_id = verify_jwt_token(credentials.credentials)
        if user_id is None:
            raise credentials_exception
    except:
        raise credentials_exception
    
    user = await get_user_by_id(user_id)
    if user is None:
        raise credentials_exception
    return user

async def get_current_user_optional(credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))):
    if credentials is None:
        return None
    try:
        user_id = verify_jwt_token(credentials.credentials)
        if user_id is None:
            return None
        user = await get_user_by_id(user_id)
        return user
    except:
        return None

# Routes
@app.get("/api/test-simple")
async def test_simple():
    return {"status": "working"}

@app.get("/")
async def root():
    return {"message": "Restroom Review API"}

@app.get("/api/")
async def api_root():
    return {"message": "Restroom Review API"}

@app.get("/api/config")
async def get_config():
    return {
        "message": "Restroom Review API Configuration",
        "google_maps_api_key": os.environ.get('GOOGLE_MAPS_API_KEY', ''),
        "google_client_id": os.environ.get('GOOGLE_CLIENT_ID', '')
    }

# Auth Routes (what your frontend expects)
@app.post("/api/auth/register", response_model=Token)
async def register_user(user_data: UserCreate):
    # Check if user exists
    existing_user = await get_user_by_email(user_data.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user_id = str(uuid.uuid4())
    hashed_password = hash_password(user_data.password)
    
    user_doc = {
        "id": user_id,
        "email": user_data.email,
        "hashed_password": hashed_password,
        "full_name": user_data.full_name,
        "is_verified": False,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    await users_collection.insert_one(user_doc)
    
    # Create access token
    access_token = create_jwt_token(user_id)
    
    user_response = User(
        id=user_id,
        email=user_data.email,
        full_name=user_data.full_name,
        is_verified=False,
        created_at=user_doc["created_at"],
        updated_at=user_doc["updated_at"]
    )
    
    return Token(access_token=access_token, token_type="bearer", user=user_response)

@app.get("/api/debug-user-fields/{email}")
async def debug_user_fields(email: str):
    """Debug endpoint to check user document structure"""
    try:
        user = await get_user_by_email(email)
        if user:
            return {
                "found": True,
                "fields": list(user.keys()),
                "has_hashed_password": "hashed_password" in user,
                "has_password": "password" in user,
                "email": user.get("email"),
                "id": user.get("id")
            }
        else:
            return {"found": False}
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/auth/login", response_model=Token)
async def login_user(user_data: UserLogin):
    try:
        # Find user
        user = await get_user_by_email(user_data.email)
        
        if not user or not verify_password(user_data.password, user['hashed_password']):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Create JWT token
        access_token = create_jwt_token(user['id'])
        
        user_response = User(
            id=user['id'],
            email=user['email'],
            full_name=user['full_name'],
            profile_picture=user.get('profile_picture'),
            is_verified=user.get('is_verified', False),
            created_at=user['created_at'],
            updated_at=user['updated_at']
        )
        
        return Token(access_token=access_token, token_type="bearer", user=user_response)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

@app.get("/api/auth/me", response_model=User)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    return User(
        id=current_user["id"],
        email=current_user["email"],
        full_name=current_user["full_name"],
        profile_picture=current_user.get("profile_picture"),
        is_verified=current_user.get("is_verified", False),
        created_at=current_user["created_at"],
        updated_at=current_user["updated_at"]
    )

@app.post("/api/auth/google", response_model=Token)
async def google_auth(auth_request: GoogleAuthRequest):
    try:
        async with httpx.AsyncClient() as client:
            token_info_response = await client.get(
                f'https://oauth2.googleapis.com/tokeninfo?id_token={auth_request.credential}'
            )
            
            if token_info_response.status_code != 200:
                raise HTTPException(status_code=400, detail="Invalid Google token")
                
            user_info = token_info_response.json()
            
            # Verify the token is for our app
            if user_info.get('aud') != os.environ.get('GOOGLE_CLIENT_ID'):
                raise HTTPException(status_code=400, detail="Token not for this application")
            
            email = user_info.get('email')
            name = user_info.get('name')
            picture = user_info.get('picture')
            google_id = user_info.get('sub')
            
            if not email or not name:
                raise HTTPException(status_code=400, detail="Missing required user information")
            
            # Check if user exists
            existing_user = await get_user_by_email(email)
            
            if existing_user:
                user = existing_user
            else:
                # Create new user
                user_id = str(uuid.uuid4())
                user_doc = {
                    "id": user_id,
                    "email": email,
                    "full_name": name,
                    "profile_picture": picture,
                    "google_id": google_id,
                    "is_verified": True,
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                }
                
                await users_collection.insert_one(user_doc)
                # Remove the MongoDB _id field to avoid serialization issues
                if "_id" in user_doc:
                    del user_doc["_id"]
                user = user_doc
            
            # Create access token
            access_token = create_jwt_token(user["id"])
            
            user_response = User(
                id=user["id"],
                email=user["email"],
                full_name=user["full_name"],
                profile_picture=user.get("profile_picture"),
                is_verified=user.get("is_verified", False),
                created_at=user["created_at"],
                updated_at=user["updated_at"]
            )
            
            return Token(access_token=access_token, token_type="bearer", user=user_response)
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Google authentication failed: {str(e)}")

# Bathroom Routes
@app.post("/api/bathrooms")
async def create_bathroom_review(
    sink_rating: int = Form(...),
    floor_rating: int = Form(...),
    toilet_rating: int = Form(...),
    smell_rating: int = Form(...),
    niceness_rating: int = Form(...),
    location: str = Form(...),
    latitude: Optional[float] = Form(None),
    longitude: Optional[float] = Form(None),
    comments: str = Form(""),
    image: UploadFile = File(...),
    current_user: Optional[dict] = Depends(get_current_user_optional)
):
    # Validate file type
    if not image.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="File must be an image")
    
    # Validate ratings
    for rating_value in [sink_rating, floor_rating, toilet_rating, smell_rating, niceness_rating]:
        if rating_value < 1 or rating_value > 5:
            raise HTTPException(status_code=400, detail="All ratings must be between 1 and 5")
    
    # Calculate overall rating
    overall_rating = (sink_rating + floor_rating + toilet_rating + smell_rating + niceness_rating) / 5
    
    # Generate unique filename
    file_extension = os.path.splitext(image.filename)[1] if image.filename else '.jpg'
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    file_path = f"/app/backend/uploads/{unique_filename}"
    
    # Save the uploaded file to both locations
    backend_file_path = f"/app/backend/uploads/{unique_filename}"
    static_file_path = f"/app/railway-deployment/static/uploads/{unique_filename}"
    
    try:
        with open(backend_file_path, "wb") as buffer:
            content = await image.read()
            buffer.write(content)
        
        # Also copy to static directory for serving
        with open(static_file_path, "wb") as buffer:
            buffer.write(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save image: {str(e)}")
    
    # Create bathroom review
    bathroom_id = str(uuid.uuid4())
    bathroom_doc = {
        "id": bathroom_id,
        "user_id": current_user["id"] if current_user else None,
        "user_name": current_user["full_name"] if current_user else None,
        "image_url": f"/static/uploads/{unique_filename}",
        "sink_rating": sink_rating,
        "floor_rating": floor_rating,
        "toilet_rating": toilet_rating,
        "smell_rating": smell_rating,
        "niceness_rating": niceness_rating,
        "overall_rating": round(overall_rating, 1),
        "location": location,
        "latitude": latitude,
        "longitude": longitude,
        "comments": comments,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    await bathrooms_collection.insert_one(bathroom_doc)
    
    return bathroom_doc

@app.get("/api/bathrooms")
async def get_bathrooms():
    bathrooms = []
    async for bathroom in bathrooms_collection.find().sort("timestamp", -1):
        bathrooms.append({
            "id": bathroom["id"],
            "user_id": bathroom.get("user_id"),
            "user_name": bathroom.get("user_name"),
            "image_url": bathroom["image_url"],
            "sink_rating": bathroom["sink_rating"],
            "floor_rating": bathroom["floor_rating"],
            "toilet_rating": bathroom["toilet_rating"],
            "smell_rating": bathroom["smell_rating"],
            "niceness_rating": bathroom["niceness_rating"],
            "overall_rating": bathroom["overall_rating"],
            "location": bathroom["location"],
            "latitude": bathroom.get("latitude"),
            "longitude": bathroom.get("longitude"),
            "comments": bathroom["comments"],
            "timestamp": bathroom["timestamp"]
        })
    
    return bathrooms

def get_image_base64(filename: str) -> str:
    """Convert image file to base64 string"""
    try:
        file_path = f"/app/backend/uploads/{filename}"
        if os.path.exists(file_path):
            with open(file_path, "rb") as image_file:
                encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
                return encoded_string
        return ""
    except Exception as e:
        print(f"Error encoding image {filename}: {e}")
        return ""

@app.get("/api/uploads/{filename}")
async def get_upload(filename: str):
    file_path = f"/app/backend/uploads/{filename}"
    print(f"DEBUG: Looking for file at: {file_path}")
    print(f"DEBUG: File exists: {os.path.exists(file_path)}")
    if os.path.exists(file_path):
        print(f"DEBUG: Returning file: {file_path}")
        return FileResponse(file_path)
    else:
        print(f"DEBUG: File not found: {file_path}")
        raise HTTPException(status_code=404, detail=f"File not found: {filename}")

@app.get("/api/test-upload")
async def test_upload():
    return {"message": "Test endpoint working", "files": os.listdir("/app/backend/uploads")[:5]}

# Report Content Routes
@app.post("/api/reports")
async def create_report(
    report_data: ReportRequest,
    current_user: dict = Depends(get_current_user)
):
    """Create a new content report"""
    report_id = str(uuid.uuid4())
    
    report_doc = {
        "id": report_id,
        "reporter_id": current_user["id"],
        "reporter_name": current_user["full_name"],
        "content_type": report_data.content_type,
        "content_id": report_data.content_id,
        "reason": report_data.reason,
        "description": report_data.description,
        "status": "pending",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    await reports_collection.insert_one(report_doc)
    
    return {
        "id": report_id,
        "message": "Report submitted successfully",
        "status": "pending"
    }

@app.get("/api/reports")
async def get_reports(current_user: dict = Depends(get_current_user)):
    """Get all reports (for admin dashboard)"""
    reports = []
    async for report in reports_collection.find().sort("created_at", -1):
        reports.append({
            "id": report["id"],
            "reporter_id": report["reporter_id"],
            "reporter_name": report["reporter_name"],
            "content_type": report["content_type"],
            "content_id": report["content_id"],
            "reason": report["reason"],
            "description": report.get("description"),
            "status": report["status"],
            "created_at": report["created_at"].isoformat()
        })
    
    return reports

# Add this near the end of your file, before the if __name__ == "__main__": line
@app.options("/{full_path:path}")
async def options_handler(request, full_path: str):
    return {
        "message": "OK"
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)# Debug update Wed Jul  2 00:55:36 UTC 2025


    
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT"))
    uvicorn.run(app, host="0.0.0.0", port=port)
