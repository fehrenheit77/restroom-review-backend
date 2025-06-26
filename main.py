from fastapi import FastAPI, HTTPException, Depends, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
import motor.motor_asyncio
import bcrypt
import jwt
import os
import uuid
from datetime import datetime, timedelta
import json

# Environment variables
MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
DATABASE_NAME = os.environ.get('DATABASE_NAME', 'restroom_review')

# FastAPI app
app = FastAPI(title="Restroom Review API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

# Create uploads directory
os.makedirs("uploads", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# Pydantic models
class UserCreate(BaseModel):
    email: str
    password: str
    name: str

class UserLogin(BaseModel):
    email: str
    password: str

class BathroomReview(BaseModel):
    sink_rating: int
    floor_rating: int
    toilet_rating: int
    smell_rating: int
    niceness_rating: int
    location: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    comments: str

class User(BaseModel):
    id: str
    email: str
    name: str
    
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

# Helper functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str) -> str:
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(minutes=30)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_jwt_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload.get('user_id')
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Routes
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

@app.post("/api/register")
async def register_user(user_data: UserCreate):
    # Check if user exists
    existing_user = await users_collection.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user_id = str(uuid.uuid4())
    hashed_password = hash_password(user_data.password)
    
    user_doc = {
        "id": user_id,
        "email": user_data.email,
        "password": hashed_password,
        "name": user_data.name,
        "created_at": datetime.utcnow().isoformat()
    }
    
    await users_collection.insert_one(user_doc)
    
    # Create JWT token
    token = create_jwt_token(user_id)
    
    return {
        "user": {
            "id": user_id,
            "email": user_data.email,
            "name": user_data.name
        },
        "token": token
    }

@app.post("/api/login")
async def login_user(user_data: UserLogin):
    # Find user
    user = await users_collection.find_one({"email": user_data.email})
    if not user or not verify_password(user_data.password, user['password']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create JWT token
    token = create_jwt_token(user['id'])
    
    return {
        "user": {
            "id": user['id'],
            "email": user['email'],
            "name": user['name']
        },
        "token": token
    }

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
    comments: str = Form(...),
    image: UploadFile = File(...),
    authorization: Optional[str] = None
):
    # Get user info if authenticated
    user_id = None
    user_name = None
    if authorization and authorization.startswith('Bearer '):
        token = authorization.split(' ')[1]
        user_id = verify_jwt_token(token)
        if user_id:
            user = await users_collection.find_one({"id": user_id})
            if user:
                user_name = user['name']
    
    # Save uploaded image
    image_id = str(uuid.uuid4())
    image_extension = image.filename.split('.')[-1] if '.' in image.filename else 'jpg'
    image_filename = f"{image_id}.{image_extension}"
    image_path = f"uploads/{image_filename}"
    
    with open(image_path, "wb") as buffer:
        content = await image.read()
        buffer.write(content)
    
    # Calculate overall rating
    overall_rating = (sink_rating + floor_rating + toilet_rating + smell_rating + niceness_rating) / 5
    
    # Create bathroom review
    bathroom_id = str(uuid.uuid4())
    bathroom_doc = {
        "id": bathroom_id,
        "user_id": user_id,
        "user_name": user_name,
        "image_url": f"/uploads/{image_filename}",
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

@app.get("/api/uploads/{filename}")
async def get_upload(filename: str):
    file_path = f"uploads/{filename}"
    if os.path.exists(file_path):
        return FileResponse(file_path)
    else:
        raise HTTPException(status_code=404, detail="File not found")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

