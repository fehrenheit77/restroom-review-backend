1|from fastapi import FastAPI, HTTPException, Depends, File, UploadFile, Form, status
2|from fastapi.middleware.cors import CORSMiddleware
3|from fastapi.staticfiles import StaticFiles
4|from fastapi.responses import FileResponse
5|from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
6|from pydantic import BaseModel, EmailStr
7|from typing import Optional, List
8|import motor.motor_asyncio
9|import bcrypt
10|import jwt
11|import os
12|import uuid
13|import base64
14|from datetime import datetime, timedelta
15|import httpx
16|from pathlib import Path
17|
18|# Environment variables
19|MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
20|JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
21|DATABASE_NAME = os.environ.get('DATABASE_NAME', 'restroom_review')
22|
23|# FastAPI app
24|app = FastAPI(title="Restroom Review API", version="1.0.0")
25|
26|# CORS middleware
27|app.add_middleware(
28|    CORSMiddleware,
29|    allow_origins=[
30|        "https://restroom-review-frontend-production.up.railway.app",
31|        "https://*.up.railway.app",
32|        "http://localhost:3000",
33|        "http://127.0.0.1:3000",
34|        "*"
35|    ],
36|    allow_credentials=True,
37|    allow_methods=["*"],
38|    allow_headers=["*"],
39|)
40|
41|# MongoDB client
42|client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URL)
43|db = client[DATABASE_NAME]
44|
45|# Collections
46|users_collection = db.users
47|bathrooms_collection = db.bathrooms
48|
49|# Create uploads directory and serve static files
50|os.makedirs("/app/railway-deployment/static/uploads", exist_ok=True)
51|app.mount("/static", StaticFiles(directory="/app/railway-deployment/static"), name="static")
52|
53|# Security
54|security = HTTPBearer()
55|
56|# Pydantic models
57|class UserCreate(BaseModel):
58|    email: EmailStr
59|    password: str
60|    full_name: str
61|
62|class UserLogin(BaseModel):
63|    email: EmailStr
64|    password: str
65|
66|class User(BaseModel):
67|    id: str
68|    email: EmailStr
69|    full_name: str
70|    profile_picture: Optional[str] = None
71|    is_verified: bool = False
72|    created_at: datetime
73|    updated_at: datetime
74|
75|class Token(BaseModel):
76|    access_token: str
77|    token_type: str
78|    user: User
79|
80|class GoogleAuthRequest(BaseModel):
81|    credential: str
82|
83|class BathroomResponse(BaseModel):
84|    id: str
85|    user_id: Optional[str]
86|    user_name: Optional[str]
87|    image_url: str
88|    sink_rating: int
89|    floor_rating: int
90|    toilet_rating: int
91|    smell_rating: int
92|    niceness_rating: int
93|    overall_rating: float
94|    location: str
95|    latitude: Optional[float]
96|    longitude: Optional[float]
97|    comments: str
98|    timestamp: str
99|
100|# Helper functions
101|def hash_password(password: str) -> str:
102|    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
103|
104|def verify_password(password: str, hashed: str) -> bool:
105|    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
106|
107|def create_jwt_token(user_id: str) -> str:
108|    payload = {
109|        'sub': user_id,
110|        'exp': datetime.utcnow() + timedelta(minutes=30)
111|    }
112|    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')
113|
114|def verify_jwt_token(token: str) -> Optional[str]:
115|    try:
116|        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
117|        return payload.get('sub')
118|    except jwt.ExpiredSignatureError:
119|        return None
120|    except jwt.InvalidTokenError:
121|        return None
122|
123|async def get_user_by_email(email: str):
124|    user_doc = await users_collection.find_one({"email": email})
125|    if user_doc:
126|        # If the user has a custom 'id' field, use it; otherwise, convert _id to string
127|        if "id" not in user_doc:
128|            user_doc["id"] = str(user_doc["_id"])
129|        return user_doc
130|    return None
131|
132|async def get_user_by_id(user_id: str):
133|    try:
134|        user_doc = await users_collection.find_one({"id": user_id})
135|        if user_doc:
136|            return user_doc
137|        return None
138|    except:
139|        return None
140|
141|async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
142|    credentials_exception = HTTPException(
143|        status_code=status.HTTP_401_UNAUTHORIZED,
144|        detail="Could not validate credentials",
145|        headers={"WWW-Authenticate": "Bearer"},
146|    )
147|    try:
148|        user_id = verify_jwt_token(credentials.credentials)
149|        if user_id is None:
150|            raise credentials_exception
151|    except:
152|        raise credentials_exception
153|    
154|    user = await get_user_by_id(user_id)
155|    if user is None:
156|        raise credentials_exception
157|    return user
158|
159|async def get_current_user_optional(credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))):
160|    if credentials is None:
161|        return None
162|    try:
163|        user_id = verify_jwt_token(credentials.credentials)
164|        if user_id is None:
165|            return None
166|        user = await get_user_by_id(user_id)
167|        return user
168|    except:
169|        return None
170|
171|# Routes
172|@app.get("/api/test-simple")
173|async def test_simple():
174|    return {"status": "working"}
175|
176|@app.get("/")
177|async def root():
178|    return {"message": "Restroom Review API"}
179|
180|@app.get("/api/")
181|async def api_root():
182|    return {"message": "Restroom Review API"}
183|
184|@app.get("/api/config")
185|async def get_config():
186|    return {
187|        "message": "Restroom Review API Configuration",
188|        "google_maps_api_key": os.environ.get('GOOGLE_MAPS_API_KEY', ''),
189|        "google_client_id": os.environ.get('GOOGLE_CLIENT_ID', '')
190|    }
191|
192|# Auth Routes (what your frontend expects)
193|@app.post("/api/auth/register", response_model=Token)
194|async def register_user(user_data: UserCreate):
195|    # Check if user exists
196|    existing_user = await get_user_by_email(user_data.email)
197|    if existing_user:
198|        raise HTTPException(status_code=400, detail="Email already registered")
199|    
200|    # Create user
201|    user_id = str(uuid.uuid4())
202|    hashed_password = hash_password(user_data.password)
203|    
204|    user_doc = {
205|        "id": user_id,
206|        "email": user_data.email,
207|        "hashed_password": hashed_password,
208|        "full_name": user_data.full_name,
209|        "is_verified": False,
210|        "created_at": datetime.utcnow(),
211|        "updated_at": datetime.utcnow()
212|    }
213|    
214|    await users_collection.insert_one(user_doc)
215|    
216|    # Create access token
217|    access_token = create_jwt_token(user_id)
218|    
219|    user_response = User(
220|        id=user_id,
221|        email=user_data.email,
222|        full_name=user_data.full_name,
223|        is_verified=False,
224|        created_at=user_doc["created_at"],
225|        updated_at=user_doc["updated_at"]
226|    )
227|    
228|    return Token(access_token=access_token, token_type="bearer", user=user_response)
229|
230|@app.get("/api/debug-user-fields/{email}")
231|async def debug_user_fields(email: str):
232|    """Debug endpoint to check user document structure"""
233|    try:
234|        user = await get_user_by_email(email)
235|        if user:
236|            return {
237|                "found": True,
238|                "fields": list(user.keys()),
239|                "has_hashed_password": "hashed_password" in user,
240|                "has_password": "password" in user,
241|                "email": user.get("email"),
242|                "id": user.get("id")
243|            }
244|        else:
245|            return {"found": False}
246|    except Exception as e:
247|        return {"error": str(e)}
248|
249|@app.post("/api/auth/login", response_model=Token)
250|async def login_user(user_data: UserLogin):
251|    try:
252|        # Find user
253|        user = await get_user_by_email(user_data.email)
254|        
255|        if not user or not verify_password(user_data.password, user['hashed_password']):
256|            raise HTTPException(status_code=401, detail="Invalid credentials")
257|        
258|        # Create JWT token
259|        access_token = create_jwt_token(user['id'])
260|        
261|        user_response = User(
262|            id=user['id'],
263|            email=user['email'],
264|            full_name=user['full_name'],
265|            profile_picture=user.get('profile_picture'),
266|            is_verified=user.get('is_verified', False),
267|            created_at=user['created_at'],
268|            updated_at=user['updated_at']
269|        )
270|        
271|        return Token(access_token=access_token, token_type="bearer", user=user_response)
272|        
273|    except HTTPException:
274|        raise
275|    except Exception as e:
276|        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")
277|
278|@app.get("/api/auth/me", response_model=User)
279|async def get_current_user_info(current_user: dict = Depends(get_current_user)):
280|    return User(
281|        id=current_user["id"],
282|        email=current_user["email"],
283|        full_name=current_user["full_name"],
284|        profile_picture=current_user.get("profile_picture"),
285|        is_verified=current_user.get("is_verified", False),
286|        created_at=current_user["created_at"],
287|        updated_at=current_user["updated_at"]
288|    )
289|
290|@app.post("/api/auth/google", response_model=Token)
291|async def google_auth(auth_request: GoogleAuthRequest):
292|    try:
293|        async with httpx.AsyncClient() as client:
294|            token_info_response = await client.get(
295|                f'https://oauth2.googleapis.com/tokeninfo?id_token={auth_request.credential}'
296|            )
297|            
298|            if token_info_response.status_code != 200:
299|                raise HTTPException(status_code=400, detail="Invalid Google token")
300|                
301|            user_info = token_info_response.json()
302|            
303|            # Verify the token is for our app
304|            if user_info.get('aud') != os.environ.get('GOOGLE_CLIENT_ID'):
305|                raise HTTPException(status_code=400, detail="Token not for this application")
306|            
307|            email = user_info.get('email')
308|            name = user_info.get('name')
309|            picture = user_info.get('picture')
310|            google_id = user_info.get('sub')
311|            
312|            if not email or not name:
313|                raise HTTPException(status_code=400, detail="Missing required user information")
314|            
315|            # Check if user exists
316|            existing_user = await get_user_by_email(email)
317|            
318|            if existing_user:
319|                user = existing_user
320|            else:
321|                # Create new user
322|                user_id = str(uuid.uuid4())
323|                user_doc = {
324|                    "id": user_id,
325|                    "email": email,
326|                    "full_name": name,
327|                    "profile_picture": picture,
328|                    "google_id": google_id,
329|                    "is_verified": True,
330|                    "created_at": datetime.utcnow(),
331|                    "updated_at": datetime.utcnow()
332|                }
333|                
334|                await users_collection.insert_one(user_doc)
335|                # Remove the MongoDB _id field to avoid serialization issues
336|                if "_id" in user_doc:
337|                    del user_doc["_id"]
338|                user = user_doc
339|            
340|            # Create access token
341|            access_token = create_jwt_token(user["id"])
342|            
343|            user_response = User(
344|                id=user["id"],
345|                email=user["email"],
346|                full_name=user["full_name"],
347|                profile_picture=user.get("profile_picture"),
348|                is_verified=user.get("is_verified", False),
349|                created_at=user["created_at"],
350|                updated_at=user["updated_at"]
351|            )
352|            
353|            return Token(access_token=access_token, token_type="bearer", user=user_response)
354|            
355|    except HTTPException:
356|        raise
357|    except Exception as e:
358|        raise HTTPException(status_code=400, detail=f"Google authentication failed: {str(e)}")
359|
360|# Bathroom Routes
361|@app.post("/api/bathrooms")
362|async def create_bathroom_review(
363|    sink_rating: int = Form(...),
364|    floor_rating: int = Form(...),
365|    toilet_rating: int = Form(...),
366|    smell_rating: int = Form(...),
367|    niceness_rating: int = Form(...),
368|    location: str = Form(...),
369|    latitude: Optional[float] = Form(None),
370|    longitude: Optional[float] = Form(None),
371|    comments: str = Form(""),
372|    image: UploadFile = File(...),
373|    current_user: Optional[dict] = Depends(get_current_user_optional)
374|):
375|    # Validate file type
376|    if not image.content_type.startswith('image/'):
377|        raise HTTPException(status_code=400, detail="File must be an image")
378|    
379|    # Validate ratings
380|    for rating_value in [sink_rating, floor_rating, toilet_rating, smell_rating, niceness_rating]:
381|        if rating_value < 1 or rating_value > 5:
382|            raise HTTPException(status_code=400, detail="All ratings must be between 1 and 5")
383|    
384|    # Calculate overall rating
385|    overall_rating = (sink_rating + floor_rating + toilet_rating + smell_rating + niceness_rating) / 5
386|    
387|    # Generate unique filename
388|    file_extension = os.path.splitext(image.filename)[1] if image.filename else '.jpg'
389|    unique_filename = f"{uuid.uuid4()}{file_extension}"
390|    file_path = f"/app/backend/uploads/{unique_filename}"
391|    
392|    # Save the uploaded file to both locations
393|    backend_file_path = f"/app/backend/uploads/{unique_filename}"
394|    static_file_path = f"/app/railway-deployment/static/uploads/{unique_filename}"
395|    
396|    try:
397|        with open(backend_file_path, "wb") as buffer:
398|            content = await image.read()
399|            buffer.write(content)
400|        
401|        # Also copy to static directory for serving
402|        with open(static_file_path, "wb") as buffer:
403|            buffer.write(content)
404|    except Exception as e:
405|        raise HTTPException(status_code=500, detail=f"Failed to save image: {str(e)}")
406|    
407|    # Create bathroom review
408|    bathroom_id = str(uuid.uuid4())
409|    bathroom_doc = {
410|        "id": bathroom_id,
411|        "user_id": current_user["id"] if current_user else None,
412|        "user_name": current_user["full_name"] if current_user else None,
413|        "image_url": f"/static/uploads/{unique_filename}",
414|        "sink_rating": sink_rating,
415|        "floor_rating": floor_rating,
416|        "toilet_rating": toilet_rating,
417|        "smell_rating": smell_rating,
418|        "niceness_rating": niceness_rating,
419|        "overall_rating": round(overall_rating, 1),
420|        "location": location,
421|        "latitude": latitude,
422|        "longitude": longitude,
423|        "comments": comments,
424|        "timestamp": datetime.utcnow().isoformat()
425|    }
426|    
427|    await bathrooms_collection.insert_one(bathroom_doc)
428|    
429|    return bathroom_doc
430|
431|@app.get("/api/bathrooms")
432|async def get_bathrooms():
433|    bathrooms = []
434|    async for bathroom in bathrooms_collection.find().sort("timestamp", -1):
435|        bathrooms.append({
436|            "id": bathroom["id"],
437|            "user_id": bathroom.get("user_id"),
438|            "user_name": bathroom.get("user_name"),
439|            "image_url": bathroom["image_url"],
440|            "sink_rating": bathroom["sink_rating"],
441|            "floor_rating": bathroom["floor_rating"],
442|            "toilet_rating": bathroom["toilet_rating"],
443|            "smell_rating": bathroom["smell_rating"],
444|            "niceness_rating": bathroom["niceness_rating"],
445|            "overall_rating": bathroom["overall_rating"],
446|            "location": bathroom["location"],
447|            "latitude": bathroom.get("latitude"),
448|            "longitude": bathroom.get("longitude"),
449|            "comments": bathroom["comments"],
450|            "timestamp": bathroom["timestamp"]
451|        })
452|    
453|    return bathrooms
454|
455|def get_image_base64(filename: str) -> str:
456|    """Convert image file to base64 string"""
457|    try:
458|        file_path = f"/app/backend/uploads/{filename}"
459|        if os.path.exists(file_path):
460|            with open(file_path, "rb") as image_file:
461|                encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
462|                return encoded_string
463|        return ""
464|    except Exception as e:
465|        print(f"Error encoding image {filename}: {e}")
466|        return ""
467|
468|@app.get("/api/uploads/{filename}")
469|async def get_upload(filename: str):
470|    file_path = f"/app/backend/uploads/{filename}"
471|    print(f"DEBUG: Looking for file at: {file_path}")
472|    print(f"DEBUG: File exists: {os.path.exists(file_path)}")
473|    if os.path.exists(file_path):
474|        print(f"DEBUG: Returning file: {file_path}")
475|        return FileResponse(file_path)
476|    else:
477|        print(f"DEBUG: File not found: {file_path}")
478|        raise HTTPException(status_code=404, detail=f"File not found: {filename}")
479|
480|@app.get("/api/test-upload")
481|async def test_upload():
482|    return {"message": "Test endpoint working", "files": os.listdir("/app/backend/uploads")[:5]}
483|
484|if __name__ == "__main__":
485|    import uvicorn
486|    port = int(os.environ.get("PORT", 8000))
487|    uvicorn.run(app, host="0.0.0.0", port=port)# Debug update Wed Jul  2 00:55:36 UTC 2025
488|

