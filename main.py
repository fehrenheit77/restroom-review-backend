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
48|reports_collection = db.reports
49|
50|# Create uploads directory and serve static files
51|os.makedirs("/app/railway-deployment/static/uploads", exist_ok=True)
52|app.mount("/static", StaticFiles(directory="/app/railway-deployment/static"), name="static")
53|
54|# Security
55|security = HTTPBearer()
56|
57|# Pydantic models
58|class UserCreate(BaseModel):
59|    email: EmailStr
60|    password: str
61|    full_name: str
62|
63|class UserLogin(BaseModel):
64|    email: EmailStr
65|    password: str
66|
67|class User(BaseModel):
68|    id: str
69|    email: EmailStr
70|    full_name: str
71|    profile_picture: Optional[str] = None
72|    is_verified: bool = False
73|    created_at: datetime
74|    updated_at: datetime
75|
76|class Token(BaseModel):
77|    access_token: str
78|    token_type: str
79|    user: User
80|
81|class GoogleAuthRequest(BaseModel):
82|    credential: str
83|
84|class BathroomResponse(BaseModel):
85|    id: str
86|    user_id: Optional[str]
87|    user_name: Optional[str]
88|    image_url: str
89|    sink_rating: int
90|    floor_rating: int
91|    toilet_rating: int
92|    smell_rating: int
93|    niceness_rating: int
94|    overall_rating: float
95|    location: str
96|    latitude: Optional[float]
97|    longitude: Optional[float]
98|    comments: str
99|    timestamp: str
100|
101|class TermsResponse(BaseModel):
102|    terms_text: str
103|    version: str
104|    last_updated: str
105|
106|class ReportRequest(BaseModel):
107|    content_type: str  # "review" or "user"
108|    content_id: str
109|    reason: str
110|    description: Optional[str] = None
111|
112|class ReportResponse(BaseModel):
113|    id: str
114|    reporter_id: str
115|    reporter_name: str
116|    content_type: str
117|    content_id: str
118|    reason: str
119|    description: Optional[str]
120|    status: str
121|    created_at: datetime
122|
123|# Helper functions
124|def hash_password(password: str) -> str:
125|    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
126|
127|def verify_password(password: str, hashed: str) -> bool:
128|    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
129|
130|def create_jwt_token(user_id: str) -> str:
131|    payload = {
132|        'sub': user_id,
133|        'exp': datetime.utcnow() + timedelta(minutes=30)
134|    }
135|    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')
136|
137|def verify_jwt_token(token: str) -> Optional[str]:
138|    try:
139|        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
140|        return payload.get('sub')
141|    except jwt.ExpiredSignatureError:
142|        return None
143|    except jwt.InvalidTokenError:
144|        return None
145|
146|async def get_user_by_email(email: str):
147|    user_doc = await users_collection.find_one({"email": email})
148|    if user_doc:
149|        # If the user has a custom 'id' field, use it; otherwise, convert _id to string
150|        if "id" not in user_doc:
151|            user_doc["id"] = str(user_doc["_id"])
152|        return user_doc
153|    return None
154|
155|async def get_user_by_id(user_id: str):
156|    try:
157|        user_doc = await users_collection.find_one({"id": user_id})
158|        if user_doc:
159|            return user_doc
160|        return None
161|    except:
162|        return None
163|
164|async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
165|    credentials_exception = HTTPException(
166|        status_code=status.HTTP_401_UNAUTHORIZED,
167|        detail="Could not validate credentials",
168|        headers={"WWW-Authenticate": "Bearer"},
169|    )
170|    try:
171|        user_id = verify_jwt_token(credentials.credentials)
172|        if user_id is None:
173|            raise credentials_exception
174|    except:
175|        raise credentials_exception
176|    
177|    user = await get_user_by_id(user_id)
178|    if user is None:
179|        raise credentials_exception
180|    return user
181|
182|async def get_current_user_optional(credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))):
183|    if credentials is None:
184|        return None
185|    try:
186|        user_id = verify_jwt_token(credentials.credentials)
187|        if user_id is None:
188|            return None
189|        user = await get_user_by_id(user_id)
190|        return user
191|    except:
192|        return None
193|
194|# Routes
195|@app.get("/api/test-simple")
196|async def test_simple():
197|    return {"status": "working"}
198|
199|@app.get("/")
200|async def root():
201|    return {"message": "Restroom Review API"}
202|
203|@app.get("/api/")
204|async def api_root():
205|    return {"message": "Restroom Review API"}
206|
207|@app.get("/api/config")
208|async def get_config():
209|    return {
210|        "message": "Restroom Review API Configuration",
211|        "google_maps_api_key": os.environ.get('GOOGLE_MAPS_API_KEY', ''),
212|        "google_client_id": os.environ.get('GOOGLE_CLIENT_ID', '')
213|    }
214|
215|# Auth Routes (what your frontend expects)
216|@app.post("/api/auth/register", response_model=Token)
217|async def register_user(user_data: UserCreate):
218|    # Check if user exists
219|    existing_user = await get_user_by_email(user_data.email)
220|    if existing_user:
221|        raise HTTPException(status_code=400, detail="Email already registered")
222|    
223|    # Create user
224|    user_id = str(uuid.uuid4())
225|    hashed_password = hash_password(user_data.password)
226|    
227|    user_doc = {
228|        "id": user_id,
229|        "email": user_data.email,
230|        "hashed_password": hashed_password,
231|        "full_name": user_data.full_name,
232|        "is_verified": False,
233|        "created_at": datetime.utcnow(),
234|        "updated_at": datetime.utcnow()
235|    }
236|    
237|    await users_collection.insert_one(user_doc)
238|    
239|    # Create access token
240|    access_token = create_jwt_token(user_id)
241|    
242|    user_response = User(
243|        id=user_id,
244|        email=user_data.email,
245|        full_name=user_data.full_name,
246|        is_verified=False,
247|        created_at=user_doc["created_at"],
248|        updated_at=user_doc["updated_at"]
249|    )
250|    
251|    return Token(access_token=access_token, token_type="bearer", user=user_response)
252|
253|@app.get("/api/debug-user-fields/{email}")
254|async def debug_user_fields(email: str):
255|    """Debug endpoint to check user document structure"""
256|    try:
257|        user = await get_user_by_email(email)
258|        if user:
259|            return {
260|                "found": True,
261|                "fields": list(user.keys()),
262|                "has_hashed_password": "hashed_password" in user,
263|                "has_password": "password" in user,
264|                "email": user.get("email"),
265|                "id": user.get("id")
266|            }
267|        else:
268|            return {"found": False}
269|    except Exception as e:
270|        return {"error": str(e)}
271|
272|@app.post("/api/auth/login", response_model=Token)
273|async def login_user(user_data: UserLogin):
274|    try:
275|        # Find user
276|        user = await get_user_by_email(user_data.email)
277|        
278|        if not user or not verify_password(user_data.password, user['hashed_password']):
279|            raise HTTPException(status_code=401, detail="Invalid credentials")
280|        
281|        # Create JWT token
282|        access_token = create_jwt_token(user['id'])
283|        
284|        user_response = User(
285|            id=user['id'],
286|            email=user['email'],
287|            full_name=user['full_name'],
288|            profile_picture=user.get('profile_picture'),
289|            is_verified=user.get('is_verified', False),
290|            created_at=user['created_at'],
291|            updated_at=user['updated_at']
292|        )
293|        
294|        return Token(access_token=access_token, token_type="bearer", user=user_response)
295|        
296|    except HTTPException:
297|        raise
298|    except Exception as e:
299|        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")
300|
301|@app.get("/api/auth/me", response_model=User)
302|async def get_current_user_info(current_user: dict = Depends(get_current_user)):
303|    return User(
304|        id=current_user["id"],
305|        email=current_user["email"],
306|        full_name=current_user["full_name"],
307|        profile_picture=current_user.get("profile_picture"),
308|        is_verified=current_user.get("is_verified", False),
309|        created_at=current_user["created_at"],
310|        updated_at=current_user["updated_at"]
311|    )
312|
313|@app.post("/api/auth/google", response_model=Token)
314|async def google_auth(auth_request: GoogleAuthRequest):
315|    try:
316|        async with httpx.AsyncClient() as client:
317|            token_info_response = await client.get(
318|                f'https://oauth2.googleapis.com/tokeninfo?id_token={auth_request.credential}'
319|            )
320|            
321|            if token_info_response.status_code != 200:
322|                raise HTTPException(status_code=400, detail="Invalid Google token")
323|                
324|            user_info = token_info_response.json()
325|            
326|            # Verify the token is for our app
327|            if user_info.get('aud') != os.environ.get('GOOGLE_CLIENT_ID'):
328|                raise HTTPException(status_code=400, detail="Token not for this application")
329|            
330|            email = user_info.get('email')
331|            name = user_info.get('name')
332|            picture = user_info.get('picture')
333|            google_id = user_info.get('sub')
334|            
335|            if not email or not name:
336|                raise HTTPException(status_code=400, detail="Missing required user information")
337|            
338|            # Check if user exists
339|            existing_user = await get_user_by_email(email)
340|            
341|            if existing_user:
342|                user = existing_user
343|            else:
344|                # Create new user
345|                user_id = str(uuid.uuid4())
346|                user_doc = {
347|                    "id": user_id,
348|                    "email": email,
349|                    "full_name": name,
350|                    "profile_picture": picture,
351|                    "google_id": google_id,
352|                    "is_verified": True,
353|                    "created_at": datetime.utcnow(),
354|                    "updated_at": datetime.utcnow()
355|                }
356|                
357|                await users_collection.insert_one(user_doc)
358|                # Remove the MongoDB _id field to avoid serialization issues
359|                if "_id" in user_doc:
360|                    del user_doc["_id"]
361|                user = user_doc
362|            
363|            # Create access token
364|            access_token = create_jwt_token(user["id"])
365|            
366|            user_response = User(
367|                id=user["id"],
368|                email=user["email"],
369|                full_name=user["full_name"],
370|                profile_picture=user.get("profile_picture"),
371|                is_verified=user.get("is_verified", False),
372|                created_at=user["created_at"],
373|                updated_at=user["updated_at"]
374|            )
375|            
376|            return Token(access_token=access_token, token_type="bearer", user=user_response)
377|            
378|    except HTTPException:
379|        raise
380|    except Exception as e:
381|        raise HTTPException(status_code=400, detail=f"Google authentication failed: {str(e)}")
382|
383|# Bathroom Routes
384|@app.post("/api/bathrooms")
385|async def create_bathroom_review(
386|    sink_rating: int = Form(...),
387|    floor_rating: int = Form(...),
388|    toilet_rating: int = Form(...),
389|    smell_rating: int = Form(...),
390|    niceness_rating: int = Form(...),
391|    location: str = Form(...),
392|    latitude: Optional[float] = Form(None),
393|    longitude: Optional[float] = Form(None),
394|    comments: str = Form(""),
395|    image: UploadFile = File(...),
396|    current_user: Optional[dict] = Depends(get_current_user_optional)
397|):
398|    # Validate file type
399|    if not image.content_type.startswith('image/'):
400|        raise HTTPException(status_code=400, detail="File must be an image")
401|    
402|    # Validate ratings
403|    for rating_value in [sink_rating, floor_rating, toilet_rating, smell_rating, niceness_rating]:
404|        if rating_value < 1 or rating_value > 5:
405|            raise HTTPException(status_code=400, detail="All ratings must be between 1 and 5")
406|    
407|    # Calculate overall rating
408|    overall_rating = (sink_rating + floor_rating + toilet_rating + smell_rating + niceness_rating) / 5
409|    
410|    # Generate unique filename
411|    file_extension = os.path.splitext(image.filename)[1] if image.filename else '.jpg'
412|    unique_filename = f"{uuid.uuid4()}{file_extension}"
413|    file_path = f"/app/backend/uploads/{unique_filename}"
414|    
415|    # Save the uploaded file to both locations
416|    backend_file_path = f"/app/backend/uploads/{unique_filename}"
417|    static_file_path = f"/app/railway-deployment/static/uploads/{unique_filename}"
418|    
419|    try:
420|        with open(backend_file_path, "wb") as buffer:
421|            content = await image.read()
422|            buffer.write(content)
423|        
424|        # Also copy to static directory for serving
425|        with open(static_file_path, "wb") as buffer:
426|            buffer.write(content)
427|    except Exception as e:
428|        raise HTTPException(status_code=500, detail=f"Failed to save image: {str(e)}")
429|    
430|    # Create bathroom review
431|    bathroom_id = str(uuid.uuid4())
432|    bathroom_doc = {
433|        "id": bathroom_id,
434|        "user_id": current_user["id"] if current_user else None,
435|        "user_name": current_user["full_name"] if current_user else None,
436|        "image_url": f"/static/uploads/{unique_filename}",
437|        "sink_rating": sink_rating,
438|        "floor_rating": floor_rating,
439|        "toilet_rating": toilet_rating,
440|        "smell_rating": smell_rating,
441|        "niceness_rating": niceness_rating,
442|        "overall_rating": round(overall_rating, 1),
443|        "location": location,
444|        "latitude": latitude,
445|        "longitude": longitude,
446|        "comments": comments,
447|        "timestamp": datetime.utcnow().isoformat()
448|    }
449|    
450|    await bathrooms_collection.insert_one(bathroom_doc)
451|    
452|    return bathroom_doc
453|
454|@app.get("/api/bathrooms")
455|async def get_bathrooms():
456|    bathrooms = []
457|    async for bathroom in bathrooms_collection.find().sort("timestamp", -1):
458|        bathrooms.append({
459|            "id": bathroom["id"],
460|            "user_id": bathroom.get("user_id"),
461|            "user_name": bathroom.get("user_name"),
462|            "image_url": bathroom["image_url"],
463|            "sink_rating": bathroom["sink_rating"],
464|            "floor_rating": bathroom["floor_rating"],
465|            "toilet_rating": bathroom["toilet_rating"],
466|            "smell_rating": bathroom["smell_rating"],
467|            "niceness_rating": bathroom["niceness_rating"],
468|            "overall_rating": bathroom["overall_rating"],
469|            "location": bathroom["location"],
470|            "latitude": bathroom.get("latitude"),
471|            "longitude": bathroom.get("longitude"),
472|            "comments": bathroom["comments"],
473|            "timestamp": bathroom["timestamp"]
474|        })
475|    
476|    return bathrooms
477|
478|def get_image_base64(filename: str) -> str:
479|    """Convert image file to base64 string"""
480|    try:
481|        file_path = f"/app/backend/uploads/{filename}"
482|        if os.path.exists(file_path):
483|            with open(file_path, "rb") as image_file:
484|                encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
485|                return encoded_string
486|        return ""
487|    except Exception as e:
488|        print(f"Error encoding image {filename}: {e}")
489|        return ""
490|
491|@app.get("/api/uploads/{filename}")
492|async def get_upload(filename: str):
493|    file_path = f"/app/backend/uploads/{filename}"
494|    print(f"DEBUG: Looking for file at: {file_path}")
495|    print(f"DEBUG: File exists: {os.path.exists(file_path)}")
496|    if os.path.exists(file_path):
497|        print(f"DEBUG: Returning file: {file_path}")
498|        return FileResponse(file_path)
499|    else:
500|        print(f"DEBUG: File not found: {file_path}")
501|        raise HTTPException(status_code=404, detail=f"File not found: {filename}")
502|
503|@app.get("/api/test-upload")
504|async def test_upload():
505|    return {"message": "Test endpoint working", "files": os.listdir("/app/backend/uploads")[:5]}
506|
507|# Report Content Routes
508|@app.post("/api/reports")
509|async def create_report(
510|    report_data: ReportRequest,
511|    current_user: dict = Depends(get_current_user)
512|):
513|    """Create a new content report"""
514|    report_id = str(uuid.uuid4())
515|    
516|    report_doc = {
517|        "id": report_id,
518|        "reporter_id": current_user["id"],
519|        "reporter_name": current_user["full_name"],
520|        "content_type": report_data.content_type,
521|        "content_id": report_data.content_id,
522|        "reason": report_data.reason,
523|        "description": report_data.description,
524|        "status": "pending",
525|        "created_at": datetime.utcnow(),
526|        "updated_at": datetime.utcnow()
527|    }
528|    
529|    await reports_collection.insert_one(report_doc)
530|    
531|    return {
532|        "id": report_id,
533|        "message": "Report submitted successfully",
534|        "status": "pending"
535|    }
536|
537|@app.get("/api/reports")
538|async def get_reports(current_user: dict = Depends(get_current_user)):
539|    """Get all reports (for admin dashboard)"""
540|    reports = []
541|    async for report in reports_collection.find().sort("created_at", -1):
542|        reports.append({
543|            "id": report["id"],
544|            "reporter_id": report["reporter_id"],
545|            "reporter_name": report["reporter_name"],
546|            "content_type": report["content_type"],
547|            "content_id": report["content_id"],
548|            "reason": report["reason"],
549|            "description": report.get("description"),
550|            "status": report["status"],
551|            "created_at": report["created_at"].isoformat()
552|        })
553|    
554|    return reports
555|
556|# Add this near the end of your file, before the if __name__ == "__main__": line
557|@app.options("/{full_path:path}")
558|async def options_handler(request, full_path: str):
559|    return {
560|        "message": "OK"
561|    }
562|
563|if __name__ == "__main__":
564|    import uvicorn
565|    port = int(os.environ.get("PORT", 8000))
566|    uvicorn.run(app, host="0.0.0.0", port=port)# Debug update Wed Jul  2 00:55:36 UTC 2025
567|

    
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT"))
    uvicorn.run(app, host="0.0.0.0", port=port)
