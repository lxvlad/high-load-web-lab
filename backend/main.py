import os
import time
import json
import asyncio
import random
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy.exc import OperationalError
from passlib.context import CryptContext
from jose import JWTError, jwt
from database import engine, Base, get_db
from models import User, Task

# --- RETRY LOGIC ---
while True:
    try:
        Base.metadata.create_all(bind=engine)
        print("Successful connection to Database!")
        break
    except OperationalError:
        print("Database is not ready yet. Waiting 3 seconds...")
        time.sleep(3)

app = FastAPI()
SERVER_ID = os.getenv("SERVER_ID", "Unknown")
SECRET_KEY = os.getenv("SECRET_KEY", "secret_for_lab_work")
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- AUTH FUNCTIONS ---
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None: raise HTTPException(status_code=401)
    except JWTError:
        raise HTTPException(status_code=401)
    user = db.query(User).filter(User.username == username).first()
    if user is None: raise HTTPException(status_code=401)
    return user

# --- HEAVY TASK LOGIC ---
async def heavy_matrix_task(task_id: int, size: int, db: Session):
    try:
        task = db.query(Task).filter(Task.id == task_id).first()
        task.status = "PROCESSING"
        task.server_handler = SERVER_ID
        db.commit()

        matrix_a = [[random.random() for _ in range(size)] for _ in range(size)]
        matrix_b = [[random.random() for _ in range(size)] for _ in range(size)]
        result_matrix = [[0] * size for _ in range(size)]

        for i in range(size):
            if i % 10 == 0 or i == size - 1:
                db.refresh(task)
                if task.status == "CANCELED":
                    return 
                await asyncio.sleep(0) 
                progress_percent = int((i + 1) / size * 100)
                if task.progress != progress_percent:
                    task.progress = progress_percent
                    db.commit()

            for j in range(size):
                dot_product = 0
                for k in range(size):
                    dot_product += matrix_a[i][k] * matrix_b[k][j]
                result_matrix[i][j] = dot_product

        task.status = "COMPLETED"
        task.result = json.dumps({"message": f"Matrix {size}x{size} multiplied successfully."})
        db.commit()
    except Exception as e:
        try:
            task.status = "ERROR"
            task.result = str(e)
            db.commit()
        except:
            pass

# --- ROUTES ---

# ТУТ БІЛЬШЕ НЕМАЄ @app.get("/") - це тепер робить Nginx!

@app.post("/register")
def register(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = User(username=form_data.username, hashed_password=pwd_context.hash(form_data.password))
    try:
        db.add(user)
        db.commit()
    except:
        raise HTTPException(status_code=400, detail="User already exists")
    return {"msg": "Created"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect credentials")
    token = jwt.encode({"sub": user.username}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/tasks")
def create_task(size: int, background_tasks: BackgroundTasks, 
                user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if size > 2000:
        raise HTTPException(status_code=400, detail="Matrix too big (Max 2000)")
    
    active_task = db.query(Task).filter(
        Task.user_id == user.id,
        Task.status.in_(["PENDING", "PROCESSING"])
    ).first()

    if active_task:
        raise HTTPException(status_code=400, detail="You already have an active task.")

    new_task = Task(user_id=user.id, matrix_size=size, status="PENDING")
    db.add(new_task)
    db.commit()
    db.refresh(new_task)

    background_tasks.add_task(heavy_matrix_task, new_task.id, size, db)
    return {"id": new_task.id, "status": "PENDING", "handled_by_api": SERVER_ID}

@app.get("/tasks")
def get_my_tasks(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Task).filter(Task.user_id == user.id).order_by(Task.id.desc()).all()

@app.post("/tasks/{task_id}/cancel")
def cancel_task(task_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.id == task_id, Task.user_id == user.id).first()
    if not task:
        raise HTTPException(status_code=404)
    if task.status in ["PENDING", "PROCESSING"]:
        task.status = "CANCELED"
        db.commit()
    return {"msg": "Canceled"}