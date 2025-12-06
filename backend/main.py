import os
import time
import json
import asyncio
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse # <--- Додано для HTML
import random
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

# --- HTML INTERFACE (Вбудований прямо в код для надійності) ---
html_content = """
<!DOCTYPE html>
<html lang="uk">
<head>
    <meta charset="UTF-8">
    <title>High Load Matrix App</title>
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .box { border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
        .hidden { display: none; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .status-PROCESSING { color: orange; font-weight: bold; }
        .status-COMPLETED { color: green; font-weight: bold; }
        .status-CANCELED { color: red; }
    </style>
</head>
<body>
    <h1>Web Computing System (Load Balancer Demo)</h1>
    
    <div id="auth-section" class="box">
        <h3>Вхід / Реєстрація</h3>
        <input type="text" id="username" placeholder="Логін">
        <input type="password" id="password" placeholder="Пароль">
        <button onclick="auth('register')">Зареєструватись</button>
        <button onclick="auth('token')">Увійти</button>
    </div>

    <div id="app-section" class="box hidden">
        <h3>Запустити нову задачу</h3>
        <p>Задача: Обчислення матриці N*N</p>
        <input type="number" id="matrixSize" placeholder="Розмір N (макс 2000)">
        <button onclick="createTask()">Запустити обчислення</button>
        <p id="server-msg" style="color: blue; font-weight: bold;"></p>

        <h3>Історія та статус задач</h3>
        <button onclick="loadTasks()">Оновити список</button>
        <table id="tasksTable">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Розмір</th>
                    <th>Статус</th>
                    <th>Прогрес</th>
                    <th>Сервер</th>
                    <th>Дія</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
        <button onclick="logout()" style="margin-top: 20px; background: #f88;">Вийти</button>
    </div>

    <script>
        let token = localStorage.getItem('access_token');

        function updateUI() {
            if (token) {
                document.getElementById('auth-section').classList.add('hidden');
                document.getElementById('app-section').classList.remove('hidden');
                loadTasks();
            } else {
                document.getElementById('auth-section').classList.remove('hidden');
                document.getElementById('app-section').classList.add('hidden');
            }
        }

        async function auth(endpoint) {
            const user = document.getElementById('username').value;
            const pass = document.getElementById('password').value;
            const formData = new FormData();
            formData.append('username', user);
            formData.append('password', pass);

            // Використовуємо відносний шлях, щоб запит йшов через Nginx
            const res = await fetch(`/${endpoint}`, {
                method: 'POST', body: formData
            });

            if (res.ok) {
                if (endpoint === 'token') {
                    const data = await res.json();
                    token = data.access_token;
                    localStorage.setItem('access_token', token);
                    updateUI();
                } else {
                    alert('Зареєстровано! Тепер увійдіть.');
                }
            } else {
                alert('Помилка авторизації');
            }
        }

        async function createTask() {
            const size = document.getElementById('matrixSize').value;
            if (size > 2000) { alert("Помилка: Макс розмір 2000!"); return; }

            const res = await fetch(`/tasks?size=${size}`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });

            if (res.ok) {
                const data = await res.json();
                document.getElementById('server-msg').innerText = `Запит обробив: ${data.handled_by_api}`;
                loadTasks();
            } else {
                alert('Помилка створення задачі');
            }
        }

        async function loadTasks() {
            const res = await fetch('/tasks', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const tasks = await res.json();
            const tbody = document.querySelector('#tasksTable tbody');
            tbody.innerHTML = '';
            
            tasks.forEach(t => {
                let action = '';
                if (t.status === 'PENDING' || t.status === 'PROCESSING') {
                    action = `<button onclick="cancelTask(${t.id})">Скасувати</button>`;
                }
                const row = `<tr>
                    <td>${t.id}</td>
                    <td>${t.matrix_size}</td>
                    <td class="status-${t.status}">${t.status}</td>
                    <td>${t.progress}%</td>
                    <td>${t.server_handler || '-'}</td>
                    <td>${action}</td>
                </tr>`;
                tbody.innerHTML += row;
            });
        }

        async function cancelTask(id) {
            await fetch(`/tasks/${id}/cancel`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            loadTasks();
        }

        function logout() {
            localStorage.removeItem('access_token');
            token = null;
            updateUI();
        }

        setInterval(() => { if(token) loadTasks(); }, 2000);
        updateUI();
    </script>
</body>
</html>
"""

# --- AUTH CONFIG ---
SECRET_KEY = "secret_for_lab_work"
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

        # 1. Генерація матриць (імітуємо вхідні дані)
        # Для N=500 це вже буде відчутно довго на чистому Python
        matrix_a = [[random.random() for _ in range(size)] for _ in range(size)]
        matrix_b = [[random.random() for _ in range(size)] for _ in range(size)]
        result_matrix = [[0] * size for _ in range(size)]

        # 2. Множення матриць (O(N^3))
        for i in range(size):
            # Перевірка скасування та оновлення прогресу
            # Робимо це не на кожній ітерації, а, наприклад, кожні 10 рядків, щоб не гальмувати БД
            if i % 10 == 0 or i == size - 1:
                db.refresh(task)
                if task.status == "CANCELED":
                    print(f"Task {task_id} was canceled")
                    return 
                
                # Даємо "подихати" серверу, щоб він міг обробити інші запити (наприклад, cancel)
                await asyncio.sleep(0) 

                # Оновлюємо прогрес
                progress_percent = int((i + 1) / size * 100)
                if task.progress != progress_percent:
                    task.progress = progress_percent
                    db.commit()

            # Власне математика
            for j in range(size):
                dot_product = 0
                for k in range(size):
                    dot_product += matrix_a[i][k] * matrix_b[k][j]
                result_matrix[i][j] = dot_product

        task.status = "COMPLETED"
        # Не записуємо всю матрицю в результат, бо це заб'є базу. Тільки повідомлення.
        task.result = json.dumps({"message": f"Matrix {size}x{size} multiplied successfully. Element [0][0]={result_matrix[0][0]:.2f}"})
        db.commit()
        
    except Exception as e:
        print(f"Error processing task {task_id}: {e}")
        # Потрібно перевідкрити сесію або відкотити, якщо сталася помилка БД
        try:
            task.status = "ERROR"
            task.result = str(e)
            db.commit()
        except:
            pass

# --- ROUTES ---

# ГОЛОВНА СТОРІНКА (Ось чого не вистачало!)
@app.get("/", response_class=HTMLResponse)
async def read_root():
    return html_content

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