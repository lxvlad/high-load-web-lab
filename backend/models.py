from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime
from sqlalchemy.sql import func
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    matrix_size = Column(Integer) # Вхідний параметр
    status = Column(String, default="PENDING") # PENDING, PROCESSING, COMPLETED, CANCELED
    progress = Column(Integer, default=0)
    result = Column(String, nullable=True)
    server_handler = Column(String, nullable=True) # Хто обробив
    created_at = Column(DateTime(timezone=True), server_default=func.now())