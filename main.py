import os
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext

# O Railway injeta a variável DATABASE_URL automaticamente se conectarmos o Postgres deles.
# Caso ela não exista, o código usa o SQLite local como fallback.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./carwatch.db")

# Ajuste do driver para o PostgreSQL (Railway costuma enviar como postgres://, mas o SQLAlchemy exige postgresql://)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Configurações do Engine baseadas no banco de dados ativo
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Configuração de Segurança para Criptografia de Senhas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Modelo da Tabela de Usuários no Banco de Dados
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

# Cria as tabelas estruturadas no banco conectado (caso não existam)
Base.metadata.create_all(bind=engine)

# Schemas de validação de dados (Pydantic)
class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    message: str

    class Config:
        from_attributes = True

# Inicialização do FastAPI
app = FastAPI(title="CarWatch Auth Backend")

# Permite requisições de qualquer origem (crucial para o Android Studio / Emuladores de fora acessarem)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependência para gerenciar o ciclo de vida da sessão do banco
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ROTA 1: Cadastro de Usuário
@app.post("/api/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    # Verifica duplicidade de e-mail
    db_user = db.query(UserDB).filter(UserDB.email == user_data.email).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Este e-mail já está cadastrado."
        )
    
    # Gera o hash seguro da senha
    hashed_pwd = pwd_context.hash(user_data.password)
    
    new_user = UserDB(
        name=user_data.name,
        email=user_data.email,
        hashed_password=hashed_pwd
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {
        "id": new_user.id,
        "name": new_user.name,
        "email": new_user.email,
        "message": "Usuário registrado com sucesso!"
    }

# ROTA 2: Login de Usuário
@app.post("/api/auth/login", response_model=UserResponse)
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    # Localiza o usuário pelo e-mail informado
    user = db.query(UserDB).filter(UserDB.email == credentials.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="E-mail ou senha incorretos."
        )
    
    # Compara a senha enviada com o hash salvo no banco
    if not pwd_context.verify(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="E-mail ou senha incorretos."
        )
    
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "message": "Autenticado com sucesso!"
    }
