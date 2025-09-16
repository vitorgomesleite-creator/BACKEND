from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from auth import create_access_token, verify_token, ACCESS_TOKEN_EXPIRE_MINUTES
from database import fake_users_db
from models import TokenResponse

app = FastAPI()

# Rota de Login
@app.post("/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or form_data.password != user["password"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha incorretos"
        )
    access_token = create_access_token(
        data={"sub": user["username"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token}

# Rota protegida (apenas logados acessam)
@app.get("/user/me")
def get_user(username: str = Depends(verify_token)):
    return {"msg": f"Bem-vindo, {username}!"}

# Rota de Logout (simulação)
@app.post("/logout")
def logout():
    # Em produção: invalidar token (lista negra, redis etc.)
    return {"msg": "Logout realizado com sucesso"}
