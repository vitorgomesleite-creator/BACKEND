from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from jose import jwt
from auth import JWT_SECRET, JWT_ALGORITHM
from .mail_service import mail, create_message
from .database import fake_users_db  # troque pelo seu banco real

router = APIRouter()

# Esquema para requisição de esqueci a senha
class ForgotPasswordRequest(BaseModel):
    email: EmailStr

# Esquema para resetar senha
class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

# Gerar token de reset
def create_reset_token(email: str):
    expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode = {"sub": email, "exp": expire}
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


@router.post("/forgot-password")
async def forgot_password(data: ForgotPasswordRequest):
    user = fake_users_db.get(data.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )

    reset_token = create_reset_token(user["email"])

    link = f"http://localhost:3000/reset-password?token={reset_token}"

    message = create_message(
        recipients=[user["email"]],
        subject="Resetar sua senha",
        body=f"<p>Clique no link para resetar a senha:</p><a href='{link}'>{link}</a>"
    )

    await mail.send_message(message)

    return {"msg": "E-mail de redefinição enviado com sucesso"}


@router.post("/reset-password")
async def reset_password(data: ResetPasswordRequest):
    try:
        payload = jwt.decode(data.token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token inválido")
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token inválido ou expirado")

    user = fake_users_db.get(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")

    # Aqui você deveria salvar a nova senha no banco (hash!)
    user["password"] = data.new_password

    return {"msg": "Senha redefinida com sucesso"}
