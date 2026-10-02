from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session
from ...db.session import get_db
from ...schemas.user import UsuarioRegistroRequest, UsuarioLoginRequest, UsuarioResponse, TokenResponse
from ...services.user_service import UserService
from ..dependencies import rate_limit_login_dependency

router = APIRouter(prefix="/auth", tags=["Autenticação"])

@router.post("/register", response_model=UsuarioResponse, status_code=status.HTTP_201_CREATED)
def registrar(req: UsuarioRegistroRequest, request: Request, db: Session = Depends(get_db)):
    """Cadastra um novo usuário com sua chave pública e credenciais."""
    client_ip = request.client.host if request.client else "unknown"
    return UserService.registrar_usuario(db=db, req=req, ip_origem=client_ip)

@router.post("/login", response_model=TokenResponse, dependencies=[Depends(rate_limit_login_dependency)])
def login(req: UsuarioLoginRequest, request: Request, db: Session = Depends(get_db)):
    """Autentica o usuário e emite o token JWT de acesso."""
    client_ip = request.client.host if request.client else "unknown"
    return UserService.autenticar_usuario(
        db=db,
        nome_usuario=req.nome_usuario,
        senha_plana=req.senha,
        ip_origem=client_ip
    )
