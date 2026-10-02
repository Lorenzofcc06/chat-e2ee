from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from typing import List
from ...db.session import get_db
from ...schemas.user import UsuarioResponse, ChavePublicaResponse
from ...services.user_service import UserService
from ..dependencies import get_current_user, rate_limit_dependency
from ...models.user import Usuario

router = APIRouter(prefix="/users", tags=["Usuários e Descoberta de Chaves"], dependencies=[Depends(rate_limit_dependency)])

@router.get("", response_model=List[UsuarioResponse])
def listar_contatos(
    db: Session = Depends(get_db),
    usuario_atual: Usuario = Depends(get_current_user)
):
    """Descoberta: Lista os usuários disponíveis para troca de mensagens."""
    return UserService.listar_usuarios_para_contato(db=db)

@router.get("/{nome_usuario}/public-key", response_model=ChavePublicaResponse)
def obter_chave_publica(
    nome_usuario: str,
    request: Request,
    db: Session = Depends(get_db),
    usuario_atual: Usuario = Depends(get_current_user)
):
    """Recupera a chave pública do usuário destinatário para cifragem E2EE."""
    client_ip = request.client.host if request.client else "unknown"
    alvo = UserService.obter_chave_publica(
        db=db,
        nome_usuario=nome_usuario,
        solicitante=usuario_atual.nome_usuario,
        ip_origem=client_ip
    )
    return ChavePublicaResponse(
        id=str(alvo.id),
        nome_usuario=alvo.nome_usuario,
        chave_publica=alvo.chave_publica
    )
