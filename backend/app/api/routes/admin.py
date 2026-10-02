from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session
from typing import List
from ...db.session import get_db
from ...schemas.user import UsuarioResponse, UsuarioUpdateRequest, Papel
from ...schemas.audit import AuditLogResponse
from ...services.user_service import UserService
from ...services.audit_service import AuditService
from ..dependencies import require_role, rate_limit_dependency
from ...models.user import Usuario

router = APIRouter(
    prefix="/admin",
    tags=["Administração e Auditoria (RBAC: Admin)"],
    dependencies=[Depends(rate_limit_dependency), Depends(require_role(Papel.ADMINISTRADOR))]
)

@router.get("/users", response_model=List[UsuarioResponse])
def listar_todos_usuarios(
    db: Session = Depends(get_db),
    admin_atual: Usuario = Depends(require_role(Papel.ADMINISTRADOR))
):
    """Listagem administrativa de todos os usuários."""
    return UserService.listar_todos_admin(db=db)

@router.patch("/users/{user_id}", response_model=UsuarioResponse)
def atualizar_usuario(
    user_id: str,
    dados: UsuarioUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin_atual: Usuario = Depends(require_role(Papel.ADMINISTRADOR))
):
    """Atualiza o papel ou status ativo/desativado de um usuário."""
    client_ip = request.client.host if request.client else "unknown"
    return UserService.atualizar_usuario(
        db=db,
        user_id=user_id,
        dados=dados,
        admin_usuario=admin_atual.nome_usuario,
        ip_origem=client_ip
    )

@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remover_usuario(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    admin_atual: Usuario = Depends(require_role(Papel.ADMINISTRADOR))
):
    """Remove permanentemente um usuário do sistema."""
    client_ip = request.client.host if request.client else "unknown"
    UserService.remover_usuario(
        db=db,
        user_id=user_id,
        admin_usuario=admin_atual.nome_usuario,
        ip_origem=client_ip
    )
    return None

@router.get("/audit-logs", response_model=List[AuditLogResponse])
def consultar_logs_auditoria(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    admin_atual: Usuario = Depends(require_role(Papel.ADMINISTRADOR))
):
    """Consulta os registros da trilha de auditoria 5W."""
    return AuditService.listar_eventos(db=db, limit=limit, offset=offset)
