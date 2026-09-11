from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from typing import Optional, List
from ..models.user import Usuario
from ..schemas.user import UsuarioRegistroRequest, UsuarioUpdateRequest, Papel, TokenResponse
from ..core.security import hash_senha, verificar_senha, criar_token_acesso
from .audit_service import AuditService
import logging

class UserService:
    @staticmethod
    def registrar_usuario(db: Session, req: UsuarioRegistroRequest, ip_origem: str) -> Usuario:
        # Prevenção contra injeção: consulta parametrizada pelo ORM
        existente = db.query(Usuario).filter(Usuario.nome_usuario == req.nome_usuario).first()
        if existente:
            AuditService.registrar_evento(
                db=db,
                who="ANONYMOUS",
                what="USER_REGISTER_FAILED",
                where=f"{ip_origem} -> /auth/register",
                why=f"Tentativa de cadastro com nome de usuário já existente: '{req.nome_usuario}'",
                level=logging.WARNING
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Nome de usuário já cadastrado no sistema."
            )
        
        # Hash seguro de senha com bcrypt
        senha_cifrada = hash_senha(req.senha)

        novo_usuario = Usuario(
            nome_usuario=req.nome_usuario,
            hash_senha=senha_cifrada,
            chave_publica=req.chave_publica,
            papel=req.papel.value if req.papel else Papel.USUARIO.value,
            ativo=True
        )

        db.add(novo_usuario)
        db.commit()
        db.refresh(novo_usuario)

        # Trilha de auditoria 5W
        AuditService.registrar_evento(
            db=db,
            who=novo_usuario.nome_usuario,
            what="USER_REGISTER_SUCCESS",
            where=f"{ip_origem} -> /auth/register",
            why=f"Usuário criado com sucesso com papel '{novo_usuario.papel}'"
        )

        return novo_usuario

    @staticmethod
    def autenticar_usuario(db: Session, nome_usuario: str, senha_plana: str, ip_origem: str) -> TokenResponse:
        usuario = db.query(Usuario).filter(Usuario.nome_usuario == nome_usuario).first()
        
        if not usuario or not verificar_senha(senha_plana, usuario.hash_senha):
            AuditService.registrar_evento(
                db=db,
                who=nome_usuario,
                what="USER_LOGIN_FAILED",
                where=f"{ip_origem} -> /auth/login",
                why="Credenciais inválidas (senha incorreta ou usuário inexistente)",
                level=logging.WARNING
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuário ou senha incorretos",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        if not usuario.ativo:
            AuditService.registrar_evento(
                db=db,
                who=usuario.nome_usuario,
                what="USER_LOGIN_BLOCKED",
                where=f"{ip_origem} -> /auth/login",
                why="Tentativa de login em conta desativada por administrador",
                level=logging.WARNING
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Conta de usuário desativada pelo administrador."
            )

        # Gera token JWT com claims de identificação e papel
        token = criar_token_acesso(dados={
            "sub": str(usuario.id),
            "username": usuario.nome_usuario,
            "role": usuario.papel
        })

        AuditService.registrar_evento(
            db=db,
            who=usuario.nome_usuario,
            what="USER_LOGIN_SUCCESS",
            where=f"{ip_origem} -> /auth/login",
            why="Login realizado com sucesso e token JWT emitido"
        )

        return TokenResponse(
            access_token=token,
            user_id=str(usuario.id),
            nome_usuario=usuario.nome_usuario,
            papel=Papel(usuario.papel)
        )

    @staticmethod
    def obter_chave_publica(db: Session, nome_usuario: str, solicitante: str, ip_origem: str) -> Usuario:
        usuario = db.query(Usuario).filter(Usuario.nome_usuario == nome_usuario, Usuario.ativo == True).first()
        if not usuario:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuário destinatário não encontrado ou inativo"
            )
        
        AuditService.registrar_evento(
            db=db,
            who=solicitante,
            what="PUBLIC_KEY_FETCH",
            where=f"{ip_origem} -> /users/{nome_usuario}/public-key",
            why=f"Chave pública de '{nome_usuario}' recuperada para início de sessão E2EE"
        )
        return usuario

    @staticmethod
    def listar_usuarios_para_contato(db: Session) -> List[Usuario]:
        return db.query(Usuario).filter(Usuario.ativo == True).all()

    @staticmethod
    def listar_todos_admin(db: Session) -> List[Usuario]:
        return db.query(Usuario).all()

    @staticmethod
    def atualizar_usuario(db: Session, user_id: str, dados: UsuarioUpdateRequest, admin_usuario: str, ip_origem: str) -> Usuario:
        usuario = db.query(Usuario).filter(Usuario.id == user_id).first()
        if not usuario:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")
        
        alteracoes = []
        if dados.papel is not None:
            alteracoes.append(f"papel: {usuario.papel} -> {dados.papel.value}")
            usuario.papel = dados.papel.value
        
        if dados.ativo is not None:
            alteracoes.append(f"ativo: {usuario.ativo} -> {dados.ativo}")
            usuario.ativo = dados.ativo

        db.commit()
        db.refresh(usuario)

        AuditService.registrar_evento(
            db=db,
            who=admin_usuario,
            what="USER_UPDATED_BY_ADMIN",
            where=f"{ip_origem} -> /admin/users/{user_id}",
            why=f"Alterações realizadas no usuário '{usuario.nome_usuario}': {', '.join(alteracoes)}"
        )
        return usuario

    @staticmethod
    def remover_usuario(db: Session, user_id: str, admin_usuario: str, ip_origem: str):
        usuario = db.query(Usuario).filter(Usuario.id == user_id).first()
        if not usuario:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")
        
        nome_alvo = usuario.nome_usuario
        db.delete(usuario)
        db.commit()

        AuditService.registrar_evento(
            db=db,
            who=admin_usuario,
            what="USER_DELETED_BY_ADMIN",
            where=f"{ip_origem} -> /admin/users/{user_id}",
            why=f"Usuário '{nome_alvo}' excluído permanentemente por administrador",
            level=logging.WARNING
        )
