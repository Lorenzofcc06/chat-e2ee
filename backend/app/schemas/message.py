from pydantic import BaseModel, Field
from typing import Optional

class MensagemE2EE(BaseModel):
    id_remetente: str
    id_destinatario: str
    chave_sessao_cifrada: str = Field(..., description="Chave simétrica AES cifrada com RSA do destinatário (Base64)")
    iv: str = Field(..., description="Vetor de inicialização/Nonce AES-GCM (Base64)")
    texto_cifrado: str = Field(..., description="Mensagem cifrada com AES-GCM (Base64)")
    tag_autenticacao: str = Field(..., description="Tag de autenticação GCM (Base64)")
    assinatura: str = Field(..., description="Assinatura digital RSA-PSS do remetente (Base64)")
    data_hora: str

class NotificacaoWebSocket(BaseModel):
    tipo: str  # "MENSAGEM", "USUARIO_CONECTADO", "USUARIO_DESCONECTADO", "ERRO"
    dados: dict
