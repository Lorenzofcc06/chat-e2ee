from pydantic import BaseModel

class MensagemE2EE(BaseModel):
    id_remetente: str
    id_destinatario: str
    texto_cifrado: str
    assinatura: str
    data_hora: str
