from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64
import json
from typing import Tuple, Dict

class E2EEManager:
    """Gerenciador criptográfico E2EE local (RSA-2048 + AES-256-GCM + Assinatura RSA-PSS)."""

    @staticmethod
    def gerar_par_chaves() -> Tuple[str, str]:
        """Gera localmente um par de chaves assimétricas RSA-2048.
        Retorna: (chave_privada_pem, chave_publica_pem)
        """
        chave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        privada_pem = chave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        publica_pem = chave_privada.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        return privada_pem, publica_pem

    @staticmethod
    def carregar_chave_privada(privada_pem: str):
        return serialization.load_pem_private_key(
            privada_pem.encode("utf-8"),
            password=None
        )

    @staticmethod
    def carregar_chave_publica(publica_pem: str):
        return serialization.load_pem_public_key(
            publica_pem.encode("utf-8")
        )

    @classmethod
    def cifrar_mensagem(
        cls,
        mensagem_texto: str,
        chave_publica_destinatario_pem: str,
        chave_privada_remetente_pem: str
    ) -> Dict[str, str]:
        """Processo de Criptografia Híbrida e Assinatura Digital:
        1. Gera chave de sessão aleatória AES-256 (32 bytes).
        2. Cifra a mensagem com AES-GCM (gera ciphertext e iv).
        3. Cifra a chave de sessão AES com a chave pública RSA do destinatário (RSA-OAEP).
        4. Assina o conjunto com a chave privada RSA do remetente (RSA-PSS).
        """
        pub_destinatario = cls.carregar_chave_publica(chave_publica_destinatario_pem)
        priv_remetente = cls.carregar_chave_privada(chave_privada_remetente_pem)

        # 1. Chave de sessão simétrica AES-256
        chave_sessao_aes = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(chave_sessao_aes)

        # 2. Cifragem simétrica com AES-256-GCM (Nonce de 12 bytes)
        nonce = os.urandom(12)
        texto_bytes = mensagem_texto.encode("utf-8")
        # AESGCM.encrypt retorna ciphertext + tag combinados nos últimos 16 bytes
        encrypted_data = aesgcm.encrypt(nonce, texto_bytes, None)
        ciphertext_bytes = encrypted_data[:-16]
        tag_bytes = encrypted_data[-16:]

        # 3. Cifragem da chave AES com RSA-OAEP do destinatário
        chave_sessao_cifrada = pub_destinatario.encrypt(
            chave_sessao_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 4. Criação da Assinatura Digital com RSA-PSS do remetente
        payload_para_assinar = chave_sessao_cifrada + nonce + ciphertext_bytes + tag_bytes
        assinatura = priv_remetente.sign(
            payload_para_assinar,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return {
            "chave_sessao_cifrada": base64.b64encode(chave_sessao_cifrada).decode("utf-8"),
            "iv": base64.b64encode(nonce).decode("utf-8"),
            "texto_cifrado": base64.b64encode(ciphertext_bytes).decode("utf-8"),
            "tag_autenticacao": base64.b64encode(tag_bytes).decode("utf-8"),
            "assinatura": base64.b64encode(assinatura).decode("utf-8")
        }

    @classmethod
    def decifrar_mensagem(
        cls,
        payload_cifrado: Dict[str, str],
        chave_privada_destinatario_pem: str,
        chave_publica_remetente_pem: str
    ) -> str:
        """Processo de Recepção, Verificação de Assinatura e Descriptografia:
        1. Verifica a assinatura digital RSA-PSS com a chave pública do remetente.
        2. Decifra a chave de sessão AES com a chave privada RSA do destinatário (RSA-OAEP).
        3. Decifra a mensagem com AES-256-GCM.
        """
        chave_sessao_cifrada = base64.b64decode(payload_cifrado["chave_sessao_cifrada"])
        nonce = base64.b64decode(payload_cifrado["iv"])
        ciphertext_bytes = base64.b64decode(payload_cifrado["texto_cifrado"])
        tag_bytes = base64.b64decode(payload_cifrado["tag_autenticacao"])
        assinatura = base64.b64decode(payload_cifrado["assinatura"])

        pub_remetente = cls.carregar_chave_publica(chave_publica_remetente_pem)
        priv_destinatario = cls.carregar_chave_privada(chave_privada_destinatario_pem)

        # 1. Validação da integridade e autenticidade da assinatura digital
        payload_para_verificar = chave_sessao_cifrada + nonce + ciphertext_bytes + tag_bytes
        try:
            pub_remetente.verify(
                assinatura,
                payload_para_verificar,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e:
            raise ValueError(f"Violação de Integridade: Assinatura digital inválida! ({str(e)})")

        # 2. Decifragem da chave AES com RSA-OAEP da chave privada do destinatário
        chave_sessao_aes = priv_destinatario.decrypt(
            chave_sessao_cifrada,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 3. Decifragem da mensagem com AES-256-GCM
        aesgcm = AESGCM(chave_sessao_aes)
        encrypted_combined = ciphertext_bytes + tag_bytes
        texto_plano_bytes = aesgcm.decrypt(nonce, encrypted_combined, None)

        return texto_plano_bytes.decode("utf-8")
