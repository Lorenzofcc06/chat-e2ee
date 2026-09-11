import os

class KeyStore:
    """Armazenamento seguro de chaves criptográficas privadas na máquina do cliente."""

    def __init__(self, directory: str = ".keys"):
        self.directory = directory
        os.makedirs(self.directory, exist_ok=True)

    def _get_path(self, username: str) -> str:
        return os.path.join(self.directory, f"{username}_private.pem")

    def salvar_chave_privada(self, username: str, private_key_pem: str):
        path = self._get_path(username)
        with open(path, "w", encoding="utf-8") as f:
            f.write(private_key_pem)

    def carregar_chave_privada(self, username: str) -> str:
        path = self._get_path(username)
        if not os.path.exists(path):
            raise FileNotFoundError(f"Chave privada para o usuário '{username}' não encontrada localmente.")
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    def existe_chave(self, username: str) -> bool:
        return os.path.exists(self._get_path(username))
