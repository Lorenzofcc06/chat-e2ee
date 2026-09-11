import asyncio
import websockets
import requests
import json
import os
import sys
from datetime import datetime, timezone
from crypto.e2ee import E2EEManager
from storage.key_store import KeyStore

SERVER_HTTP_URL = os.getenv("SERVER_HTTP_URL", "http://127.0.0.1:8000")
SERVER_WS_URL = os.getenv("SERVER_WS_URL", "ws://127.0.0.1:8000")

keystore = KeyStore()

class ChatClient:
    def __init__(self):
        self.username = None
        self.token = None
        self.user_id = None
        self.role = None
        self.private_key_pem = None
        self.public_keys_cache = {}  # username -> pem
        self.ws = None

    def registrar(self):
        print("\n=== CADASTRO DE NOVO USUÁRIO ===")
        username = input("Nome de usuário desejado: ").strip()
        senha = input("Senha: ").strip()
        
        if not username or not senha:
            print("Erro: Nome de usuário e senha são obrigatórios.")
            return

        print("\n[1/3] Gerando par de chaves assimétricas RSA-2048 localmente...")
        priv_pem, pub_pem = E2EEManager.gerar_par_chaves()
        keystore.salvar_chave_privada(username, priv_pem)
        print("  -> Chave privada salva com segurança no seu dispositivo (em .keys/).")

        print("[2/3] Enviando apenas a Chave Pública e credenciais para o Servidor...")
        try:
            resp = requests.post(f"{SERVER_HTTP_URL}/api/v1/auth/register", json={
                "nome_usuario": username,
                "senha": senha,
                "chave_publica": pub_pem,
                "papel": "Usuario"
            })
            if resp.status_code == 201:
                print("  -> Usuário registrado com sucesso no backend!")
                print("Agora você já pode fazer o Login.")
            else:
                print(f"Erro no cadastro ({resp.status_code}): {resp.json().get('detail')}")
        except Exception as e:
            print(f"Erro ao conectar ao servidor: {e}")

    def login(self) -> bool:
        print("\n=== LOGIN NO CHAT E2EE ===")
        username = input("Nome de usuário: ").strip()
        senha = input("Senha: ").strip()

        try:
            resp = requests.post(f"{SERVER_HTTP_URL}/api/v1/auth/login", json={
                "nome_usuario": username,
                "senha": senha
            })
            if resp.status_code != 200:
                print(f"Falha de autenticação ({resp.status_code}): {resp.json().get('detail')}")
                return False

            data = resp.json()
            self.token = data["access_token"]
            self.username = data["nome_usuario"]
            self.user_id = data["user_id"]
            self.role = data["papel"]

            # Carrega a chave privada local do usuário
            if not keystore.existe_chave(self.username):
                print(f"\nAVISO: Não foi encontrada a chave privada local para '{self.username}'.")
                print("Se você registrou este usuário em outra máquina, precisará importar a chave.")
                return False

            self.private_key_pem = keystore.carregar_chave_privada(self.username)
            print(f"\nAutenticado com sucesso! Bem-vindo, {self.username} (Papel: {self.role})")
            return True

        except Exception as e:
            print(f"Erro ao conectar com o servidor: {e}")
            return False

    def listar_contatos(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            resp = requests.get(f"{SERVER_HTTP_URL}/api/v1/users", headers=headers)
            if resp.status_code == 200:
                usuarios = resp.json()
                print("\n--- CONTATOS DISPONÍVEIS ---")
                for u in usuarios:
                    status_str = "Ativo" if u["ativo"] else "Inativo"
                    eu = " (você)" if u["nome_usuario"] == self.username else ""
                    print(f"- {u['nome_usuario']} [{u['papel']}]{eu} - Status: {status_str}")
            else:
                print(f"Erro ao listar usuários: {resp.text}")
        except Exception as e:
            print(f"Erro de conexão: {e}")

    def obter_chave_publica_destinatario(self, destinatario: str) -> str:
        if destinatario in self.public_keys_cache:
            return self.public_keys_cache[destinatario]

        headers = {"Authorization": f"Bearer {self.token}"}
        resp = requests.get(f"{SERVER_HTTP_URL}/api/v1/users/{destinatario}/public-key", headers=headers)
        if resp.status_code == 200:
            pub_key = resp.json()["chave_publica"]
            self.public_keys_cache[destinatario] = pub_key
            return pub_key
        else:
            raise ValueError(f"Não foi possível obter a chave pública de '{destinatario}': {resp.text}")

    async def _ouvinte_mensagens(self, ws):
        """Loop assíncrono que escuta mensagens cifradas recebidas via WebSocket e as decifra."""
        try:
            async for raw_msg in ws:
                try:
                    msg_data = json.loads(raw_msg)
                    tipo = msg_data.get("tipo")

                    if tipo == "MENSAGEM_RECEBIDA":
                        dados = msg_data["dados"]
                        remetente = dados["id_remetente"]
                        
                        # Obtém a chave pública do remetente para verificar a assinatura
                        pub_remetente = self.obter_chave_publica_destinatario(remetente)
                        
                        # Processo de Recepção e Descriptografia E2EE
                        texto_plano = E2EEManager.decifrar_mensagem(
                            payload_cifrado=dados,
                            chave_privada_destinatario_pem=self.private_key_pem,
                            chave_publica_remetente_pem=pub_remetente
                        )
                        print(f"\n\r🔒 [{remetente}]: {texto_plano}")
                        print(f"Você: ", end="", flush=True)

                    elif tipo == "STATUS_ENTREGA":
                        status = msg_data.get("status")
                        dest = msg_data.get("destinatario")
                        if status == "OFFLINE":
                            print(f"\n\r[Sistema] ⚠️ O destinatário '{dest}' está offline.")
                            print(f"Você: ", end="", flush=True)

                    elif tipo == "ERRO":
                        print(f"\n\r[Erro Servidor]: {msg_data.get('mensagem')}")
                        print(f"Você: ", end="", flush=True)

                except Exception as e:
                    print(f"\n\r[Erro ao processar mensagem]: {e}")
                    print(f"Você: ", end="", flush=True)

        except websockets.exceptions.ConnectionClosed:
            print("\n[Conexão WebSocket com o servidor encerrada.]")

    async def chat_loop(self, destinatario: str):
        # 1. Troca de Chaves (obter chave pública de destino)
        try:
            pub_destinatario = self.obter_chave_publica_destinatario(destinatario)
        except Exception as e:
            print(f"Erro: {e}")
            return

        # 2. Conectar ao WebSocket com o token JWT
        uri = f"{SERVER_WS_URL}/ws?token={self.token}"
        print(f"\nConectando canal seguro E2EE com '{destinatario}'...")
        
        async with websockets.connect(uri) as ws:
            self.ws = ws
            print(f"--- Chat E2EE iniciado com '{destinatario}' ---")
            print("Digite sua mensagem e pressione Enter (ou digite '/sair' para voltar):")

            # Inicia tarefa em background para escutar mensagens recebidas
            ouvinte_task = asyncio.create_task(self._ouvinte_mensagens(ws))

            loop = asyncio.get_running_loop()
            while True:
                # Leitura não-bloqueante do input do terminal
                mensagem = await loop.run_in_executor(None, input, "Você: ")
                mensagem = mensagem.strip()

                if not mensagem:
                    continue

                if mensagem.lower() == "/sair":
                    break

                # 3. Processo de Criptografia e Envio
                try:
                    payload_cifrado = E2EEManager.cifrar_mensagem(
                        mensagem_texto=mensagem,
                        chave_publica_destinatario_pem=pub_destinatario,
                        chave_privada_remetente_pem=self.private_key_pem
                    )
                    payload_cifrado["id_remetente"] = self.username
                    payload_cifrado["id_destinatario"] = destinatario
                    payload_cifrado["data_hora"] = datetime.now(timezone.utc).isoformat()

                    # Envia pacote cifrado via WebSocket
                    await ws.send(json.dumps(payload_cifrado))

                except Exception as e:
                    print(f"Erro ao cifrar/enviar mensagem: {e}")

            ouvinte_task.cancel()
            await ws.close()

def main():
    client = ChatClient()
    while True:
        print("\n" + "="*45)
        print("          CHAT E2EE (ANÁLOGO WHATSAPP)       ")
        print("="*45)
        if not client.token:
            print("1. Cadastrar novo usuário (Gera par de chaves local)")
            print("2. Fazer Login")
            print("3. Sair")
            opcao = input("\nEscolha uma opção: ").strip()

            if opcao == "1":
                client.registrar()
            elif opcao == "2":
                client.login()
            elif opcao == "3":
                print("Encerrando aplicação.")
                break
            else:
                print("Opção inválida.")
        else:
            print(f"Logado como: {client.username} ({client.role})")
            print("1. Iniciar conversa com um contato (Chat E2EE)")
            print("2. Listar contatos / usuários")
            print("3. Logout")
            opcao = input("\nEscolha uma opção: ").strip()

            if opcao == "1":
                client.listar_contatos()
                dest = input("\nCom quem você deseja falar? (nome de usuário): ").strip()
                if dest:
                    if dest == client.username:
                        print("Você não pode iniciar um chat consigo mesmo.")
                    else:
                        asyncio.run(client.chat_loop(dest))
            elif opcao == "2":
                client.listar_contatos()
            elif opcao == "3":
                client.token = None
                client.username = None
                print("Logout efetuado com sucesso.")
            else:
                print("Opção inválida.")

if __name__ == "__main__":
    main()
