import sys
import os
import uuid

# Adiciona backend e client ao sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)
CLIENT_DIR = os.path.join(os.path.dirname(BASE_DIR), "client")
sys.path.append(CLIENT_DIR)

from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings
from crypto.e2ee import E2EEManager

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "online"

def test_full_e2ee_and_security_flow():
    # Gera identificadores únicos para permitir múltiplas execuções idempotentes
    run_id = uuid.uuid4().hex[:6]
    user_alice = f"alice_{run_id}"
    user_bob = f"bob_{run_id}"

    print(f"\n--- 1. GERAÇÃO DE CHAVES LOCAIS ({user_alice} & {user_bob}) ---")
    alice_priv, alice_pub = E2EEManager.gerar_par_chaves()
    bob_priv, bob_pub = E2EEManager.gerar_par_chaves()
    assert "BEGIN PUBLIC KEY" in alice_pub
    assert "BEGIN PUBLIC KEY" in bob_pub

    print("--- 2. REGISTRO DE USUÁRIOS NO BACKEND COM MENOR PRIVILÉGIO ---")
    res_reg_alice = client.post("/api/v1/auth/register", json={
        "nome_usuario": user_alice,
        "senha": "AlicePassword123!",
        "chave_publica": alice_pub,
        "papel": "Usuario"
    })
    assert res_reg_alice.status_code == 201

    res_reg_bob = client.post("/api/v1/auth/register", json={
        "nome_usuario": user_bob,
        "senha": "BobPassword123!",
        "chave_publica": bob_pub,
        "papel": "Usuario"
    })
    assert res_reg_bob.status_code == 201

    print("--- 3. AUTENTICAÇÃO E EMISSÃO DE JWT ---")
    res_login_alice = client.post("/api/v1/auth/login", json={
        "nome_usuario": user_alice,
        "senha": "AlicePassword123!"
    })
    assert res_login_alice.status_code == 200
    alice_token = res_login_alice.json()["access_token"]
    assert alice_token is not None

    res_login_bob = client.post("/api/v1/auth/login", json={
        "nome_usuario": user_bob,
        "senha": "BobPassword123!"
    })
    assert res_login_bob.status_code == 200
    bob_token = res_login_bob.json()["access_token"]

    print("--- 4. DESCOBERTA E TROCA DE CHAVES ---")
    headers_alice = {"Authorization": f"Bearer {alice_token}"}
    res_key = client.get(f"/api/v1/users/{user_bob}/public-key", headers=headers_alice)
    assert res_key.status_code == 200
    bob_pub_from_server = res_key.json()["chave_publica"]
    assert bob_pub_from_server == bob_pub

    print("--- 5. RBAC: CONTROLE DE ACESSO BASEADO EM PAPÉIS ---")
    # Alice (Usuario) tentando rota de Admin -> deve ser 403 Forbidden!
    res_admin_forbidden = client.get("/api/v1/admin/users", headers=headers_alice)
    assert res_admin_forbidden.status_code == 403
    print("  -> RBAC validado: Usuário comum bloqueado de rota administrativa (HTTP 403)!")

    # Login do Admin do sistema
    res_login_admin = client.post("/api/v1/auth/login", json={
        "nome_usuario": "admin",
        "senha": "Admin@123456"
    })
    assert res_login_admin.status_code == 200
    admin_token = res_login_admin.json()["access_token"]
    headers_admin = {"Authorization": f"Bearer {admin_token}"}

    # Admin acessando rota administrativa -> deve ser 200 OK!
    res_admin_ok = client.get("/api/v1/admin/users", headers=headers_admin)
    assert res_admin_ok.status_code == 200
    print("  -> RBAC validado: Administrador acessou a gerência com sucesso (HTTP 200)!")

    print("--- 6. AUDITORIA 5W PERSISTENTE ---")
    res_audit = client.get("/api/v1/admin/audit-logs", headers=headers_admin)
    assert res_audit.status_code == 200
    logs = res_audit.json()
    assert len(logs) > 0
    print(f"  -> Trilha de auditoria 5W ativa com {len(logs)} eventos registrados!")

    print("--- 7. DEFESA CONTRA EXAUSTÃO DE RECURSOS (DOS) ---")
    hit_429 = False
    for i in range(15):
        r = client.post("/api/v1/auth/login", json={
            "nome_usuario": f"atacante_{run_id}",
            "senha": "wrongpassword"
        })
        if r.status_code == 429:
            hit_429 = True
            break
    assert hit_429, "Rate limiter não bloqueou requisições em excesso!"
    print("  -> DoS Defense validada: Rate limiter bloqueou requisições abusivas com HTTP 429!")

    print("--- 8. WEBSOCKET ZERO-KNOWLEDGE RELAY E E2EE EM TEMPO REAL ---")
    # Conexão simultânea de Alice e Bob no WebSocket
    with client.websocket_connect(f"/ws?token={bob_token}") as ws_bob:
        with client.websocket_connect(f"/ws?token={alice_token}") as ws_alice:
            texto_original = "Olá Bob! Esta é uma mensagem ultra secreta E2EE protegida por RSA e AES."
            pacote_cifrado = E2EEManager.cifrar_mensagem(
                mensagem_texto=texto_original,
                chave_publica_destinatario_pem=bob_pub,
                chave_privada_remetente_pem=alice_priv
            )
            pacote_cifrado["id_remetente"] = user_alice
            pacote_cifrado["id_destinatario"] = user_bob
            pacote_cifrado["data_hora"] = "2026-09-11T20:00:00Z"

            # Alice envia via WebSocket
            ws_alice.send_json(pacote_cifrado)

            # Alice recebe confirmação de entrega
            ack = ws_alice.receive_json()
            assert ack["status"] == "ENTREGUE"

            # Bob recebe a mensagem cifrada pelo WebSocket
            msg_recebida_bob = ws_bob.receive_json()
            assert msg_recebida_bob["tipo"] == "MENSAGEM_RECEBIDA"
            payload_recebido = msg_recebida_bob["dados"]

            # Bob decifra a mensagem usando sua chave privada e valida a assinatura de Alice
            texto_decifrado = E2EEManager.decifrar_mensagem(
                payload_cifrado=payload_recebido,
                chave_privada_destinatario_pem=bob_priv,
                chave_publica_remetente_pem=alice_pub
            )
            assert texto_decifrado == texto_original
            print(f"  -> E2EE validado! Mensagem recebida e decifrada por Bob: '{texto_decifrado}'")

    print("\nTODOS OS REQUISITOS FORAM TESTADOS E VALIDADOS COM SUCESSO!")

if __name__ == "__main__":
    test_health()
    test_full_e2ee_and_security_flow()
