# Chat E2EE - Comunicação Segura Ponta a Ponta

Projeto desenvolvido para a disciplina de **Segurança e Auditoria de Sistemas de Informação**.

Aplicação completa de troca de mensagens em tempo real (análoga ao WhatsApp) utilizando o conceito de **End-to-End Encryption (E2EE)** com arquitetura Zero-Knowledge Relay, RBAC, auditoria estruturada nos 5W e princípios de defesa em profundidade.

---

## 🛡️ Funcionalidades e Requisitos de Segurança Implementados

1. **Criptografia Ponta a Ponta (E2EE)**:
   - **Geração de Chaves Locais**: Chaves assimétricas RSA-2048 geradas exclusivamente na máquina do cliente via biblioteca padrão de mercado `cryptography`. A chave privada nunca sai do dispositivo.
   - **Descoberta e Troca de Chaves**: Endpoint REST para obtenção segura da chave pública do destinatário.
   - **Criptografia Híbrida e Envio**: Cada mensagem gera uma chave simétrica efêmera AES-256-GCM. A chave AES é cifrada com a chave pública RSA do destinatário (RSA-OAEP) e assinada digitalmente com a chave privada do remetente (RSA-PSS).
   - **Recepção e Descriptografia**: Destinatário valida a assinatura digital e decifra a mensagem com sua chave privada.
   - **Zero-Knowledge Relay**: O servidor apenas roteia pacotes cifrados via WebSockets sem acesso ao conteúdo em texto claro.

2. **Autenticação e Autorização (RBAC)**:
   - **Senhas Seguras**: Criptografadas com `bcrypt` (salt automático).
   - **Sessões JWT**: Tokens com expiração e claims validados em rotas HTTP e handshakes WebSocket.
   - **Papéis**:
     - `Usuario`: Acesso restrito a chat, troca de chaves e visualização de contatos.
     - `Administrador`: Acesso exclusivo à governança (gestão de usuários, ativação/bloqueio, exclusão e auditoria).

3. **Logs Estruturados 5W e Auditoria de Segurança**:
   - Campos padronizados:
     - `Who`: Usuário responsável (ou `ANONYMOUS`/IP).
     - `What`: Ação auditada (`USER_REGISTER_SUCCESS`, `USER_LOGIN_FAILED`, `PUBLIC_KEY_FETCH`, `E2EE_MESSAGE_RELAYED`, `DOS_RATE_LIMIT_TRIGGERED`, etc.).
     - `When`: Timestamp UTC ISO-8601.
     - `Where`: IP de origem, rota HTTP ou canal WebSocket.
     - `Why`: Motivo, status code ou resultado da operação.
   - Trilha persistente no banco de dados (`audit_logs`) e logs em arquivo (`logs/audit_5w.log`).

4. **Banco de Dados Seguro e Menor Privilégio**:
   - Script SQL com criação da role restrita `chat_api_user` (sem `SUPERUSER`, restrita estritamente a DML no schema do projeto).
   - Prevenção total contra SQL Injection via SQLAlchemy ORM com consultas parametrizadas.
   - Diretrizes de restrição à rede local (`localhost` e `pg_hba.conf`).

5. **Defesa contra Exaustão de Recursos (DoS)**:
   - Rate limiting por IP (proteção contra força bruta em `/auth/login` e flood em endpoints e WebSocket).
   - Limite estrito de tamanho de payload (máximo de 64KB por mensagem).

---

## 🔒 Por que a biblioteca `cryptography`?
O Python nativo possui apenas funções para geração de hashes (como SHA-256), mas **não possui algoritmos criptográficos assimétricos (RSA)** nem **cifradores de bloco simétricos modernos (AES-GCM)** em sua biblioteca padrão. A biblioteca `cryptography` (desenvolvida pela *PyCA - Python Cryptographic Authority*) é o padrão oficial de mercado e acadêmico para implementar E2EE, geração segura de pares de chaves e assinaturas digitais, evitando a má prática de implementar algoritmos matemáticos manualmente (*Don't roll your own crypto*).

---

## 🚀 Como Rodar o Projeto

### 1. Pré-requisitos
- Python 3.9+ instalado
- PostgreSQL rodando localmente

### 2. Configurar o Banco com Menor Privilégio
Abra o psql (ou pgAdmin) conectado como `postgres` e execute o script:
```sql
\i backend/scripts/setup_postgres_roles.sql
```
*(Ou copie e cole o conteúdo do script no Query Tool do pgAdmin)*.

### 3. Configurar as Variáveis de Ambiente
Na pasta `backend`, copie o `.env.example`:
```bash
cd backend
cp .env.example .env
```
*(No Windows PowerShell: `Copy-Item .env.example .env`)*

### 4. Instalar as Dependências do Backend
No terminal (dentro da pasta `backend`):
```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 5. Iniciar o Servidor Backend
```powershell
uvicorn app.main:app --reload
```
- API e WebSockets: `http://localhost:8000`
- Swagger UI (Documentação Interativa): `http://localhost:8000/docs`
- Credenciais padrão do Administrador inicial:
  - Usuário: `admin`
  - Senha: `Admin@123456`

---

## 💬 Como Executar o Cliente E2EE (CLI Interativo)

Você pode abrir **dois terminais diferentes** para simular dois usuários conversando em tempo real (ex: Alice e Bob):

No terminal do cliente:
```powershell
# Usando o mesmo ambiente virtual:
.\backend\venv\Scripts\python.exe client/cli.py
```

1. Escolha a opção **1** para cadastrar o usuário:
   - Ele gerará o par de chaves RSA localmente e salvará a chave privada em `.keys/`.
2. Faça o login (opção **2**).
3. No outro terminal, faça o mesmo para um segundo usuário.
4. Escolha **1. Iniciar conversa com um contato** e envie mensagens em tempo real!
   - As mensagens trafegam 100% cifradas pelo backend e são descriptografadas apenas no terminal de destino.

---

## 🧪 Como Rodar os Testes Automatizados

Com o ambiente virtual ativado na pasta `backend`:
```powershell
python tests/test_full_suite.py
```
O teste valida automaticamente:
- Geração de chaves RSA
- Cadastro e hash bcrypt
- Login e emissão de JWT
- Troca de chaves públicas
- Bloqueio de usuário comum em rota admin (HTTP 403)
- Acesso do Administrador e consulta de auditoria 5W
- Bloqueio de ataque de força bruta / DoS pelo rate limiter (HTTP 429)
- Handshake WebSocket autenticado, relay Zero-Knowledge e decifragem ponta a ponta
