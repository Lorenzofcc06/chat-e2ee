# chat-e2ee
Projeto para disciplina de Segurança e Auditoria de Sistemas de Informação

## Como rodar o projeto localmente

### 1. Pré-requisitos
- Python 3.9+ instalado
- PostgreSQL rodando localmente (ou via Docker)

### 2. Configurando o Banco de Dados e Variáveis
1. Crie um banco de dados vazio no seu PostgreSQL (ex: `chat_e2ee`).
2. Entre na pasta `backend` e faça uma cópia do arquivo de configuração:
   ```bash
   cd backend
   cp .env.example .env
   ```
3. Abra o arquivo `.env` e ajuste a variável `DATABASE_URL` com as suas credenciais locais do Postgres:
   `DATABASE_URL=postgresql://SEU_USUARIO:SUA_SENHA@localhost:5432/NOME_DO_BANCO`

### 3. Instalando as Dependências
Abra o terminal (dentro da pasta `backend`), crie o ambiente virtual e instale as bibliotecas:

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 4. Iniciando o Servidor
Com o ambiente virtual ativado (`venv` aparecendo no terminal), rode o servidor FastAPI:
```bash
uvicorn app.main:app --reload
```
A API estará disponível em: `http://localhost:8000`
A documentação interativa (Swagger) para testar as rotas estará em: `http://localhost:8000/docs`
