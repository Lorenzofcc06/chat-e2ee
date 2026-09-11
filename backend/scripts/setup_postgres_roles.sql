-- ==============================================================================
-- SCRIPT DE CONFIGURAÇÃO DE ROLES DO BANCO DE DADOS (Princípio do Menor Privilégio)
-- Disciplina: Segurança e Auditoria de Dados
-- Projeto: Chat E2EE
-- ==============================================================================

-- 1. Executar conectado como SUPERUSUÁRIO (ex: 'postgres')

-- Criação do banco de dados da aplicação se não existir
SELECT 'CREATE DATABASE chat_e2ee_db'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'chat_e2ee_db')\gexec

-- Criação do usuário exclusivo para a API FastAPI com senha forte
-- Nota: substitua 'senha_forte_api_123' pela senha de produção ou defina via .env
DO
$do$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles
      WHERE rolname = 'chat_api_user') THEN

      CREATE ROLE chat_api_user WITH LOGIN PASSWORD 'senha_forte_api_123'
         NOSUPERUSER
         NOCREATEDB
         NOCREATEROLE
         NOREPLICATION;
   END IF;
END
$do$;

-- ==============================================================================
-- 2. Conectar-se ao banco 'chat_e2ee_db' antes de rodar os comandos abaixo:
-- \c chat_e2ee_db
-- ==============================================================================

-- Revoga permissões públicas no schema public por padrão (Hardening)
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Permite que a role da API se conecte ao banco
GRANT CONNECT ON DATABASE chat_e2ee_db TO chat_api_user;

-- Permite uso do schema public
GRANT USAGE, CREATE ON SCHEMA public TO chat_api_user;

-- Concede privilégios estritos de DML (apenas o necessário para a aplicação funcionar)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO chat_api_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO chat_api_user;

-- Garante que tabelas criadas no futuro herdem essas permissões estritas
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO chat_api_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO chat_api_user;

-- ==============================================================================
-- 3. DIRETRIZES DE AUDITORIA E REDE LOCAL (pg_hba.conf e postgresql.conf)
-- ==============================================================================
-- Para permitir APENAS conexões da máquina local / rede local conforme requisito:
-- No arquivo postgresql.conf:
--   listen_addresses = 'localhost' (ou IP fixo da interface de rede local desejada)
--
-- No arquivo pg_hba.conf (Host-Based Authentication):
--   # Permitir apenas conexões locais via TCP/IP com autenticação scram-sha-256
--   host    chat_e2ee_db    chat_api_user    127.0.0.1/32            scram-sha-256
--   host    chat_e2ee_db    chat_api_user    ::1/128                 scram-sha-256
--   # Bloquear explicitamente qualquer conexão externa/remota não autorizada
--   host    all             all              0.0.0.0/0               reject
-- ==============================================================================
