-- ==============================================================================
-- SCRIPT DE CONFIGURAÇÃO DE ROLES DO BANCO DE DADOS (RBAC e Menor Privilégio)
-- Disciplina: Segurança e Auditoria de Dados
-- Projeto: Chat E2EE
-- Padrão: Grupo (Role sem LOGIN) + Usuário (Role com LOGIN) + Herança (INHERIT)
-- ==============================================================================

-- 1. Executar conectado como SUPERUSUÁRIO (ex: 'postgres')

-- Criação do banco de dados da aplicação se não existir
SELECT 'CREATE DATABASE chat_e2ee_db'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'chat_e2ee_db')\gexec

-- ==============================================================================
-- 2. CRIAÇÃO DE ROLES SEGUINDO AS BOAS PRÁTICAS DO RBAC
-- ==============================================================================

DO
$do$
BEGIN
   -- A) Criação do GRUPO (Role sem login para agrupar permissões)
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'app_chat_group') THEN
      CREATE ROLE app_chat_group NOLOGIN;
   END IF;

   -- B) Criação do USUÁRIO (Role com login e senha, herdando as regras do grupo)
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'chat_api_user') THEN
      CREATE ROLE chat_api_user WITH LOGIN PASSWORD 'senha_forte_api_123'
         INHERIT
         NOSUPERUSER
         NOCREATEDB
         NOCREATEROLE
         NOREPLICATION;
   END IF;

   -- C) Associação do usuário ao respectivo grupo (Herança de permissões)
   GRANT app_chat_group TO chat_api_user;
END
$do$;

-- ==============================================================================
-- 3. PERMISSÕES CONCEDIDAS AO GRUPO (Menor Privilégio)
-- Conectar-se ao banco 'chat_e2ee_db' antes de rodar os comandos abaixo:
-- \c chat_e2ee_db
-- ==============================================================================

-- Hardening: Revoga permissões públicas padrão no schema public
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Permite que o grupo conecte no banco e use o schema public
GRANT CONNECT ON DATABASE chat_e2ee_db TO app_chat_group;
GRANT USAGE, CREATE ON SCHEMA public TO app_chat_group;

-- Concede privilégios estritos de DML (apenas o necessário para a aplicação funcionar) ao GRUPO
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_chat_group;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_chat_group;

-- Garante que tabelas criadas no futuro herdem essas permissões estritas para o GRUPO
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_chat_group;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO app_chat_group;

-- ==============================================================================
-- 4. DIRETRIZES DE REDE LOCAL (pg_hba.conf e postgresql.conf)
-- ==============================================================================
-- No arquivo postgresql.conf:
--   listen_addresses = 'localhost'
--
-- No arquivo pg_hba.conf (Host-Based Authentication):
--   host    chat_e2ee_db    chat_api_user    127.0.0.1/32            scram-sha-256
--   host    chat_e2ee_db    chat_api_user    ::1/128                 scram-sha-256
--   host    all             all              0.0.0.0/0               reject
-- ==============================================================================
