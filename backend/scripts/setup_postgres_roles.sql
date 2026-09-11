-- ==============================================================================
-- SCRIPT DE SEGURANÇA E AUDITORIA DE DADOS: CONFIGURAÇÃO DE ROLES (RBAC)
-- Disciplina: Segurança e Auditoria de Sistemas de Informação
-- Projeto: Chat E2EE
-- ==============================================================================
-- Estrutura de Roles estabelecida:
-- 1. db_admin       -> Administrador exclusivo do banco de dados (DBA do chat_e2ee_db)
-- 2. app_chat_group -> Grupo de regras da aplicação (NOLOGIN - Padrão RBAC)
-- 3. chat_api_user  -> Usuário de serviço da API FastAPI (Membro de app_chat_group)
-- Regra de Ouro da Auditoria: Tabela 'audit_logs' é Append-Only (INSERT/SELECT apenas)
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- ETAPA 1: Executar conectado como SUPERUSER (ex: 'postgres')
-- ------------------------------------------------------------------------------

-- 1.1 Criação do Banco de Dados
SELECT 'CREATE DATABASE chat_e2ee_db'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'chat_e2ee_db')\gexec

-- 1.2 Criação das Roles e Usuários
DO
$do$
BEGIN
   -- Role 1: Administrador do Banco de Dados (DBA local do chat_e2ee_db)
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'db_admin') THEN
      CREATE ROLE db_admin WITH LOGIN PASSWORD 'AdminDbSenhaForte_2026'
         NOSUPERUSER
         CREATEDB
         CREATEROLE
         INHERIT;
   END IF;

   -- Role 2: Grupo de Permissões da Aplicação (Role sem login para RBAC)
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'app_chat_group') THEN
      CREATE ROLE app_chat_group NOLOGIN;
   END IF;

   -- Role 3: Usuário da Aplicação FastAPI (Menor Privilégio - com login)
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'chat_api_user') THEN
      CREATE ROLE chat_api_user WITH LOGIN PASSWORD 'senha_forte_api_123'
         NOSUPERUSER
         NOCREATEDB
         NOCREATEROLE
         NOREPLICATION
         INHERIT;
   END IF;

   -- Vincula o usuário da API ao seu grupo de perfil
   GRANT app_chat_group TO chat_api_user;
END
$do$;

-- 1.3 Torna o 'db_admin' dono do banco de dados chat_e2ee_db
ALTER DATABASE chat_e2ee_db OWNER TO db_admin;

-- ------------------------------------------------------------------------------
-- ETAPA 2: Executar CONECTADO AO BANCO 'chat_e2ee_db'
-- \c chat_e2ee_db
-- ------------------------------------------------------------------------------

-- Hardening: Revoga privilégios públicos padrão no schema public
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Permissões do DBA no banco
GRANT ALL PRIVILEGES ON SCHEMA public TO db_admin;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO db_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO db_admin;

-- Permissões de Conexão e Acesso do Grupo da Aplicação
GRANT CONNECT ON DATABASE chat_e2ee_db TO app_chat_group;
GRANT USAGE, CREATE ON SCHEMA public TO app_chat_group;

-- Permissões na tabela de Usuários (CRUD normal para gerência de contas)
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE usuarios TO app_chat_group;

-- ==============================================================================
-- ETAPA 3: REGRA DE OURO DE AUDITORIA - IMUTABILIDADE (APPEND-ONLY)
-- A aplicação DEVE poder gravar novos logs e consultar histórico.
-- A aplicação JAMAIS deve poder alterar (UPDATE) ou apagar (DELETE/TRUNCATE) logs!
-- ==============================================================================
GRANT SELECT, INSERT ON TABLE audit_logs TO app_chat_group;
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_logs FROM app_chat_group;

-- Permissões em sequências (IDs auto-incremento)
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_chat_group;

-- Garante que futuras tabelas herdem o menor privilégio para o grupo
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_chat_group;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO app_chat_group;

-- ------------------------------------------------------------------------------
-- ETAPA 4: DIRETRIZES DE AUDITORIA E REDE LOCAL (pg_hba.conf e postgresql.conf)
-- ------------------------------------------------------------------------------
-- No postgresql.conf:
--   listen_addresses = 'localhost'
--
-- No pg_hba.conf:
--   host    chat_e2ee_db    db_admin         127.0.0.1/32            scram-sha-256
--   host    chat_e2ee_db    chat_api_user    127.0.0.1/32            scram-sha-256
--   host    all             all              0.0.0.0/0               reject
-- ==============================================================================
