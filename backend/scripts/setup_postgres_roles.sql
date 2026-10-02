-- ==============================================================================
-- SCRIPT DE SEGURANÇA E AUDITORIA DE DADOS: SETUP COMPLETO DO BANCO DE DADOS
-- Disciplina: Segurança e Auditoria de Sistemas de Informação
-- Alinhado com o caderno de práticas: seguranca_bd.py
-- ==============================================================================
-- Este script é 100% autônomo e pode ser executado do zero.
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- PARTE 1: Executar conectado como SUPERUSER ('postgres')
-- ------------------------------------------------------------------------------

-- 1.1 Criação do Banco de Dados
SELECT 'CREATE DATABASE chat_e2ee_db'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'chat_e2ee_db')\gexec

-- 1.2 Criação das Roles e Usuários (Padrão RBAC)
DO
$do$
BEGIN
   -- Role 1: Administrador do Banco de Dados (DBA do chat_e2ee_db)
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

-- 1.4 Proteção contra Ataques DoS no Usuário da API (Conforme seguranca_bd.py)
ALTER ROLE chat_api_user CONNECTION LIMIT 20;
ALTER ROLE chat_api_user SET statement_timeout = '5s';

-- ------------------------------------------------------------------------------
-- PARTE 2: Conectar na Query Tool DENTRO do banco 'chat_e2ee_db' (como 'postgres')
-- \c chat_e2ee_db
-- ------------------------------------------------------------------------------

-- Hardening: Revoga criação pública padrão no schema public
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Permissões totais do DBA no schema do banco
GRANT ALL PRIVILEGES ON SCHEMA public TO db_admin;

-- Permissões de Conexão e Acesso do Grupo da Aplicação
GRANT CONNECT ON DATABASE chat_e2ee_db TO app_chat_group;
GRANT USAGE, CREATE ON SCHEMA public TO app_chat_group;

-- 2.1 Criação das Tabelas Principais
CREATE TABLE IF NOT EXISTS usuarios (
    id VARCHAR(36) PRIMARY KEY,
    nome_usuario VARCHAR(50) UNIQUE NOT NULL,
    hash_senha VARCHAR(255) NOT NULL,
    chave_publica VARCHAR(2048) NOT NULL,
    papel VARCHAR(20) NOT NULL DEFAULT 'Usuario',
    ativo BOOLEAN NOT NULL DEFAULT TRUE,
    criado_em TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    atualizado_em TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    "when" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    who VARCHAR(100) NOT NULL,
    what VARCHAR(100) NOT NULL,
    "where" VARCHAR(255) NOT NULL,
    why TEXT
);

-- Permissões na tabela de Usuários (CRUD para gerência de contas)
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE usuarios TO app_chat_group;

-- REGRA DE OURO DE AUDITORIA: Imutabilidade (Append-Only)
-- A aplicação pode ler e gravar novos logs, mas NUNCA pode alterar ou apagar!
GRANT SELECT, INSERT ON TABLE audit_logs TO app_chat_group;
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_logs FROM app_chat_group;

-- Permissões em sequências (IDs auto-incremento)
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_chat_group;

-- Garante que futuras tabelas herdem o menor privilégio para o grupo
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_chat_group;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO app_chat_group;

-- 2.2 AUDITORIA ATIVA COM TRIGGERS (Defesa em Profundidade)
CREATE OR REPLACE FUNCTION registrar_auditoria_banco()
RETURNS TRIGGER
SECURITY DEFINER
AS $$
BEGIN
    IF (TG_OP = 'DELETE') THEN
        INSERT INTO audit_logs (who, what, "where", why)
        VALUES (session_user, 'DB_TRIGGER_USER_DELETED', TG_TABLE_NAME, concat('Registro excluído: ', OLD.nome_usuario));
        RETURN OLD;

    ELSIF (TG_OP = 'UPDATE') THEN
        INSERT INTO audit_logs (who, what, "where", why)
        VALUES (session_user, 'DB_TRIGGER_USER_UPDATED', TG_TABLE_NAME, concat('Alteração em ', NEW.nome_usuario, ': papel=', NEW.papel, ', ativo=', NEW.ativo));
        RETURN NEW;

    ELSIF (TG_OP = 'INSERT') THEN
        INSERT INTO audit_logs (who, what, "where", why)
        VALUES (session_user, 'DB_TRIGGER_USER_INSERTED', TG_TABLE_NAME, concat('Novo registro inserido no banco: ', NEW.nome_usuario));
        RETURN NEW;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_auditoria_usuarios ON usuarios;

CREATE TRIGGER trg_auditoria_usuarios
AFTER INSERT OR UPDATE OR DELETE ON usuarios
FOR EACH ROW EXECUTE FUNCTION registrar_auditoria_banco();
