CREATE SCHEMA IF NOT EXISTS open_platform;
REVOKE ALL ON SCHEMA open_platform FROM PUBLIC;
CREATE TABLE IF NOT EXISTS open_platform.owners(owner_key text PRIMARY KEY, closed boolean NOT NULL DEFAULT false, closure_id text NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS open_platform.apps(id text PRIMARY KEY,owner_key text NOT NULL,state text NOT NULL,revision bigint NOT NULL,secret_hash text NOT NULL,document jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS apps_owner ON open_platform.apps(owner_key,id);
CREATE TABLE IF NOT EXISTS open_platform.grants(id text PRIMARY KEY,app_id text NOT NULL REFERENCES open_platform.apps(id),owner_key text NOT NULL,app_revision bigint NOT NULL,state text NOT NULL,expires_at timestamptz NOT NULL,document jsonb NOT NULL,UNIQUE(app_id,owner_key));
CREATE INDEX IF NOT EXISTS grants_owner ON open_platform.grants(owner_key,id);
CREATE INDEX IF NOT EXISTS grants_expiry ON open_platform.grants(expires_at,id) WHERE state='active';
CREATE INDEX IF NOT EXISTS grants_app_revision ON open_platform.grants(app_id,app_revision,id) WHERE state='active';
CREATE TABLE IF NOT EXISTS open_platform.consents(id text PRIMARY KEY,owner_key text NOT NULL,app_id text NOT NULL REFERENCES open_platform.apps(id),code_hash text UNIQUE,expires_at timestamptz NOT NULL,document jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS open_platform.tokens(hash text PRIMARY KEY,grant_id text NOT NULL REFERENCES open_platform.grants(id),expires_at timestamptz NOT NULL,document jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS open_platform.quotas(app_id text NOT NULL REFERENCES open_platform.apps(id),day text NOT NULL,used integer NOT NULL,PRIMARY KEY(app_id,day));
CREATE TABLE IF NOT EXISTS open_platform.notices(id text PRIMARY KEY,position bigint GENERATED ALWAYS AS IDENTITY UNIQUE,created_at timestamptz NOT NULL,app_id text NOT NULL REFERENCES open_platform.apps(id),document jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS notices_app ON open_platform.notices(app_id,position);
CREATE TABLE IF NOT EXISTS open_platform.requests(actor text NOT NULL,key text NOT NULL,digest text NOT NULL,result jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(actor,key));
CREATE TABLE IF NOT EXISTS open_platform.events(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,actor text NOT NULL,kind text NOT NULL,object_id text NOT NULL,operation text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(), reason text NOT NULL DEFAULT '', result text NOT NULL DEFAULT 'unknown' CHECK(result IN ('success','denied','failed','unknown')), recorded_xid xid8 NOT NULL DEFAULT pg_current_xact_id(), audit_actor text NOT NULL DEFAULT 'unknown', audit_target text NOT NULL DEFAULT 'unknown', audit_action text NOT NULL DEFAULT 'unknown', audit_school text NOT NULL DEFAULT '*', audit_group text NOT NULL DEFAULT '*', audit_time timestamptz NOT NULL DEFAULT now());
REVOKE ALL ON ALL TABLES IN SCHEMA open_platform FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA open_platform FROM PUBLIC;

CREATE INDEX IF NOT EXISTS consents_pending_owner ON open_platform.consents(owner_key) WHERE COALESCE(document->>'Decision','')='';

CREATE INDEX IF NOT EXISTS requests_expiry ON open_platform.requests(created_at,actor,key);
CREATE INDEX IF NOT EXISTS tokens_expiry ON open_platform.tokens(expires_at,hash);
CREATE INDEX IF NOT EXISTS tokens_consent ON open_platform.tokens((document->>'ConsentID'));
CREATE INDEX IF NOT EXISTS consents_expiry ON open_platform.consents(expires_at,id);
CREATE INDEX IF NOT EXISTS events_expiry ON open_platform.events(created_at,id);
CREATE INDEX IF NOT EXISTS notices_expiry ON open_platform.notices(created_at,id);


CREATE TABLE IF NOT EXISTS open_platform.audit_retention(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), revision bigint NOT NULL DEFAULT 0);
INSERT INTO open_platform.audit_retention(singleton) VALUES(true) ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION open_platform.audit_project() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.audit_actor=COALESCE(NULLIF(NEW.actor,''),'unknown'); NEW.audit_target=COALESCE(NULLIF(NEW.object_id,''),'unknown'); NEW.audit_action=NEW.kind; NEW.audit_time=NEW.created_at; RETURN NEW; END $$;
CREATE OR REPLACE TRIGGER audit_project BEFORE INSERT OR UPDATE ON open_platform.events FOR EACH ROW EXECUTE FUNCTION open_platform.audit_project();
CREATE OR REPLACE FUNCTION open_platform.audit_invalidate() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN UPDATE open_platform.audit_retention SET revision=revision+1 WHERE singleton; RETURN NULL; END $$;
REVOKE ALL ON FUNCTION open_platform.audit_invalidate() FROM PUBLIC;
CREATE OR REPLACE TRIGGER audit_invalidate AFTER UPDATE OR DELETE OR TRUNCATE ON open_platform.events FOR EACH STATEMENT EXECUTE FUNCTION open_platform.audit_invalidate();
CREATE INDEX IF NOT EXISTS audit_query_order ON open_platform.events(audit_time DESC,(id::text) COLLATE "C" DESC);
