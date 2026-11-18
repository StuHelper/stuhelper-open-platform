CREATE SCHEMA IF NOT EXISTS open_platform;
REVOKE ALL ON SCHEMA open_platform FROM PUBLIC;
CREATE TABLE IF NOT EXISTS open_platform.owners(owner_key text PRIMARY KEY, closed boolean NOT NULL DEFAULT false, closure_id text NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS owners_closed ON open_platform.owners(owner_key) WHERE closed;
CREATE TABLE IF NOT EXISTS open_platform.apps(id text PRIMARY KEY,owner_key text NOT NULL,state text NOT NULL,revision bigint NOT NULL,secret_hash text NOT NULL,document jsonb NOT NULL,updated_at timestamptz NOT NULL DEFAULT now(),terminated_at timestamptz);
ALTER TABLE open_platform.apps ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now(), ADD COLUMN IF NOT EXISTS terminated_at timestamptz;
CREATE INDEX IF NOT EXISTS apps_owner ON open_platform.apps(owner_key,id);
CREATE INDEX IF NOT EXISTS apps_terminated ON open_platform.apps(terminated_at,id) WHERE terminated_at IS NOT NULL;
CREATE TABLE IF NOT EXISTS open_platform.grants(id text PRIMARY KEY,app_id text NOT NULL REFERENCES open_platform.apps(id),owner_key text NOT NULL,app_revision bigint NOT NULL,state text NOT NULL,expires_at timestamptz NOT NULL,document jsonb NOT NULL,updated_at timestamptz NOT NULL DEFAULT now(),terminated_at timestamptz,UNIQUE(app_id,owner_key));
ALTER TABLE open_platform.grants ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now(), ADD COLUMN IF NOT EXISTS terminated_at timestamptz;
ALTER TABLE open_platform.apps ADD COLUMN IF NOT EXISTS reviewed_by text NOT NULL DEFAULT '';
ALTER TABLE open_platform.apps ADD COLUMN IF NOT EXISTS reviewed_at timestamptz;
CREATE INDEX IF NOT EXISTS apps_updated ON open_platform.apps(updated_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS apps_state_updated ON open_platform.apps(state,updated_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS apps_owner_updated ON open_platform.apps(owner_key,updated_at DESC,id DESC);
ALTER TABLE open_platform.apps ADD COLUMN IF NOT EXISTS archived_at timestamptz;
CREATE INDEX IF NOT EXISTS apps_archived_expiry ON open_platform.apps(archived_at,id) WHERE archived_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS grants_owner ON open_platform.grants(owner_key,id);
CREATE INDEX IF NOT EXISTS grants_active_owner ON open_platform.grants(owner_key,id) WHERE state='active';
ALTER TABLE open_platform.grants ADD COLUMN IF NOT EXISTS granted_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE open_platform.grants ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE open_platform.grants ADD COLUMN IF NOT EXISTS last_data_read_at timestamptz;
CREATE INDEX IF NOT EXISTS grants_owner_updated ON open_platform.grants(owner_key,updated_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS grants_expiry ON open_platform.grants(expires_at,id) WHERE state='active';
CREATE INDEX IF NOT EXISTS grants_app_revision ON open_platform.grants(app_id,app_revision,id) WHERE state='active';
-- Existing grants can already be stale when this migration first runs.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='open_platform' AND table_name='apps' AND column_name='revision_work_pending') THEN
    ALTER TABLE open_platform.apps ADD COLUMN revision_work_pending boolean NOT NULL DEFAULT false;
    UPDATE open_platform.apps a SET revision_work_pending=true WHERE EXISTS (
      SELECT 1 FROM open_platform.grants g WHERE g.app_id=a.id AND g.state='active' AND (a.state<>'active' OR g.app_revision<>a.revision)
    );
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS apps_pending_work ON open_platform.apps(id) WHERE revision_work_pending;
CREATE INDEX IF NOT EXISTS grants_terminated ON open_platform.grants(terminated_at,id) WHERE terminated_at IS NOT NULL;
CREATE TABLE IF NOT EXISTS open_platform.consents(id text PRIMARY KEY,owner_key text NOT NULL,app_id text NOT NULL REFERENCES open_platform.apps(id),code_hash text UNIQUE,expires_at timestamptz NOT NULL,document jsonb NOT NULL);
-- Older consent records stored the approval revision in the application shown to the user.
UPDATE open_platform.consents SET document=jsonb_set(document,'{AppRevision}',document#>'{View,application,revision}')
WHERE NOT document ? 'AppRevision' AND jsonb_typeof(document#>'{View,application,revision}')='number';
CREATE TABLE IF NOT EXISTS open_platform.tokens(hash text PRIMARY KEY,grant_id text NOT NULL REFERENCES open_platform.grants(id),expires_at timestamptz NOT NULL,document jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS open_platform.quotas(app_id text NOT NULL REFERENCES open_platform.apps(id),day text NOT NULL,used integer NOT NULL,PRIMARY KEY(app_id,day));
CREATE TABLE IF NOT EXISTS open_platform.notices(id text PRIMARY KEY,position bigint GENERATED ALWAYS AS IDENTITY UNIQUE,created_at timestamptz NOT NULL,app_id text NOT NULL REFERENCES open_platform.apps(id),document jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS notices_app ON open_platform.notices(app_id,position);
CREATE INDEX IF NOT EXISTS notices_pending_ack ON open_platform.notices(app_id,position) WHERE COALESCE(document->>'acknowledgement','') NOT IN ('deleted','retention_exception');
CREATE INDEX IF NOT EXISTS notices_overdue_ack ON open_platform.notices(created_at,app_id) WHERE COALESCE(document->>'acknowledgement','') NOT IN ('deleted','retention_exception');
CREATE TABLE IF NOT EXISTS open_platform.requests(actor text NOT NULL,key text NOT NULL,digest text NOT NULL,result jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(actor,key));
CREATE TABLE IF NOT EXISTS open_platform.events(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,actor text NOT NULL,kind text NOT NULL,object_id text NOT NULL,operation text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(), reason text NOT NULL DEFAULT '', result text NOT NULL DEFAULT 'unknown' CHECK(result IN ('success','denied','failed','unknown')), recorded_xid xid8 NOT NULL DEFAULT pg_current_xact_id(), audit_actor text NOT NULL DEFAULT 'unknown', audit_target text NOT NULL DEFAULT 'unknown', audit_action text NOT NULL DEFAULT 'unknown', audit_school text NOT NULL DEFAULT '*', audit_group text NOT NULL DEFAULT '*', audit_time timestamptz NOT NULL DEFAULT now());
REVOKE ALL ON ALL TABLES IN SCHEMA open_platform FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA open_platform FROM PUBLIC;

CREATE INDEX IF NOT EXISTS consents_pending_owner ON open_platform.consents(owner_key) WHERE COALESCE(document->>'Decision','')='';
CREATE INDEX IF NOT EXISTS consents_pending_owner_expiry ON open_platform.consents(owner_key,expires_at) WHERE COALESCE(document->>'Decision','')='';

CREATE INDEX IF NOT EXISTS requests_expiry ON open_platform.requests(created_at,actor,key);
CREATE INDEX IF NOT EXISTS tokens_expiry ON open_platform.tokens(expires_at,hash);
CREATE INDEX IF NOT EXISTS tokens_consent ON open_platform.tokens((document->>'ConsentID'));
CREATE INDEX IF NOT EXISTS consents_expiry ON open_platform.consents(expires_at,id);
CREATE INDEX IF NOT EXISTS events_expiry ON open_platform.events(created_at,id);
CREATE INDEX IF NOT EXISTS notices_expiry ON open_platform.notices(created_at,id);
CREATE INDEX IF NOT EXISTS quotas_day ON open_platform.quotas(day,app_id);


CREATE TABLE IF NOT EXISTS open_platform.audit_retention(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), revision bigint NOT NULL DEFAULT 0);
INSERT INTO open_platform.audit_retention(singleton) VALUES(true) ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION open_platform.audit_project() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.audit_actor=COALESCE(NULLIF(NEW.actor,''),'unknown'); NEW.audit_target=COALESCE(NULLIF(NEW.object_id,''),'unknown'); NEW.audit_action=NEW.kind; NEW.audit_time=NEW.created_at; RETURN NEW; END $$;
CREATE OR REPLACE TRIGGER audit_project BEFORE INSERT OR UPDATE ON open_platform.events FOR EACH ROW EXECUTE FUNCTION open_platform.audit_project();
CREATE OR REPLACE FUNCTION open_platform.audit_invalidate() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN UPDATE open_platform.audit_retention SET revision=revision+1 WHERE singleton; RETURN NULL; END $$;
REVOKE ALL ON FUNCTION open_platform.audit_invalidate() FROM PUBLIC;
CREATE OR REPLACE FUNCTION open_platform.audit_invalidate_rows() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN IF EXISTS (SELECT 1 FROM affected_rows) THEN UPDATE open_platform.audit_retention SET revision=revision+1 WHERE singleton; END IF; RETURN NULL; END $$;
REVOKE ALL ON FUNCTION open_platform.audit_invalidate_rows() FROM PUBLIC;
DROP TRIGGER IF EXISTS audit_invalidate ON open_platform.events;
CREATE OR REPLACE TRIGGER audit_invalidate_update AFTER UPDATE ON open_platform.events REFERENCING OLD TABLE AS affected_rows FOR EACH STATEMENT EXECUTE FUNCTION open_platform.audit_invalidate_rows();
CREATE OR REPLACE TRIGGER audit_invalidate_delete AFTER DELETE ON open_platform.events REFERENCING OLD TABLE AS affected_rows FOR EACH STATEMENT EXECUTE FUNCTION open_platform.audit_invalidate_rows();
CREATE OR REPLACE TRIGGER audit_invalidate_truncate AFTER TRUNCATE ON open_platform.events FOR EACH STATEMENT EXECUTE FUNCTION open_platform.audit_invalidate();
CREATE INDEX IF NOT EXISTS audit_query_order ON open_platform.events(audit_time DESC,(id::text) COLLATE "C" DESC);

ALTER TABLE open_platform.owners ADD COLUMN IF NOT EXISTS closed_at timestamptz;
UPDATE open_platform.owners u SET closed_at=COALESCE(
  (SELECT min(created_at) FROM open_platform.events e WHERE e.actor=u.owner_key AND e.kind='account_closed'),now())
WHERE u.closed AND u.closed_at IS NULL;
CREATE INDEX IF NOT EXISTS owners_closed_at ON open_platform.owners(closed_at,owner_key) WHERE closed;

DO $$ BEGIN
  IF to_regclass('open_platform.invalid_revisions') IS NULL THEN
    CREATE TABLE open_platform.invalid_revisions(
      app_id text NOT NULL REFERENCES open_platform.apps(id) ON DELETE CASCADE,
      revision bigint NOT NULL,invalidated_at timestamptz NOT NULL,PRIMARY KEY(app_id,revision)
    );
    INSERT INTO open_platform.invalid_revisions
      SELECT DISTINCT g.app_id,g.app_revision,coalesce(a.terminated_at,a.updated_at)
      FROM open_platform.grants g JOIN open_platform.apps a ON a.id=g.app_id
      WHERE g.state='active' AND (a.state<>'active' OR a.revision<>g.app_revision);
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS invalid_revisions_time ON open_platform.invalid_revisions(invalidated_at,app_id,revision);
