-- Argos AI / M2 database schema v1.2 (compatible with M1 initial schema)
-- Basis: M1 public.raw_items(id) is BIGINT (GENERATED ALWAYS AS IDENTITY).
-- M2 internal IDs remain UUID; references to M1 raw_items use BIGINT + FK.
-- EMBED_MODEL=bge-m3 is configured in .env.example; standard embeddings are 1024-D.
-- Verify the actual embedding output dimension at runtime before inserting vectors.
-- Install after m1_initial.sql on a FRESH database (Docker db/init/ alphabetical order).
-- This is an initial schema, NOT a migration: existing m2 tables are NOT altered.
-- Do not reset a database volume containing data merely to apply this file.
-- All business tables are created in m2; FK targets exist in public.raw_items.
-- M2 writes only its own tables; M1 remains the sole owner of raw_items.
-- Review v1.2: model/input-aware uniqueness, canonical comparison pairs,
-- timeline source junction, CVE validation and automatic updated_at.
-- All vectors remain 1024-D; models with other dimensions require new storage/index design.

BEGIN;
CREATE EXTENSION IF NOT EXISTS vector;
CREATE SCHEMA IF NOT EXISTS m2;

-- Fail early if M1 was not initialized or uses an incompatible ID type.
DO $$
BEGIN
    IF to_regclass('public.raw_items') IS NULL THEN
        RAISE EXCEPTION 'M1 table public.raw_items does not exist. Run m1_initial.sql first.';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'raw_items'
          AND column_name = 'id'
          AND data_type = 'bigint'
    ) THEN
        RAISE EXCEPTION 'Expected public.raw_items.id to be BIGINT; check the M1 schema.';
    END IF;
END $$;

CREATE FUNCTION m2.touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

CREATE TABLE m2.entities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_item_id bigint NOT NULL REFERENCES public.raw_items(id),
    entity_type text NOT NULL CHECK (entity_type IN ('VENDOR','PRODUCT','VERSION','CVE','THREAT_ACTOR')),
    name text NOT NULL CHECK (btrim(name) <> ''),
    normalized_name text CHECK (normalized_name IS NULL OR btrim(normalized_name) <> ''),
    canonical_id text,
    version_text text,
    confidence numeric(5,4) CHECK (confidence BETWEEN 0 AND 1),
    extraction_method text NOT NULL CHECK (extraction_method IN ('REGEX','RULE','LLM','HYBRID')),
    evidence_text text,
    attributes jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(attributes) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT entities_cve_format CHECK (
        entity_type <> 'CVE' OR
        (canonical_id IS NOT NULL AND canonical_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$')
    )
);
-- One normalized entity per article/type, preserving distinct version strings
-- in the existing attributes/version fields as appropriate.
CREATE UNIQUE INDEX entities_identity_uidx ON m2.entities
    (raw_item_id, entity_type, lower(btrim(coalesce(normalized_name, name))));
CREATE INDEX IF NOT EXISTS entities_lookup_idx ON m2.entities (entity_type, normalized_name);
CREATE INDEX IF NOT EXISTS entities_canonical_idx ON m2.entities (canonical_id) WHERE canonical_id IS NOT NULL;

CREATE TABLE m2.summaries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_item_id bigint NOT NULL UNIQUE REFERENCES public.raw_items(id),
    summary_text text NOT NULL CHECK (btrim(summary_text) <> ''),
    category text NOT NULL CHECK (category IN ('VULNERABILITY','ATTACK','OUTAGE','REGULATION','GEOPOLITICS','OTHER')),
    key_claims jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(key_claims) = 'array'),
    language text NOT NULL DEFAULT 'de' CHECK (language ~ '^[a-z]{2}(-[a-z]{2})?$'),
    model_name text NOT NULL,
    prompt_version text,
    analyzed_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS summaries_category_idx ON m2.summaries (category);
CREATE INDEX IF NOT EXISTS summaries_claims_gin_idx ON m2.summaries USING gin (key_claims);

CREATE TABLE m2.embeddings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_item_id bigint NOT NULL REFERENCES public.raw_items(id),
    embedding vector(1024) NOT NULL,
    embedding_model text NOT NULL,
    input_type text NOT NULL CHECK (input_type IN ('TRANSLATED_TEXT','ORIGINAL_TEXT','SUMMARY','TIMELINE_TEXT')),
    input_hash text,
    embedded_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT embeddings_identity UNIQUE (raw_item_id, embedding_model, input_type)
);
-- For small demo data exact cosine search is sufficient; HNSW speeds larger datasets.
-- Compare only vectors from the same model; the application filters by model.
-- Model-specific ANN indexes may be useful later; exact search is used for event lookup.
CREATE INDEX IF NOT EXISTS embeddings_hnsw_idx ON m2.embeddings USING hnsw (embedding vector_cosine_ops);

-- Chunk vectors cover article text, not just its summary.
-- The application splits text into ordered chunks, subject to configured limits.
CREATE TABLE m2.text_chunks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_item_id bigint NOT NULL REFERENCES public.raw_items(id),
    chunk_index integer NOT NULL CHECK (chunk_index >= 0),
    chunk_text text NOT NULL CHECK (btrim(chunk_text) <> ''),
    time_context text,
    embedding vector(1024) NOT NULL,
    embedding_model text NOT NULL,
    source_hash text NOT NULL,
    input_type text NOT NULL
        CHECK (input_type IN ('TRANSLATED_TEXT','ORIGINAL_TEXT','SUMMARY','TIMELINE_TEXT')),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT text_chunks_item_index_unique UNIQUE (raw_item_id, embedding_model, input_type, chunk_index)
);
CREATE INDEX IF NOT EXISTS text_chunks_hnsw_idx ON m2.text_chunks USING hnsw (embedding vector_cosine_ops);

CREATE TABLE m2.clusters (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_name text NOT NULL,
    description text,
    representative_raw_item_id bigint REFERENCES public.raw_items(id) ON DELETE SET NULL,
    clustering_method text,
    algorithm_version text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Multiple clusters per news item; an explicit junction table is required.
-- The raw_item_id FK guarantees each member references an M1 record.
CREATE TABLE m2.cluster_members (
    cluster_id uuid NOT NULL REFERENCES m2.clusters(id) ON DELETE CASCADE,
    raw_item_id bigint NOT NULL REFERENCES public.raw_items(id),
    similarity numeric(5,4) CHECK (similarity BETWEEN 0 AND 1),
    assigned_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (cluster_id, raw_item_id)
);
CREATE INDEX IF NOT EXISTS cluster_members_item_idx ON m2.cluster_members (raw_item_id);

-- The two claims stay paired with their article IDs. Canonical order is
-- numeric ID order, not publication order; ADDITION does not imply direction.
CREATE FUNCTION m2.canonicalize_comparison() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    tmp_id bigint;
    tmp_claim text;
    tmp_evidence text;
BEGIN
    IF NEW.raw_item_id_1 > NEW.raw_item_id_2 THEN
        tmp_id := NEW.raw_item_id_1;
        NEW.raw_item_id_1 := NEW.raw_item_id_2;
        NEW.raw_item_id_2 := tmp_id;
        tmp_claim := NEW.claim_1;
        NEW.claim_1 := NEW.claim_2;
        NEW.claim_2 := tmp_claim;
        tmp_evidence := NEW.claim_evidence_1;
        NEW.claim_evidence_1 := NEW.claim_evidence_2;
        NEW.claim_evidence_2 := tmp_evidence;
    END IF;
    -- Hash the ordered pair of claims to keep the unique index bounded.
    NEW.claim_fingerprint := encode(sha256(convert_to(
        jsonb_build_array(NEW.claim_1, NEW.claim_2,
                          NEW.claim_evidence_1, NEW.claim_evidence_2)::text, 'UTF8')), 'hex');
    RETURN NEW;
END;
$$;

CREATE TABLE m2.contradictions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id uuid NOT NULL REFERENCES m2.clusters(id) ON DELETE CASCADE,
    raw_item_id_1 bigint NOT NULL REFERENCES public.raw_items(id),
    raw_item_id_2 bigint NOT NULL REFERENCES public.raw_items(id),
    relation_type text NOT NULL CHECK (relation_type IN ('CONFIRMATION','ADDITION','CONTRADICTION')),
    claim_type text NOT NULL,
    claim_1 text NOT NULL,
    claim_2 text NOT NULL,
    claim_evidence_1 text,
    claim_evidence_2 text,
    reasoning text NOT NULL,
    confidence numeric(5,4) CHECK (confidence BETWEEN 0 AND 1),
    model_name text NOT NULL,
    analyzed_at timestamptz NOT NULL DEFAULT now(),
    claim_fingerprint text NOT NULL,
    CONSTRAINT contradictions_canonical_items CHECK (raw_item_id_1 < raw_item_id_2),
    CONSTRAINT contradictions_identity UNIQUE
        (cluster_id, raw_item_id_1, raw_item_id_2, claim_type, claim_fingerprint)
);
CREATE TRIGGER contradictions_canonicalize
    BEFORE INSERT OR UPDATE ON m2.contradictions
    FOR EACH ROW EXECUTE FUNCTION m2.canonicalize_comparison();
CREATE INDEX IF NOT EXISTS contradictions_first_item_idx ON m2.contradictions (raw_item_id_1);
CREATE INDEX IF NOT EXISTS contradictions_second_item_idx ON m2.contradictions (raw_item_id_2);

CREATE TABLE m2.trust_scores (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_item_id bigint NOT NULL UNIQUE REFERENCES public.raw_items(id),
    trust_score numeric(5,4) NOT NULL CHECK (trust_score BETWEEN 0 AND 1),
    trust_label text NOT NULL CHECK (trust_label IN ('CONFIRMED','UNCONFIRMED','CONTRADICTORY')),
    source_type_score numeric(5,4) NOT NULL CHECK (source_type_score BETWEEN 0 AND 1),
    corroboration_score numeric(5,4) NOT NULL CHECK (corroboration_score BETWEEN 0 AND 1),
    primary_source_score numeric(5,4) NOT NULL CHECK (primary_source_score BETWEEN 0 AND 1),
    recency_score numeric(5,4) NOT NULL CHECK (recency_score BETWEEN 0 AND 1),
    contradiction_score numeric(5,4) NOT NULL CHECK (contradiction_score BETWEEN 0 AND 1),
    score_breakdown jsonb NOT NULL CHECK (jsonb_typeof(score_breakdown) = 'object'),
    reasoning text NOT NULL,
    scoring_version text NOT NULL,
    scored_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS trust_scores_score_idx ON m2.trust_scores (trust_score DESC);
CREATE INDEX IF NOT EXISTS trust_scores_label_idx ON m2.trust_scores (trust_label);

-- Historical event knowledge base: multiple articles / clusters can refer to one event.
-- Dates are structured fields for exact chronological comparisons, not vector substitutes.
-- Embed textual event narratives with BGE-M3; keep actual times in TIMESTAMPTZ.
CREATE TABLE m2.events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_title text NOT NULL CHECK (btrim(event_title) <> ''),
    event_type text NOT NULL CHECK (event_type IN ('VULNERABILITY','ATTACK','OUTAGE','REGULATION','GEOPOLITICS','OTHER')),
    event_summary text NOT NULL,
    timeline_text text NOT NULL DEFAULT '',
    narrative_hash text,  -- identifies the latest event narrative; older model vectors may be stale
    occurred_start_at timestamptz,
    occurred_end_at timestamptz,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL DEFAULT 'ONGOING' CHECK (status IN ('ONGOING','RESOLVED','UNKNOWN')),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT events_time_order CHECK (occurred_start_at IS NULL OR occurred_end_at IS NULL OR occurred_start_at <= occurred_end_at),
    CONSTRAINT events_seen_order CHECK (first_seen_at <= last_seen_at)
);
CREATE INDEX IF NOT EXISTS events_start_idx ON m2.events (occurred_start_at);
CREATE INDEX IF NOT EXISTS events_seen_idx ON m2.events (last_seen_at DESC);
CREATE INDEX IF NOT EXISTS events_type_idx ON m2.events (event_type);

CREATE TABLE m2.event_members (
    event_id uuid NOT NULL REFERENCES m2.events(id) ON DELETE CASCADE,
    raw_item_id bigint NOT NULL REFERENCES public.raw_items(id),
    role text NOT NULL DEFAULT 'EVIDENCE' CHECK (role IN ('EVIDENCE','UPDATE','CORRECTION')),
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, raw_item_id)
);
CREATE INDEX IF NOT EXISTS event_members_item_idx ON m2.event_members (raw_item_id);

-- A separate vector for event narratives (including their textual timeline).
CREATE TABLE m2.event_embeddings (
    event_id uuid NOT NULL REFERENCES m2.events(id) ON DELETE CASCADE,
    embedding vector(1024) NOT NULL,
    embedding_model text NOT NULL,
    narrative_hash text NOT NULL,
    embedded_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, embedding_model)
);
CREATE INDEX IF NOT EXISTS event_embeddings_hnsw_idx ON m2.event_embeddings USING hnsw (embedding vector_cosine_ops);

-- Each time-stamped event update is searchable semantically and chronologically.
-- A timeline entry retains one current vector; its sources are independent of the model.
-- This prevents a long evolving timeline from being compressed into one vector.
CREATE TABLE m2.event_timeline_entries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id uuid NOT NULL REFERENCES m2.events(id) ON DELETE CASCADE,
    occurred_at timestamptz,
    entry_text text NOT NULL CHECK (btrim(entry_text) <> ''),
    embedding vector(1024) NOT NULL,
    embedding_model text NOT NULL,
    content_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT event_timeline_entry_unique UNIQUE NULLS NOT DISTINCT (event_id, occurred_at, content_hash)
);
CREATE INDEX IF NOT EXISTS event_timeline_time_idx ON m2.event_timeline_entries (event_id, occurred_at);
CREATE INDEX IF NOT EXISTS event_timeline_embedding_idx ON m2.event_timeline_entries USING hnsw (embedding vector_cosine_ops);

-- One timeline entry may have multiple article sources. A publication date
-- is not proof of an event date. The source rows retain the article identity.
CREATE TABLE m2.event_timeline_sources (
    timeline_entry_id uuid NOT NULL REFERENCES m2.event_timeline_entries(id) ON DELETE CASCADE,
    raw_item_id bigint NOT NULL REFERENCES public.raw_items(id),
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (timeline_entry_id, raw_item_id)
);
CREATE INDEX event_timeline_sources_item_idx ON m2.event_timeline_sources (raw_item_id);

CREATE TABLE m2.event_relations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    from_event_id uuid NOT NULL REFERENCES m2.events(id) ON DELETE CASCADE,
    to_event_id uuid NOT NULL REFERENCES m2.events(id) ON DELETE CASCADE,
    relation_type text NOT NULL CHECK (relation_type IN ('PRECEDES','RELATED','EVOLVES_INTO','SAME_CAMPAIGN')),
    confidence numeric(5,4) CHECK (confidence BETWEEN 0 AND 1),
    explanation text NOT NULL,
    evidence jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(evidence) = 'array'),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT event_relation_distinct CHECK (from_event_id <> to_event_id),
    CONSTRAINT event_relation_unique UNIQUE (from_event_id, to_event_id, relation_type)
);
CREATE INDEX IF NOT EXISTS event_relations_to_idx ON m2.event_relations (to_event_id);

-- An optional link from an analytical cluster to its most relevant historical event.
-- Not mandatory: one event can include articles from several clusters.
ALTER TABLE m2.clusters
    ADD COLUMN IF NOT EXISTS primary_event_id uuid REFERENCES m2.events(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS clusters_event_idx ON m2.clusters (primary_event_id);

CREATE INDEX clusters_representative_item_idx ON m2.clusters (representative_raw_item_id);

CREATE TRIGGER summaries_touch_updated_at BEFORE UPDATE ON m2.summaries
    FOR EACH ROW EXECUTE FUNCTION m2.touch_updated_at();
CREATE TRIGGER clusters_touch_updated_at BEFORE UPDATE ON m2.clusters
    FOR EACH ROW EXECUTE FUNCTION m2.touch_updated_at();
CREATE TRIGGER events_touch_updated_at BEFORE UPDATE ON m2.events
    FOR EACH ROW EXECUTE FUNCTION m2.touch_updated_at();

COMMIT;
