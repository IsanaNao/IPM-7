-- Run ONLY against a disposable database with m1_initial.sql and m2_initial.sql v1.2 loaded.
-- All test rows are rolled back. No Ollama required. Fixture vectors are synthetic.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL plpgsql.check_asserts = on;
DO $$
DECLARE
    s1 bigint; s2 bigint; a bigint; b bigint;
    c1 uuid; c2 uuid; ev uuid; t1 uuid; t2 uuid;
    v vector(1024) := array_fill(0.01::real, ARRAY[1024])::vector;
    suffix text := gen_random_uuid()::text;
BEGIN
    INSERT INTO public.sources(name,url,connector,source_type)
    VALUES ('M2 test A '||suffix,'https://example.invalid/a','rss','authority') RETURNING id INTO s1;
    INSERT INTO public.sources(name,url,connector,source_type)
    VALUES ('M2 test B '||suffix,'https://example.invalid/b','rss','vendor') RETURNING id INTO s2;
    INSERT INTO public.raw_items(source_id,external_id,url,title,translation_status,content_hash)
    VALUES (s1,'a','https://example.invalid/a/1','Test A','failed',repeat('a',64)) RETURNING id INTO a;
    INSERT INTO public.raw_items(source_id,external_id,url,title,translation_status,content_hash)
    VALUES (s2,'b','https://example.invalid/b/1','Test B','failed',repeat('b',64)) RETURNING id INTO b;

    INSERT INTO m2.embeddings(raw_item_id,embedding,embedding_model,input_type) VALUES
        (a,v,'model-A','ORIGINAL_TEXT'),(a,v,'model-A','SUMMARY'),(a,v,'model-B','ORIGINAL_TEXT');
    BEGIN
        INSERT INTO m2.embeddings(raw_item_id,embedding,embedding_model,input_type) VALUES (a,v,'model-A','SUMMARY');
        RAISE EXCEPTION 'duplicate vector accepted';
    EXCEPTION WHEN unique_violation THEN NULL; END;
    INSERT INTO m2.text_chunks(raw_item_id,chunk_index,chunk_text,embedding,embedding_model,input_type,source_hash) VALUES
        (a,0,'Text',v,'model-A','ORIGINAL_TEXT','hash'),(a,0,'Summary',v,'model-A','SUMMARY','hash'),
        (a,0,'Text',v,'model-B','ORIGINAL_TEXT','hash');
    BEGIN
        INSERT INTO m2.text_chunks(raw_item_id,chunk_index,chunk_text,embedding,embedding_model,input_type,source_hash)
        VALUES (a,0,'Text',v,'model-A','ORIGINAL_TEXT','hash');
        RAISE EXCEPTION 'duplicate chunk accepted';
    EXCEPTION WHEN unique_violation THEN NULL; END;

    INSERT INTO m2.entities(raw_item_id,entity_type,name,normalized_name,extraction_method)
    VALUES (a,'PRODUCT','Example App','example app','RULE');
    BEGIN
        INSERT INTO m2.entities(raw_item_id,entity_type,name,normalized_name,extraction_method)
        VALUES (a,'PRODUCT','Alias','EXAMPLE APP','LLM');
        RAISE EXCEPTION 'duplicate entity accepted';
    EXCEPTION WHEN unique_violation THEN NULL; END;
    FOR i IN 1..2 LOOP
        BEGIN
            INSERT INTO m2.entities(raw_item_id,entity_type,name,canonical_id,extraction_method)
            VALUES (a,'CVE','CVE test',CASE WHEN i=1 THEN 'garbage' ELSE NULL END,'RULE');
            RAISE EXCEPTION 'invalid CVE accepted';
        EXCEPTION WHEN check_violation THEN NULL; END;
    END LOOP;
    INSERT INTO m2.entities(raw_item_id,entity_type,name,canonical_id,extraction_method)
        VALUES (a,'CVE','CVE-2025-12345','CVE-2025-12345','RULE');

    INSERT INTO m2.clusters(cluster_name,updated_at) VALUES ('A','2000-01-01T00:00:00Z') RETURNING id INTO c1;
    INSERT INTO m2.clusters(cluster_name) VALUES ('B') RETURNING id INTO c2;
    INSERT INTO m2.cluster_members(cluster_id,raw_item_id) VALUES (c1,a),(c1,b),(c2,a),(c2,b);
    INSERT INTO m2.contradictions(cluster_id,raw_item_id_1,raw_item_id_2,relation_type,claim_type,
        claim_1,claim_2,claim_evidence_1,claim_evidence_2,reasoning,model_name)
    VALUES (c1,b,a,'CONTRADICTION','patch_available','false','true','evidence B','evidence A','test','rules');
    ASSERT EXISTS(SELECT 1 FROM m2.contradictions WHERE cluster_id=c1 AND raw_item_id_1=a
          AND raw_item_id_2=b AND claim_1='true' AND claim_evidence_1='evidence A'), 'canonical swap failed';
    BEGIN
        INSERT INTO m2.contradictions(cluster_id,raw_item_id_1,raw_item_id_2,relation_type,claim_type,
          claim_1,claim_2,claim_evidence_1,claim_evidence_2,reasoning,model_name)
        VALUES (c1,a,b,'CONTRADICTION','patch_available','true','false','evidence A','evidence B','test','rules');
        RAISE EXCEPTION 'reversed duplicate comparison accepted';
    EXCEPTION WHEN unique_violation THEN NULL; END;
    -- Same comparison in a different cluster AND another claim in the same cluster are valid.
    INSERT INTO m2.contradictions(cluster_id,raw_item_id_1,raw_item_id_2,relation_type,claim_type,
          claim_1,claim_2,claim_evidence_1,claim_evidence_2,reasoning,model_name) VALUES
        (c2,a,b,'CONTRADICTION','patch_available','true','false','evidence A','evidence B','test','rules'),
        (c1,a,b,'CONFIRMATION','patch_available','true','true','evidence A2','evidence B2','test','rules'),
        (c1,a,b,'CONTRADICTION','patch_available','true','false','other evidence A','other evidence B','test','rules');
    ASSERT (SELECT count(*) FROM m2.contradictions WHERE cluster_id=c1)=3, 'valid comparison lost';
    BEGIN
        INSERT INTO m2.contradictions(cluster_id,raw_item_id_1,raw_item_id_2,relation_type,claim_type,
            claim_1,claim_2,reasoning,model_name)
        VALUES (c1,a,a,'CONFIRMATION','patch_available','true','true','test','rules');
        RAISE EXCEPTION 'self comparison accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;
    UPDATE m2.clusters SET description='changed' WHERE id=c1;
    ASSERT (SELECT updated_at > '2000-01-01T00:00:00Z'::timestamptz FROM m2.clusters WHERE id=c1), 'cluster timestamp failed';
    INSERT INTO m2.summaries(raw_item_id,summary_text,category,model_name,updated_at)
      VALUES (a,'Test','OTHER','test','2000-01-01T00:00:00Z');
    UPDATE m2.summaries SET summary_text='Changed' WHERE raw_item_id=a;
    ASSERT (SELECT updated_at > '2000-01-01T00:00:00Z'::timestamptz FROM m2.summaries WHERE raw_item_id=a), 'summary timestamp failed';

    INSERT INTO m2.events(event_title,event_type,event_summary,updated_at,narrative_hash)
      VALUES ('Test','OTHER','Test','2000-01-01T00:00:00Z','narrative') RETURNING id INTO ev;
    UPDATE m2.events SET event_summary='changed' WHERE id=ev;
    ASSERT (SELECT updated_at > '2000-01-01T00:00:00Z'::timestamptz FROM m2.events WHERE id=ev), 'event timestamp failed';
    INSERT INTO m2.event_embeddings(event_id,embedding,embedding_model,narrative_hash)
      VALUES (ev,v,'model-A','narrative'),(ev,v,'model-B','narrative');
    INSERT INTO m2.event_timeline_entries(event_id,occurred_at,entry_text,embedding,embedding_model,content_hash)
      VALUES (ev,NULL,'Same event entry',v,'model-A','h') RETURNING id INTO t1;
    INSERT INTO m2.event_timeline_sources(timeline_entry_id,raw_item_id) VALUES (t1,a),(t1,b);
    INSERT INTO m2.event_timeline_sources(timeline_entry_id,raw_item_id) VALUES (t1,b) ON CONFLICT DO NOTHING;
    ASSERT (SELECT count(*) FROM m2.event_timeline_sources WHERE timeline_entry_id=t1)=2, 'source lost or duplicated';
    BEGIN
        INSERT INTO m2.event_timeline_entries(event_id,occurred_at,entry_text,embedding,embedding_model,content_hash)
        VALUES (ev,NULL,'Same event entry',v,'model-A','h');
        RAISE EXCEPTION 'duplicate timeline entry accepted';
    EXCEPTION WHEN unique_violation THEN NULL; END;
    INSERT INTO m2.event_timeline_entries(event_id,occurred_at,entry_text,embedding,embedding_model,content_hash)
        VALUES (ev,'2026-01-02T00:00:00Z','Same event entry',v,'model-A','h') RETURNING id INTO t2;
    ASSERT t1<>t2, 'different event time incorrectly deduplicated';
    RAISE NOTICE 'M2 review regression checks passed';
END;
$$;
ROLLBACK;
