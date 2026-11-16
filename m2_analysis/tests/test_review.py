"""Offline regression tests for the changed functions, no DB/Ollama needed.
Load actual function definitions using AST so psycopg/FastAPI are not required.
This does not test imports, route wiring, actual SQL execution or transactions.
"""
import ast
import json
import hashlib
import math
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Any
import unittest

CODE = Path(__file__).resolve().parents[1] / 'm2_analysis' / 'main.py'
NAMES = {'canonical_comparison', 'claim_value_text', 'find_relations_and_score',
         'save_timeline_entry', 'text_hash', 'vector_literal', 'cleaned_entities',
         'article_input_type', 'find_clusters'}
node = ast.parse(CODE.read_text(encoding='utf-8'))
ns = dict(json=json, hashlib=hashlib, math=math, re=re, Any=Any, datetime=datetime,
          EMBED_MODEL='bge-m3', EMBED_DIM=1024, CLUSTER_THRESHOLD=.82,
          CVE_RE=re.compile(r'\bCVE-[0-9]{4}-[0-9]{4,}\b', re.I),
          ENTITY_TYPES={'VENDOR','PRODUCT','VERSION','CVE','THREAT_ACTOR'})
selected = ast.Module(body=[ast.ImportFrom(module='__future__', names=[ast.alias(name='annotations')], level=0)] +
                      [n for n in node.body if isinstance(n, ast.FunctionDef) and n.name in NAMES], type_ignores=[])
exec(compile(ast.fix_missing_locations(selected), str(CODE), 'exec'), ns)

class Result:
    def __init__(self, rows): self.rows = rows
    def fetchall(self): return self.rows
    def fetchone(self): return self.rows[0] if self.rows else None

class ComparisonDB:
    def __init__(self, peers): self.peers = peers; self.inserts = []
    def execute(self, sql, args):
        if 'FROM m2.cluster_members' in sql:
            return Result(self.peers[args[0]])
        if 'INSERT INTO m2.contradictions' in sql:
            self.inserts.append(args); return Result([])
        raise AssertionError(sql)

class TimelineDB:
    def __init__(self): self.rows = {}; self.links = set(); self.writes = 0
    def execute(self, sql, args):
        if 'SELECT id, embedding_model' in sql:
            v = self.rows.get(args); return Result([v] if v else [])
        if 'INSERT INTO m2.event_timeline_entries' in sql:
            event, date, desc, vec, model, h = args
            key = (event, date, h); entry = self.rows.setdefault(key, {'id': f'e{len(self.rows)+1}', 'embedding_model': model})
            entry['embedding_model'] = model; self.writes += 1; return Result([entry])
        if 'INSERT INTO m2.event_timeline_sources' in sql:
            self.links.add(args); return Result([])
        raise AssertionError(sql)

class ReviewTests(unittest.TestCase):
    def test_reverse_pair_preserves_evidence(self):
        f=ns['canonical_comparison']
        self.assertEqual(f(30,10,'B','A','evB','evA'),f(10,30,'A','B','evA','evB'))
        with self.assertRaises(ValueError): f(1,1,'A','B')

    def test_clusters_and_distinct_claims(self):
        d=datetime(2026,1,1,tzinfo=timezone.utc)
        c={'claim_type':'patch_available','value':True,'evidence':'current product A'}
        old={'id':30,'source_id':2,'published_at':d,'content_hash':'other',
             'key_claims':[{'claim_type':'patch_available','value':True,'evidence':'old A'},
                           {'claim_type':'patch_available','value':True,'evidence':'old B'}]}
        db=ComparisonDB({'cluster1':[old],'cluster2':[old]})
        score, contrary, rel=ns['find_relations_and_score'](db,
            {'id':10,'source_id':1,'published_at':d,'content_hash':'current'},
            ['cluster1','cluster2','cluster1'],[c,c])
        self.assertEqual(len(db.inserts),4)
        self.assertEqual(len(rel),4)
        self.assertEqual({a[0] for a in db.inserts},{'cluster1','cluster2'})
        self.assertTrue(all(a[1:3]==(10,30) and a[7]=='current product A' for a in db.inserts))
        self.assertEqual(score,.5); self.assertFalse(contrary)

    def test_same_hash_not_counted_as_independent(self):
        d=datetime(2026,1,1,tzinfo=timezone.utc)
        c={'claim_type':'patch_available','value':True,'evidence':'statement'}
        db=ComparisonDB({'c':[{'id':2,'source_id':2,'published_at':d,'content_hash':'same','key_claims':[c]}]})
        score,_,_=ns['find_relations_and_score'](db,{'id':1,'source_id':1,'published_at':d,'content_hash':'same'},['c'],[c])
        self.assertEqual(score,0)

    def test_timeline_second_source_and_different_date(self):
        db=TimelineDB(); calls=[]; original=ns.get('embed')
        ns['embed']=lambda t: calls.append(t) or [.01]*1024
        try:
            f=ns['save_timeline_entry']; d=datetime(2026,1,1,tzinfo=timezone.utc)
            first=f(db,'event',10,d,'Maintenance finished')
            second=f(db,'event',30,d,'Maintenance  finished')
            f(db,'event',30,d,'Maintenance finished')
            other=f(db,'event',10,datetime(2026,1,2,tzinfo=timezone.utc),'Maintenance finished')
            self.assertEqual(first,second); self.assertNotEqual(first,other)
            self.assertEqual(db.links,{(first,10),(first,30),(other,10)})
            self.assertEqual(db.writes,2); self.assertEqual(len(calls),2)
        finally:
            if original is None: ns.pop('embed',None)
            else: ns['embed']=original

    def test_entity_alias_cve_dedup(self):
        candidates=[{'type':'PRODUCT','name':'Foo App','normalized_name':'foo'},
                    {'type':'PRODUCT','name':'Foo Software','normalized_name':'FOO'},
                    {'type':'CVE','name':'CVE-2025-12345'}, {'type':'CVE','name':'garbage'}]
        result=ns['cleaned_entities'](candidates,'CVE-2025-12345','Foo App',[])
        self.assertEqual(len(result),2)
        self.assertEqual(result[0]['canonical_id'],'CVE-2025-12345')

    def test_dimensions_and_input_type(self):
        f=ns['vector_literal']
        self.assertTrue(f([.01]*1024).startswith('['))
        for v in ([.1]*768,[0.0]*1024,[float('nan')]*1024):
            with self.assertRaises(ValueError): f(v)
        g=ns['article_input_type']
        self.assertEqual(g({'translation_status':'done','body_de':'text'}),'TRANSLATED_TEXT')
        self.assertEqual(g({'translation_status':'not_needed','body_de':'text'}),'ORIGINAL_TEXT')





if __name__=='__main__': unittest.main()
