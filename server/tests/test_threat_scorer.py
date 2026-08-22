from pathlib import Path
import sys
import pandas as pd
import pytest
SERVER_DIR=Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:sys.path.insert(0,str(SERVER_DIR))
from services.threat_scorer import _threat_level,score_threats

def row(**o):
 r={"timestamp":pd.Timestamp("2026-08-04 10:00:00"),"src_ip":"10.0.0.1","dst_ip":"192.168.0.2","event_type":"connection","protocol":"HTTPS","dst_port":443,"bytes_transferred":1000.0,"is_anomaly":False,"ml_is_anomaly":False,"anomaly_reasons":[]};r.update(o);return r

def score_one(**o):return score_threats(pd.DataFrame([row(**o)])).iloc[0]

def test_clean():
 r=score_one();assert r["threat_score"]==0 and r["threat_level"]=="None" and r["threat_signals"]==[]

@pytest.mark.parametrize("reason,points,label",[("AMOUNT_SPIKE",25,"Unusual data volume"),("RAPID_SUCCESSION",30,"High-frequency event pattern"),("OFF_HOURS",10,"Off-hours activity"),("ROUND_BYTES",15,"Structured data transfer"),("NEW_SOURCE",20,"Unknown source"),("PORT_SCAN",25,"Port scanning detected"),("CROSS_BORDER",20,"Cross-border network activity"),("BRUTE_FORCE",30,"Brute force authentication attempt")])
def test_each_reason(reason,points,label):
 r=score_one(is_anomaly=True,ml_is_anomaly=False,anomaly_reasons=[reason]);assert r["threat_score"]==points and r["threat_signals"]==[label] and "Statistical outlier (ML)" not in r["threat_signals"]

def test_ml_provenance_positive_and_rule_only_negative():
 r=score_threats(pd.DataFrame([row(is_anomaly=True,ml_is_anomaly=True,anomaly_reasons=["OFF_HOURS"]),row(is_anomaly=True,ml_is_anomaly=False,anomaly_reasons=["OFF_HOURS"])]));assert r.loc[0,"threat_score"]==25 and r.loc[0,"threat_signals"]==["Off-hours activity","Statistical outlier (ML)"];assert r.loc[1,"threat_score"]==10 and r.loc[1,"threat_signals"]==["Off-hours activity"] and "Statistical outlier (ML)" not in r.loc[1,"threat_signals"]

def test_clamped():
 r=score_one(is_anomaly=True,ml_is_anomaly=True,anomaly_reasons=["AMOUNT_SPIKE","RAPID_SUCCESSION","OFF_HOURS","ROUND_BYTES","NEW_SOURCE","PORT_SCAN","CROSS_BORDER","BRUTE_FORCE"],event_type="darknet proxy",bytes_transferred=50_000_001,protocol="HTTP",dst_port=443);assert r["threat_score"]==100 and r["threat_level"]=="Critical"

@pytest.mark.parametrize("score,level",[(0,"None"),(1,"Low"),(24,"Low"),(25,"Medium"),(50,"High"),(75,"Critical")])
def test_boundaries(score,level):assert _threat_level(score)==level

def test_signals_only_fired():
 r=score_one(is_anomaly=True,ml_is_anomaly=False,anomaly_reasons=["NEW_SOURCE"]);assert r["threat_signals"]==["Unknown source"]

def test_input_not_mutated():
 d=pd.DataFrame([row()]);o=d.copy(deep=True);score_threats(d);pd.testing.assert_frame_equal(d,o)

def test_protocol_anomaly():
 r=score_threats(pd.DataFrame([row(protocol="HTTP",dst_port=443),row(protocol="HTTPS",dst_port=443)]));assert r.loc[0,"threat_score"]==20 and r.loc[0,"threat_signals"]==["Protocol anomaly"] and r.loc[1,"threat_score"]==0

def test_large_transfer_boundary():
 r=score_threats(pd.DataFrame([row(bytes_transferred=50_000_001),row(bytes_transferred=50_000_000)]));assert r.loc[0,"threat_score"]==25 and r.loc[1,"threat_score"]==0

def test_high_risk_category_once():
 r=score_one(event_type="TOR darknet proxy activity");assert r["threat_score"]==20 and r["threat_signals"]==["High-risk service category"]

def test_duplicate_reason_not_double_counted():
 r=score_one(is_anomaly=True,anomaly_reasons=["OFF_HOURS","OFF_HOURS"]);assert r["threat_score"]==10