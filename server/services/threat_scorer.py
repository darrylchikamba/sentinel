"""Explainable threat scoring for SENTINEL anomaly output."""
from __future__ import annotations
import pandas as pd
REASON_RULES={
"AMOUNT_SPIKE":(25,"Unusual data volume"),"RAPID_SUCCESSION":(30,"High-frequency event pattern"),"OFF_HOURS":(10,"Off-hours activity"),"ROUND_BYTES":(15,"Structured data transfer"),"NEW_SOURCE":(20,"Unknown source"),"PORT_SCAN":(25,"Port scanning detected"),"CROSS_BORDER":(20,"Cross-border network activity"),"BRUTE_FORCE":(30,"Brute force authentication attempt")}
EXPECTED_PROTOCOLS={80:{"HTTP"},443:{"HTTPS","TLS","SSL"},22:{"SSH"},25:{"SMTP"},53:{"DNS"}}
HIGH_RISK_SERVICE_TERMS=("crypto","tor","proxy","casino","darknet")

def _threat_level(score:int)->str:
    if score==0:return "None"
    if score<=24:return "Low"
    if score<=49:return "Medium"
    if score<=74:return "High"
    return "Critical"

def _normalise_reasons(value:object)->tuple[str,...]:
    if value is None:return ()
    if isinstance(value,float) and pd.isna(value):return ()
    if isinstance(value,(list,tuple,set)):return tuple(str(x) for x in value)
    raise ValueError("anomaly_reasons must contain a list-like value per row")

def _protocol_anomaly(row:pd.Series)->bool:
    if "protocol" not in row.index:return False
    try: port=int(row.get("dst_port",0))
    except (TypeError,ValueError):return False
    if port not in EXPECTED_PROTOCOLS:return False
    value=row.get("protocol")
    if value is None or pd.isna(value):return False
    protocol=str(value).strip().upper()
    return bool(protocol) and protocol not in EXPECTED_PROTOCOLS[port]

def score_threats(df:pd.DataFrame)->pd.DataFrame:
    if not isinstance(df,pd.DataFrame):raise TypeError("df must be a pandas DataFrame")
    required=("is_anomaly","ml_is_anomaly","anomaly_reasons")
    missing=[c for c in required if c not in df.columns]
    if missing:raise ValueError(f"Missing required columns: {', '.join(missing)}")
    result=df.copy(deep=True); scores=[]; levels=[]; signal_rows=[]
    for _,row in result.iterrows():
        score=0; signals=[]; reasons=set(_normalise_reasons(row["anomaly_reasons"]))
        for reason,(points,label) in REASON_RULES.items():
            if reason in reasons:score+=points;signals.append(label)
        if _protocol_anomaly(row):score+=20;signals.append("Protocol anomaly")
        if bool(row["ml_is_anomaly"]):score+=15;signals.append("Statistical outlier (ML)")
        event_type=str(row.get("event_type","")).lower()
        if any(t in event_type for t in HIGH_RISK_SERVICE_TERMS):score+=20;signals.append("High-risk service category")
        try: transferred=float(row.get("bytes_transferred",0.0))
        except (TypeError,ValueError):transferred=0.0
        if transferred>50_000_000:score+=25;signals.append("Large data transfer (exfiltration risk)")
        final=min(max(int(score),0),100);scores.append(final);levels.append(_threat_level(final));signal_rows.append(signals)
    result["threat_score"]=scores;result["threat_level"]=levels;result["threat_signals"]=signal_rows
    return result