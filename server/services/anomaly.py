"""Anomaly detection for normalised SENTINEL cybersecurity logs."""
from __future__ import annotations
from collections import deque
from ipaddress import ip_address
from typing import Iterable
import pandas as pd
from sklearn.ensemble import IsolationForest

REQUIRED_COLUMNS=("timestamp","src_ip","dst_ip","event_type","dst_port","bytes_transferred")
SA_PUBLIC_PREFIXES=("196.","197.","105.","41.")
FAILED_EVENT_TERMS=("fail","denied","invalid")

def _validate_input(df: pd.DataFrame)->None:
    if not isinstance(df,pd.DataFrame): raise TypeError("df must be a pandas DataFrame")
    missing=[c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing: raise ValueError(f"Missing required columns: {', '.join(missing)}")
    if df.empty: raise ValueError("Anomaly detection requires at least one log event")

def _mark(indices: Iterable[int], reasons:list[list[str]], label:str)->None:
    for i in indices:
        if label not in reasons[i]: reasons[i].append(label)

def _window_members(frame:pd.DataFrame,*,minimum_events:int,window_seconds:int,eligible_mask:pd.Series|None=None)->set[int]:
    qualifying:set[int]=set()
    working=frame[["src_ip","timestamp"]].copy(); working["_position"]=range(len(frame))
    if eligible_mask is not None: working=working.loc[eligible_mask.to_numpy()].copy()
    for _,group in working.groupby("src_ip",sort=False):
        ordered=group.sort_values("timestamp",kind="stable")
        queue:deque[tuple[pd.Timestamp,int]]=deque()
        for timestamp,position in ordered[["timestamp","_position"]].itertuples(index=False,name=None):
            while queue and (timestamp-queue[0][0]).total_seconds()>window_seconds: queue.popleft()
            queue.append((timestamp,position))
            if len(queue)>=minimum_events: qualifying.update(item[1] for item in queue)
    return qualifying

def _is_cross_border(destination:object)->bool:
    try: parsed=ip_address(str(destination).strip())
    except ValueError: return False
    if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_reserved or parsed.is_unspecified: return False
    return not str(parsed).startswith(SA_PUBLIC_PREFIXES)

def detect_anomalies(df:pd.DataFrame)->pd.DataFrame:
    _validate_input(df); result=df.copy(deep=True)
    result["timestamp"]=pd.to_datetime(result["timestamp"],errors="raise")
    result["bytes_transferred"]=pd.to_numeric(result["bytes_transferred"],errors="coerce").fillna(0.0).astype(float)
    result["dst_port"]=pd.to_numeric(result["dst_port"],errors="coerce").fillna(0).astype(int)
    features=pd.DataFrame(index=result.index)
    features["bytes_transferred"]=result["bytes_transferred"]
    features["dst_port"]=result["dst_port"]
    features["hour_of_day"]=result["timestamp"].dt.hour
    features["day_of_week"]=result["timestamp"].dt.dayofweek
    clock_hour=result["timestamp"].dt.floor("h")
    features["events_per_src_ip_per_hour"]=(pd.DataFrame({"src_ip":result["src_ip"],"clock_hour":clock_hour}).groupby(["src_ip","clock_hour"])["src_ip"].transform("size").astype(float))
    features["unique_dst_ports_per_src_ip"]=result.groupby("src_ip")["dst_port"].transform("nunique").astype(float)
    model=IsolationForest(contamination=0.05,random_state=42)
    result["ml_is_anomaly"]=model.fit_predict(features)==-1
    reasons=[[] for _ in range(len(result))]
    source_counts=result.groupby("src_ip")["src_ip"].transform("size")
    source_means=result.groupby("src_ip")["bytes_transferred"].transform("mean")
    mask=(source_counts>=3)&(result["bytes_transferred"]>3*source_means)
    _mark([i for i,f in enumerate(mask) if f],reasons,"AMOUNT_SPIKE")
    _mark(_window_members(result,minimum_events=3,window_seconds=60),reasons,"RAPID_SUCCESSION")
    mask=result["timestamp"].dt.hour.isin([0,1,2,3,4]); _mark([i for i,f in enumerate(mask) if f],reasons,"OFF_HOURS")
    mask=(result["bytes_transferred"]>0)&(result["bytes_transferred"]%1000==0); _mark([i for i,f in enumerate(mask) if f],reasons,"ROUND_BYTES")
    mask=source_counts==1; _mark([i for i,f in enumerate(mask) if f],reasons,"NEW_SOURCE")
    scan_sources=set(result.groupby("src_ip")["dst_port"].nunique().loc[lambda s:s>=10].index)
    mask=result["src_ip"].isin(scan_sources); _mark([i for i,f in enumerate(mask) if f],reasons,"PORT_SCAN")
    mask=result["dst_ip"].map(_is_cross_border); _mark([i for i,f in enumerate(mask) if f],reasons,"CROSS_BORDER")
    failed_mask=result["event_type"].astype(str).str.lower().map(lambda v:any(t in v for t in FAILED_EVENT_TERMS))
    _mark(_window_members(result,minimum_events=5,window_seconds=600,eligible_mask=failed_mask),reasons,"BRUTE_FORCE")
    result["anomaly_reasons"]=reasons
    rule_is_anomaly=pd.Series([bool(x) for x in reasons],index=result.index,dtype=bool)
    result["is_anomaly"]=result["ml_is_anomaly"]|rule_is_anomaly
    return result