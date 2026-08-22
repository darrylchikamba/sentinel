from pathlib import Path
import sys
import pandas as pd
SERVER_DIR=Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:sys.path.insert(0,str(SERVER_DIR))
from services.anomaly import detect_anomalies

def base_row(**o):
 r={"timestamp":pd.Timestamp("2026-08-04 10:00:00"),"src_ip":"10.0.0.1","dst_ip":"192.168.0.2","event_type":"connection","severity":"low","user_account":"analyst","device_id":"endpoint-1","protocol":"HTTPS","dst_port":443,"bytes_transferred":1234.0};r.update(o);return r

def test_isolation_and_columns():
 d=pd.DataFrame([base_row(timestamp=pd.Timestamp("2026-08-04 10:00:00")+pd.Timedelta(minutes=i),bytes_transferred=1000+i) for i in range(6)])
 r=detect_anomalies(d);assert {"ml_is_anomaly","is_anomaly","anomaly_reasons"}<=set(r.columns)

def test_input_not_mutated():
 d=pd.DataFrame([base_row()]);o=d.copy(deep=True);detect_anomalies(d);pd.testing.assert_frame_equal(d,o)

def test_off_hours():
 r=detect_anomalies(pd.DataFrame([base_row(src_ip="10.0.0.1",timestamp=pd.Timestamp("2026-08-04 02:00:00")),base_row(src_ip="10.0.0.2",timestamp=pd.Timestamp("2026-08-04 10:00:00"))]));assert "OFF_HOURS" in r.loc[0,"anomaly_reasons"] and "OFF_HOURS" not in r.loc[1,"anomaly_reasons"]

def test_port_scan():
 d=pd.DataFrame([base_row(src_ip="10.0.0.5",dst_port=1000+i,timestamp=pd.Timestamp("2026-08-04 10:00:00")+pd.Timedelta(minutes=i)) for i in range(10)]);r=detect_anomalies(d);assert all("PORT_SCAN" in x for x in r["anomaly_reasons"])

def test_rapid_succession():
 r=detect_anomalies(pd.DataFrame([base_row(timestamp=pd.Timestamp("2026-08-04 10:00:00")),base_row(timestamp=pd.Timestamp("2026-08-04 10:00:20")),base_row(timestamp=pd.Timestamp("2026-08-04 10:00:40"))]));assert all("RAPID_SUCCESSION" in x for x in r["anomaly_reasons"])

def test_brute_force():
 d=pd.DataFrame([base_row(event_type="login failed",timestamp=pd.Timestamp("2026-08-04 10:00:00")+pd.Timedelta(minutes=i)) for i in range(5)]);r=detect_anomalies(d);assert all("BRUTE_FORCE" in x for x in r["anomaly_reasons"])

def test_cross_border_private_malformed():
 r=detect_anomalies(pd.DataFrame([base_row(src_ip="10.0.0.1",dst_ip="8.8.8.8"),base_row(src_ip="10.0.0.2",dst_ip="192.168.1.1"),base_row(src_ip="10.0.0.3",dst_ip="bad-ip")]));assert "CROSS_BORDER" in r.loc[0,"anomaly_reasons"] and "CROSS_BORDER" not in r.loc[1,"anomaly_reasons"] and "CROSS_BORDER" not in r.loc[2,"anomaly_reasons"]

def test_new_source():
 r=detect_anomalies(pd.DataFrame([base_row(src_ip="10.0.0.1"),base_row(src_ip="10.0.0.2"),base_row(src_ip="10.0.0.2",timestamp=pd.Timestamp("2026-08-04 11:00:00"))]));assert "NEW_SOURCE" in r.loc[0,"anomaly_reasons"] and "NEW_SOURCE" not in r.loc[1,"anomaly_reasons"]

def test_round_bytes():
 r=detect_anomalies(pd.DataFrame([base_row(src_ip="10.0.0.1",bytes_transferred=5000),base_row(src_ip="10.0.0.2",bytes_transferred=5001)]));assert "ROUND_BYTES" in r.loc[0,"anomaly_reasons"] and "ROUND_BYTES" not in r.loc[1,"anomaly_reasons"]

def test_amount_spike_four_events():
 r=detect_anomalies(pd.DataFrame([base_row(bytes_transferred=1),base_row(bytes_transferred=1,timestamp=pd.Timestamp("2026-08-04 11:00:00")),base_row(bytes_transferred=1,timestamp=pd.Timestamp("2026-08-04 12:00:00")),base_row(bytes_transferred=100,timestamp=pd.Timestamp("2026-08-04 13:00:00"))]));assert "AMOUNT_SPIKE" in r.loc[3,"anomaly_reasons"]

def test_rule_forces_is_anomaly():
 r=detect_anomalies(pd.DataFrame([base_row(timestamp=pd.Timestamp("2026-08-04 02:00:00"))]));assert bool(r.loc[0,"is_anomaly"]) is True

def test_reason_lists_independent():
 r=detect_anomalies(pd.DataFrame([base_row(src_ip="10.0.0.1",bytes_transferred=5000),base_row(src_ip="10.0.0.2",bytes_transferred=5001)]));r.at[0,"anomaly_reasons"].append("TEST_ONLY");assert "TEST_ONLY" not in r.at[1,"anomaly_reasons"]