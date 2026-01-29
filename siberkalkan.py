import time
import joblib
import pandas as pd
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
import os
import warnings


os.environ["PYTHONWARNINGS"] = "ignore"


warnings.filterwarnings("ignore")
warnings.simplefilter("ignore")
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", module="sklearn")
warnings.filterwarnings("ignore", module="joblib")

MODEL = "profesyonel_model.pkl"
SCALER = "profesyonel_scaler.pkl"
ESIK = 0.95
NORMAL_BAS = False

COOLDOWN_SN = 5.0
son_alarm = {}

WH_UDP_PORTS = {53, 5353, 1900, 3702, 443, 80}

model = joblib.load(MODEL)
scaler = joblib.load(SCALER)

try:
    with open("ioc_ips.txt", "r", encoding="utf-8") as f:
        IOC_IPS = set(line.strip() for line in f if line.strip())
except FileNotFoundError:
    IOC_IPS = set()

print("CANLI IDS BASLADI (CTRL+C ile durdur)")
print(f"Esik={ESIK}  NORMAL_BAS={NORMAL_BAS}  COOLDOWN={COOLDOWN_SN}s")
print("-" * 50)

def xai(feats, proba, ioc_hit):
    length, proto, sport, dport, flags = feats
    reasons = []
    if ioc_hit:
        reasons.append("IOC(eslesme)")
    if length < 80:
        reasons.append("kucuk_paket")
    if dport in [22, 23, 3389, 445]:
        reasons.append("hassas_port")
    if proto == 1 and flags in [2, 18]:
        reasons.append("syn/synack")
    if proba >= ESIK:
        reasons.append("yuksek_olasilik")
    return ", ".join(reasons) if reasons else "anormal_trafik"

def multicast_mi(ip):
    try:
        first = int(ip.split(".")[0])
        return 224 <= first <= 239
    except:
        return False

def feature_cikar(pkt):
    if not pkt.haslayer(IP):
        return None

    src = pkt[IP].src
    dst = pkt[IP].dst

    if multicast_mi(dst) or dst == "255.255.255.255":
        return None

    length = len(pkt)

    if pkt.haslayer(TCP):
        proto = 1
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
        flags = int(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        proto = 2
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
        flags = 0
        if sport in WH_UDP_PORTS or dport in WH_UDP_PORTS:
            return None
    else:
        return None

    return [length, proto, sport, dport, flags], src, dst

def cooldown_gec(src, dst, proto, dport):
    key = (src, dst, proto, dport)
    now = time.time()
    if key in son_alarm and (now - son_alarm[key]) < COOLDOWN_SN:
        return False
    son_alarm[key] = now
    return True

def handle(pkt):
    out = feature_cikar(pkt)
    if out is None:
        return

    feats, src, dst = out
    t = datetime.now().strftime("%H:%M:%S")

    ioc_hit = (src in IOC_IPS) or (dst in IOC_IPS)

    X = pd.DataFrame([feats], columns=["length", "protocol", "src_port", "dst_port", "flags"])
    Xs = scaler.transform(X)

    proba = float(model.predict_proba(Xs)[0][1])
    pred = 1 if (proba >= ESIK or ioc_hit) else 0

    if pred == 1:
        proto = feats[1]
        dport = feats[3]
        if not cooldown_gec(src, dst, proto, dport):
            return
        print(f"[{t}] 🚨 ALARM p={proba:.2f} {src} -> {dst} feats={feats}")
        print(f"    XAI: {xai(feats, proba, ioc_hit)}")
        print("-" * 50)
    elif NORMAL_BAS:
        print(f"[{t}] ✅ normal p={proba:.2f} {src} -> {dst}")

try:
    sniff(prn=handle, store=0, filter="ip and tcp")

except KeyboardInterrupt:
    print("DURDURULDU")
