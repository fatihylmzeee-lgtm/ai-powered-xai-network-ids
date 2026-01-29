import csv
import os
from scapy.all import sniff, IP, TCP, UDP

dosya_adi = "trafik_verisi.csv"

if not os.path.isfile(dosya_adi):
    with open(dosya_adi, "w", newline="") as dosya:
        yazici = csv.writer(dosya)
        yazici.writerow(["length", "protocol", "src_port", "dst_port", "flags", "label"])

print(f"[*] Veri Ajanı Başlatıldı. Hedef Dosya: {dosya_adi}")
print("1 -> NORMAL ...")
print("2 -> SALDIRI ...")
secim = input("Seçimin (1 veya 2):  ")

if secim == '1':
    etiket = 0
    print("MOD: TEMİZ Trafik kaydediliyor...")

elif secim == '2':
    etiket = 1
    print("MOD: SALDIRI Trafiği kaydediliyor...")

else:
    print("Hatali seçim! Programi kapatip tekrar aç")
    exit()

dosya = open(dosya_adi, "a", newline="")
yazici = csv.writer(dosya)

def paket_isleyici(paket):
    if not paket.haslayer(IP):
        return

    uzunluk = len(paket)

    protokol = 0
    src_port = 0
    dst_port = 0
    flags = 0

    if paket.haslayer(TCP):
        protokol = 1
        src_port = paket[TCP].sport
        dst_port = paket[TCP].dport
        flags = int(paket[TCP].flags)

    elif paket.haslayer(UDP):
        protokol = 2
        src_port = paket[UDP].sport
        dst_port = paket[UDP].dport
        flags = 0

    else:
        return

    yazici.writerow([
        uzunluk,
        protokol,
        src_port,
        dst_port,
        flags,
        etiket
    ])

    print(".", end="", flush=True)

try:
    sniff(prn=paket_isleyici, store=0)
except KeyboardInterrupt:
    print("\n\n[*] Kayit tamamlandi. Dosya kapatiliyor.")
    dosya.close()
