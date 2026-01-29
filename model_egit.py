import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

print("veri seti yukleniyor...")

df = pd.read_csv("trafik_verisi.csv")
df = df.apply(pd.to_numeric, errors="coerce").dropna().astype(int)

X = df.drop("label", axis=1)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

scaler = StandardScaler()

X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

print("Yapay zeka ogreniyor!")

model = RandomForestClassifier(
    n_estimators=200,
    n_jobs=-1,
    random_state=42,
    class_weight="balanced"
)

model.fit(X_train, y_train)

pred = model.predict(X_test)

basari = accuracy_score(y_test, pred)

print(f"🎉 BASARI ORANI: %{basari*100:.2f}")

print("\nConfusion Matrix:\n", confusion_matrix(y_test, pred))
print("\nDetayli Rapor:\n", classification_report(y_test, pred))

joblib.dump(model, "profesyonel_model.pkl")
joblib.dump(scaler, "profesyonel_scaler.pkl")

print("[+] Dosyalar hazir: profesyonel_model.pkl ve profesyonel_scaler.pkl")
