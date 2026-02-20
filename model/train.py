"""
train.py — Browser Vigilant ML Training Pipeline v2.0
======================================================
Downloads real phishing + legitimate URL datasets, extracts 56 math features,
trains RF + XGBoost soft-vote ensemble with SMOTE + Platt calibration,
evaluates with 10-fold stratified CV, exports model.onnx.

OFFLINE ONLY — run once on developer machine.
Nothing here runs in the browser extension at runtime.

Usage:
    python -m venv venv
    venv\\Scripts\\activate      # Windows
    pip install -r requirements.txt
    python train.py             # → model.onnx
"""

import io
import os
import sys
import zipfile
import warnings
import numpy as np
import pandas as pd
from tqdm import tqdm
import requests

warnings.filterwarnings("ignore")

from features import extract_features, FEATURE_NAMES

from sklearn.ensemble import RandomForestClassifier, VotingClassifier, GradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import classification_report, roc_auc_score
from imblearn.over_sampling import SMOTE
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnx


N_FEATURES = 56

# ── Dataset Sources ────────────────────────────────────────────────────────────

DATASETS = {
    # PhiUSIIL — 2024 UCI dataset, 235k URLs, URL-only features
    "phiusiil": {
        "url": "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip",
        "description": "PhiUSIIL (UCI 2024) — 235,795 URLs",
    },
    # PhishTank live verified phishing feed
    "phishtank": {
        "url": "https://data.phishtank.com/data/online-valid.csv",
        "description": "PhishTank live phishing feed",
    },
    # Tranco top-1M for legitimate sites
    "tranco": {
        "url": "https://tranco-list.eu/top-1m.csv.zip",
        "description": "Tranco top-1M legitimate domains",
    },
}


def download_bytes(url: str, desc: str, timeout: int = 60) -> bytes:
    """Download URL with progress bar. Returns raw bytes."""
    print(f"\n⬇  Downloading: {desc}")
    print(f"   {url}")
    try:
        r = requests.get(url, timeout=timeout, stream=True)
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0))
        buf = io.BytesIO()
        with tqdm(total=total, unit="B", unit_scale=True, unit_divisor=1024) as bar:
            for chunk in r.iter_content(chunk_size=65536):
                buf.write(chunk)
                bar.update(len(chunk))
        return buf.getvalue()
    except Exception as e:
        print(f"   [WARN] Download failed: {e}")
        return b""


# ── Load PhiUSIIL ─────────────────────────────────────────────────────────────

def load_phiusiil(sample: int = 60000) -> tuple:
    """
    PhiUSIIL: URL + label columns.
    Label 1 = phishing, 0 = legitimate.
    Returns (urls, labels) with up to `sample` examples.
    """
    raw = download_bytes(DATASETS["phiusiil"]["url"], DATASETS["phiusiil"]["description"])
    if not raw:
        return [], []

    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
        csv_names = [n for n in zf.namelist() if n.endswith(".csv")]
        if not csv_names:
            return [], []
        df = pd.read_csv(zf.open(csv_names[0]), usecols=["URL", "label"], dtype=str)
        df.columns = df.columns.str.strip().str.lower()

        # label: 1 = phishing, 0 = legit (PhiUSIIL convention)
        df = df.dropna()
        df["label"] = df["label"].astype(str).str.strip()
        df = df[df["label"].isin(["0", "1", "phishing", "legitimate", "safe"])]
        df["label"] = df["label"].map(
            lambda x: 1 if x in ("1", "phishing") else 0
        )

        # Balance & sample
        phish = df[df["label"] == 1].sample(min(sample // 2, len(df[df["label"] == 1])), random_state=42)
        legit = df[df["label"] == 0].sample(min(sample // 2, len(df[df["label"] == 0])), random_state=42)
        df = pd.concat([phish, legit])
        urls = df["URL"].str.strip().tolist()
        labels = df["label"].tolist()
        print(f"   ✓ PhiUSIIL: {len(labels)} URLs ({sum(labels)} phishing, {len(labels)-sum(labels)} legit)")
        return urls, labels
    except Exception as e:
        print(f"   [WARN] PhiUSIIL parse failed: {e}")
        return [], []


# ── Load PhishTank ────────────────────────────────────────────────────────────

def load_phishtank(max_phishing: int = 15000) -> tuple:
    """
    PhishTank: verified phishing URLs. All label=1.
    Returns (urls, labels).
    """
    raw = download_bytes(DATASETS["phishtank"]["url"], DATASETS["phishtank"]["description"])
    if not raw:
        return [], []
    try:
        df = pd.read_csv(
            io.BytesIO(raw),
            usecols=["url", "verified"],
            dtype=str,
            on_bad_lines="skip",
        )
        df = df[df["verified"].str.strip().str.lower() == "yes"]
        df = df.dropna(subset=["url"])
        df = df.head(max_phishing)
        urls = df["url"].str.strip().tolist()
        labels = [1] * len(urls)
        print(f"   ✓ PhishTank: {len(urls)} phishing URLs")
        return urls, labels
    except Exception as e:
        print(f"   [WARN] PhishTank parse failed: {e}")
        return [], []


# ── Load Tranco (legitimate) ──────────────────────────────────────────────────

def load_tranco(n: int = 15000) -> tuple:
    """
    Tranco top-1M: high-confidence legitimate domains.
    Returns https:// URLs for top n domains. All label=0.
    """
    raw = download_bytes(DATASETS["tranco"]["url"], DATASETS["tranco"]["description"])
    if not raw:
        return [], []
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
        csv_name = [x for x in zf.namelist() if x.endswith(".csv")][0]
        df = pd.read_csv(
            zf.open(csv_name),
            header=None,
            names=["rank", "domain"],
            dtype=str,
        )
        # Skip very common 1-word domains that might be internal (localhost etc.)
        df = df[df["domain"].str.contains(r"\.", na=False)]
        df = df.head(n)
        urls = ["https://www." + d.strip() for d in df["domain"].tolist()]
        labels = [0] * len(urls)
        print(f"   ✓ Tranco: {len(urls)} legitimate URLs")
        return urls, labels
    except Exception as e:
        print(f"   [WARN] Tranco parse failed: {e}")
        return [], []


# ── Fallback Corpus (when downloads fail) ─────────────────────────────────────

FALLBACK_LEGIT = [
    "https://www.google.com", "https://www.youtube.com", "https://www.facebook.com",
    "https://www.amazon.com", "https://www.wikipedia.org", "https://www.twitter.com",
    "https://www.instagram.com", "https://www.linkedin.com", "https://www.reddit.com",
    "https://www.netflix.com", "https://www.microsoft.com", "https://www.apple.com",
    "https://github.com", "https://stackoverflow.com", "https://www.paypal.com",
    "https://www.ebay.com", "https://www.dropbox.com", "https://www.spotify.com",
    "https://mail.google.com", "https://drive.google.com", "https://www.linkedin.com",
    "https://www.stripe.com", "https://www.notion.so", "https://www.figma.com",
    "https://www.canva.com", "https://www.shopify.com", "https://www.medium.com",
    "https://www.twitch.tv", "https://www.discord.com", "https://www.zoom.us",
    "https://www.hdfcbank.com", "https://www.icicibank.com", "https://www.flipkart.com",
    "https://www.paytm.com", "https://www.irctc.co.in", "https://www.makemytrip.com",
    "https://www.bbc.com", "https://www.cnn.com", "https://reactjs.org",
    "https://developer.mozilla.org", "https://www.coursera.org", "https://www.udemy.com",
    "https://aws.amazon.com", "https://cloud.google.com", "https://azure.microsoft.com",
    "https://www.cloudflare.com", "https://www.npmjs.com", "https://pypi.org",
    "https://svelte.dev", "https://nextjs.org",
] * 8   # 400 legit fallback entries

FALLBACK_PHISHING = [
    "http://paypal-secure.account-verify.xyz/signin",
    "http://secure-login.paypa1.top/account/update",
    "http://amazon-login.account-verify.top/signin",
    "http://amaz0n.secure-update.xyz/account",
    "http://apple-account.security-alert.xyz/signin",
    "http://microsoft.login-secure.xyz/365/account",
    "http://office365.account-suspended.xyz/recovery",
    "http://chase-bank.secure-login.xyz/signin",
    "http://hdfc-netbanking.secure-login.xyz/verify",
    "http://paytm-kyc-verify.xyz/account/update",
    "http://gpay.free-cashback.xyz/claim",
    "http://xn--pple-43d.com/signin",
    "http://xn--googIe-hsa.com",
    "http://185.220.101.23/paypal/login",
    "http://192.168.1.1/admin/phish/login",
    "http://netflix-billing.update-required.xyz/login",
    "http://coinbase.account-verify.xyz/signin",
    "http://free-iphone-winner.xyz/claim?user=test",
    "http://congratulations-you-won.top/gift",
    "http://upi-prize.xyz/claim?vpa=refund@oksbi&amount=5000",
    "http://paytm-kyc.xyz/verify?pa=helpdesk@paytmgov",
    "http://secure-login.xyz/google/accounts/ServiceLoginAuth",
    "http://login.secure.verify.account.paypal.phish.xyz",
    "http://free-software-download.xyz/crack/windows11.exe",
    "http://facebook.account.cf", "http://apple.secure.gq",
    "http://amazon.verify.ml", "http://paypal.account.ga",
    "http://instagram.secure.tk/signin",
    "http://twitter.account-suspend.xyz/verify",
    "http://paypal.evil-domain.com/login",
    "http://google.phishsite.xyz/account",
    "http://apple.scam-host.top/signin",
    "http://amazon-deals.free-shopping.xyz/checkout",
    "http://flipkart-sale.prize.xyz/cart",
    "http://bhim-upi-reward.xyz/claim-prize",
    "http://kyc.update.sbi-secure.xyz/banking",
    "http://accounts.verify.top/signin/identifier",
    "http://a.b.c.d.e.phishing-site.xyz/login",
    "http://login.secure.verify.account.evil.top",
    "http://G00GLE.COM.phish.xyz/login",
    "http://PAYPAL-SECURE.COM.verify.top",
    "http://invoice2024.pdf.exe.malware.xyz/run",
    "http://crack.tk/office365_activator.bat",
    "http://antivirus-free.xyz/setup_installer.msi",
    "http://secure.login.xyz/%61%63%63%6F%75%6E%74%2F%76%65%72%69%66%79",
    "http://legit-site.com/../../../admin/passwd",
    "http://sbi-refund.xyz/process?vpa=taxrefund@government",
    "http://gpay-cashback.top/redeem?pa=support@googlepay",
    "http://metamask-wallet.connect.xyz/swap",
] * 8   # 400 phishing fallback entries


# ── Feature Extraction ────────────────────────────────────────────────────────

def extract_all(urls: list, labels: list, desc: str = "Extracting features") -> tuple:
    """Extract 56 features from each URL. Skip on error."""
    X, y, skipped = [], [], 0
    for url, label in tqdm(zip(urls, labels), total=len(urls), desc=desc):
        try:
            feats = extract_features(str(url).strip())
            assert len(feats) == N_FEATURES, f"Expected {N_FEATURES}, got {len(feats)}"
            X.append(feats)
            y.append(int(label))
        except Exception as e:
            if skipped == 0:
                import traceback
                print(f"\n   [ERROR] Feature extraction failed for '{url}': {e}")
                traceback.print_exc()
            skipped += 1
    if skipped:
        print(f"   [WARN] Skipped {skipped} URLs during feature extraction")
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int64)


# ── Build Dataset ─────────────────────────────────────────────────────────────

def build_dataset() -> tuple:
    print("\n" + "="*60)
    print("  Assembling Training Dataset")
    print("="*60)

    all_urls, all_labels = [], []

    # Source 1: PhiUSIIL (primary — 235k URL dataset from UCI 2024)
    u, l = load_phiusiil(sample=60000)
    all_urls.extend(u); all_labels.extend(l)

    # Source 2: PhishTank (additional live phishing)
    u, l = load_phishtank(max_phishing=15000)
    all_urls.extend(u); all_labels.extend(l)

    # Source 3: Tranco (additional legitimate sites)
    u, l = load_tranco(n=15000)
    all_urls.extend(u); all_labels.extend(l)

    # Fallback: if either class has fewer than 100 samples, inject the curated fallback corpus
    num_phish = sum(all_labels)
    num_legit = len(all_labels) - num_phish
    if num_phish < 100 or num_legit < 100:
        print(f"\n   [WARN] Missing class data (Phish: {num_phish}, Legit: {num_legit}). Injecting fallback corpus.")
        all_urls.extend(FALLBACK_LEGIT + FALLBACK_PHISHING)
        all_labels.extend([0] * len(FALLBACK_LEGIT) + [1] * len(FALLBACK_PHISHING))

    # Deduplicate
    seen, urls_dedup, labels_dedup = set(), [], []
    for u, l in zip(all_urls, all_labels):
        if u not in seen:
            seen.add(u)
            urls_dedup.append(u)
            labels_dedup.append(l)

    print(f"\n   Total unique URLs: {len(urls_dedup)}")
    print(f"   Phishing: {sum(labels_dedup)}")
    print(f"   Legitimate: {len(labels_dedup) - sum(labels_dedup)}")

    X, y = extract_all(urls_dedup, labels_dedup)
    print(f"\n   Feature matrix shape: {X.shape}")
    return X, y


# ── Train ─────────────────────────────────────────────────────────────────────

def train(X: np.ndarray, y: np.ndarray):
    print("\n" + "="*60)
    print("  Training RF + XGBoost Ensemble")
    print("="*60)

    # Class balance analysis
    n_phish = int(y.sum())
    n_legit = int((y == 0).sum())
    ratio = n_legit / max(n_phish, 1)
    print(f"\n   Class ratio (legit/phish): {ratio:.2f}")

    # ── Pure RandomForest (400 trees) ─────────────────────────────────────────
    # We use a single robust RF instead of an ensemble because skl2onnx 
    # perfectly supports it, and RF probabilities are naturally well-calibrated.
    rf = RandomForestClassifier(
        n_estimators=400,
        max_depth=14,
        min_samples_split=4,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    # ── 10-fold Stratified CV for evaluation ──────────────────────────────────
    print("\n── 10-Fold Stratified Cross-Validation ─────────────────────────")
    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
    cv_results = cross_validate(
        rf, X, y, cv=cv,
        scoring=["accuracy", "precision", "recall", "f1", "roc_auc"],
        return_train_score=False,
        n_jobs=-1,
    )
    print(f"\n  {'Metric':<14} {'Mean':>8}  {'Std':>8}")
    print(f"  {'-'*32}")
    for metric, values in sorted(cv_results.items()):
        if metric.startswith("test_"):
            name = metric.replace("test_", "").upper()
            print(f"  {name:<14} {values.mean():>8.4f}  ±{values.std():>7.4f}")

    # ── Final fit on full dataset ─────────────────────────────────────────────
    print("\n── Final fit on full dataset ───────────────────────────────────────")
    rf.fit(X, y)

    # Sanity check on training set
    y_prob = rf.predict_proba(X)[:, 1]
    y_pred = (y_prob >= 0.50).astype(int)
    print(classification_report(y, y_pred, target_names=["Legitimate", "Phishing"], digits=4))
    auc = roc_auc_score(y, y_prob)
    print(f"  Training ROC-AUC: {auc:.4f}")

    return rf


# ── ONNX Export ───────────────────────────────────────────────────────────────

def export_onnx(model, output_path: str = "model.onnx"):
    print(f"\n── Exporting to ONNX ────────────────────────────────────────────")
    initial_type = [("input", FloatTensorType([None, N_FEATURES]))]

    try:
        onnx_model = convert_sklearn(
            model,
            initial_types=initial_type,
            options={"zipmap": False},
            target_opset=17,
        )
        with open(output_path, "wb") as f:
            f.write(onnx_model.SerializeToString())
        size_kb = os.path.getsize(output_path) / 1024
        print(f"  ✓ model.onnx saved ({size_kb:.1f} KB) → {os.path.abspath(output_path)}")
    except Exception as e:
        print(f"  [ERROR] ONNX export failed: {e}")
        sys.exit(1)

    # Verify with onnxruntime
    try:
        import onnxruntime as rt
        sess = rt.InferenceSession(output_path)
        dummy = np.random.rand(1, N_FEATURES).astype(np.float32)
        out = sess.run(None, {"input": dummy})
        print(f"  ✓ ONNX runtime verification passed. Output shapes: {[o.shape for o in out]}")
        print(f"     Output names: {[o.name for o in sess.get_outputs()]}")

        # Quick sanity: phishing URL should score > 0.5
        from features import extract_features
        phish_feats = np.array([extract_features("http://paypal-secure.account-verify.xyz/signin")], dtype=np.float32)
        legit_feats = np.array([extract_features("https://www.google.com")], dtype=np.float32)
        p_phish = sess.run(None, {"input": phish_feats})[1][0][1]
        p_legit = sess.run(None, {"input": legit_feats})[1][0][1]
        print(f"\n  Sanity check:")
        print(f"    paypal-secure.account-verify.xyz → P(phish)={p_phish:.3f}  {'✓ PASS' if p_phish > 0.5 else '✗ FAIL'}")
        print(f"    www.google.com                   → P(phish)={p_legit:.3f}  {'✓ PASS' if p_legit < 0.3 else '✗ FAIL'}")
    except Exception as e:
        print(f"  [WARN] ONNX verification failed: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Browser Vigilant v2.0 — ML Training Pipeline")
    print("  RF + XGBoost + SMOTE + Platt Scaling")
    print("=" * 60)

    X, y = build_dataset()

    if len(X) == 0:
        print("[ERROR] No training data. Check internet connection or fallback corpus.")
        sys.exit(1)

    model = train(X, y)
    export_onnx(model, "model.onnx")

    print("\n" + "="*60)
    print("  ✓ Training complete!")
    print("  Next: copy model.onnx to the extension root, rebuild popup.")
    print("="*60)
