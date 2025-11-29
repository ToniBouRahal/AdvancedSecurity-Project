import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import joblib

DATASET = "dataset.csv"
MODEL_PATH = "model.joblib"

def train():
    df = pd.read_csv(DATASET)

    # Features must match the ones you compute in app.py (compute_features_for_ip)
    X = df[["total_attempts", "failed_attempts", "success_rate", "unique_usernames", "min_delta"]]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    # Pipeline: scaler + logistic regression
    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression())
    ])

    model.fit(X_train, y_train)

    train_acc = model.score(X_train, y_train)
    test_acc = model.score(X_test, y_test)

    print(f"Train accuracy: {train_acc:.2f}")
    print(f"Test accuracy: {test_acc:.2f}")

    joblib.dump(model, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    train()
