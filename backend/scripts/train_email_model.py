import os
import joblib
import xgboost as xgb
from sklearn.feature_extraction.text import TfidfVectorizer
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType

# Set up paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
os.makedirs(MODELS_DIR, exist_ok=True)

ONNX_MODEL_PATH = os.path.join(MODELS_DIR, 'xgboost_model.onnx')
VECTORIZER_PATH = os.path.join(MODELS_DIR, 'vectorizer.pkl')

print(f"Generating synthetic dataset...")
# Generate a robust synthetic dataset
# 0 = Safe, 1 = Phishing
safe_emails = [
    "Hi team, let's meet tomorrow at 10 AM to discuss the quarterly report.",
    "Please find attached the invoice for your recent purchase. Thank you.",
    "Your flight booking to New York is confirmed. Check-in details are below.",
    "Hey! Are we still on for lunch today?",
    "The code review for the latest PR is done, everything looks great.",
    "Reminder: Office will be closed next Monday for the public holiday.",
    "Weekly project sync agenda is attached. Please review before the meeting.",
    "Hi, I wanted to follow up on our previous conversation regarding the proposal.",
    "Your package has been shipped and will arrive by Tuesday.",
    "Can you please review this document when you have a moment?"
] * 10  # Multiply to give it some weight

phishing_emails = [
    "URGENT: Your account will be suspended in 24 hours. Click here to verify your login immediately.",
    "You have won a free iPhone! Claim your prize now by clicking this secure link.",
    "Security Alert: We detected unusual activity on your bank account. Update your password here.",
    "Your PayPal payment was declined. Please update your billing information immediately.",
    "Action Required: Verify your email address to prevent service termination.",
    "Dear customer, your invoice is overdue. Please pay immediately using the attached link.",
    "Congratulations! You've been selected for a $1000 Amazon Gift Card. Claim here.",
    "Your Netflix membership has been paused. Please update your payment details.",
    "IT Helpdesk: Please click here to upgrade your mailbox quota immediately.",
    "Important: Suspicious login attempt blocked. Click to secure your account."
] * 10

X_text = safe_emails + phishing_emails
y = [0] * len(safe_emails) + [1] * len(phishing_emails)

print("Training TfidfVectorizer...")
# Force 5000 max_features just in case the backend code ever explicitly expects 5000 features
# Though since we are training both the model and vectorizer in sync, it just needs to match
vectorizer = TfidfVectorizer(max_features=5000)
X_features = vectorizer.fit_transform(X_text)
X_features_dense = X_features.toarray().astype('float32')

print(f"Fitted vectorizer with {len(vectorizer.vocabulary_)} features.")

print("Training XGBoost Classifier...")
# We use a relatively simple model for this synthetic data
model = xgb.XGBClassifier(n_estimators=20, max_depth=3, eval_metric='logloss')
model.fit(X_features_dense, y)

print("Exporting vectorizer to .pkl...")
joblib.dump(vectorizer, VECTORIZER_PATH)
print(f"Saved: {VECTORIZER_PATH}")

print("Converting XGBoost model to ONNX...")
# XGBoost conversion requires defining the input dimensions explicitly
input_shape = [None, X_features_dense.shape[1]]
initial_types = [('float_input', FloatTensorType(input_shape))]

onnx_model = onnxmltools.convert.convert_xgboost(
    model, 
    initial_types=initial_types,
    target_opset=12  # Standard compatible opset
)

print("Exporting ONNX model...")
with open(ONNX_MODEL_PATH, "wb") as f:
    f.write(onnx_model.SerializeToString())

print(f"Saved: {ONNX_MODEL_PATH}")
print("\nSuccess! Email classification bundle generated and synchronized.")
