import pandas as pd

dataset = pd.read_csv("pe_features.csv")
print(dataset)
print(dataset['malware'].value_counts(), dataset.isnull().sum().sum() )
X = dataset.drop('malware', axis=1) 
y = dataset['malware']

from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

from xgboost import XGBClassifier

model = XGBClassifier(
    n_estimators=200,
    learning_rate=0.05,
    max_depth=6,
    subsample=0.8,
    colsample_bytree=0.8,
    use_label_encoder=False,
    eval_metric='logloss'
)
# Train
model.fit(X_train, y_train)

importance_df = pd.DataFrame({'Feature': feature_names, 'Importance': importances})

# Sort the DataFrame by importance
importance_df = importance_df.sort_values(by='Importance', ascending=False)

# Print the feature importances
print(importance_df)


from sklearn.metrics import classification_report , accuracy_score
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

import joblib
joblib.dump(model, 'smartshield-V1.pkl')

import feature_extract
data = feature_extract.extract_features(".\\kapi2.0peys-malwares\\Scribble.exe")
prediction = model.predict(data)
print("Malware" if prediction[0] == 1 else "Safe")