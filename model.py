#libraries
import pandas as pd
import pickle

from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

from sklearn.metrics import classification_report
from sklearn.metrics import precision_score, recall_score, f1_score

from sklearn.metrics import confusion_matrix
from sklearn.metrics import ConfusionMatrixDisplay

import matplotlib.pyplot as plt



#load dataset
data = pd.read_csv("dataset/data.csv")


#print dataset
print(data)


#split features and label
X = data.drop("label", axis=1)

print("Columns:", list(X.columns))
print("Number of features:", len(X.columns))

y = data["label"]

print("Features (X):")
print(X)

print("\nLabels (y):")
print(y)


#Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)
print("\nTraining data size:", len(X_train))
print("Testing data size:", len(X_test))


# train Decision Tree
dt_model = DecisionTreeClassifier(
    max_depth=5,
    random_state=42
)
dt_model.fit(X_train, y_train)


# train Random Forest
rf_model = RandomForestClassifier(
    n_estimators=200,
    random_state=42
)
rf_model.fit(X_train, y_train)


#========================================================================================================
# 5-FOLD CROSS VALIDATION METHOS 
dt_cv_scores = cross_val_score(
    DecisionTreeClassifier(
        max_depth=5,
        random_state=42
    ),
    X,
    y,
    cv=5,
    scoring="accuracy"
)

rf_cv_scores = cross_val_score(
    RandomForestClassifier(
        n_estimators=200,
        random_state=42
    ),
    X,
    y,
    cv=5,
    scoring="accuracy"
)

#check accuracy for both models
dt_acc = dt_model.score(X_test, y_test)
rf_acc = rf_model.score(X_test, y_test)


# predictions
dt_pred = dt_model.predict(X_test)
rf_pred = rf_model.predict(X_test)


#========================================================================================================
#============ CONFUSION MATRIX ===============#
#Decision Tree Confusion Matrix
dt_cm = confusion_matrix(y_test, dt_pred)

dt_display = ConfusionMatrixDisplay(
    confusion_matrix = dt_cm,
    display_labels=["Legitimate", "Phishing"]
)

dt_display.plot(cmap="Blues")
plt.title("Decision Tree Confusion Matrix")
plt.savefig("dt_confusion_matrix.png")
plt.close()

#Random Forest Confusion Matrix
rf_cm = confusion_matrix(y_test, rf_pred)

rf_display = ConfusionMatrixDisplay(
    confusion_matrix = rf_cm,
    display_labels=["Legitimate", "Phishing"]
)

rf_display.plot(cmap="Greens")

print("\n========== CONFUSION MATRICES ==========\n")
print("Decision Tree Cofusion matrix")
print(dt_cm)

print()

print("Random Forest Confusion matrix")
print(rf_cm)

plt.title("Rondom Forest Confusion Matrix")
plt.savefig("rf_confusion_matrix.png")
plt.close()


print("DT Accuracy:", dt_acc)
print(classification_report(y_test, dt_pred))

print("DT Precision:", precision_score(y_test, dt_pred))
print("DT Recall:", recall_score(y_test, dt_pred))
print("DT F1:", f1_score(y_test, dt_pred))

print("\n-----------------------------------\n")

print("RF Accuracy:", rf_acc)
print(classification_report(y_test, rf_pred))

print("RF Precision:", precision_score(y_test, rf_pred))
print("RF Recall:", recall_score(y_test, rf_pred))
print("RF F1:", f1_score(y_test, rf_pred))

print(("\n========== CROSS VALIDATION ==========\n"))

print("Decision Tree Fold Accuracies:")
print(dt_cv_scores)
print("Average Decision Tree Accuracy:", dt_cv_scores.mean())

print()

print("Random Forest Fold Accuracies:")
print(rf_cv_scores)
print("Average Random Forest Accuracy:", rf_cv_scores.mean())


# Save all model performance metrics
with open("accuracy.txt", "w") as f:

    # Decision Tree
    f.write(f"DT_Accuracy:{dt_acc:.4f}\n")
    f.write(f"DT_Precision:{precision_score(y_test, dt_pred):.4f}\n")
    f.write(f"DT_Recall:{recall_score(y_test, dt_pred):.4f}\n")
    f.write(f"DT_F1:{f1_score(y_test, dt_pred):.4f}\n")
    f.write(f"DT_CV:{dt_cv_scores.mean():.4f}\n\n")

    # Random Forest
    f.write(f"RF_Accuracy:{rf_acc:.4f}\n")
    f.write(f"RF_Precision:{precision_score(y_test, rf_pred):.4f}\n")
    f.write(f"RF_Recall:{recall_score(y_test, rf_pred):.4f}\n")
    f.write(f"RF_F1:{f1_score(y_test, rf_pred):.4f}\n")
    f.write(f"RF_CV:{rf_cv_scores.mean():.4f}\n")


#save model
pickle.dump(dt_model, open("dt_model.pkl", "wb"))
pickle.dump(rf_model, open("rf_model.pkl", "wb"))
print("Model saved successfully")