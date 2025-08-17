from flask import Flask, render_template, request
import pandas as pd
import joblib
import traceback

app = Flask(__name__)

# Load the trained model
model = joblib.load("phishing_model.pkl")

# Define the exact list of features used during training
FEATURE_COLUMNS = ['URLLength', 'DomainLength', 'IsDomainIP', 'URLSimilarityIndex', 'CharContinuationRate',
                   'TLDLegitimateProb', 'URLCharProb', 'TLDLength', 'NoOfSubDomain', 'HasObfuscation',
                   'NoOfObfuscatedChar', 'ObfuscationRatio', 'NoOfLettersInURL', 'LetterRatioInURL',
                   'NoOfDegitsInURL', 'DegitRatioInURL', 'NoOfEqualsInURL', 'NoOfQMarkInURL',
                   'NoOfAmpersandInURL', 'NoOfOtherSpecialCharsInURL', 'SpacialCharRatioInURL',
                   'IsHTTPS', 'LineOfCode', 'LargestLineLength', 'HasTitle', 'DomainTitleMatchScore',
                   'URLTitleMatchScore', 'HasFavicon', 'Robots', 'IsResponsive', 'NoOfURLRedirect',
                   'NoOfSelfRedirect', 'HasDescription', 'NoOfPopup', 'NoOfiFrame', 'HasExternalFormSubmit',
                   'HasSocialNet', 'HasSubmitButton', 'HasHiddenFields', 'HasPasswordField', 'Bank', 'Pay',
                   'Crypto', 'HasCopyrightInfo', 'NoOfImage', 'NoOfCSS', 'NoOfJS', 'NoOfSelfRef',
                   'NoOfEmptyRef', 'NoOfExternalRef']

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    url_input = ""

    if request.method == "POST":
        url_input = request.form.get("url", "")

        try:
            # ⚠️ Simulate feature extraction (replace with actual code in production)
            features = [0] * len(FEATURE_COLUMNS)
            input_df = pd.DataFrame([features], columns=FEATURE_COLUMNS)

            # Run prediction
            prediction = model.predict(input_df)[0]
            result = "🟢 Legitimate" if prediction == 1 else "🔴 Phishing"

        except ValueError as ve:
            result = f"Feature Error: {str(ve)}"
        except KeyError as ke:
            result = f"Missing Feature: {str(ke)}"
        except Exception as e:
            result = f"Unknown Error: {str(e)}\nTraceback: {traceback.format_exc()}"

    return render_template("index.html", result=result, url=url_input)

if __name__ == "__main__":
    app.run(debug=True)
