import os
import google.generativeai as genai

# Keep empty for now
MODEL_NAME = ""

DEFAULT_API_KEY = os.getenv("GEMINI_API_KEY")

# Existing GENERAL_KNOWLEDGE stays here


def ask_gemini(message, user_api_key=None):
    api_key = user_api_key or DEFAULT_API_KEY

    if not api_key:
        return {
            "needs_api_key": True,
            "message": "Please enter your Gemini API key."
        }

    try:
        genai.configure(api_key=api_key)

        model = genai.GenerativeModel(MODEL_NAME)
        response = model.generate_content(message)

        return {
            "needs_api_key": False,
            "message": response.text
        }

    except Exception as e:
        error = str(e).lower()

        if "quota" in error or "429" in error:
            return {
                "needs_api_key": True,
                "message": "My Gemini quota expired. Please enter your Gemini API key."
            }

        return {
            "needs_api_key": False,
            "message": f"Error: {str(e)}"
        }


def chatbot_reply(message, results=None, user_api_key=None):
    msg = message.lower().strip()

    if not msg:
        return "Please type a question."

    # -------------------------------
    # KEEP ALL YOUR EXISTING SCAN LOGIC HERE
    # (risk score, xss count, sql count, summary, etc.)
    # -------------------------------

    if results:
        risk = results.get("risk", {})
        sqli = results.get("sqli", [])
        xss = results.get("xss", [])

        if any(w in msg for w in ["score", "risk"]):
            return (
                f"Risk Score: {risk.get('score', 'N/A')}/10 "
                f"({risk.get('level', 'N/A')})"
            )

        if "sql" in msg and "found" in msg:
            return f"SQL Injection issues: {len(sqli)}"

        if "xss" in msg and "found" in msg:
            return f"XSS issues: {len(xss)}"

    # Rule-based general knowledge first
    for topic, info in GENERAL_KNOWLEDGE.items():
        if any(kw in msg for kw in info["keywords"]):
            return info["answer"]

    # If nothing matches → Gemini fallback
    gemini_response = ask_gemini(message, user_api_key)

    if isinstance(gemini_response, dict):
        return gemini_response["message"]

    return gemini_response