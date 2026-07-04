import os
import google.generativeai as genai

MODEL_NAME = "gemini-1.5-flash"
DEFAULT_API_KEY = os.getenv("GEMINI_API_KEY")


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