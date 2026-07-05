import os
from google import genai

MODEL_NAME = "gemini-2.5-flash"
DEFAULT_API_KEY = os.getenv("GEMINI_API_KEY")


def ask_gemini(message, user_api_key=None):
    api_key = user_api_key or DEFAULT_API_KEY

    if not api_key:
        return {
            "needs_api_key": True,
            "message": "Please enter your Gemini API key."
        }

    try:
        client = genai.Client(api_key=api_key)

        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=message
        )

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