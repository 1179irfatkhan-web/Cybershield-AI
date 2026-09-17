import os

from decouple import config
from google import genai


def test_gemini_connection():
    api_key = config("GEMINI_API_KEY")
    model_name = config(
        "GEMINI_MODEL",
        default="gemini-3.6-flash",
    )

    client = genai.Client(api_key=api_key)

    try:
        response = client.models.generate_content(
            model=model_name,
            contents=(
                "Reply with exactly this sentence: "
                "CyberShield AI Gemini connection successful."
            ),
        )

        print("Model:", model_name)
        print("Response:", response.text)

    except Exception as error:
        print("Gemini connection failed.")
        print("Model:", model_name)
        print("Error:", error)


if __name__ == "__main__":
    test_gemini_connection()