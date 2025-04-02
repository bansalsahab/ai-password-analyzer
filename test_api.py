import requests
import sys
import json

API_KEY = "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"

def test_api_key():
    print("Testing OpenRouter API connection...")
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "HTTP-Referer": "https://localhost:5000/",
        "Content-Type": "application/json"
    }
    
    try:
        # Simple request to test connectivity
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json={
                "model": "deepseek/deepseek-v3-base:free",
                "messages": [
                    {"role": "user", "content": "Hello, just testing the API connection."}
                ],
                "max_tokens": 5
            },
            timeout=10
        )
        
        print(f"Status code: {response.status_code}")
        
        if response.status_code == 200:
            print("API key is working correctly!")
            result = response.json()
            print("\nAPI Response:")
            print(json.dumps(result, indent=2)[:200] + "...")
            return True
        else:
            print("API key is not working.")
            print(f"Error: {response.text}")
            return False
            
    except Exception as e:
        print(f"Error connecting to OpenRouter API: {e}")
        return False

if __name__ == "__main__":
    test_api_key() 