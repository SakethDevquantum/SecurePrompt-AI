import sys
import os
import uvicorn

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from apps.app import app

if __name__ == "__main__":
    print("Starting SecurePrompt Security Gateway on http://127.0.0.1:8000 ...")
    uvicorn.run(app, host="127.0.0.1", port=8000)
