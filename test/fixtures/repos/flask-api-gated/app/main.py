import os
from flask import Flask

app = Flask(__name__)


@app.get("/entries")
def entries():
    return []


if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", "5000")))
