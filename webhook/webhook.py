import sys

from flask import Flask, request

import hmac

app = Flask(__name__)


def webhook_key() -> bytes:
    with open("/webhook-secret") as f:
        return f.read().strip().encode()


@app.route("/")
def index():
    return "OK\n"


@app.route("/webhook", methods=["POST"])
def webhook():
    delivered = request.headers.get("X-JOBSERV-SIG")
    print("HMAC SIG", delivered)

    if not delivered or not delivered.startswith("sha256:"):
      return "Invalid HMAC Sig format", 400

    key = webhook_key()
    computed = hmac.new(key, request.data, "sha256").hexdigest()
    if not (hmac.compare_digest(computed, delivered[7:])):
      return "Invalid HMAC Sig", 400

    print("BODY", request.data, file=sys.stderr)
    return 'OK\n'
