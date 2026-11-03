from fastapi import FastAPI
import requests

app = FastAPI()

@app.get("/pay")
def pay():
    # Call out to Stripe (or similar) — the destination is an HTTPS target.
    r = requests.get("https://api.stripe.com/v1/charges", timeout=5)
    return r.json()
