from flask import Flask, request, jsonify, render_template
import os
import requests
from pymongo import MongoClient
from datetime import datetime
import schedule, time
import threading

app = Flask(__name__)

# MongoDB setup
client = MongoClient("mongodb://localhost:27017")
db = client.cti_dashboard
iocs = db.iocs

# API keys from environment
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_KEY")
OTX_KEY = os.getenv("OTX_KEY")

# Threat feed ingestion
def fetch_abuseipdb(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    headers = {'Key': ABUSE_KEY, 'Accept': 'application/json'}
    resp = requests.get(url, headers=headers, params=params)
    return resp.json()

def fetch_virustotal_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {'x-apikey': VT_API_KEY}
    resp = requests.get(url, headers=headers)
    return resp.json()

def ingest_ioc_ip(ip):
    """Enrich and store an IP IOC."""
    abuse_data = fetch_abuseipdb(ip)
    vt_data = fetch_virustotal_ip(ip)

    # Normalize some fields
    doc = {
        "ioc": ip,
        "type": "ip",
        "first_seen": datetime.utcnow(),
        "sources": [],
        "reputation": {},
        "history": []
    }

    if abuse_data.get("data"):
        doc["sources"].append("AbuseIPDB")
        doc["reputation"]["abuseipdb"] = abuse_data["data"]["abuseConfidenceScore"]
    if vt_data:
        doc["sources"].append("VirusTotal")
        # extract relevant vt info, e.g. malicious_votes
        vt_attrs = vt_data.get("data", {}).get("attributes", {})
        doc["reputation"]["virustotal"] = {
            "malicious_votes": vt_attrs.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious_votes": vt_attrs.get("last_analysis_stats", {}).get("suspicious", 0)
        }

    doc["history"].append({
        "timestamp": datetime.utcnow(),
        "sources": doc["sources"]
    })

    # Upsert into DB
    iocs.update_one({"ioc": ip}, {"$set": doc}, upsert=True)


def ingestion_job():
    # Example job: ingest some fixed IPs (or from a list)
    sample_ips = ["8.8.8.8", "1.1.1.1"]
    for ip in sample_ips:
        try:
            ingest_ioc_ip(ip)
        except Exception as e:
            print("Error ingesting", ip, e)

def run_scheduler():
    schedule.every(10).minutes.do(ingestion_job)
    while True:
        schedule.run_pending()
        time.sleep(1)

# Run scheduler in background thread
threading.Thread(target=run_scheduler, daemon=True).start()

# Flask endpoints

@app.route("/")
def home():
    total = iocs.count_documents({})
    return render_template("dashboard.html", total_iocs=total)

@app.route("/lookup", methods=["GET"])
def lookup():
    ioc = request.args.get("ioc")
    if not ioc:
        return jsonify({"error": "ioc param required"}), 400

    doc = iocs.find_one({"ioc": ioc})
    if doc:
        # convert datetime
        doc["first_seen"] = doc["first_seen"].isoformat()
        return jsonify(doc)
    else:
        return jsonify({"message": "IOC not found"}), 404

@app.route("/export", methods=["GET"])
def export_iocs():
    docs = list(iocs.find({}))
    # convert datetimes
    for d in docs:
        if "first_seen" in d:
            d["first_seen"] = d["first_seen"].isoformat()
        if "history" in d:
            for h in d["history"]:
                h["timestamp"] = h["timestamp"].isoformat()
    return jsonify(docs)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

