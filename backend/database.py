import requests
from datetime import datetime
from flask import Flask, jsonify
from pymongo import MongoClient
import sys

MONGO_URI = "mongodb+srv://arunbalsen27:cvedata2003@cluster0.a0vpa.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
CVE_JSON_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

app = Flask(__name__)

def init_mongo():
    try:
        client = MongoClient(MONGO_URI)
        client.admin.command('ping')
        print("MongoDB initiated")
        return client
    except Exception as e:
        print(f"MongoDB initialization error: {e}")
        return None

def drop_all_collections(client):
    try:
        db = client['cluster0']
        collections = db.list_collection_names()
        for collection in collections:
            db[collection].drop()
            print(f"Dropped collection: {collection}")
        print("All collections dropped successfully")
    except Exception as e:
        print(f"Error dropping collections: {e}")

def parse_date(date_str):
    try:
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return dt.strftime('%d %b %Y')
    except (ValueError, TypeError):
        return None

def load_cve_data(client):
    if client is None:
        print("MongoDB connection not established")
        return 0

    try:
        response = requests.get(CVE_JSON_URL, timeout=30)
        response.raise_for_status()
        json_data = response.json()
        db = client['cluster0']
        processed_count = 0

        for vuln_entry in json_data.get('vulnerabilities', []):
            cve = vuln_entry.get('cve', {})
            cve_id = cve.get('id')

            if not cve_id:
                continue

            metadata = {
                'cve_id': cve_id,
                'source_identifier': cve.get('sourceIdentifier'),
                'published': parse_date(cve.get('published')),
                'last_modified': parse_date(cve.get('lastModified')),
                'vuln_status': cve.get('vulnStatus')
            }
            db['cve_metadata'].insert_one(metadata)

            descriptions = cve.get('descriptions', [])
            if descriptions:
                description_doc = {
                    'cve_id': cve_id,
                    'descriptions': [{
                        'lang': desc.get('lang'),
                        'value': desc.get('value')
                    } for desc in descriptions]
                }
                db['descriptions'].insert_one(description_doc)

            metrics = cve.get('metrics', {}).get('cvssMetricV2', [])
            for metric in metrics:
                cvss_data = metric.get('cvssData', {})
                metrics_doc = {
                    'cve_id': cve_id,
                    'cvss_data': {
                        'version': cvss_data.get('version'),
                        'vector_string': cvss_data.get('vectorString'),
                        'base_score': cvss_data.get('baseScore'),
                        'access_vector': cvss_data.get('accessVector'),
                        'access_complexity': cvss_data.get('accessComplexity'),
                        'authentication': cvss_data.get('authentication'),
                        'confidentiality_impact': cvss_data.get('confidentialityImpact'),
                        'integrity_impact': cvss_data.get('integrityImpact'),
                        'availability_impact': cvss_data.get('availabilityImpact')
                    },
                    'exploitability_score': metric.get('exploitabilityScore'),
                    'impact_score': metric.get('impactScore')
                }
                db['metrics'].insert_one(metrics_doc)

            configurations = cve.get('configurations', [])
            for config in configurations:
                for node in config.get('nodes', []):
                    cpe_doc = {
                        'cve_id': cve_id,
                        'cpe_matches': [{
                            'vulnerable': cpe_match.get('vulnerable'),
                            'criteria': cpe_match.get('criteria'),
                            'match_criteria_id': cpe_match.get('matchCriteriaId')
                        } for cpe_match in node.get('cpeMatch', [])]
                    }
                    db['cpe'].insert_one(cpe_doc)

            processed_count += 1

        print(f"Processed and inserted {processed_count} CVE entries in MongoDB")
        return processed_count

    except requests.RequestException as e:
        print(f"Request error: {e}")
        return 0
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 0

def initialize_app():
    client = init_mongo()
    if client is None:
        print("Failed to initialize MongoDB. Exiting.")
        sys.exit(1)
    
    drop_all_collections(client)
    
    return client

@app.route('/load_cve_data', methods=['POST'])
def trigger():
    client = initialize_app()
    processed_count = load_cve_data(client)
    if processed_count > 0:
        return jsonify({
            "message": "CVE data loaded successfully",
            "processed_entries": processed_count
        }), 200
    else:
        return jsonify({"message": "Failed to load CVE data"}), 500

if __name__ == '__main__':
    client = initialize_app()
    load_cve_data(client)
    client.close()