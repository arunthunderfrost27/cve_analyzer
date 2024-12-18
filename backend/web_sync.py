import requests
from datetime import datetime
import json
from flask import Flask, jsonify
from pymongo import MongoClient

app = Flask(__name__)

MONGO_URI = "mongodb+srv://arunbalsen27:cvedata2003@cluster0.a0vpa.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
CVE_JSON_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def log_update_status(action, details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {action.upper()}: {details}")

def parse_date(date_str):
    try:
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return dt.strftime('%d %b %Y')
    except (ValueError, TypeError):
        return None

def fetch_cve_data():
    try:
        log_update_status("fetch", "Initiating CVE data retrieval")
        response = requests.get(CVE_JSON_URL, params={
            'resultsPerPage': 2000,
            'startIndex': 0
        }, timeout=30)
        
        response.raise_for_status()
        log_update_status("fetch", f"Successfully retrieved CVE data. Status code: {response.status_code}")
        return response.json()
    
    except requests.RequestException as e:
        log_update_status("error", f"Network error during CVE data fetch: {e}")
        return None
    except json.JSONDecodeError as e:
        log_update_status("error", f"JSON decoding error: {e}")
        return None
    except Exception as e:
        log_update_status("error", f"Unexpected error during fetch: {e}")
        return None

def init_mongo():
    try:
        log_update_status("database", "Initiating MongoDB connection")
        client = MongoClient(MONGO_URI, 
                           serverSelectionTimeoutMS=10000,
                           socketTimeoutMS=10000)
        client.admin.command('ping')
        log_update_status("database", "MongoDB connection established successfully")
        return client
    except Exception as e:
        log_update_status("error", f"MongoDB connection error: {e}")
        return None

def is_record_changed(existing_record, new_record):
    metadata_fields = [
        'source_identifier', 
        'vuln_status',
        'cveTags',
        'descriptions', 
        'metrics', 
        'cpe_matches', 
        'weaknesses', 
        'configurations', 
        'references'
    ]
    
    for field in metadata_fields:
        if existing_record.get(field) != new_record.get(field):
            return True
    
    return False

def process_cve_data(client, json_data):
    if not client or not json_data:
        log_update_status("error", "Invalid client or data")
        return 0

    try:
        db = client['cluster0']
        processed_count = 0
        updated_count = 0
        new_count = 0

        metadata_bulk = []
        descriptions_bulk = []
        metrics_bulk = []
        cpe_bulk = []

        log_update_status("process", "Starting CVE data processing")

        for vuln_entry in json_data.get('vulnerabilities', []):
            cve = vuln_entry.get('cve', {})
            cve_id = cve.get('id')

            if not cve_id:
                continue

            new_metadata = {
                'cve_id': cve_id,
                'source_identifier': cve.get('sourceIdentifier'),
                'published': parse_date(cve.get('published')),
                'last_modified': parse_date(cve.get('lastModified')),
                'vuln_status': cve.get('vulnStatus')
            }

            existing_metadata = db['cve_metadata'].find_one({'cve_id': cve_id})
            
            if not existing_metadata:
                new_count += 1
                log_update_status("new", f"New CVE discovered: {cve_id}")
            elif is_record_changed(existing_metadata, new_metadata):
                new_metadata['last_modified'] = datetime.now().strftime('%d %b %Y')
                updated_count += 1
                log_update_status("update", f"CVE updated: {cve_id}")
            
            metadata_bulk.append(new_metadata)

            descriptions = cve.get('descriptions', [])
            if descriptions:
                descriptions_bulk.append({
                    'cve_id': cve_id,
                    'descriptions': [{
                        'lang': desc.get('lang'),
                        'value': desc.get('value')
                    } for desc in descriptions]
                })

            metrics = cve.get('metrics', {}).get('cvssMetricV2', [])
            for metric in metrics:
                cvss_data = metric.get('cvssData', {})
                metrics_bulk.append({
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
                })

            configurations = cve.get('configurations', [])
            for config in configurations:
                for node in config.get('nodes', []):
                    cpe_bulk.append({
                        'cve_id': cve_id,
                        'cpe_matches': [{
                            'vulnerable': cpe_match.get('vulnerable'),
                            'criteria': cpe_match.get('criteria'),
                            'match_criteria_id': cpe_match.get('matchCriteriaId')
                        } for cpe_match in node.get('cpeMatch', [])]
                    })

            processed_count += 1

            if processed_count % 1000 == 0:
                load_cve_data(db, metadata_bulk, descriptions_bulk, metrics_bulk, cpe_bulk)
                metadata_bulk, descriptions_bulk = [], []
                metrics_bulk, cpe_bulk = [], []

        if any([metadata_bulk, descriptions_bulk, metrics_bulk, cpe_bulk]):
            load_cve_data(db, metadata_bulk, descriptions_bulk, metrics_bulk, cpe_bulk)

        log_update_status("summary", f"Processed {processed_count} CVE entries. New: {new_count}, Updated: {updated_count}")
        return processed_count

    except Exception as e:
        log_update_status("error", f"Processing error: {e}")
        return 0

def load_cve_data(db, metadata_bulk, descriptions_bulk, metrics_bulk, cpe_bulk):
    if metadata_bulk:
        for metadata in metadata_bulk:
            db['cve_metadata'].replace_one(
                {'cve_id': metadata['cve_id']}, 
                metadata, 
                upsert=True
            )
    if descriptions_bulk:
        db['descriptions'].insert_many(descriptions_bulk)
    if metrics_bulk:
        db['metrics'].insert_many(metrics_bulk)
    if cpe_bulk:
        db['cpe'].insert_many(cpe_bulk)

@app.route('/load_cve_data', methods=['POST'])
def trigger_cve_load():
    client = init_mongo()
    if not client:
        return jsonify({"error": "MongoDB connection failed"}), 500

    try:
        json_data = fetch_cve_data()
        if not json_data:
            return jsonify({"error": "CVE data fetch failed"}), 500
        
        processed_count = process_cve_data(client, json_data)
        
        if processed_count > 0:
            return jsonify({
                "message": "CVE data loaded successfully",
                "processed_entries": processed_count
            }), 200
        else:
            return jsonify({"error": "Failed to process CVE data"}), 500
    
    finally:
        if client:
            client.close()

if __name__ == '__main__':
    log_update_status("startup", "CVE Synchronization Process Initiated")
    client = init_mongo()
    if client:
        try:
            log_update_status("process", "Fetching latest CVE data")
            json_data = fetch_cve_data()
            
            if json_data:
                log_update_status("process", "Processing CVE data")
                process_cve_data(client, json_data)
            else:
                log_update_status("error", "Failed to retrieve CVE data")
        
        finally:
            client.close()
            log_update_status("shutdown", "MongoDB connection closed")