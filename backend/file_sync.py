import requests
from datetime import datetime
import json
from pathlib import Path
from flask import Flask, jsonify, request
from pymongo import MongoClient

app = Flask(__name__)

MONGO_URI = "mongodb+srv://arunbalsen27:cvedata2003@cluster0.a0vpa.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
CVE_JSON_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DATA_DIR = Path(__file__).parent / "data"
JSON_FILE_PATH = DATA_DIR / "cve_data.json"

def dir_exist():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

def download_cve_data(results_per_page=10):
    
    valid_page_sizes = [10, 50, 100]
    if results_per_page not in valid_page_sizes:
        return False

    dir_exist()
    
    try:
        print(f"Downloading CVE data - {results_per_page} records per page")
        all_vulnerabilities = []
        start_index = 0
        
        while True:
            params = {
                'startIndex': start_index,
                'resultsPerPage': results_per_page
            }
            
            response = requests.get(CVE_JSON_URL, params=params, timeout=60)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            all_vulnerabilities.extend(vulnerabilities)
            
            if len(vulnerabilities) < results_per_page:
                break
            
            start_index += results_per_page
        
        complete_data = {
            'vulnerabilities': all_vulnerabilities,
            'total_results': len(all_vulnerabilities),
            'results_per_page': results_per_page,
            'last_updated': datetime.now().isoformat()
        }
        
        JSON_FILE_PATH.write_text(json.dumps(complete_data, indent=2))
        
        print(f"Total CVE entries downloaded: {len(all_vulnerabilities)}")
        return True
    
    except requests.RequestException as e:
        print(f"Download error: {e}")
        return False

def parse_date(date_str):
    try:
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return dt.strftime('%d %b %Y')
    except (ValueError, TypeError):
        return None

def init_mongo():
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000, socketTimeoutMS=10000)
        client.admin.command('ping')
        print("MongoDB initiated")
        return client
    except Exception as e:
        print(f"MongoDB initialization error: {e}")
        return None

def is_record_changed(existing_record, new_record):
    metadata_fields = ['source_identifier', 'vuln_status', 'descriptions', 'metrics', 'cpe_matches', 'cveTags', 'weaknesses', 'configurations', 'references']
    
    for field in metadata_fields:
        if existing_record.get(field) != new_record.get(field):
            return True
    
    return False

def load_cve_data(client):
    if not client:
        print("MongoDB client is None")
        return 0

    if not JSON_FILE_PATH.exists():
        print("JSON file not found. Attempting download.")
        if not download_cve_data():
            return 0

    try:
        with open(JSON_FILE_PATH, 'r') as f:
            json_data = json.load(f)
        
        db = client['cluster0']
        processed_count = 0
        updated_count = 0
        results_per_page = json_data.get('results_per_page', 10)

        metadata_bulk = []
        descriptions_bulk = []
        metrics_bulk = []
        cpe_bulk = []

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
            
            if existing_metadata:
                if is_record_changed(existing_metadata, new_metadata):
                    new_metadata['last_modified'] = datetime.now().strftime('%d %b %Y')
                    updated_count += 1
            
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
                if metadata_bulk:
                    for metadata in metadata_bulk:
                        db['cve_metadata'].replace_one({'cve_id': metadata['cve_id']}, metadata, upsert=True)
                    metadata_bulk.clear()

                if descriptions_bulk:
                    db['descriptions'].insert_many(descriptions_bulk)
                    descriptions_bulk.clear()
                if metrics_bulk:
                    db['metrics'].insert_many(metrics_bulk)
                    metrics_bulk.clear()
                if cpe_bulk:
                    db['cpe'].insert_many(cpe_bulk)
                    cpe_bulk.clear()

        if metadata_bulk:
            for metadata in metadata_bulk:
                db['cve_metadata'].replace_one({'cve_id': metadata['cve_id']}, metadata, upsert=True)
        if descriptions_bulk:
            db['descriptions'].insert_many(descriptions_bulk)
        if metrics_bulk:
            db['metrics'].insert_many(metrics_bulk)
        if cpe_bulk:
            db['cpe'].insert_many(cpe_bulk)

        print(f"Processed {processed_count} CVE entries")
        if processed_count >= db['cve_metadata'].count_documents({}):
            print(f"Updated {updated_count} entries of the database")
        else:
            print(f"{db['cve_metadata'].count_documents({}) - processed_count} entries have been deleted")
        return processed_count

    except Exception as e:
        print(f"Synchronization error: {e}")
        return 0
    
@app.route('/load_cve_data', methods=['POST'])
def trigger_cve_load():
    results_per_page = request.args.get('results_per_page', default=10, type=int)
    
    client = init_mongo()
    if not client:
        return jsonify({"error": "MongoDB connection failed"}), 500

    try:
        if not download_cve_data(results_per_page):
            return jsonify({"error": "CVE data download failed"}), 500
        
        processed_count = load_cve_data(client)
        
        if processed_count > 0:
            return jsonify({
                "message": "CVE data loaded successfully",
                "processed_entries": processed_count
            }), 200
        else:
            return jsonify({"error": "Failed to load CVE data"}), 500
    
    finally:
        if client:
            client.close()

if __name__ == '__main__':
    client = init_mongo()
    if client:
        load_cve_data(client)
        client.close()