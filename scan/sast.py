import requests
import json
import time
import argparse
import os
import sys
import subprocess
import shutil
import hashlib
from datetime import datetime
from requests_toolbelt.multipart.encoder import MultipartEncoder, MultipartEncoderMonitor


def get_api_key():

    # Getting the MobSF REST API key from environment variables

    api_key = os.getenv('MOBSF_API_KEY')

    if bool(api_key):
        print('[INFO]: API Key read from environment variable')
        return api_key

    else:
        print('[ERROR]: API Key could not be retrieved.')
        sys.exit(1)


def get_server_url():

    # Getting the MobSF Server URL from environment variables

    server_url = os.getenv('MOBSF_SERVER')
    
    if bool(server_url):
        print('[INFO]: MOBSF Server URL read from environment variable')
        return server_url
    else:
        print('[ERROR]: MOBSF Server URL could be retrieved.')
        sys.exit(1)


def mobsf_server_up(url):

    # Checking if the Mobile Security Framework server is up and running

    try:
        response = session.get(url, timeout=30)
        response.raise_for_status()

        if response.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.Timeout as errt:
        print("[ERROR]: ", errt)
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print("[ERROR]: ", errc)
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:
        print("[ERROR]: ", errh)
        sys.exit(1)


def upload_app():

    # Uploading Android APP to MobSF Server
    # MIME Type for APP, IPA or zip file is 'application/octet-stream'

    try:
        encoder = MultipartEncoder(
            fields={"file": (APP_PATH, open(APP_PATH, "rb"), "application/octet-stream")})

        response = session.post(
            url=SERVER + os.getenv('ENDPOINT_UPLOAD_APP'),
            data=encoder,
            headers={"Content-Type": encoder.content_type,
                     "Authorization": API_KEY})

        response.raise_for_status()

        if response.status_code == 200:
            print('[INFO]: APP Uploaded')
            return response.text

    except requests.exceptions.Timeout as errt:
        print("[ERROR]: Could not upload the APP. ", errt)
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print("[ERROR]: Could not upload the APP. ", errc)
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:
        print("[ERROR]: Could not upload the APP. ", errh)
        sys.exit(1)


def scan_app(data):

    # Requesting an APP scan to MOBSF server

    try:
        response = session.post(
            url=SERVER + os.getenv('ENDPOINT_SCAN_APP'),
            data=json.loads(data),
            headers={"Authorization": API_KEY})

        response.raise_for_status()

        if response.status_code == 200:
            print('[INFO]: Scan requested')

    except requests.exceptions.Timeout as errt:
        print("[ERROR]: While scanning the APP. ", errt)
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print("[ERROR]: While scanning the APP. ", errc)
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:
        print("[ERROR]: While scanning the APP. ", errh)
        sys.exit(1)


def download_pdf_report(scan_hash):

    # Generating a PDF report from an Static Analysis
    # Filename follows this guideline :
    # sast_report_ + yyyy-mm-dd hh:mm:ss + .pdf

    try:
        report_name = "sast_report_" + str(datetime.now()) + ".pdf"

        response = session.post(
            url=SERVER + os.getenv('ENDPOINT_DOWNLOAD_PDF_REPORT'),
            data={"hash": scan_hash},
            headers={'Authorization': API_KEY},
            stream=True)

        response.raise_for_status()

        if response.status_code == 200:
            # As PDF as binary file they need to be written in 1024 bits chunks
            with open(os.getenv('REPORT_PATH') + report_name, 'wb') as report:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        report.write(chunk)

            print('[INFO]: PDF Report Generated')

    except requests.exceptions.Timeout as errt:
        print("[ERROR]: While generating PDF report. ", errt)
    except requests.exceptions.ConnectionError as errc:
        print("[ERROR]: While generating PDF report. ", errc)
    except requests.exceptions.HTTPError as errh:
        print("[ERROR]: While generating PDF report. ", errh)


def download_json_report(scan_hash):
    
    # Generating a JSON report from an Static Analysis
    # Filename follows this guideline :
    # sast_report_ + yyyy-mm-dd hh:mm:ss + .json

    # The JSON report can be processed by OWASP Glue to fail the build if any security issues found

    try:
        report_name = "sast_report_" + str(datetime.now()) + ".json"
        response = session.post(
            url=SERVER + os.getenv('ENDPOINT_DOWNLOAD_JSON_REPORT'),
            data={"hash": scan_hash},
            headers={'Authorization': API_KEY})

        if response.status_code == 200:
            with open(os.getenv('REPORT_PATH') + report_name, 'w') as report:
                json.dump(response.text, report)
            report.close()
            print('[INFO]: JSON Report Generated')

    except requests.exceptions.Timeout as errt:
        print("[ERROR]: ", errt)
    except requests.exceptions.ConnectionError as errc:
        print("[ERROR]: ", errc)
    except requests.exceptions.HTTPError as errh:
        print("[ERROR]: ", errh)
    

def delete_scan_record(scan_hash):

    # Deleting the Static Analysis Record from the SQLite scan database

    try:
        response = session.post(
            url=SERVER + os.getenv('ENDPOINT_DELETE_SCAN'),
            data={"hash": scan_hash},
            headers={"Authorization": API_KEY})

        response.raise_for_status()

        if response.status_code == 200:
            print('[INFO]: Last scan record deleted')
            

    except requests.exceptions.Timeout as errt:
        print("[ERROR]: ", errt)
    except requests.exceptions.ConnectionError as errc:
        print("[ERROR]: ", errc)
    except requests.exceptions.HTTPError as errh:
        print("[ERROR]: ", errh)

    else:
        print("ERROR while deleting the analysis record")


def get_recent_scan():
    
    # Getting the most recent APP scan
    # We get the scan hash (identifier)
    try:
        response = session.get(
            url=SERVER + os.getenv('ENDPOINT_RECENT_SCANS'),
            headers={"Authorization": API_KEY})

        response.raise_for_status()

        if response.status_code == 200:
            n_scans = len(response.json()['content'])
            if n_scans != 0:
                scan_hash = response.json()['content'][0]['MD5']
                print('[INFO]: Last scan fetched. Scan hash: ', scan_hash)
                return scan_hash, n_scans
            else:
                raise ValueError

    except requests.exceptions.Timeout as errt:
        print("[ERROR]: ", errt)
        turn_mobsf_server_down()
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print("[ERROR]: ", errc)
        turn_mobsf_server_down()
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:
        print("[ERROR]: ", errh)
        turn_mobsf_server_down()
        sys.exit(1)
    except ValueError as err_scan:
        print('[ERROR]: No recent scans in the database. ', err_scan)
        turn_mobsf_server_down()
        sys.exit(1)


    # (1) Transfering report to X location. For Atlassian Confluence location use atlassian-python-api.
    # (2) Remove report from instance

    print()


def init_http_session(retries=5):

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=5)
    session.mount('http://', adapter)

    return session

if __name__ == '__main__':

    session = init_http_session()        
    SERVER = get_server_url()
    APP_PATH = os.getenv('APP_PATH')
    API_KEY = get_api_key()

    if mobsf_server_up(url=SERVER):
        app_data = upload_app()
        scan_app(data=app_data)
        scan_hash, n_scans = get_recent_scan()
        download_pdf_report(scan_hash=scan_hash)
        download_json_report(scan_hash=scan_hash)

        
