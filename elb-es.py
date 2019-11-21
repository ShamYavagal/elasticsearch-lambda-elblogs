#!/usr/bin/env python3.6
# Sham Yavagal - SniOps 2019

import os
import sys
import boto3
import codecs
import io
import re
import json
import gzip
import shlex
import requests
from requests_aws4auth import AWS4Auth
from datetime import datetime
import logging
from elblogs.event1 import event

logger = logging.getLogger()
logger.setLevel(logging.INFO)

access_key = os.environ.get("PROD_ACCESS_KEY")
secret_key = os.environ.get("PROD_SECRET_ACCESS_KEY")

indexTimestamp = str(datetime.now()).split()[0]

params = {
    "es_endpoint": "https://search-sniops-awslogs-osmilkcpm5d74tmljcrwce644i.us-east-1.es.amazonaws.com",
    "Region": 'us-east-1',
    "headers": {"content-type": "application/json"},
    "geoip_headers": {'accept': "application/json", 'content-type': "application/json"}
}

creds = boto3.Session(aws_access_key_id=access_key,
                      aws_secret_access_key=secret_key).get_credentials()

awsauth = AWS4Auth(creds.access_key, creds.secret_key,
                   'us-east-1', 'es', session_token=creds.token)

class GetGeo():
    def __init__(self, logDocTrimmed_dict, cip):
        self.LogDocTrimmed_dict = logDocTrimmed_dict
        self.cip = cip
        try:
            geo_url = "https://freegeoip.app/json" + \
                '/' + self.cip
            geo_resp = requests.request(
                "GET", geo_url, headers=params.get("geoip_headers"))

            self.georesult = json.loads(geo_resp.text)
        except Exception as E:
            self.georesult = "Failed To Fetch GeoIP Info"
            logger.error("FAILED TO FETCH GEOIP INFO:::### " + str(E))
    
    @property
    def result(self):
        return self.georesult


def doctoes(line):
    
    if line.startswith("#"):
        logging.error("START OF THE LOG FILE:::### " + line)
        return None

    url = params.get('es_endpoint') + '/' + params.get('index') + \
        '-' + indexTimestamp + '/' + 'lambda'

    log_doc_list = []

    if re.search("\w*\.cloudfront.net", line):

        logentry = shlex.split(line)

        date_time = logentry[0] + ' ' + logentry[1]

        datetime_object = datetime.strptime(
            date_time, "%Y-%m-%d %H:%M:%S").isoformat()

        log_doc = {"@timestamp": datetime_object, "x-edge-location": logentry[2], "sc-bytes": int(
            logentry[3]), "client_ip": logentry[4], "cs_method": logentry[5], "cs_host": logentry[6], "cs_uri_stem": logentry[7],
            "sc_status": int(logentry[8]), "referrer": logentry[9], "user_agent": logentry[10], "cs_uri_query": logentry[11], "cookie": logentry[12],
            "x_edge_result_type": logentry[13], "x_edge_request_id": logentry[14], "x_host_header": logentry[15], "cs_protocol": logentry[16],
            "cs_bytes": int(logentry[17]), "time_taken": float(logentry[18]), "x_forwarded_for": logentry[19], "ssl_protocol": logentry[20],
            "ssl_cipher": logentry[21],  "x_edge_response_result_type": logentry[22], "cs_protocol_version": logentry[23]}

        log_doc_trimmed = {key: value for key,
                           value in log_doc.items() if value != '-'}

        if not "Amazon-Route53-Health-Check" in log_doc_trimmed.get("user_agent"):
            log_doc_trimmed_obj = GetGeo(log_doc_trimmed, log_doc_trimmed.get("client_ip"))
            log_doc_trimmed["geoip"] = (log_doc_trimmed_obj.result)
            
        print(log_doc_trimmed)

        log_doc_list.append(log_doc_trimmed)

    elif shlex.split(line)[1] == "sniorigin": #Replace This With Bucket Name
        logentry = shlex.split(line)

        date_time = datetime.strptime(logentry[2] + ' ' + logentry[3], "[%d/%b/%Y:%H:%M:%S %z]").isoformat()

        Bytes = int(logentry[12]) if (logentry[12]) != '-' else (logentry[12])
        object_size = int(logentry[13]) if (
            logentry[13]) != '-' else (logentry[13])
        request_time_ms = int(logentry[14]) if (
            logentry[14]) != '-' else (logentry[14])
        turnaround_time_ms = int(logentry[15]) if (logentry[15]) != '-' else (logentry[15]) 
        
        verb = logentry[9].split()[0]
        request = logentry[9].split()[1]
        httpversion = logentry[9].split()[2]

        log_doc = {"owner": logentry[0], "bucket": logentry[1], "@timestamp": date_time,
                   "clientip": logentry[4], "requester": logentry[5], "request_id": logentry[6], "operation": logentry[7], "key": logentry[8], "verb": verb,
                   "request": request, "httpversion": httpversion, "response": int(logentry[10]), "error_code": logentry[11], "bytes_sent": Bytes,
                   "object_size": object_size, "total_time_ms": request_time_ms, "turnaround_time_ms": turnaround_time_ms,  "referrer": logentry[16],
                   "user-agent": logentry[17], "version_id": logentry[18]}

        log_doc_trimmed = {key: value for key,
                           value in log_doc.items() if value != '-'}

        log_doc_trimmed_obj = GetGeo(log_doc_trimmed, log_doc_trimmed.get("clientip"))
        
        log_doc_trimmed["geoip"] = (log_doc_trimmed_obj.result)
        
        print(log_doc_trimmed)

        log_doc_list.append(log_doc_trimmed)

    elif params.get("index") == "elb-logs":
        logentry = shlex.split(line)

        clientip = logentry[3].split(':')[0]
        clientport = int(logentry[3].split(':')[1])
        backendip = logentry[4].split(':')[0]
        backendport = int(logentry[4].split(':')[1])
        verb = logentry[12].split()[0]
        request = logentry[12].split()[1]
        httpversion = logentry[12].split()[2]

        log_doc = {"type": logentry[0], "@timestamp": logentry[1], "elb": logentry[2], "clientip": clientip, "clientport": clientport, "backendip": backendip,
                   "backendport": backendport, "request_processing_time": float(logentry[5]), "backend_processing_time": float(logentry[6]),
                   "response_processing_time": float(logentry[7]), "response": int(logentry[8]), "backend_response": int(logentry[9]),
                   "received_bytes": int(logentry[10]), "sent_bytes": int(logentry[11]), "verb": verb, "request": request, "httpversion": httpversion,
                   "raw_request": logentry[12], "user_agent": logentry[13], "ssl_cipher": logentry[14], "ssl_protocol": logentry[15], "target_group_arn": logentry[16],
                   "trace_id": logentry[17], "domain_name": logentry[18], "chosen_cert_arn": logentry[19], "matched_rule_priority": [20],
                   "request_creation_time": logentry[21], "actions_executed": logentry[22], "redirect_url": logentry[23], "error_reason": logentry[24]}

        log_doc_trimmed = {key: value for key,
                           value in log_doc.items() if value != '-'}

        log_doc_trimmed_obj = GetGeo(log_doc_trimmed, log_doc_trimmed.get("clientip"))
        
        log_doc_trimmed["geoip"] = (log_doc_trimmed_obj.result)
        
        print(log_doc_trimmed)

        log_doc_list.append(log_doc_trimmed)

    if log_doc_list:
        for doc in log_doc_list:
            if not "Amazon-Route53-Health-Check" in doc.get("user_agent", "NONE"):
                try:
                    resp = requests.post(url, auth=awsauth, json=doc,
                                        headers=params.get('headers'))
                    logger.info("STATUS CODE:::### " + str(resp.status_code))
                except Exception as E:
                    logger.error("FAILED TO POST TO ELASTICSEARCH:::#### " + str(E))


def getlogfile(event):
    s3 = boto3.client('s3', aws_access_key_id=access_key,
                      aws_secret_access_key=secret_key)
    try:
        bucket = event.get("Records")[0].get("s3").get("bucket").get("name")
        obj_key = event.get("Records")[0].get("s3").get("object").get("key")

        if "elasticloadbalancing" in obj_key:
            params['index'] = "elb-logs"
        else:
            params['index'] = 'cdn-logs'

        compressed = True if obj_key.endswith(".gz") else False

        obj_get = s3.get_object(Bucket=bucket, Key=obj_key)

        body = obj_get['Body']

        if compressed:
            with gzip.open(body, 'rt') as file:
                for line in file:
                    doctoes(line)
        else:
            for line in codecs.getreader('utf-8')(body):
                doctoes(line)
    except Exception as E:
        logger.error("FAILED TO READ LOG FILE:::### " + str(E))

getlogfile(event)
