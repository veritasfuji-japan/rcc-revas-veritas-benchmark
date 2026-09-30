#!/usr/bin/env python3
"""Non-benchmark capability probe. Requires a user-supplied localhost OpenAI-compatible model server."""
import argparse,json,urllib.request
def get_json(url):
    with urllib.request.urlopen(url,timeout=10) as r:return json.load(r)
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--port",type=int,default=8000);a=ap.parse_args()
    base=f"http://127.0.0.1:{a.port}/v1"
    models=get_json(base+"/models")
    ids=[x.get("id") for x in models.get("data",[]) if x.get("id")]
    if len(ids)!=1: raise SystemExit(f"FAIL_MODEL_ID_CARDINALITY:{ids}")
    print(json.dumps({"status":"LOCAL_ENDPOINT_IDENTIFIED","model_id":ids[0],"benchmark_executed":False,"clean_ab_executed":False},sort_keys=True))
if __name__=="__main__":main()
