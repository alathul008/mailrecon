#!/usr/bin/env python3
import argparse, json, sys, urllib.error, urllib.request

VERSION="1.0.0"

def req(base, path, method="GET", payload=None):
    data=json.dumps(payload).encode() if payload is not None else None
    r=urllib.request.Request(base.rstrip('/')+path,data=data,method=method,headers={"content-type":"application/json","accept":"application/json"})
    try:
        with urllib.request.urlopen(r,timeout=30) as x:
            raw=x.read()
            return json.loads(raw.decode()) if raw else {}
    except urllib.error.URLError as exc:
        raise SystemExit(f"MailRecon API unavailable at {base}. Start the backend first. ({exc})")

def main():
    p=argparse.ArgumentParser(prog="mailrecon",description="MailRecon defensive email intelligence CLI")
    p.add_argument("--base-url",default="http://127.0.0.1:8000/api",help="MailRecon API base URL")
    sub=p.add_subparsers(dest="cmd",required=True)
    q=sub.add_parser("scan"); q.add_argument("email"); q.add_argument("--privacy",action="store_true")
    sub.add_parser("providers"); sub.add_parser("version"); sub.add_parser("demo")
    q=sub.add_parser("report"); q.add_argument("id"); q.add_argument("--format",choices=["json","csv","html","pdf"],default="json")
    a=p.parse_args()
    if a.cmd=="version": print(f"MailRecon {VERSION}"); return
    if a.cmd=="providers": print(json.dumps(req(a.base_url,"/providers"),indent=2)); return
    if a.cmd=="demo": print(json.dumps(req(a.base_url,"/demo","POST"),indent=2)); return
    if a.cmd=="scan": print(json.dumps(req(a.base_url,"/investigations","POST",{"email":a.email,"privacy_mode":a.privacy}),indent=2)); return
    if a.cmd=="report":
        path=f"/investigations/{a.id}/report?format={a.format}"
        if a.format=="json": print(json.dumps(req(a.base_url,path),indent=2)); return
        print(f"Report endpoint: {a.base_url.rstrip('/')}{path}")

if __name__=="__main__": main()
