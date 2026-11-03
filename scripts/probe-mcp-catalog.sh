#!/usr/bin/env bash
# Probe public, keyless Streamable HTTP MCP servers using initialize + tools/list only.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 - "$@" <<'PY'
import argparse, json, subprocess, sys, tomllib
from pathlib import Path
parser=argparse.ArgumentParser()
parser.add_argument('path',nargs='?',default='catalog/mcp-servers.toml')
parser.add_argument('--ids',help='comma-separated IDs to probe; omit to probe all eligible entries')
args=parser.parse_args()
path=Path(args.path)
data=tomllib.loads(path.read_text())
selected=set(args.ids.split(',')) if args.ids else None
class MCPError(Exception): pass
def rpc(endpoint, method, ident, params, session=None):
    message={'jsonrpc':'2.0','method':method,'params':params}
    if ident is not None: message['id']=ident
    args=['curl','--silent','--show-error','--max-time','10','--include','--request','POST',
          '--header','Content-Type: application/json','--header','Accept: application/json, text/event-stream',
          '--header','User-Agent: Auxesis-MCP-Catalog-Probe/1.0 (read-only initialize and tools/list)']
    if session: args += ['--header','Mcp-Session-Id: '+session]
    args += ['--data-binary','@-','--write-out','\nHTTP_CODE:%{http_code}',endpoint]
    try: run=subprocess.run(args,input=json.dumps(message),text=True,capture_output=True,check=False)
    except FileNotFoundError as e: raise MCPError('curl unavailable') from e
    if run.returncode: raise MCPError(run.stderr.strip()[:100] or f'curl exit {run.returncode}')
    raw=run.stdout
    marker='\nHTTP_CODE:'
    if marker not in raw: raise MCPError('missing HTTP status')
    payload,code=raw.rsplit(marker,1)
    if not code.startswith('2'): raise MCPError('HTTP '+code[:3])
    head,sep,body=payload.partition('\r\n\r\n')
    if not sep: head,sep,body=payload.partition('\n\n')
    for line in head.splitlines():
        if line.lower().startswith('mcp-session-id:'): session=line.split(':',1)[1].strip()
    if ident is None: return {},session
    if not body.strip(): raise MCPError('empty response')
    for line in body.splitlines():
        if line.startswith('data:'):
            try: obj=json.loads(line[5:].strip())
            except json.JSONDecodeError: continue
            if isinstance(obj,dict) and (obj.get('id')==ident or 'error' in obj): return obj,session
    try: return json.loads(body),session
    except json.JSONDecodeError as e: raise MCPError('unrecognized response') from e
def one(s):
    endpoint=s.get('endpoint','')
    try:
        obj,sid=rpc(endpoint,'initialize',1,{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'Auxesis catalog probe','version':'1.0'}},None)
        if obj.get('error') or not isinstance(obj.get('result'),dict): raise MCPError('initialize rejected')
        rpc(endpoint,'notifications/initialized',None,{},sid)
        obj,sid=rpc(endpoint,'tools/list',2,{},sid)
        if obj.get('error') or not isinstance(obj.get('result',{}).get('tools'),list): raise MCPError('tools/list rejected')
        return len(obj['result']['tools']),None
    except Exception as e:
        reason=(str(e) or type(e).__name__).replace('\n',' ')[:100]
        return None,reason
for s in data['server']:
    if selected is not None and s.get('id') not in selected: continue
    if s.get('transport')=='http' and s.get('auth')=='none' and str(s.get('endpoint','')).startswith('https://'):
        n,err=one(s)
        print(f"{s['id']}: {'OK tools='+str(n) if err is None else 'FAILED '+err}")
PY
