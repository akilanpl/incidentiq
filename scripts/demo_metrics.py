"""Synthetic local telemetry exporter. Never measures production recovery."""
import argparse,json
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
ROOT=Path(__file__).resolve().parent.parent
STATE=ROOT/'data/demo-telemetry.json'
SCENARIOS={'healthy':{'service_up':1,'error_rate':0.002,'db_pool':0.35},'degraded':{'service_up':1,'error_rate':0.12,'db_pool':0.95},'down':{'service_up':0,'error_rate':0.25,'db_pool':0.95}}
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path!='/metrics':self.send_error(404);return
  state=json.loads(STATE.read_text()) if STATE.exists() else SCENARIOS['healthy']
  lines=[]
  for name,value in state.items():
   metric='incidentiq_demo_'+name
   lines.extend([f'# HELP {metric} Synthetic demonstration only; not production telemetry.',f'# TYPE {metric} gauge',f'{metric}{{service="incidentiq-demo",synthetic="true"}} {float(value)}'])
  body=('\n'.join(lines)+'\n').encode();self.send_response(200);self.send_header('Content-Type','text/plain; version=0.0.4; charset=utf-8');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--state',choices=SCENARIOS);args=p.parse_args()
 if args.state:
  STATE.parent.mkdir(exist_ok=True);tmp=STATE.with_suffix('.tmp');tmp.write_text(json.dumps(SCENARIOS[args.state]));tmp.replace(STATE);print('Synthetic telemetry state:',args.state)
 else:
  server=ThreadingHTTPServer(('127.0.0.1',9108),Handler)
  print('Synthetic demo exporter http://127.0.0.1:9108/metrics',flush=True)
  try:server.serve_forever()
  except KeyboardInterrupt:pass
  finally:server.server_close()
