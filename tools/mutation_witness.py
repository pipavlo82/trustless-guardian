"""Execute one boundary witness against this checkout's physical implementation."""
import argparse
import json
from pathlib import Path
from lab import Lab,write
from guardian import windows as win
from guardian.policy import canonical


def run(kind,out):
    lab=Lab(out)
    try:
        positive=lab.check_request('positive')
        positive_ok=(positive['decision']['decision']=='ALLOW' and positive['broker_result']=='EXECUTED'
          and lab.resource.read_bytes()==b'approved:positive' and positive['independent_verifier_exit']==0)
        patches={'actor':{'actor':'other'},'action':{'action':'delete'},'resource':{'resource':'other'},
          'scope':{'scope':'arbitrary'},'version':{'policy_version':'other'},'expiry':{'expires_at':999},
          'replay':{'nonce':''},'content':{'content':'unapproved'},
          'evidence':{'evidence':{**lab.request('negative')['evidence'],'unvalidated':True}},
          'precondition':{'evidence':{'before_sha256':'0'*64}},'enforcement':{'action':'delete'}}
        if kind=='acl':
            before=lab.resource.read_bytes()
            _,worker,process=lab.agent('negative','single_write')
            wrote=lab.resource.read_bytes()!=before
            negative={'worker':worker,'process_exit':process['exit_code'],'host_changed':wrote}
        elif kind=='nonce_consumption':
            negative=lab.check_request('negative',{'nonce':'positive'})
            wrote=negative['before_sha256']!=negative['after_sha256']
        elif kind=='policy_pin':
            negative=lab.check_request('negative',preexecute=lambda:lab.policy_path.write_bytes(canonical({**lab.policy,'max_bytes':129})))
            wrote=negative['before_sha256']!=negative['after_sha256']
        elif kind=='resource_identity':
            def substitute():
                lab.resource.rename(lab.secure/'previous.txt')
                lab.resource.write_bytes(b'approved:positive');win.acl(lab.root,lab.resource,lab.principal)
            negative=lab.check_request('negative',preexecute=substitute)
            wrote=negative['before_sha256']!=negative['after_sha256']
        else:
            negative=lab.check_request('negative',patches[kind])
            wrote=negative['before_sha256']!=negative['after_sha256']
        report={'kind':kind,'positive_ok':positive_ok,'negative_wrote':wrote,'positive':positive,'negative':negative}
        write(out/'witness.json',report)
        print(json.dumps({'kind':kind,'positive_ok':positive_ok,'negative_wrote':wrote}))
    finally:lab.close()


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('kind');p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    run(a.kind,a.out.absolute())
