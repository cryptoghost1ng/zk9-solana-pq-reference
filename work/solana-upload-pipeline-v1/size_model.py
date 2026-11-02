"""Proof size against trace width. Fits a line through the two SEND relations (v2 baseline and v3 public-binding liveness, sizes from the project's own paired benchmark) and checks it
against the WITHDRAW relation, a point that was not used in the fit, using the width read by width-probe and the proofs inside the archived withdraw wires. Also records the
prediction that failed (the withdraw width). Read-only: archived wires, the probe output and the project's benchmark numbers.
usage: size_model.py LABEL   (new label each time)"""
import json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent;WORK=ROOT.parent
label=sys.argv[1] if len(sys.argv)==2 else None
assert label and re.fullmatch(r'[a-z0-9-]+',label);out=ROOT/'evidence'/(label+'.json');assert not out.exists()
CAP=WORK/'solana-multiwallet-privacy-v1/evidence/privacy-live-02/public-capsule'
probe={json.loads(l)['relation'].split(' (')[0]:json.loads(l) for l in (ROOT/'evidence/width-01.stdout').read_text().splitlines() if l.startswith('{')}
w_send_v2=probe['send v2']['width'];w_send_v3=probe['send v3 public-binding liveness']['width'];w_wd=probe['withdraw v2']['width']
# sizes of the paired native benchmark (CHATGPT-HANDOFF-2026-10-15-V3-TRANSPORT-QUALIFIED.txt): baseline v2 3893829 bytes, candidate v3 median 2968715.5 bytes
p_v2,p_v3=3893829,2968715.5
slope=(p_v2-p_v3)/(w_send_v2-w_send_v3);fixed=p_v2-slope*w_send_v2
def proof_len(name,start):return (CAP/name).stat().st_size-start
checks=[]
for name,start,w in (('3d7c8907982a26eb.withdraw.wire',481+3464,w_wd),('bad3d160130343d1.withdraw.wire',481+3464,w_wd),('2e0996342aed43b1.send.wire',440+3464,w_send_v3),('8e99c8bf5aef087b.send.wire',440+3464,w_send_v3)):
    n=proof_len(name,start);pred=slope*w+fixed
    checks.append({'wire':name,'kind':name.split('.')[1],'trace_width_used':w,'proof_bytes':n,'model_bytes':round(pred),'error_percent':round(100*(pred-n)/n,2),'used_in_the_fit':name.endswith('send.wire')})
# input-mmcs compute against width (two points; NOT a validation)
mm_send,mm_wd=523.2e6,710.0e6
a=(mm_wd-mm_send)/((w_wd+8)-(w_send_v3+8));b=mm_send-a*(w_send_v3+8)
res={'widths':{'send_v2':w_send_v2,'send_v3_public_binding_liveness':w_send_v3,'withdraw_v2':w_wd},
 'proof_size_model':{'slope_bytes_per_column':round(slope,2),'fixed_bytes':round(fixed),'expected_slope_from_structure':'64 queries x 4 bytes = 256 for the opened main-trace rows, plus 2 opening points x 8 base-field coefficients x 4 bytes = 64 for out-of-domain openings: 320',
  'fitted_on':'the two send relations','checked_on':'the withdraw relation (width read independently by the probe)','checks':checks},
 'failed_prediction':{'written_before_building_the_probe':'width-probe/PREDICTION.txt','predicted_withdraw_width':10214,'accepted_range':[9900,10500],'measured':w_wd,'result':'MISSED (+%.1f %% over the prediction, outside the accepted range)'%(100*(w_wd-10214)/10214),
  'probable_cause':'the Merkle-opening stage is not proportional to width alone: a two-point fit gives %.1f K compute units per column plus a fixed %.0f M, so the compute ratio (1.357) understates the width ratio (1.425). That fit has two points and is not a validation.'%(a/1e3,b/1e6)},
 'input_mmcs_two_point_fit':{'compute_units_per_column':round(a),'fixed_compute_units':round(b),'width_proportional_share_of_the_send_v3_stage':round(a*(w_send_v3+8)/mm_send,3)},
 'what_if_not_verified':{'withdraw_with_the_same_absolute_width_reduction_as_send_v3':{'width':w_wd-(w_send_v2-w_send_v3),'proof_bytes':round(slope*(w_wd-(w_send_v2-w_send_v3))+fixed)},
  'note':'Whether the public-binding change of v3 applies to the withdraw relation is an untested hypothesis.'},
 'scope':'Arithmetic over measured widths and archived proof sizes. Says nothing about security parameters, privacy or mainnet cost.'}
out.write_text(json.dumps(res,indent=1)+'\n');print(json.dumps({k:res[k] for k in ('widths','failed_prediction')},indent=1));print(json.dumps(checks,indent=1))
