#!/usr/bin/env python3
"""Exercise Rust appraisal against public native evidence and negative variants.

Run verify_native_aci.py first. Policy variants are local test inputs and never
update governance. Tampered evidence retains the original, now-invalid outer
signature; this does not produce or claim a signed malformed hardware report.
"""
import argparse
import copy
import hashlib
import json
import pathlib
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    parser.add_argument('--bundle', type=pathlib.Path, required=True)
    args = parser.parse_args()
    root = args.bundle.resolve()
    binary = args.binary.resolve()
    now = int((root / 'verification-time.txt').read_text())
    policy = json.loads((root / 'policy.json').read_text())
    variants = root / 'variants'
    def altered_policy(label, change):
        altered = copy.deepcopy(policy)
        change(altered)
        path = variants / (label + '.json')
        path.write_text(json.dumps(altered, indent=2) + '\n')
        return path
    cases = []
    def case(name, error=None, profile='azure-aci-snp', evidence='evidence.cose', spki='spki.der', policy_path=None, meaning=None):
        cases.append(dict(name=name, error=error, profile=profile, evidence=root/evidence, spki=root/spki,
                          policy_path=policy_path or root/'policy.json', meaning=meaning))
    case('positive-native-capture')
    case('wrong-spki', 'SIGNATURE_INVALID', spki='variants/wrong-spki.der', meaning='Different valid P256 SPKI fails outer ES256 signature; captured key was never exported.')
    case('report-tamper', 'SIGNATURE_INVALID', evidence='variants/report-tamper.cose', meaning='Altered captured measurement byte retains old outer signature; rejected before native report appraisal.')
    case('padding-tamper', 'SIGNATURE_INVALID', evidence='variants/padding-tamper.cose', meaning='Altered captured report-data padding retains old outer signature; this is not a freshly hardware-signed malformed-padding report.')
    case('unsupported-profile', 'UNSUPPORTED_PROFILE', profile='host-amd-sev-snp')
    case('inactive-profile', 'PROFILE_NOT_ACTIVE', policy_path=altered_policy('inactive-profile', lambda p: p.update(active_profiles=[])))
    case('wrong-cce', 'CCE_HOST_DATA_REJECTED', policy_path=altered_policy('wrong-cce', lambda p: p.update(approved_host_data=['00'*32])))
    case('wrong-measurement', 'MEASUREMENT_REJECTED', policy_path=altered_policy('wrong-measurement', lambda p: p.update(approved_measurements=['00'*48])))
    for component in ['bootloader', 'tee', 'snp', 'microcode']:
        def raise_minimum(p, component=component):
            p['minimum_tcb']['Genoa'][component] += 1
        case('tcb-below-minimum-'+component, 'TCB_BELOW_MINIMUM', policy_path=altered_policy('tcb-'+component, raise_minimum),
             meaning='Unchanged genuine report fails a component-wise policy minimum raised above the captured platform.')
    case('uvm-svn-below-minimum', 'UVM_SVN_BELOW_MINIMUM', policy_path=altered_policy('minimum-uvm-svn', lambda p: p['uvm'][0].update(minimum_svn=105)))
    case('expired-policy', 'POLICY_NOT_VALID', policy_path=altered_policy('expired-policy', lambda p: p.update(valid_until=now)))
    case('future-policy', 'POLICY_NOT_VALID', policy_path=altered_policy('future-policy', lambda p: p.update(valid_from=now+1)))
    case('strict-uvm-current-certificate', 'CERTIFICATE_INVALID', policy_path=altered_policy('strict-uvm-current-certificate', lambda p: p.update(uvm_endorsement_time_policy='current_certificate')),
         meaning='The genuine immutable Microsoft UVM publisher certificate is expired at verification time; exact approved-release policy is required for this capture.')
    case('wrong-uvm-feed', 'UVM_IDENTITY_REJECTED', policy_path=altered_policy('wrong-uvm-feed', lambda p: p['uvm'][0].update(feed='Wrong-Feed')))
    results = []
    for item in cases:
        command = [str(binary), item['profile'], str(item['evidence']), str(item['spki']), str(item['policy_path']), str(now)]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=30)
        row = {'case': item['name'], 'exit_code': completed.returncode, 'expected_error': item['error'],
               'actual_error': completed.stderr.strip() or None, 'meaning': item['meaning'],
               'evidence': str(item['evidence'].relative_to(root)), 'spki': str(item['spki'].relative_to(root)),
               'policy': str(item['policy_path'].relative_to(root)), 'profile': item['profile']}
        if item['error'] is None:
            assert completed.returncode == 0, row
            appraisal = json.loads(completed.stdout)
            assert bytes(appraisal['evidence_digest']).hex() == hashlib.sha256((root/'evidence.cose').read_bytes()).hexdigest()
            assert bytes(appraisal['spki_sha256']).hex() == hashlib.sha256((root/'spki.der').read_bytes()).hexdigest()
            assert appraisal['valid_until'] > now
            (root/'verified-appraisal.json').write_text(completed.stdout)
        else:
            assert completed.returncode != 0 and completed.stderr.strip().startswith(item['error']), row
        row['passed'] = True
        results.append(row)
    output = {'verification_time': now, 'appraiser_binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'positive_cases': 1, 'negative_cases': len(results)-1, 'all_passed': True, 'results': results}
    (root/'appraisal-results.json').write_text(json.dumps(output, indent=2)+'\n')
    print(json.dumps({'positive_cases':1,'negative_cases':len(results)-1,'all_passed':True},indent=2))

if __name__ == '__main__':
    main()
