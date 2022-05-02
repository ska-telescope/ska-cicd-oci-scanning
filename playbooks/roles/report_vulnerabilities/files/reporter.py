import json
import glob
import sys

default = 'Unreported'
count = 0
# ST-1159: Open the vulnerability report
for filename in glob.glob(sys.argv[1]):
    with open(filename, 'r') as fd:
        data = json.load(fd)

    count = count + 1
    # ST-1159: Retrieve the desired information
    for result in data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            report = {
                'target': result.get('Target', default),
                'id': result.get('VulnerabilityID', default),
                'package': result.get('PkgName', default),
                'installed_version': result.get('InstalledVersion', default),
                'fixed_version': result.get('FixedVersion', default),
                'url': result.get('PrimaryURL', default),
                'severity': result.get('Severity', default),
                'msg': result.get('Description', default),
            }

            # TODO: make pretty message for slack
            # TODO: Report to slack

print(count)
