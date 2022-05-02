import json
import glob
import sys
import os


# ST-1159: Identify the host being reported on
def get_hostname(filepath: str) -> str:
    # ST-1159: Remove the last two fields separated by _ from the filename
    basename = os.path.basename(filepath)
    return '_'.join(basename.split('_')[:-2])


# ST-1159: Aggregate reports to ease reporting
def aggregate_reports(pathglob: str) -> dict:
    reports = {}

    # ST-1159: Open the vulnerability report
    for filepath in glob.glob(pathglob):
        with open(filepath, 'r') as fd:
            data = json.load(fd)

        hostname = get_hostname(filepath)
        repoTag = data['Metadata']['RepoTags'][0]

        # ST-1159: Skip duplicate images
        if repoTag in reports.keys():
            reports[repoTag]['hosts'].append(hostname)
            continue

        # ST-1159: Create a report for the repoTag
        report = {
            'hosts': [hostname],
            'issues': {},
        }

        # ST-1159: Retrieve vulnerabilities
        for result in data.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                issues = report['issues'].get(vuln['Severity'], {})
                issues[vuln['VulnerabilityID']] = vuln.get('PrimaryURL', None)
                report['issues'][vuln['Severity']] = issues

        # ST-1159: Save the generated repotag report
        reports[repoTag] = report

    # ST-1159: Return all generated reports
    return reports


# ST-1159: Report the issues found to slack
def report_to_slack(webhook: str, reports: dict) -> None:
    pass


if __name__ == "__main__":
    webhook = sys.argv[1]
    pathglob = sys.argv[2]
    reports = aggregate_reports(pathglob)
    report_to_slack(webhook, reports)
