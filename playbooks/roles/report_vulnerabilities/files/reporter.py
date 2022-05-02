import json
import glob
import sys
import os
import requests
import time


icons = {
    'CRITICAL': ':red_circle:',
    'HIGH': ':large_orange_circle:',
    'MEDIUM': ':large_yellow_circle:',
    'LOW': ':large_green_circle:',
    'UNKNOWN': ':black_circle:',
}
sorted_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
slack_endpoint = 'https://slack.com/api/chat.postMessage'


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
        if 'RepoTags' in data['Metadata'].keys():
            image = data['Metadata']['RepoTags'][0]
        else:
            image = data['Metadata']['ImageID']

        # ST-1159: Skip duplicate images
        if image in reports.keys():
            reports[image]['hosts'].append(hostname)
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
        reports[image] = report

    # ST-1159: Return all generated reports
    return reports


# ST-1159: Message to slack
def message_to_slack(token: str, message: str) -> str:
    time.sleep(1)
    data = {
        "channel": "C03DQMEMRMY",
        "unfurl_links": False,
        "unfurl_media": False,
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{message}"
                }
            }
        ]
    }
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json; charset=utf-8',
    }
    response = None
    while not response or response.status_code != 200:
        time.sleep(1)
        response = requests.post(
            url=slack_endpoint, 
            data=json.dumps(data), 
            headers=headers
        )
    return response.json()['ts']


# ST-1159: Message to slack thread
def message_to_slack_thread(token: str, message: str, thread: str) -> None:
    data = {
        "channel": "C03DQMEMRMY",
        "thread_ts": thread,
        "unfurl_links": False,
        "unfurl_media": False,
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{message}"
                }
            }
        ]
    }
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json; charset=utf-8',
    }
    response = None
    while not response or response.status_code != 200:
        time.sleep(1)
        response = requests.post(
            url=slack_endpoint, 
            data=json.dumps(data), 
            headers=headers
        )


# ST-1159: Report the issues found to slack
def report_to_slack(webhook: str, reports: dict) -> None:
    for repotag in reports.keys():
        # ST-1159: Join hosts list into readable form
        hosts = '; '.join(reports[repotag]['hosts'])

        # ST-1159: Generate vulnerabilities summary
        summary = ''
        issues = reports[repotag]['issues']
        for level in [x for x in sorted_levels if x in issues.keys()]:
            summary = f"{summary}{icons[level]} {len(issues[level].keys())} "
            
        # ST-1159: Congratulate on 0 vulnerabilities :D
        if not summary:
            summary = ":tada: None!"

        # ST-1159: Send a header for the report
        msg = f":rotating_light: *Image Scan Report:* {repotag}"
        msg = f"{msg}\n:desktop_computer: *Running on Hosts:* {hosts}"
        msg = f"{msg}\n:radioactive_sign: *Vulnerabilities:* {summary}"
        thread = message_to_slack(webhook, msg)
        msg = ''

        # ST-1159: For each severity level
        for level in [x for x in sorted_levels if x in issues.keys()]:
            msg = f"{msg}\n {icons[level]} *{level}*\n"
            for issue in issues[level].items():
                # ST-1159: Add a link to the issue if there is one
                if issue[1]:
                    msg = f"{msg} <{issue[1]}|{issue[0]}>;"
                else:
                    msg = f"{msg} {issue[0]};"

                # ST-1159: Truncate the message if it gets too long
                if len(msg) > 2000:
                    message_to_slack_thread(webhook, msg, thread)
                    msg = ''

            # ST-1159: Send the issues found
            message_to_slack_thread(webhook, msg, thread)
            msg = ''


if __name__ == "__main__":
    token = sys.argv[1]
    pathglob = sys.argv[2]
    reports = aggregate_reports(pathglob)
    report_to_slack(token, reports)
