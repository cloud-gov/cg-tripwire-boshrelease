#!/var/vcap/packages/python3
# -*- coding: utf-8 -*-

import re
import sys
import shutil
import tempfile
import collections

alert = re.compile(r'^".+"$')
label = re.compile(r'[^a-z_]', re.IGNORECASE)

def summarize(path):
    with open(path) as fp:
        lines = fp.readlines()
    counts = {}
    section = None
    for line in lines:
        if line.startswith('Rule Name:'):
            section = line.split('Rule Name:')[-1].strip()
            counts[section] = collections.defaultdict(int)
            action = None
        elif line.strip() == 'Added:':
            action = 'add'
        elif line.strip() == 'Modified:':
            action = 'modify'
        elif line.strip() == 'Removed:':
            action = 'remove'
        elif section is not None and action is not None and alert.match(line):
            counts[section][action] += 1
    return counts


def format_summary(summary, output):
    with tempfile.NamedTemporaryFile(delete=False) as fp:
        for section, counts in summary.items():
            for action, value in counts.items():
                fp.write('tripwire_violation_count {{section="{section}",action="{action}"}} {value}\n'.format(
                    section=label.sub('_', section.split('(')[0].strip().lower()),
                    action=action,
                    value=value,
                ))
    shutil.move(fp.name, output)


if __name__ == "__main__":
    report = sys.argv[1]
    output = sys.argv[2]

    summary = summarize(report)
    format_summary(summary, output)
