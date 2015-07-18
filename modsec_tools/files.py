import gzip
import re
import os
from modsec_tools.event import AuditInfo

SECTION_re = re.compile(b"--(\w{8})-([A-Z])--")
UNIQUE_ID_re = re.compile(b"\[.*\]\s+([A-Za-z0-9\\\@\-]+)\s+")
AUDIT_IDS = {}


def process_file(_fn, _entries):
    # Process a log file, which may be gzipped, line by line to rebuild
    # audit log events.
    if not os.path.exists(_fn):
        print("File {} does not exist. Skipping...".format(_fn))
        return

    print("  Processing {}".format(_fn))
    if _fn.endswith('.gz'):
        fh = gzip.open(_fn, 'rb')
    else:
        fh = open(_fn, 'rb')

    parts = []
    for line in [l.strip() for l in fh.readlines()]:
        ck = SECTION_re.match(line)
        if ck is not None:
            if len(parts) != 0:
                if parts[1] == b'A':
                    uid = UNIQUE_ID_re.match(parts[2][0])
                    if uid is None:
                        raise Exception("Unable to find unique id.")
                    AUDIT_IDS[parts[0]] = uid.group(1)

                _entries.setdefault(AUDIT_IDS[parts[0]], AuditInfo(_fn)).add_section(parts)
            parts = [ck.group(1), ck.group(2), []]
        else:
            if len(line) > 0:
                parts[2].append(line)
    fh.close()


class RulesFile(object):
    def __init__(self, fn):
        with open(fn, 'r') as fh:
            self.lines = fh.readlines()

    def get_rule(self, line):
        """ Given the line number reported in the modsec_audit.log entry,
            get all lines that constitute the rule.
             NB We assume the line numbers start at 1, whereas the lines are
                stored in a 0 referenced list, so we always remove 1.
        :param line: The line number
        :return: List of rule lines.
        """
        line -= 1
        rule_lines = []
        n = 0
        while True:
            ln = self.lines[line - n].strip()
            n += 1
            if ln == '' and len(rule_lines) > 0:
                break
            if ln.startswith('#'):
                continue
            rule_lines.insert(0, ln)
            if ln.startswith('SecRule'):
                break

        return rule_lines
