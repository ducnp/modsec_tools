import sys
import gzip
import re
import os
import argparse

from event import AuditInfo

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

def print_rule_summary(_entries):
    # Print a summary of the rules used.
    print("\nRule Summary\n")
    warnings = {}
    for e in _entries:
        _obj = entries[e]
        for r in _obj.rules:
            uniq = "{} [{} {}]".format(r.tag(b'msg').decode(),
                                       r.tag(b'id').decode(),
                                       r.tag(b'severity').decode())
            n = warnings.setdefault(uniq, 0)
            warnings[uniq] = n + 1

    for w in sorted(warnings):
        print("  {:6d}: {}".format(warnings[w], w))

def print_file_summary(_entries):
    # Print a summary of the rules used.
    files = {}
    print("\nFile Summary\n")
    for e in _entries:
        _obj = entries[e]
        for r in _obj.rules:
            ff = files.setdefault(r.tag(b'file'), {'lines': {}})
            n = ff['lines'].setdefault(r.tag(b'line'), 0)
            ff['lines'][r.tag(b'line')] = n + 1

    for f in sorted(files):
        print("  {}".format(f.decode()))
        for ln in sorted(files[f]['lines']):
            print("      Line {:>5s}: {}".format(ln.decode(),
                                                 files[f]['lines'][ln]))

def print_client_summary(_entries):
    clients = {}
    print("\nClient Summary\n")
    for e in _entries:
        _obj = _entries[e]
        n = clients.setdefault(_obj.remote_addr[0], 0)
        clients[_obj.remote_addr[0]] = n + 1

    for c in sorted(clients):
        print("  {:>15s}: {:10d}".format(c.decode(), clients[c]))

def main():
    parser = argparse.ArgumentParser(description='Analyse audit information from mod_security2')
    parser.add_argument('--rule-summary', action='store_true', help='Print a summary of rules triggered')
    parser.add_argument('--file-summary', action='store_true', help='Print a summary of rule files used')
    parser.add_argument('--client-summary', action='store_true', help='Print a summary of clients')
    parser.add_argument('--filter', help='String to match for rule message')
    parser.add_argument('--filter-id', help='Filter by ID of rule')
    parser.add_argument('files', nargs="*", help="Audit file(s) to parse")

    args = parser.parse_args()
    entries = {}

    if len(args.files) == 0:
        print("No files specified, nothing to do :-)")
        sys.exit(0)

    if args.filter is not None and args.filter_id is not None:
        print("Are you sure you want to specify both text & ID for filters?")

    for fn in args.files:
        process_file(fn, entries)
    print("Total of {} entries were found.".format(len(entries)))

    if args.filter is not None or args.filter_id is not None:
        print("Applying requested filters...")
        filtered = {}
        for _e in entries:
            _obj = entries[_e]
            if (args.filter is not None and _obj.filter(args.filter)) or \
                    (args.filter_id is not None and _obj.filter_id(args.filter_id)):
                filtered[_e] = _obj
                continue
        entries = filtered
        print("    done\nAfter filtering, {} entries were left.".format(len(entries)))

    if args.rule_summary:
        print_rule_summary(entries)

    if args.file_summary:
        print_file_summary(entries)

    if args.client_summary:
        print_client_summary(entries)
