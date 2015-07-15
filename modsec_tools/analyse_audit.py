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


def rule_summary(_entries):
    # Print a summary of the rules used.
    s = "\nRule Summary\n"
    warnings = {'No rules matched': 0}
    for e in _entries:
        _obj = _entries[e]
        if len(_obj.rules) == 0:
            warnings['No rules matched'] += 1
        for r in _obj.rules:
            n = warnings.setdefault(r.unique, 0)
            warnings[r.unique] = n + 1

    for w in sorted(warnings):
        if warnings[w] == 0:
            continue
        s += "  {:6d}: {}\n".format(warnings[w], w)
    return s


def file_summary(_entries):
    # Print a summary of the rules used.
    files = {}
    s = "\nFile Summary\n"
    for e in _entries:
        _obj = _entries[e]
        for r in _obj.rules:
            ff = files.setdefault(r.tag(b'file'), {'lines': {}})
            n = ff['lines'].setdefault(r.tag(b'line'), 0)
            ff['lines'][r.tag(b'line')] = n + 1

    for f in sorted(files):
        s += "  {}\n".format(f.decode())
        for ln in sorted(files[f]['lines']):
            s += "      Line {:>5s}: {}\n".format(ln.decode(),
                                                  files[f]['lines'][ln])
    return s


def client_summary(_entries):
    clients = {}
    s = "\nClient Summary\n"
    for e in _entries:
        _obj = _entries[e]
        n = clients.setdefault(_obj.remote_addr, 0)
        clients[_obj.remote_addr] = n + 1

    for c in sorted(clients):
        s += "  {:>15s}: {:10d}".format(c.decode(), clients[c])
    return s


def uri_summary(_entries):
    uris = {}
    s = "\nHost/URI Summary\n"
    for e in _entries:
        _obj = _entries[e]
        uris.setdefault(_obj.host, {}).setdefault(_obj.uri, {})
        for r in _obj.rules:
            n = uris[_obj.host][_obj.uri].setdefault(r.unique, 0)
            uris[_obj.host][_obj.uri][r.unique] = n + 1

    for h in sorted(uris):
        s += "  {}\n".format(h)
        for u in sorted(uris[h]):
            s += "    {}\n".format(u)
            if len(uris[h][u]) == 0:
                s += "      No mod_security2 rules were matched.\n"
            for r in sorted(uris[h][u]):
                s += "      {:60s}: {}\n".format(r, uris[h][u][r])
    return s


def has_filters(args):
    for a in dir(args):
        if a.startswith('filter'):
            v = getattr(args, a)
            if v:
                return True
    return False


def main():
    parser = argparse.ArgumentParser(description='Analyse audit information from mod_security2')
    parser.add_argument('--rule-summary', action='store_true', help='Print a summary of rules triggered')
    parser.add_argument('--file-summary', action='store_true', help='Print a summary of rule files used')
    parser.add_argument('--client-summary', action='store_true', help='Print a summary of clients')
    parser.add_argument('--uri-summary', action='store_true', help='Print a summary of host/uri requests')

    parser.add_argument('--filter', help='String to match for rule message')
    parser.add_argument('--filter-id', help='Filter by ID of rule')
    parser.add_argument('--filter-host', help='Hostname to filter requests for')
    parser.add_argument('--filter-no-rule', action='store_true', help='Only include requests with no rules matched')
    parser.add_argument('--filter-rules', action='store_true',
                        help='Only include requests that match at least one rule')
    parser.add_argument('--filter-response', type=int, help='Filter for given response code')
    parser.add_argument('--filter-uid', help="Filter for unique id's")
    parser.add_argument('--filter-client', help="Filter for client IP")
    parser.add_argument('--filter-uri', help='Filter for URI containing supplied text')
    parser.add_argument('--show-requests', action='store_true', help='Output request and response details')
    parser.add_argument('--show-full', action='store_true', help='Show full log entry information')
    parser.add_argument('--include-headers', action='store_true', help="Show request/response headers in output")
    parser.add_argument('files', nargs="*", help="Audit file(s) to parse")

    args = parser.parse_args()
    entries = {}

    if len(args.files) == 0:
        print("No files specified, nothing to do :-)")
        sys.exit(0)

    if args.filter is not None and args.filter_id is not None:
        print("Are you sure you want to specify both text & ID for filters?")

    if args.show_requests and args.show_full:
        print("You have asked for requests and full output which will generate a lot of information. " +
              "Are you sure you mean this?")

    if args.filter_no_rule and args.filter_rules:
        print("You can't specify --filter-no-rule and --filter-rules together!")
        sys.exit(0)

    for fn in args.files:
        process_file(fn, entries)
    print("\nTotal of {} entries were found.".format(len(entries)))

    if has_filters(args):
        print("\nApplying requested filters...")
        if args.filter_host is not None:
            print("    - host must contain '{}'".format(args.filter_host))
        if args.filter is not None:
            print("    - rule message must contain '{}'".format(args.filter))
        if args.filter_id is not None:
            print("    - rule ID must be {}".format(args.filter_id))
        if args.filter_rules:
            print("    - at least one rule must be matched")
        elif args.filter_no_rule:
            print("    - request must have triggered no rules")
        if args.filter_uid:
            print("    - request unique_id must contain '{}'".format(args.filter_uid))
        if args.filter_client:
            print("    - remote IP address must contain '{}'".format(args.filter_client))
        if args.filter_uri:
            print("    - requested URI must contain '{}'".format(args.filter_uri))

        filtered = {}
        for _e in entries:
            _obj = entries[_e]
            if args.filter_uid is not None:
                if args.filter_uid in _obj.unique_id:
                    filtered[_e] = _obj
                continue
            if args.filter_host is not None:
                if _obj.host is None or not _obj.matches_host(args.filter_host):
                    continue
            if args.filter is not None and not _obj.filter(args.filter):
                continue
            if args.filter_id is not None and _obj.filter_id(args.filter_id):
                continue
            if args.filter_no_rule and len(_obj.rules) > 0:
                continue
            if args.filter_rules and len(_obj.rules) == 0:
                continue
            if args.filter_response and _obj.response != args.filter_response:
                continue
            if args.filter_client and args.filter_client not in _obj.remote_addr:
                continue
            if args.filter_uri and args.filter_uri not in _obj.uri:
                continue

            filtered[_e] = _obj

        entries = filtered
        print("\nAfter filtering, {} entries were left.".format(len(entries)))

    if len(entries) > 0:
        if args.rule_summary:
            print(rule_summary(entries))

        if args.file_summary:
            print(file_summary(entries))

        if args.client_summary:
            print(client_summary(entries))

        if args.uri_summary:
            print(uri_summary(entries))

        if args.show_requests:
            print("\nREQUEST SUMMARIES:")
            for e in entries:
                print(entries[e].as_string(args.include_headers))

        if args.show_full:
            print("\nFULL REQUEST LOG:")
            for e in entries:
                print(entries[e].raw_data())

    print("\nFinished.")