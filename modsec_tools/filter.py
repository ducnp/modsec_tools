import sys
from modsec_tools.files import process_file


def has_filters(args):
    for a in dir(args):
        if a.startswith('filter'):
            v = getattr(args, a)
            if v:
                return True
    return False


def build_parser(parser):
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
    parser.add_argument('--output', help='File to save output into')
    parser.add_argument('files', nargs="*", help="Audit file(s) to parse")


def extract_rule_data(_entries):
    warnings = {}
    for e in _entries:
        _obj = _entries[e]
        if len(_obj.rules) == 0:
            continue
        for r in _obj.rules:
            n = warnings.setdefault(r.unique, 0)
            warnings[r.unique] = n + 1
    return warnings


def extract_file_data(_entries):
    files = {}
    for e in _entries:
        _obj = _entries[e]
        for r in _obj.rules:
            ff = files.setdefault(r.tag(b'file'), {'lines': {}})
            n = ff['lines'].setdefault(r.tag(b'line'), 0)
            ff['lines'][r.tag(b'line')] = n + 1
    return files


def filter_description(args):
    desc = []
    if args.filter_host is not None:
        desc.append("host must contain '{}'".format(args.filter_host))
    if args.filter is not None:
        desc.append("rule message must contain '{}'".format(args.filter))
    if args.filter_id is not None:
        desc.append("rule ID must be {}".format(args.filter_id))
    if args.filter_rules:
        desc.append("at least one mod_security2 rule must have been triggered")
    elif args.filter_no_rule:
        desc.append("request must have triggered no rules")
    if args.filter_uid:
        desc.append("request unique_id must contain '{}'".format(args.filter_uid))
    if args.filter_client:
        desc.append("remote IP address must contain '{}'".format(args.filter_client))
    if args.filter_uri:
        desc.append("requested URI must contain '{}'".format(args.filter_uri))
    return desc


def parse_and_filter(args):
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
        print("\nApplying requested filters...\n")
        print("  - " + "\n  - ".join(filter_description(args)))

        filtered = {}
        for _e in entries:
            _obj = entries[_e]
            if args.filter_uid is not None:
                if args.filter_uid in _obj.unique_id:
                    filtered[_e] = _obj
                continue
            if args.filter_host is not None:
                if _obj.host is None or _obj.matches_host(args.filter_host) is False:
                    continue
            if args.filter is not None and _obj.filter(args.filter) is False:
                continue
            if args.filter_id is not None and _obj.filter_id(args.filter_id) is False:
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

    return entries
