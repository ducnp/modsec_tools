import sys
import argparse

from modsec_tools.filter import parse_and_filter, build_parser, extract_file_data


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
    s = "\nFile Summary\n"
    files = extract_file_data(_entries)
    for f in sorted(files):
        s += "  {}\n".format(f)
        for ln in sorted(files[f]['lines']):
            s += "      Line {:>5s}: {}\n".format(ln, files[f]['lines'][ln])
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


def main():
    parser = argparse.ArgumentParser(description='Analyse audit information from mod_security2')
    parser.add_argument('--rule-summary', action='store_true', help='Print a summary of rules triggered')
    parser.add_argument('--file-summary', action='store_true', help='Print a summary of rule files used')
    parser.add_argument('--client-summary', action='store_true', help='Print a summary of clients')
    parser.add_argument('--uri-summary', action='store_true', help='Print a summary of host/uri requests')

    build_parser(parser)
    args = parser.parse_args()
    entries = parse_and_filter(args)

    if len(entries) > 0:
        fh = sys.stdout if args.output is None else open(args.output, 'w')

        if args.rule_summary:
            fh.write(rule_summary(entries))

        if args.file_summary:
            fh.write(file_summary(entries))

        if args.client_summary:
            fh.write(client_summary(entries))

        if args.uri_summary:
            fh.write(uri_summary(entries))

        if args.show_requests:
            fh.write("\nREQUEST SUMMARIES:\n")
            for e in entries:
                fh.write(entries[e].as_string(args.include_headers))

        if args.show_full:
            fh.write("\nFULL REQUEST LOG:\n")
            for e in entries:
                fh.write(entries[e].raw_data())
        if args.output is not None:
            fh.close()
            print("\nOutput saved to {}".format(args.output))

    print("\nFinished.")