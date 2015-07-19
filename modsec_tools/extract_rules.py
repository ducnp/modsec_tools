import argparse
from datetime import datetime
import os
import sys
import re
import shutil

from modsec_tools.files import RulesFile
from modsec_tools.filter import build_parser, parse_and_filter, extract_file_data, extract_rule_data, has_filters, \
    filter_description


class Rule(object):
    RULE_re = re.compile(b"^SecRule\s+([\w\d&:\-_]+)\s+\"(.*?)\"\s+\"(.*)\"")

    def __init__(self, lines):
        self.vars = self.op = None
        self.actions = []
        if len(lines) == 0:
            return

        sl = ''
        for l in [a.strip() for a in lines]:
            sl += l if not l.endswith('\\') else l[:-1]

        ck = self.RULE_re.match(sl)
        if ck is None:
            print("Unable to parse...'{}'".format(sl))
            return

        self.vars = ck.group(1)
        self.op = ck.group(2)
        self.actions = ck.group(3).split(',')

    def as_string(self, chain=False):
        pre = '' if chain is False else '\t'
        s = "{}SecRule {} \"{}\" \\\n".format(pre, self.vars, self.op)
        s += "{}\t\"{}\"\n".format(pre, ",".join(self.actions))
        return s

    def is_chain(self):
        return 'chain' in self.actions

    def add_action(self, what):
        if self.op is None or what in self.actions:
            return
        self.actions.append(what)

    def remove_action(self, what):
        if self.op is None or what not in self.actions:
            return
        self.actions = [a for a in self.actions if a != what]

    @property
    def has_file(self):
        return self.op.startswith('@pmFromFile')

    @property
    def file(self):
        if not self.op.startswith('@pmFromFile'):
            return ''
        return self.op.split(' ', 1)[1]


class RuleSummary(object):
    RULE_re = re.compile(b"^SecRule\s+([\w\d&:\-_]+)\s+\"(.*?)\"\s+\"(.*)\"", re.MULTILINE)

    def __init__(self, rule):
        self.obj = rule
        self.rules = []
        self.actions = []
        self.vars = self.op = None
        self.n = 0

    @property
    def msg(self):
        return self.obj.tag(b'msg')

    @property
    def file(self):
        return self.obj.tag(b'file')

    @property
    def line(self):
        return int(self.obj.tag(b'line'))

    @property
    def id(self):
        return self.obj.tag('id')

    def increment(self):
        self.n += 1

    def __add__(self, other):
        self.n += other

    def get_rules(self, rf):
        r = Rule(rf.get_rule(self.line))
        if r.op is None:
            return
        self.rules.append(r)
        if r.is_chain():
            rr = Rule(rf.get_rule(self.line + 1))
            if rr.op is not None:
                self.rules.append(rr)

    def as_string(self):
        if len(self.rules) == 0:
            return ''
        s = "#\n" + \
            "# {}\n".format(self.msg) + \
            "# Triggered {} times\n".format(self.msg, self.n) + \
            "# Original Rule:\n" + \
            "#   ID:   {}\n".format(self.id) + \
            "#   file: {}\n".format(self.file) + \
            "#   line: {}\n".format(self.line) + \
            "#\n"

        chain = False
        for r in self.rules:
            s += r.as_string(chain)
            chain = self.rules[0].is_chain()

        return s

    @property
    def is_part_of_chain(self):
        if len(self.rules) == 0:
            return False
        return self.rules[0].is_chain()

    def add_action(self, what):
        if len(self.rules) == 0:
            return
        self.rules[0].add_action(what)

    def remove_action(self, what):
        if len(self.rules) == 0:
            return
        self.rules[0].remove_action(what)

    @property
    def needs_files(self):
        for r in self.rules:
            if r.has_file:
                return True
        return False

    def file_list(self):
        files = []
        for rr in [r for r in self.rules if r.has_file]:
            fn = rr.file
            if os.path.isabs(fn):
                files.append(fn)
            else:
                files.append(os.path.join(os.path.dirname(self.file), fn))

        return files


def main():
    parser = argparse.ArgumentParser(description='Analyse audit logs and extract rules')
    build_parser(parser)
    parser.add_argument('--ignore', type=int, default=20,
                        help='Level below which to ignore rules (default=20)')
    parser.add_argument('--block', action='store_true', help='Set all rules to block')
    parser.add_argument('--log', action='store_true', help='Set all rules to log')
    parser.add_argument('--nolog', action='store_true', help='Set all rules to NOT log')
    parser.add_argument('--deny', action='store_true', help='Set all rules to deny')
    parser.add_argument('--allow', action='store_true', help='Set all rules to allow')
    parser.add_argument('--skip-conf', help='Ignore rules from the file specified')
    parser.add_argument('--copy-files', action='store_true', help='Attempt to copy required files')

    args = parser.parse_args()

    if args.log and args.nolog:
        print("You cannot use --log and --nolog at the same time. D'uh.")
        sys.exit(0)

    if args.allow and (args.block or args.deny):
        print("Using --allow and --block or --deny won't work.")
        sys.exit(0)

    if args.copy_files and args.output is None:
        print("Unable to copy any files as you haven't specified an output filename.")

    entries = parse_and_filter(args)

    if len(entries) == 0:
        print("No entries to work with... Nothing to do :-)")
        sys.exit(0)

    rules = {}
    files = {}
    for e in entries:
        for rr in entries[e].rules:
            rules.setdefault(rr.tag(b'msg'), RuleSummary(rr)).increment()

    print("\nGetting a list of rules to be extracted...\n")
    for r in rules:
        rr = rules[r]
        if rr.n < args.ignore:
            print("  - '{}' is below ignore threshold, ignoring...".format(rr.msg))
            continue

        files.setdefault(rr.file, {'rules': []})['rules'].append(rr)

    print("\nComplete.\n\nExtracting rules...")
    for fn in files:
        if not os.path.exists(fn):
            print("  - {} does not exist, skipping.".format(fn))
            continue
        if args.skip_conf == fn:
            print("  - skipping file {} due --skip-conf setting".format(fn))
            continue

        rf = RulesFile(fn)
        for r in files[fn]['rules']:
            r.get_rules(rf)
            if args.block:
                r.add_action('block')
            if args.deny:
                r.add_action('deny')
            if args.allow:
                r.add_action('allow')
                r.remove_action('deny')
                r.remove_action('block')
            if args.log:
                r.add_action('log')
                r.remove_action('nolog')
            elif args.nolog:
                r.add_action('nolog')
                r.remove_action('log')

    fh = sys.stdout if args.output is None else open(args.output, 'w')

    fh.write("# Automatically generated file by extract_rules\n")
    fh.write("# https://github.com/zathras777/modsec_tools\n#\n")
    fh.write("# Created {}\n".format(datetime.today()))
    fh.write("# Files analysed:\n")
    for fn in args.files:
        fh.write("#    - {}\n".format(fn))
    fh.write("#\n")

    if has_filters(args):
        fh.write("# Filter Criteria:\n")
        for crit in filter_description(args):
            fh.write("#    - {}\n".format(crit))
        fh.write("#\n")

    fh.write("# Total of {} audit log entries analysed.\n#\n\n".format(len(entries)))

    file_list = []
    for r in rules:
        rr = rules[r]
        if rr.n < args.ignore:
            continue
        fh.write(rr.as_string())
        fh.write("\n\n")

        if rr.needs_files:
            file_list.extend(rr.file_list())

    if len(file_list) > 0:
        print("\nAdditional files are needed for some rules:\n")
        for fn in list(set(file_list)):
            print("  - {}".format(fn))
            if args.output is not None and args.copy_files:
                if os.path.exists(fn):
                    nfn = os.path.join(os.path.dirname(args.output), os.path.basename(fn))
                    if not os.path.exists(nfn):
                        print("      found file, attempting to copy...")
                        shutil.copy(fn, nfn)
                    else:
                        print("      file already exists in required location")
                else:
                    print("      file not found, unable to copy.")
        print("\n")

    if args.output is not None:
        fh.close()
        print("\nNew rule file saved to {}".format(args.output))
