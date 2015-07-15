import re
from datetime import datetime, timedelta

class AuditRule(object):
    TAG_re = re.compile(b"Message: (.*?)\s+\[(.*)\](.*)?")
    TAGS_re = re.compile(b"\]\s*\[")
    """ Each time a rule is applied to a request the details will be specified
        by a Message: entry in section H. This class interprets that information.

    """
    def __init__(self, info):
        self.tags = {}
        tags = (self.TAG_re.match(info))
        if tags is None:
            return
        self.summary = tags.group(1).decode()
        self.error = tags.group(3).decode()
        _tags = []
        for _i in self.TAGS_re.split(tags.group(2)):
            if b' ' not in _i:
                continue
            k, v = _i.split(b' ', 1)
            v = v.decode().replace('"', '')
            if k == b'tag':
                _tags.append(v)
            else:
                self.tags[k] = v
        self.tags[b'tag'] = ", ".join(_tags)
        if b'msg' not in self.tags:
            self.tags[b'msg'] = self.summary + ' ' + self.error

    def tag(self, which):
        return self.tags.get(which, b'')

    @property
    def unique(self):
        return "{} [{} {}]".format(self.tag(b'msg'),
                                   self.tag(b'id'),
                                   self.tag(b'severity'))


class AuditInfo(object):
    """ Each event recorded in the audit log has a range of sections, specified
        by letters.

        A: Header (mandatory)
        B: Request Headers
        C: Request Body
        D: -- reserved
        E: Response Body
        F: Response Headers
        G: -- reserved
        H: Audit Log Trailer
        I: Compact Request Body
        J: -- reserved
        K: List of matching rules
        Z: Final section (mandatory)
    """
    HEADER_re = re.compile(b"\[(.*)\] ([A-Za-z0-9\\\@\-]+) ([0-9\.]+) ([0-9]+) ([0-9\.]+) ([0-9]+)")
    REQUEST_re = re.compile(b'[A-Z]{3,}\s+(.*)\s+HTTP')

    def __init__(self, audit_fn):
        self.audit_fn = audit_fn
        self.sections = {}
        self.tags = {}
        self.rules = []
        self.unique_id = None
        self.audit_id = None
        self.date_time = None
        self.local_addr = self.remote_addr = None
        self.local_port = self.remote_port = None
        self.mode = None
        self.host = self.uri = None
        self.response = 0

    def __str__(self):
        return "AuditRecord: {} : connection from {} [{}] {} rule(s)".format(
            self.audit_id, self.remote_addr, self.audit_fn, len(self.rules))

    def filter(self, filter_str):
        """
        :param filter_str: String to filter on, rule msg only at present.
        :return: True or False
        """
        for r in self.rules:
            if filter_str in r.tag(b'msg'):
                return True
        return False

    def filter_id(self, _id):
        """
        :param filter_str: String to filter on, rule msg only at present.
        :return: True or False
        """
        for r in self.rules:
            if r.tag(b'id') == _id:
                return True
        return False

    def matches_host(self, _host):
        """ Check if host matches.
        :param _host: Hostname to look for.
        :return: True or False
        """
        return _host.lower() in self.host.lower()

    def add_section(self, match_info):
        """ match_info should be a list with 3 elements,
            - audit id
            - section letter
            - log lines
        :param match_info: 3 element list
        :return: None
        """
        if self.audit_id is None:
            self.audit_id = match_info[0]
        elif self.audit_id != match_info[0]:
            raise Exception("Trying to add section from {} to {}".format(self.id, match_info[0]))

        if match_info[1] in self.sections:
            raise Exception("Duplicate scetion {} for audit ID {}".format(match_info[1], match_info[0]))

        self.sections[match_info[1]] = match_info[2]

        if match_info[1] == b'A':
            self._parse_header()
        elif match_info[1] == b'B':
            self._find_host_uri()
        elif match_info[1] == b'F':
            self._find_response_code()
        elif match_info[1] == b'H':
            self._extract_tags()

    def request_header(self, which):
        for hdr in self.sections.get(b'B'):
            k, v = hdr.split(':', 1)
            print(k, v)

    def as_string(self, inc_headers=False):
        """ Return a formatted string giving a summary of the request.
        :return: Formatted string
        """
        s = b''
        for hdr in [('Unique ID', 'unique_id'),
                    ('Audit File', 'audit_fn'),
                    ('URI', 'uri'),
                    ('Host', 'host'),
                    ('Date/Time', 'date_time'),
                    ('Remote Address', 'remote_addr'),
                    ('Response Code', 'response')]:
            s += b'    {:20s}: {}\n'.format(hdr[0], getattr(self, hdr[1]))

        def add_header_list(_hdrs, title):
            hh = b'    {}\n'.format(title)
            for h in _hdrs:
                hh += b'      {}\n'.format(h)
            return hh
        if inc_headers:
            s += add_header_list(self.sections.get('B', []), 'Request Headers:')
        s += b'    {:20s}: {}\n'.format('# of Rules Matched', len(self.rules))
        for r in self.rules:
            s += b'      -  {}\n'.format(r.tag('msg'))
            s += b'         ID: {}, Severity: {}\n'.format(r.tag('id'), r.tag('severity'))
            s += b'         File: {}\n'.format(r.tag('file'))
        if inc_headers:
            s += add_header_list(self.sections.get('F', []), 'Response Headers:')

        return s.decode()

    def raw_data(self):
        """ Return a formatted string giving full request information.
        :return: Formatted string
        """
        s = b''
        for hdr in [('Unique ID', 'unique_id'),
                    ('Audit File', 'audit_fn'),
                    ('URI', 'uri'),
                    ('Host', 'host'),
                    ('Date/Time', 'date_time'),
                    ('Remote Address', 'remote_addr'),
                    ('Response Code', 'response')]:
            s += b'    {:20s}: {}\n'.format(hdr[0], getattr(self, hdr[1]))
        for sect in [('Request Header', b'B'),
                     ('Request Body', b'C'),
                     ('Audit Log', b'H'),
                     ('Response Headers', b'F'),
                     ('Response Body', b'E')]:
            data = self.sections.get(sect[1], [])
            s += b'  {} Section\n'.format(sect[0])
            if len(data) == 0:
                s += b'    EMPTY\n'
            else:
                s += b'    ' + b'\n    '.join(data)
                s += '\n'

        return s.decode('ascii', 'ignore')

    def _parse_header(self):
        hdr_line = self.sections.get(b'A', [''])[0]
        #[11/Jul/2015:09:25:29 +0000] VaDhCJBM6u8AADsjpKoAAAAW 80.82.78.96 52018 144.76.234.239 80
        hdr = self.HEADER_re.match(hdr_line)
        if hdr is None:
            return

        # %z is only available in Python 3.1 onwards, so...
        self.date_time = datetime.strptime(hdr.group(1)[:-6].decode(), "%d/%b/%Y:%H:%M:%S")
        if hdr.group(1)[-4:] != b'0000':
            diff = timedelta(seconds=(int(hdr.group(1)[-4:-2]) * 60 + int(hdr.group(1)[-2:])) * 60)
            if hdr.group(1)[-5] == b'-':
                self.date_time += diff
            else:
                self.date_time -= diff
        self.unique_id = hdr.group(2)
        self.remote_addr = hdr.group(3)
        self.remote_port = hdr.group(4)
        self.local_addr = hdr.group(5)
        self.local_port = hdr.group(6)

    def _find_host_uri(self):
        for line in self.sections.get(b'B', ['']):
            if b'host:' in line.lower():
                ignore, self.host = line.split(b':', 1)
                self.host = self.host.strip()
            else:
                ck = self.REQUEST_re.match(line)
                if ck is not None:
                    self.uri = ck.group(1)

    def _find_response_code(self):
        r = self.sections.get(b'F')
        if r is None or len(r) == 0:
            return
        self.response = int(r[0].split(b' ')[1])

    def _extract_tags(self):
        for l in self.sections.get(b'H', []):
            if l.startswith(b'Message: ') and b'[' in l:
                self.rules.append(AuditRule(l))
            elif l.startswith(b'Engine-Mode:'):
                _ignore, self.mode, _ignore = l[13:].split(b'"')
