"""Make sense of log files: parse lines, find their templates, spot unusual rates and group incidents.

Template mining follows the idea of Drain (He et al. 2017): lines with the same length and the same
fixed words share a template, and the parts that vary, such as ids and addresses, become <*>.
"""
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

MONTHS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}
LEVELS = {"TRACE": 0, "DEBUG": 1, "INFO": 2, "NOTICE": 2, "WARN": 3, "WARNING": 3, "ERROR": 4, "ERR": 4, "CRITICAL": 5, "CRIT": 5, "FATAL": 5, "ALERT": 5, "EMERG": 5}
FORMATS = [
    ("apache", re.compile(r'(?P<host>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<msg>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)')),
    ("iso", re.compile(r"(?P<time>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+(?:\[?(?P<level>[A-Za-z]+)\]?:?\s+)?(?P<msg>.*)")),
    ("syslog", re.compile(r"(?P<time>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<proc>[^:\[]+)(?:\[\d+\])?: (?P<msg>.*)")),
]
VARIABLE = [(re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<IP>"), (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<ID>"), (re.compile(r"\b0x[0-9a-f]+\b", re.I), "<HEX>"), (re.compile(r"\b[0-9a-f]{12,}\b", re.I), "<HEX>"), (re.compile(r"(?<![\w.])-?\d+(?:\.\d+)?(?:ms|s|kb|mb|gb|%)?(?![\w.])", re.I), "<NUM>")]
SECRET = re.compile(r"(?i)(password|passwd|pwd|secret|api[_-]?key|token|authorization)(\s*[=:]\s*)(\S+)")


@dataclass
class Event:
    time: datetime
    level: str
    message: str
    source: str = ""
    raw: str = ""


def redact(text):
    """Hide values that look like credentials, so that a report cannot leak them."""
    return SECRET.sub(lambda m: m.group(1) + m.group(2) + "[hidden]", text)


def parse_time(kind, text, year):
    if kind == "apache":
        return datetime.strptime(text.split()[0], "%d/%b/%Y:%H:%M:%S")
    if kind == "syslog":
        parts = text.split()
        h, m, s = map(int, parts[2].split(":"))
        return datetime(year, MONTHS[parts[0]], int(parts[1]), h, m, s)
    return datetime.strptime(text.replace("T", " "), "%Y-%m-%d %H:%M:%S")


def parse_line(line, year=2026):
    """Read one line, or return None if no known format fits."""
    line = line.rstrip("\r\n")
    for kind, rx in FORMATS:
        m = rx.fullmatch(line)
        if not m:
            continue
        g = m.groupdict()
        try:
            t = parse_time(kind, g["time"], year)
        except (ValueError, KeyError):
            continue
        msg = g.get("msg") or ""
        level = (g.get("level") or "").upper()
        if kind == "apache":
            s = int(g["status"])
            level = "ERROR" if s >= 500 else "WARN" if s >= 400 else "INFO"
            msg = f"{msg} {s}"
        elif level not in LEVELS:
            if level:
                msg = f"{g.get('level')} {msg}"
            low = msg.lower()
            level = "ERROR" if re.search(r"\b(error|failed|failure|fatal|panic|denied|refused)\b", low) else "WARN" if re.search(r"\b(warn|warning|timeout|retry)\b", low) else "INFO"
        return Event(t, level if level in LEVELS else "INFO", redact(msg), g.get("proc") or g.get("host") or "", redact(line))
    return None


def parse(lines, year=2026):
    """Returns (events, count of lines that could not be read). Stack traces join the event above."""
    out, bad = [], 0
    for line in lines:
        if not line.strip():
            continue
        e = parse_line(line, year)
        if e:
            out.append(e)
        elif out and line[:1] in (" ", "\t"):
            out[-1].raw += "\n" + redact(line.rstrip())
        else:
            bad += 1
    return out, bad


def mask(message):
    for rx, tag in VARIABLE:
        message = rx.sub(tag, message)
    return message


class Miner:
    """Group messages into templates. Same token count and at least `similarity` of the fixed words."""

    def __init__(self, similarity=0.6):
        self.similarity = similarity
        self.groups = defaultdict(list)     # (length, first token) -> [[template tokens, count]]

    def add(self, message):
        tokens = mask(message).split()
        if not tokens:
            return "<empty>"
        key = (len(tokens), tokens[0] if not tokens[0].startswith("<") else "<*>")
        best, best_score = None, -1.0
        for g in self.groups[key]:
            same = sum(1 for a, b in zip(g[0], tokens) if a == b or a == "<*>")
            score = same / len(tokens)
            if score > best_score:
                best, best_score = g, score
        if best is not None and best_score >= self.similarity:
            best[0] = [a if a == b else "<*>" for a, b in zip(best[0], tokens)]
            best[1] += 1
            return " ".join(best[0])
        self.groups[key].append([tokens, 1])
        return " ".join(tokens)

    def templates(self):
        rows = [(" ".join(g[0]), g[1]) for gs in self.groups.values() for g in gs]
        return sorted(rows, key=lambda t: -t[1])


def counts(events, minutes=5, level=None):
    """Events per time bucket, with empty buckets filled in, as [(start, count)]."""
    if not events:
        return []
    first = min(e.time for e in events)
    start = first - timedelta(minutes=first.minute % minutes, seconds=first.second)
    c = Counter()
    last = 0
    for e in events:
        i = int((e.time - start).total_seconds() // (minutes * 60))
        last = max(last, i)
        if level is None or LEVELS[e.level] >= LEVELS[level]:
            c[i] += 1
    return [(start + timedelta(minutes=minutes * i), c[i]) for i in range(last + 1)]


def median(v):
    s = sorted(v)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def anomalies(series, window=24, threshold=4.0, floor=3):
    """Flag buckets far above the recent norm, using the median and MAD. A burst of errors does not
    distort these the way it distorts a mean and standard deviation, so a spike cannot hide itself."""
    out = []
    values = [v for _, v in series]
    for i in range(3, len(values)):
        past = values[max(0, i - window):i]
        m = median(past)
        mad = median([abs(x - m) for x in past])
        spread = max(1.4826 * mad, math.sqrt(max(m, 1)))
        z = (values[i] - m) / spread
        if z >= threshold and values[i] >= floor:
            out.append({"time": series[i][0], "count": values[i], "expected": m, "score": z})
    return out


def incidents(events, gap=timedelta(minutes=10), level="ERROR"):
    """Group errors that happen close together, since one failure usually writes many lines."""
    errs = sorted((e for e in events if LEVELS[e.level] >= LEVELS[level]), key=lambda e: e.time)
    groups = []
    for e in errs:
        if groups and e.time - groups[-1][-1].time <= gap:
            groups[-1].append(e)
        else:
            groups.append([e])
    out = []
    for g in groups:
        mined = Counter(mask(e.message) for e in g)
        out.append({"start": g[0].time, "end": g[-1].time, "count": len(g), "first": g[0].message, "top": mined.most_common(3), "sources": sorted({e.source for e in g if e.source})})
    return sorted(out, key=lambda x: -x["count"])


class Rule:
    """Alert when a pattern appears at least `limit` times within `minutes`."""

    def __init__(self, name, pattern, limit=5, minutes=5):
        self.name, self.rx, self.limit, self.minutes = name, re.compile(pattern, re.I), limit, minutes

    def run(self, events):
        hits = [e.time for e in events if self.rx.search(e.message)]
        hits.sort()
        out = []
        i = 0
        window = timedelta(minutes=self.minutes)
        last_alert = None
        for j, t in enumerate(hits):
            while t - hits[i] > window:
                i += 1
            if j - i + 1 >= self.limit and (last_alert is None or t - last_alert > window):
                out.append({"rule": self.name, "time": t, "count": j - i + 1})
                last_alert = t
        return out


def summary(events, bad=0):
    if not events:
        return {"events": 0, "unread": bad}
    levels = Counter(e.level for e in events)
    errors = sum(n for k, n in levels.items() if LEVELS[k] >= LEVELS["ERROR"])
    return {"events": len(events), "unread": bad, "first": min(e.time for e in events), "last": max(e.time for e in events), "levels": dict(levels), "error_rate": errors / len(events)}
