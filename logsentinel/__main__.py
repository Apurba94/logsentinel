"""Summarise a log file: python -m logsentinel FILE [year]"""
import sys

from . import Miner, anomalies, counts, incidents, parse, summary


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    with open(argv[1], encoding="utf-8", errors="replace") as f:
        events, bad = parse(f, int(argv[2]) if len(argv) > 2 else 2026)
    s = summary(events, bad)
    print(f"{s['events']} events, {s['unread']} lines not understood")
    if not events:
        return 0
    print(f"from {s['first']} to {s['last']}, error rate {s['error_rate']:.1%}, levels {s['levels']}")
    m = Miner()
    for e in events:
        m.add(e.message)
    print("\ncommon messages:")
    for t, n in m.templates()[:10]:
        print(f"{n:>7}  {t[:100]}")
    print("\nunusual bursts of errors:")
    for a in anomalies(counts(events, level="ERROR"))[:10]:
        print(f"  {a['time']}: {a['count']} errors, usually about {a['expected']:g}")
    print("\nincidents:")
    for i in incidents(events)[:10]:
        print(f"  {i['start']} to {i['end']}: {i['count']} errors. First: {i['first'][:90]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
