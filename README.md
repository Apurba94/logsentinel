# LogSentinel

A log file with a million lines usually says only a few dozen different things. LogSentinel finds those things, spots unusual bursts, and groups errors into incidents. It uses only the Python standard library.

```
python -m logsentinel app.log
```

```python
from logsentinel import Miner, Rule, anomalies, counts, incidents, parse

with open("app.log", encoding="utf-8") as f:
    events, unread = parse(f)

print(incidents(events)[:3])
print(anomalies(counts(events, level="ERROR")))
print(Rule("ssh attacks", "failed password", limit=5, minutes=5).run(events))
```

## What it does

- **Parses** ISO timestamps, syslog and Apache or nginx access logs, and attaches stack traces to the event above them. Lines it cannot read are counted, not lost
- **Finds templates:** `User u17 logged in from 10.0.0.5` and a million like it become one line, in the spirit of the Drain algorithm
- **Spots unusual bursts** using the median and MAD. A mean and standard deviation are pulled up by the very spike they should catch, and these are not
- **Groups incidents:** errors close in time become one incident, with the first message, which is often the cause
- **Alert rules** for a pattern repeated within a time window, without a flood of repeats
- **Hides secrets:** values after words such as `password` and `token` are replaced before anything is stored or shown

## How it is tested

Template mining must recover four planted message shapes from 2,000 random lines. Anomaly detection must find a planted spike, stay quiet on normal noise, and find a second spike soon after the first. Tests also confirm that a password in a line never reaches an event.

## Limits

It reads whole files, so it does not follow live logs. It knows three common formats, and other formats are counted as unread, so check that number. Syslog lines have no year, so pass it in. Redaction catches common patterns only, so treat logs as sensitive. Times are read as written, with no time zone conversion. Rules are for review, and are not an intrusion detection system.

## Tests

```
python -m unittest discover -s tests
```

MIT licence.
