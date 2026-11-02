import random
import unittest
from datetime import datetime, timedelta

from logsentinel import Event, Miner, Rule, anomalies, counts, incidents, mask, parse, parse_line, redact, summary

T = datetime(2026, 11, 2, 9, 0)


def ev(minutes, level="INFO", msg="ok"):
    return Event(T + timedelta(minutes=minutes), level, msg)


class TestParsing(unittest.TestCase):
    def test_iso(self):
        e = parse_line("2026-11-02 09:15:30,123 ERROR database connection failed")
        self.assertEqual((e.time.minute, e.level, e.message), (15, "ERROR", "database connection failed"))
        self.assertEqual(parse_line("2026-11-02T09:15:30Z [warn] slow query").level, "WARN")

    def test_syslog(self):
        e = parse_line("Nov  2 09:15:30 web1 sshd[123]: Failed password for root from 10.0.0.5 port 22 ssh2")
        self.assertEqual((e.time.month, e.source, e.level), (11, "sshd", "ERROR"))

    def test_apache(self):
        e = parse_line('10.0.0.1 - - [02/Nov/2026:09:15:30 +0600] "GET /index.html HTTP/1.1" 500 1234')
        self.assertEqual((e.level, e.source), ("ERROR", "10.0.0.1"))
        self.assertEqual(parse_line('1.1.1.1 - - [02/Nov/2026:09:15:30 +0600] "GET / HTTP/1.1" 404 1').level, "WARN")
        self.assertEqual(parse_line('1.1.1.1 - - [02/Nov/2026:09:15:30 +0600] "GET / HTTP/1.1" 200 -').level, "INFO")

    def test_level_is_guessed_from_words(self):
        self.assertEqual(parse_line("2026-11-02 09:15:30 connection refused by peer").level, "ERROR")

    def test_unknown_lines_are_counted_not_lost(self):
        events, bad = parse(["hello there", "2026-11-02 09:15:30 INFO ok"])
        self.assertEqual((len(events), bad), (1, 1))

    def test_bad_dates_are_not_accepted(self):
        self.assertIsNone(parse_line("2026-13-40 09:15:30 INFO ok"))

    def test_stack_traces_join_their_event(self):
        events, bad = parse(["2026-11-02 09:15:30 ERROR boom", "  File x.py, line 3", "    raise E"])
        self.assertEqual(bad, 0)
        self.assertIn("raise E", events[0].raw)


class TestRedaction(unittest.TestCase):
    def test_credentials_are_hidden(self):
        for text in ("password=hunter2", "API_KEY: abc123", "token = xyz", "Authorization: Bearer"):
            out = redact(text)
            self.assertIn("[hidden]", out)
        self.assertNotIn("hunter2", redact("login password=hunter2 ok"))

    def test_events_are_redacted(self):
        e = parse_line("2026-11-02 09:15:30 INFO connect password=hunter2")
        self.assertNotIn("hunter2", e.message + e.raw)

    def test_normal_text_is_untouched(self):
        self.assertEqual(redact("user logged in"), "user logged in")


class TestTemplates(unittest.TestCase):
    def test_mask(self):
        self.assertEqual(mask("from 10.0.0.5:22 took 15ms id 0xdead"), "from <IP> took <NUM> id <HEX>")
        self.assertEqual(mask("user 7f3a9c2e-1111-2222-3333-444455556666"), "user <ID>")

    def test_digits_inside_words_stay(self):
        self.assertEqual(mask("ipv6 on eth0"), "ipv6 on eth0")

    def test_lines_group_by_shape(self):
        m = Miner()
        for i in range(50):
            m.add(f"User u{i} logged in from 10.0.0.{i}")
            m.add(f"Disk {i} is full")
        t = m.templates()
        self.assertEqual(len(t), 2)
        self.assertEqual(t[0][1], 50)
        self.assertIn("User <*> logged in from <IP>", [x[0] for x in t])

    def test_different_messages_stay_apart(self):
        m = Miner()
        m.add("Connection opened to the server")
        m.add("Backup finished without any errors")
        self.assertEqual(len(m.templates()), 2)

    def test_recovers_planted_templates(self):
        rng = random.Random(1)
        shapes = ["Sent {} bytes to {}", "Worker {} started job {}", "Cache miss for key {} on {}", "Timeout after {} ms calling {}"]
        m = Miner()
        for _ in range(2000):
            m.add(rng.choice(shapes).format(rng.randint(1, 10 ** 6), f"host{rng.randint(1, 50)}"))
        self.assertEqual(len(m.templates()), 4)
        self.assertEqual(sum(n for _, n in m.templates()), 2000)


class TestRates(unittest.TestCase):
    def series(self, values):
        return [(T + timedelta(minutes=5 * i), v) for i, v in enumerate(values)]

    def test_counts_fill_empty_buckets(self):
        c = counts([ev(0), ev(1), ev(16)], 5)
        self.assertEqual([x[1] for x in c], [2, 0, 0, 1])

    def test_level_filter(self):
        self.assertEqual(sum(x[1] for x in counts([ev(0, "ERROR"), ev(1), ev(2, "WARN")], 5, "WARN")), 2)

    def test_spike_is_found(self):
        rng = random.Random(2)
        v = [rng.randint(8, 12) for _ in range(60)]
        v[40] = 90
        hits = anomalies(self.series(v))
        self.assertEqual([x["count"] for x in hits], [90])

    def test_normal_noise_raises_few_alarms(self):
        rng = random.Random(3)
        v = [sum(rng.random() < 0.1 for _ in range(100)) for _ in range(500)]
        self.assertLess(len(anomalies(self.series(v))), 8)

    def test_a_spike_does_not_hide_the_next_one(self):
        v = [10] * 30 + [100] + [10] * 3 + [100] + [10] * 5
        self.assertEqual(len(anomalies(self.series(v))), 2)

    def test_quiet_logs_ignore_tiny_blips(self):
        self.assertEqual(anomalies(self.series([0] * 30 + [2] + [0] * 5)), [])

    def test_no_data(self):
        self.assertEqual(counts([]), [])
        self.assertEqual(anomalies([]), [])


class TestIncidents(unittest.TestCase):
    def test_errors_group_by_time(self):
        e = [ev(0, "ERROR", "db down 1"), ev(3, "ERROR", "db down 2"), ev(60, "ERROR", "disk full"), ev(5)]
        out = incidents(e)
        self.assertEqual([i["count"] for i in out], [2, 1])
        self.assertEqual(out[0]["first"], "db down 1")
        self.assertEqual(out[0]["top"][0], ("db down <NUM>", 2))

    def test_no_errors(self):
        self.assertEqual(incidents([ev(0)]), [])


class TestRules(unittest.TestCase):
    def test_rule_fires_at_the_limit(self):
        e = [ev(i, "ERROR", "Failed password") for i in range(5)]
        self.assertEqual(Rule("ssh", "failed password", 5, 5).run(e)[0]["count"], 5)
        self.assertEqual(Rule("ssh", "failed password", 6, 5).run(e), [])

    def test_slow_events_do_not_fire(self):
        self.assertEqual(Rule("x", "y", 3, 5).run([ev(i * 10, msg="y") for i in range(10)]), [])

    def test_a_long_burst_does_not_flood_alerts(self):
        self.assertLessEqual(len(Rule("x", "y", 3, 5).run([ev(i * 0.2, msg="y") for i in range(50)])), 2)


class TestSummary(unittest.TestCase):
    def test_summary(self):
        s = summary([ev(0, "ERROR"), ev(1), ev(2), ev(3)], 2)
        self.assertEqual((s["events"], s["unread"], s["error_rate"]), (4, 2, 0.25))
        self.assertEqual(summary([])["events"], 0)


if __name__ == "__main__":
    unittest.main()
