"""The daily batch: close a day of events, then roll it up.

    day_closed -> deduplicate -> summarize -> reconcile

security_events is written event by event, at least once. For a closed day
this makes the stored events exact (no copies waiting for a merge) and
builds the small tables a dashboard or a morning report reads instead of
scanning a day of events:

    daily_summary      events per type and decision (additive)
    daily_rule_hits    events per rule and decision
    daily_top_sources  the 50 most-blocked sources

Every step is idempotent: running a day twice, or backfilling a month,
gives the same tables.
"""

from datetime import date, datetime, timedelta

EVENTS = "watchtower.security_events"
DAY = "toDate(timestamp) = {day:Date}"

# How long after midnight the stream must have written events before the
# day counts as closed. Events reach ClickHouse within seconds of being
# sent (docs/streaming.md), so two minutes past midnight means the
# previous day's are all in.
CLOSE_MARGIN = timedelta(minutes=2)
# A day this long past its end is closed regardless -- a quiet stream, or a
# backfill of old days, must not wait forever.
CLOSE_ANYWAY = timedelta(hours=1)

TOP_SOURCES = 50


def _day(value):
    """A date, from a date, a datetime or an ISO string -- and nothing else,
    which is what makes it safe to spell into ALTER ... PARTITION (it
    takes no parameters)."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return datetime.fromisoformat(str(value)).date()


def day_closed(ch, day_end, now):
    if now >= day_end + CLOSE_ANYWAY:
        return True
    after = ch.value(
        f"SELECT count() FROM {EVENTS} "
        "WHERE timestamp >= toDateTime64({since:String}, 3, 'UTC') "
        "  AND timestamp < toDateTime64({since:String}, 3, 'UTC') + INTERVAL 1 HOUR",
        since=(day_end + CLOSE_MARGIN).strftime("%Y-%m-%d %H:%M:%S"),
    )
    return bool(after)


def duplicates(ch, day):
    """Rows the merge has yet to fold. FINAL merges while reading, in
    bounded memory; uniqExact(event_id) would hold a day of ids at once
    (~1.4 GB for 43M events)."""
    return ch.value(
        f"SELECT (SELECT count() FROM {EVENTS} WHERE {DAY}) "
        f"     - (SELECT count() FROM {EVENTS} FINAL WHERE {DAY})",
        day=_day(day),
    ) or 0


def deduplicate(ch, day):
    """Merge away the day's replayed copies. Returns how many there were.

    OPTIMIZE ... FINAL rewrites the whole partition, so it only runs when
    there is something to fold.
    """
    day = _day(day)
    found = duplicates(ch, day)
    if found:
        ch.command(f"OPTIMIZE TABLE {EVENTS} PARTITION '{day.isoformat()}' FINAL")
    return found


SUMMARY = f"""
INSERT INTO watchtower.daily_summary (day, event_type, recommended_action, events, sources, suspicious)
SELECT toDate(timestamp) AS d, event_type, recommended_action,
       count(), uniqExact(source_ip), countIf(is_suspicious = 1)
FROM {EVENTS} FINAL
WHERE {DAY}
GROUP BY d, event_type, recommended_action
"""

RULE_HITS = f"""
INSERT INTO watchtower.daily_rule_hits (day, rule, recommended_action, events, sources)
SELECT toDate(timestamp) AS d, rule, recommended_action, count(), uniqExact(source_ip)
FROM {EVENTS} FINAL
ARRAY JOIN splitByChar(',', toString(rule_hits)) AS rule
WHERE {DAY} AND rule_hits != ''
GROUP BY d, rule, recommended_action
"""

TOP = f"""
INSERT INTO watchtower.daily_top_sources
    (day, source_ip, events, blocked, alerted, first_seen, last_seen, rules)
SELECT toDate(timestamp) AS d, toString(source_ip) AS ip, count(),
       countIf(recommended_action = 'block') AS blocked,
       countIf(recommended_action = 'alert') AS alerted,
       min(timestamp), max(timestamp),
       arraySort(arrayFilter(r -> r != '',
                             groupUniqArrayArray(splitByChar(',', toString(rule_hits)))))
FROM {EVENTS} FINAL
WHERE {DAY}
GROUP BY d, ip
HAVING blocked + alerted > 0
ORDER BY blocked DESC, alerted DESC, ip
LIMIT {TOP_SOURCES}
"""

TABLES = ("daily_summary", "daily_rule_hits", "daily_top_sources")


def summarize(ch, day):
    """Rebuild the day in every daily table. Returns rows per table."""
    day = _day(day)
    for table, sql in zip(TABLES, (SUMMARY, RULE_HITS, TOP)):
        ch.command(f"ALTER TABLE watchtower.{table} DROP PARTITION '{day.isoformat()}'")
        ch.command(sql, day=day)
    return {
        table: ch.value(f"SELECT count() FROM watchtower.{table} WHERE day = {{day:Date}}", day=day)
        for table in TABLES
    }


def reconcile(ch, day):
    """The summary must account for every stored event of the day, exactly.

    Returns (summarized, stored); the DAG fails when they differ. A
    difference means events for the day arrived after the rollup -- re-run
    the day.
    """
    day = _day(day)
    summarized = ch.value("SELECT sum(events) FROM watchtower.daily_summary WHERE day = {day:Date}", day=day)
    stored = ch.value(f"SELECT count() FROM {EVENTS} FINAL WHERE {DAY}", day=day)
    return int(summarized or 0), int(stored or 0)
