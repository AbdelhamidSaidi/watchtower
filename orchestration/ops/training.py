"""Training the stream's ML detector (etl/core/ml.py), and promoting it.

    collect_labels   hourly: the simulator's ground truth for the closed hour,
                     read back out of Kafka, into watchtower.training_labels
                     (every attack event; normal ones sampled per source)
    dataset          labels joined to the features the pipeline stored;
                     a reviewer label outranks the simulator's
    train            LightGBM, sized for the stream (~5 us per event)
    evaluate         the candidate and the active model on the same holdout
                     -- events the reviewer never relabelled
    shadow           the candidate and the active model on the newest hour of
                     real traffic: how many alerts each would raise alone
    promote          only if the candidate is at least as good on both

A model never goes live because it is new, only because it measured
better on data neither model trained on -- and would not flood the SOC
with alerts on today's traffic.
"""

import io
import json
import math
import os
import random
import statistics
import time

from core import ml
from core.ml import FEATURES, Model, vector
from etl import config
from orchestration.ops.clickhouse import ClickHouse

# Normal events are ~97% of traffic; keeping them all would drown the
# attacks and fill the table, and a uniform sample would all but miss the
# quiet hosts -- a 2% sample left remote staff so thin that a model learned
# "external IP + data volume" as an attack and alerted on every VPN user.
# So up to PER_SOURCE normal events per source per hour are kept, each
# weighted by how many it stands for. Every attack event is kept.
PER_SOURCE = 5

# Sized for per-event scoring in the stream: ~100 trees x 15 leaves costs
# ~5 us compiled (tools/bench_model.py), 200 x 31 already ~16 us.
PARAMS = {
    "objective": "binary",
    "num_leaves": 15,
    "learning_rate": 0.08,
    "min_data_in_leaf": 40,
    "feature_fraction": 0.9,
    "bagging_fraction": 0.8,
    "bagging_freq": 1,
    "lambda_l2": 1.0,
    "verbose": -1,
    "num_threads": 2,
}
MAX_TREES = 120
MIN_ROWS = 2_000          # below this, a model says more about noise than traffic
MIN_ATTACKS = 200
# A reviewer label enters training only this sure, and weighs less than
# ground truth: an LLM is a second opinion, not an oracle.
REVIEW_MIN_CONFIDENCE = 0.8
REVIEW_WEIGHT = 0.5

# Shadow check: recent real traffic, scored by the candidate and the active
# model. Alerts the model raises alone -- no rule behind them -- go straight
# to an analyst, so a candidate may raise at most this share of events that
# way, not many more than the active model does, on not many more hosts.
# The sample spans SHADOW_HOURS and caps each source at SHADOW_PER_SOURCE:
# the newest hour alone once missed the one group of hosts a model was
# wrong about, and busy hosts would otherwise drown the quiet ones.
SHADOW_ROWS = 20_000
SHADOW_HOURS = 6
SHADOW_PER_SOURCE = 50
SHADOW_SAMPLE_PERCENT = 2       # read 2% of the window: bounded memory at any rate
MAX_MODEL_ALERT_SHARE = float(os.getenv("WATCHTOWER_ML_MAX_ALERT_SHARE", "0.005"))


# --- labels ------------------------------------------------------------------------

class NormalSampler:
    """Up to `per_source` normal events per source (a reservoir sample, so
    every event of a source has the same chance), each weighted by how many
    of that source's normal events it stands for: the weights of a source
    add up to its real count, so the model still sees the true base rate."""

    def __init__(self, per_source=PER_SOURCE, rng=None):
        self.per_source = per_source
        self.rng = rng or random.Random()
        self.sources = {}                    # source_ip -> [events seen, kept ids]

    def add(self, source_ip, event_id):
        slot = self.sources.setdefault(source_ip, [0, []])
        slot[0] += 1
        if len(slot[1]) < self.per_source:
            slot[1].append(event_id)
        else:
            j = self.rng.randrange(slot[0])
            if j < self.per_source:
                slot[1][j] = event_id

    def rows(self):
        return [{"event_id": event_id, "label": 0, "source": "simulator",
                 "weight": seen / len(kept), "detail": "normal"}
                for seen, kept in self.sources.values() for event_id in kept]


def collect_labels(start_ms, end_ms, per_source=PER_SOURCE, seed=None):
    """The simulator's labels for events appended to Kafka in [start, end).

    Streams through the hour once and keeps only what training needs --
    every attack event, and NormalSampler's share of normal ones -- so
    memory stays flat however busy the hour was. Returns rows for
    watchtower.training_labels.
    """
    import fastavro
    from kafka import KafkaConsumer, TopicPartition

    from schemas.registry import DEFAULT_SUBJECT, SchemaRegistry, unframe

    schemas = {sid: fastavro.parse_schema(json.loads(text))
               for sid, text in SchemaRegistry(config.SCHEMA_REGISTRY_URL).all_versions(DEFAULT_SUBJECT).items()}
    consumer = KafkaConsumer(bootstrap_servers=config.KAFKA_BOOTSTRAP_SERVERS, enable_auto_commit=False)
    # Seeded by the window: the same hour always gives the same sample, so a
    # re-run or backfill writes the same rows, which training_labels folds
    # (ReplacingMergeTree on event_id, source) -- never a second sample.
    normals = NormalSampler(per_source, random.Random(start_ms if seed is None else seed))
    rows = []
    try:
        partitions = [TopicPartition(config.KAFKA_TOPIC, p) for p in consumer.partitions_for_topic(config.KAFKA_TOPIC)]
        consumer.assign(partitions)
        first = consumer.offsets_for_times({tp: start_ms for tp in partitions})
        last = consumer.offsets_for_times({tp: end_ms for tp in partitions})
        ends = consumer.end_offsets(partitions)
        stop = {tp: (last[tp].offset if last[tp] else ends[tp]) for tp in partitions}
        remaining = set()
        for tp in partitions:
            begin = first[tp].offset if first[tp] else stop[tp]
            consumer.seek(tp, begin)
            if begin < stop[tp]:
                remaining.add(tp)
        while remaining:
            for tp, messages in consumer.poll(timeout_ms=2000, max_records=5000).items():
                for message in messages:
                    if message.offset >= stop[tp]:
                        remaining.discard(tp)
                        break
                    try:
                        schema_id, payload = unframe(message.value)
                        record = fastavro.schemaless_reader(io.BytesIO(payload), schemas[schema_id])
                    except Exception:
                        continue
                    scenario = record.get("scenario") or "normal"
                    if scenario == "normal":
                        normals.add(record.get("source_ip") or "", record["event_id"])
                        continue
                    rows.append({"event_id": record["event_id"], "label": 1,
                                 "source": "simulator", "weight": 1.0, "detail": scenario})
                if consumer.position(tp) >= stop[tp]:
                    remaining.discard(tp)
    finally:
        consumer.close()
    return rows + normals.rows()


# --- the dataset -------------------------------------------------------------------

def dataset(ch, since_days=14):
    """(rows, labels, weights, reviewed): features from security_events joined
    to their labels. Where both exist, the reviewer's label wins. `reviewed`
    marks rows relabelled by the reviewer -- kept out of the holdout."""
    # The labels are the small side, so they go on the right of the join:
    # ClickHouse builds its hash table from the right. The IN filter lets the
    # event_id bloom filter skip every granule without a labelled event.
    # Aliases differ from the column names on purpose: ClickHouse would read
    # `source` inside the other argMax()s as the aggregate alias.
    labels = ("SELECT event_id, argMax(label, (source = 'reviewer', labeled_at)) AS y, "
              "argMax(weight, (source = 'reviewer', labeled_at)) AS w, "
              "argMax(source, (source = 'reviewer', labeled_at)) AS src "
              "FROM watchtower.training_labels "
              "WHERE labeled_at > now() - toIntervalDay({d:UInt32}) GROUP BY event_id")
    columns = ", ".join(f"e.{c} AS {c}" for c in _stored_features())
    return ch.rows(
        f"SELECT toString(e.event_id) AS event_id, e.event_type AS event_type, {columns}, "
        "l.y AS label, l.w AS weight, l.src = 'reviewer' AS reviewed "
        f"FROM watchtower.security_events AS e INNER JOIN ({labels}) AS l ON e.event_id = l.event_id "
        "WHERE e.timestamp > now() - toIntervalDay({d:UInt32} + 1) "
        "AND e.event_id IN (SELECT event_id FROM watchtower.training_labels "
        "                   WHERE labeled_at > now() - toIntervalDay({d:UInt32}))",
        d=since_days,
    )


def _stored_features():
    """FEATURES minus the four event-type flags, which core.ml derives from
    event_type rather than reading a column."""
    derived = {"is_login_failure", "is_login_success", "is_command", "is_http"}
    return [f for f in FEATURES if f not in derived]


def matrix(rows):
    """Rows as the model sees them: core.ml.vector() on each."""
    return [vector(r) for r in rows]


# --- train, evaluate, promote ---------------------------------------------------------

def split(rows, holdout=0.2, seed=13):
    """Train / holdout, by a hash of the event so a rerun splits the same
    way. Reviewer-relabelled rows only ever train: judging a model on the
    reviewer's own opinions would reward agreeing with the reviewer."""
    import zlib

    train, test = [], []
    for r in rows:
        bucket = zlib.crc32(f"{seed}:{r.get('event_id', id(r))}".encode()) % 1000 / 1000
        (train if r["reviewed"] or bucket >= holdout else test).append(r)
    return train, test


def train(rows):
    import lightgbm as lgb
    import numpy as np

    x = np.asarray(matrix(rows), dtype=np.float64)
    y = np.asarray([int(r["label"]) for r in rows])
    return lgb.train(PARAMS, lgb.Dataset(x, y, weight=np.asarray(weights(rows)), feature_name=list(FEATURES),
                                         free_raw_data=True), num_boost_round=MAX_TREES)


def weights(rows):
    """Each row's training weight. A sampled normal row stands for many
    events (NormalSampler), so the model sees the real base rate: trained
    on counts, attacks look like most of the traffic and every score is
    inflated. A reviewer's label counts as REVIEW_WEIGHT of a typical
    sampled normal row -- next to rows worth dozens of events, its own
    weight of ~1 would be lost."""
    sampled = [float(r["weight"]) for r in rows if int(r["label"]) == 0 and not r["reviewed"]]
    typical = statistics.median(sampled) if sampled else 1.0
    return [float(r["weight"]) * typical if r["reviewed"] else float(r["weight"]) for r in rows]


def metrics(scores, labels, threshold=0.65):
    """Holdout metrics for probabilities `scores` against `labels`."""
    pairs = sorted(zip(scores, labels), key=lambda p: -p[0])
    positives = sum(labels)
    negatives = len(labels) - positives
    # Average precision: the area under the precision-recall curve -- the
    # honest number when attacks are rare.
    hits, ap = 0, 0.0
    for rank, (_, label) in enumerate(pairs, 1):
        if label:
            hits += 1
            ap += hits / rank
    flagged = [(s, lab) for s, lab in pairs if s >= threshold]
    tp = sum(lab for _, lab in flagged)
    fp = len(flagged) - tp
    return {
        "rows": len(labels),
        "attacks": positives,
        "normal": negatives,
        "false_positives": fp,
        "average_precision": ap / positives if positives else None,
        "recall_at_alert": tp / positives if positives else None,
        "false_positive_rate_at_alert": fp / negatives if negatives else None,
        "precision_at_alert": tp / len(flagged) if flagged else None,
    }


def false_alarm_bound(incumbent_fp):
    """The most false alarms a candidate may raise on the holdout before it
    counts as worse: the incumbent's count plus what chance explains -- the
    upper end of a 95% interval for a Poisson count, at least 1 expected.
    0 -> 4.9, 2 -> 6.7, 10 -> 18.1: a handful more among ~1,500 normal events
    is noise; an order of magnitude is not."""
    expected = max(incumbent_fp, 1)
    return expected + 1.96 * math.sqrt(expected) + 1.92


def recent_traffic(ch, limit=SHADOW_ROWS):
    """Recent stored events as the stream scored them -- features, event
    type, the rules' verdict -- from the last SHADOW_HOURS, every source
    represented: a hashed SHADOW_SAMPLE_PERCENT of the window, at most
    SHADOW_PER_SOURCE events per source."""
    columns = ", ".join(_stored_features())
    return ch.rows(
        f"SELECT event_type, rule_score, rule_hits, source_ip, {columns} FROM watchtower.security_events "
        "WHERE timestamp > (SELECT max(timestamp) FROM watchtower.security_events) - toIntervalHour({h:UInt32}) "
        "AND cityHash64(event_id) % 100 < {pct:UInt32} "
        "ORDER BY cityHash64(event_id) LIMIT {per:UInt32} BY source_ip LIMIT {n:UInt32}",
        h=SHADOW_HOURS, pct=SHADOW_SAMPLE_PERCENT, per=SHADOW_PER_SOURCE, n=limit)


def model_alerts(dump, rows):
    """The events the model would raise to an alert on its own -- no rule
    fired, its score alone crossed the line: (how many, on which sources)."""
    model = Model(dump, "shadow")
    raised = [r for r in rows if not r["rule_hits"] and ml.apply(dict(r), model)["ml_reason"]]
    return len(raised), {r.get("source_ip", "") for r in raised}


def shadow(candidate_dump, incumbent_dump, rows):
    out = {"rows": len(rows), "sources": len({r.get("source_ip", "") for r in rows}),
           "candidate_alerts": 0, "candidate_sources": 0, "incumbent_alerts": None, "incumbent_sources": None}
    if not rows:
        return out
    out["candidate_alerts"], hosts = model_alerts(candidate_dump, rows)
    out["candidate_sources"] = len(hosts)
    if incumbent_dump:
        out["incumbent_alerts"], hosts = model_alerts(incumbent_dump, rows)
        out["incumbent_sources"] = len(hosts)
    return out


def better(candidate, incumbent, reviewed=None, shadowed=None, tolerance=0.005):
    """Promote when, against the incumbent on the same holdout:
      - it ranks attacks at least as well (average precision, within
        `tolerance`),
      - its false alarms stay within what chance explains
        (false_alarm_bound), and
      - on the events the reviewer relabelled in live traffic, it is wrong
        no more often -- a correction, once learned, must stay learned.
      - on the newest hour of real traffic (`shadowed`), it raises alerts on
        its own for at most MAX_MODEL_ALERT_SHARE of events, and not many
        more than the incumbent would.
    `reviewed` is (candidate wrong, incumbent wrong) on those events."""
    shadow_checks = []
    if shadowed and shadowed["rows"]:
        n, alerts_c, alerts_i = shadowed["rows"], shadowed["candidate_alerts"], shadowed["incumbent_alerts"]
        shadow_checks.append((alerts_c <= MAX_MODEL_ALERT_SHARE * n,
                              f"alone it would alert on {alerts_c} of {n} recent events "
                              f"(ceiling {MAX_MODEL_ALERT_SHARE:.1%})"))
        if alerts_i is not None:
            allowed = max(1.5 * alerts_i, false_alarm_bound(alerts_i))
            shadow_checks.append((alerts_c <= allowed, f"vs {alerts_i} for the active model (allowed {allowed:.0f})"))
        # A model wrong about a whole group of hosts alerts on many hosts,
        # a few times each: count hosts, not only alerts.
        hosts_c, hosts_i = shadowed.get("candidate_sources"), shadowed.get("incumbent_sources")
        if hosts_c is not None and hosts_i is not None:
            allowed = max(1.5 * hosts_i, false_alarm_bound(hosts_i))
            shadow_checks.append((hosts_c <= allowed, f"on {hosts_c} hosts vs {hosts_i} (allowed {allowed:.0f})"))
    if incumbent is None:
        if all(ok for ok, _ in shadow_checks):
            return True, "no active model yet"
        return False, "not better: " + "; ".join(text for _, text in shadow_checks)
    if candidate["average_precision"] is None:
        return False, "holdout has no attacks"
    ap_c, ap_i = candidate["average_precision"], incumbent["average_precision"] or 0
    fp_c, fp_i = candidate["false_positives"], incumbent["false_positives"]
    bound = false_alarm_bound(fp_i)
    wrong_c, wrong_i = reviewed or (0, 0)
    checks = [
        (ap_c + tolerance >= ap_i, f"AP {ap_c:.4f} vs {ap_i:.4f}"),
        (fp_c <= bound, f"false alarms {fp_c} vs {fp_i} (chance allows up to {bound:.1f})"),
        (wrong_c <= wrong_i, f"wrong on reviewed events {wrong_c} vs {wrong_i}"),
        *shadow_checks,
    ]
    summary = "; ".join(text for _, text in checks)
    if all(ok for ok, _ in checks):
        return True, summary
    return False, "not better: " + summary


def active(ch):
    """(version, dump) of the active model, or (None, None)."""
    rows = ch.rows("SELECT a.version AS version, m.model AS model FROM "
                   "(SELECT version FROM watchtower.ml_model_active ORDER BY activated_at DESC LIMIT 1) AS a "
                   "INNER JOIN watchtower.ml_models AS m ON m.version = a.version LIMIT 1")
    return (rows[0]["version"], json.loads(rows[0]["model"])) if rows else (None, None)


def score_with(dump, rows):
    model = Model(dump, "eval")
    return [model.score(r) for r in rows]


def wrong_on(dump, rows, threshold=0.65):
    """How many of these labelled events the model gets wrong at the alert
    line: an attack below it, or a benign event at or above it."""
    return sum(1 for r, s in zip(rows, score_with(dump, rows)) if (s >= threshold) != bool(int(r["label"])))


def new_version():
    return time.strftime("lgbm-%Y%m%d-%H%M%S", time.gmtime())


def register(ch, version, booster, trained_rows, report):
    ch.insert("watchtower.ml_models", [{
        "version": version,
        "trained_rows": trained_rows,
        "metrics": json.dumps(report),
        "params": json.dumps({**PARAMS, "max_trees": MAX_TREES}),
        "model": json.dumps(booster.dump_model()),
    }])


def activate(ch, version, reason):
    ch.insert("watchtower.ml_model_active", [{"version": version, "reason": reason}])


# A promoted model's own alarms, as the reviewer judged them: at least this
# many reviewed, and this share of them benign, and it is rolled back.
GUARD_MIN_REVIEWED = 20
GUARD_MAX_FALSE_ALARMS = 0.5


def guard(ch, since_hours=24):
    """Roll the active model back if the reviewer calls most of its own
    alerts benign. Returns what it did, or None."""
    history = ch.rows("SELECT version FROM watchtower.ml_model_active ORDER BY activated_at DESC LIMIT 20")
    if not history:
        return None
    current = history[0]["version"]
    earlier = next((h["version"] for h in history[1:] if h["version"] != current), None)
    stats = ch.rows(
        "SELECT countIf(why_selected = 'model_alert') AS reviewed, "
        "countIf(why_selected = 'model_alert' AND verdict = 'benign' AND confidence >= 0.8) AS benign "
        "FROM watchtower.event_reviews WHERE ml_model = {v:String} "
        "AND reviewed_at > now() - toIntervalHour({h:UInt32})", v=current, h=since_hours)[0]
    reviewed, benign = int(stats["reviewed"]), int(stats["benign"])
    if reviewed < GUARD_MIN_REVIEWED or benign / reviewed <= GUARD_MAX_FALSE_ALARMS or earlier is None:
        return None
    reason = (f"rollback: the reviewer called {benign} of {reviewed} of {current}'s own alerts benign "
              f"in {since_hours} h")
    activate(ch, earlier, reason)
    return {"from": current, "to": earlier, "reason": reason}


def run(ch=None):
    """The whole daily step. Returns a report; raises only on real errors."""
    ch = ch or ClickHouse()
    rows = dataset(ch)
    attacks = sum(int(r["label"]) for r in rows)
    if len(rows) < MIN_ROWS or attacks < MIN_ATTACKS:
        return {"status": "skipped", "reason": f"{len(rows)} labelled rows, {attacks} attacks "
                                                f"(need {MIN_ROWS} / {MIN_ATTACKS})"}
    train_rows, test_rows = split(rows)
    booster = train(train_rows)
    labels = [int(r["label"]) for r in test_rows]
    candidate = metrics(score_with(booster.dump_model(), test_rows), labels)
    version, dump = active(ch)
    incumbent = metrics(score_with(dump, test_rows), labels) if dump else None
    reviewed = [r for r in rows if r["reviewed"]]
    wrong = (wrong_on(booster.dump_model(), reviewed), wrong_on(dump, reviewed)) if dump else None
    shadowed = shadow(booster.dump_model(), dump, recent_traffic(ch))
    promote, why = better(candidate, incumbent, wrong, shadowed)
    new = new_version()
    report = {"version": new, "trained_rows": len(train_rows), "holdout": candidate,
              "incumbent": {"version": version, "holdout": incumbent},
              "reviewed_events": {"count": len(reviewed), "wrong": wrong},
              "shadow": shadowed,
              "promoted": promote, "why": why, "trees": booster.num_trees()}
    register(ch, new, booster, len(train_rows), report)
    if promote:
        activate(ch, new, why)
    return report
