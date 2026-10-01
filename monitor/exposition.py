"""Prometheus text exposition (format 0.0.4), stdlib only.

A Family is one metric: name, type, help, samples. Collectors build fresh
Families on every pass and hand them to the Registry, which keeps the last
set each collector published and renders them all on a scrape.

Counters here are cumulative since the exporter started, like any counter:
Prometheus reads a restart as a reset, and rate()/increase() handle it.
"""

import math
import threading

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _escape_label(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _escape_help(text):
    return text.replace("\\", "\\\\").replace("\n", "\\n")


def number(value):
    """A sample value as Prometheus writes it."""
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    value = float(value)
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    return repr(value)


class Family:
    def __init__(self, name, kind, help_text):
        self.name, self.kind, self.help = name, kind, help_text
        self.samples = []       # (suffix, labels, value)

    def add(self, value, _suffix="", **labels):
        """One sample. A None value is skipped: an unknown number is absence,
        not a zero."""
        if value is not None:
            self.samples.append((_suffix, labels, value))
        return self

    def render(self):
        lines = [f"# HELP {self.name} {_escape_help(self.help)}", f"# TYPE {self.name} {self.kind}"]
        for suffix, labels, value in self.samples:
            if labels:
                pairs = ",".join(f'{k}="{_escape_label(v)}"' for k, v in labels.items())
                lines.append(f"{self.name}{suffix}{{{pairs}}} {number(value)}")
            else:
                lines.append(f"{self.name}{suffix} {number(value)}")
        return "\n".join(lines)


def gauge(name, help_text):
    return Family(name, "gauge", help_text)


def counter(name, help_text):
    return Family(name, "counter", help_text)


def histogram(name, help_text, bounds, cumulative, total, count, **labels):
    """A histogram family from cumulative bucket counts.

    `cumulative[i]` is how many observations were <= bounds[i]; `count` is
    all of them (the +Inf bucket) and `total` their sum.
    """
    family = Family(name, "histogram", help_text)
    for bound, seen in zip(bounds, cumulative):
        family.add(seen, "_bucket", le=number(float(bound)), **labels)
    family.add(count, "_bucket", le="+Inf", **labels)
    family.add(total, "_sum", **labels)
    family.add(count, "_count", **labels)
    return family


class Registry:
    def __init__(self):
        self._lock = threading.Lock()
        self._published = {}    # collector -> [Family]

    def publish(self, collector, families):
        """Replace what `collector` shows. A name two collectors both claim
        would be an invalid exposition, so it is refused here, not at scrape."""
        names = [f.name for f in families]
        if len(names) != len(set(names)):
            raise ValueError(f"{collector} publishes a metric name twice")
        with self._lock:
            for other, theirs in self._published.items():
                clash = set(names) & {f.name for f in theirs}
                if other != collector and clash:
                    raise ValueError(f"{collector} and {other} both publish {sorted(clash)[0]}")
            self._published[collector] = list(families)

    def withdraw(self, collector):
        with self._lock:
            self._published.pop(collector, None)

    def render(self):
        with self._lock:
            families = [f for fs in self._published.values() for f in fs]
        return "\n".join(f.render() for f in families) + "\n"
