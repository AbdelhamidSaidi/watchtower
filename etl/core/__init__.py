"""Engine-free detection logic: plain Python, no Flink imports.

The Flink job (stream/job.py) runs these functions per event; the tests
run them directly, without a cluster, so a threshold, a regex or a feature
is defined -- and tested -- exactly once.
"""
