"""What the Airflow DAGs do, as plain Python.

The DAG files (orchestration/dags/) only wire these functions into
schedules and dependencies. Keeping the work here means it is tested
without Airflow (tests/orchestration/test_ops.py) and can be run by hand.
"""
