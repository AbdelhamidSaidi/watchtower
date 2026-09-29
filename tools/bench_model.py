"""
Per-event cost of scoring one event with a LightGBM model, by backend.

The Flink job scores events ONE AT A TIME, so what matters is the latency
of a single-row prediction including turning the event dict into the
model's input -- not batch throughput, which every backend is good at.

    python tools/bench_model.py                       # synthetic model
    python tools/bench_model.py --model models/current/model.txt

Backends that are not installed are skipped:
    lightgbm     Booster.predict on a 1-row numpy array
    onnxruntime  the model converted with onnxmltools
    compiled     the model compiled to plain Python ifs (etl/core/ml.py) -- the job's scorer
    tl2cgen      the model compiled to C (needs a compiler), via treelite
"""

import argparse
import statistics
import sys
import tempfile
import time

import numpy as np


def synthetic(features, trees, leaves, rows=20_000, seed=7):
    import lightgbm as lgb

    rng = np.random.default_rng(seed)
    x = rng.gamma(1.0, 3.0, size=(rows, features))
    y = (x[:, 0] + 0.5 * x[:, 1] * (x[:, 2] > 3) + rng.normal(0, 1, rows) > 5).astype(int)
    return lgb.train({"objective": "binary", "num_leaves": leaves, "verbose": -1},
                     lgb.Dataset(x, y), num_boost_round=trees), x


def timed(fn, rows, repeat):
    for row in rows[:200]:                      # warm up
        fn(row)
    samples = []
    for i in range(repeat):
        row = rows[i % len(rows)]
        t0 = time.perf_counter_ns()
        fn(row)
        samples.append(time.perf_counter_ns() - t0)
    samples.sort()
    return {"p50_us": samples[len(samples) // 2] / 1000,
            "p99_us": samples[int(len(samples) * 0.99)] / 1000,
            "mean_us": statistics.fmean(samples) / 1000}


def backends(booster, n_features):
    """{name: fn(list[float]) -> probability} for every backend available."""
    out = {}
    out["lightgbm"] = lambda row: booster.predict(np.asarray([row], dtype=np.float64))[0]

    try:
        import onnxruntime as ort
        from onnxmltools import convert_lightgbm
        from onnxmltools.convert.common.data_types import FloatTensorType

        onnx = convert_lightgbm(booster, initial_types=[("x", FloatTensorType([None, n_features]))],
                                zipmap=False, target_opset=15)
        options = ort.SessionOptions()
        options.intra_op_num_threads = 1       # one Python thread per TaskManager slot
        options.inter_op_num_threads = 1
        session = ort.InferenceSession(onnx.SerializeToString(), options,
                                       providers=["CPUExecutionProvider"])
        name = session.get_inputs()[0].name
        out["onnxruntime"] = lambda row: session.run(
            None, {name: np.asarray([row], dtype=np.float32)})[1][0][1]
    except ImportError as exc:
        print(f"skip onnxruntime: {exc}", file=sys.stderr)

    # The job's own scorer: the dump compiled to nested ifs (etl/core/ml.py).
    sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "etl"))
    from core.ml import compile_model

    namespace = {}
    exec(compile_model(booster.dump_model()), namespace)
    raw = namespace["raw"]
    out["compiled"] = lambda row: 1.0 / (1.0 + __import__("math").exp(-raw(row)))

    try:
        import tl2cgen
        import treelite

        model = treelite.frontend.from_lightgbm(booster)
        lib = tempfile.mkdtemp() + "/model.so"
        tl2cgen.export_lib(model, toolchain="gcc", libpath=lib, params={"parallel_comp": 8})
        predictor = tl2cgen.Predictor(lib, nthread=1)
        out["tl2cgen"] = lambda row: predictor.predict(
            tl2cgen.DMatrix(np.asarray([row], dtype=np.float64)))[0]
    except Exception as exc:                    # no compiler, or not installed
        print(f"skip tl2cgen: {exc}", file=sys.stderr)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--model", help="a LightGBM model file; default: train a synthetic one")
    parser.add_argument("--features", type=int, default=30)
    parser.add_argument("--trees", type=int, default=200)
    parser.add_argument("--leaves", type=int, default=31)
    parser.add_argument("--repeat", type=int, default=20_000)
    args = parser.parse_args()

    import lightgbm as lgb

    if args.model:
        booster = lgb.Booster(model_file=args.model)
        n = booster.num_feature()
        x = np.random.default_rng(1).gamma(1.0, 3.0, size=(5_000, n))
    else:
        booster, x = synthetic(args.features, args.trees, args.leaves)
        n = args.features
    rows = [list(map(float, r)) for r in x[:5_000]]

    fns = backends(booster, n)
    reference = booster.predict(np.asarray(rows[:500]))
    print(f"model: {booster.num_trees()} trees, {n} features\n")
    print(f"{'backend':<14}{'p50 us':>10}{'p99 us':>10}{'mean us':>10}   max |diff| vs lightgbm")
    for name, fn in fns.items():
        diff = max(abs(float(fn(r)) - reference[i]) for i, r in enumerate(rows[:500]))
        t = timed(fn, rows, args.repeat)
        print(f"{name:<14}{t['p50_us']:>10.1f}{t['p99_us']:>10.1f}{t['mean_us']:>10.1f}   {diff:.2e}")


if __name__ == "__main__":
    main()
