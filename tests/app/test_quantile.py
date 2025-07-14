import asyncio
import random
import math

from crs.common.aio import tmpdir
from crs.app.quantile import QuantileEstimator
from crs.app.counter_db import MockCounterView, CounterDB

async def test_small_exact_median():
    """For ≤5 samples the estimate is exact."""
    est = QuantileEstimator(MockCounterView(), q=0.5)

    samples = [1, 2, 3, 4, 5]
    for x in samples:
        _ = await est.add(x)

    thr = await est.current_threshold()
    assert thr == 3.0

    # Verify the membership logic: top-50 % should be ≥ threshold.
    expected_membership = [x >= thr for x in samples]
    assert expected_membership == [False, False, True, True, True]

async def test_large_approx_p90():
    """
    After many points the P² estimate should be within a small
    relative error of the true empirical 90-th percentile.
    """
    rng = random.Random(424242)
    est = QuantileEstimator(MockCounterView(), q=0.9)

    N = 10_000
    data = [rng.random() * 1000 for _ in range(N)]
    for x in data:
        _ = await est.add(x)

    # true empirical 90-th percentile
    data_sorted = sorted(data)
    idx = math.ceil(0.9 * N) - 1
    true_p90 = data_sorted[idx]

    est_p90 = await est.current_threshold()

    # allow 2 % of the data range as slack (typical P² error << 1 %)
    tol = (max(data) - min(data)) * 0.02
    assert true_p90 - tol <= est_p90 <= true_p90 + tol

async def test_large_approx_p90_sqlite():
    """
    After many points the P² estimate should be within a small
    relative error of the true empirical 90-th percentile.
    """
    rng = random.Random(424242)
    async with tmpdir() as td:
        db = CounterDB(td / "counters.sqlite3")
        est = QuantileEstimator(db.view("test"), q=0.9)

        N = 10_000
        data = [rng.random() * 1000 for _ in range(N)]
        for x in data:
            _ = await est.add(x)

        # true empirical 90-th percentile
        data_sorted = sorted(data)
        idx = math.ceil(0.9 * N) - 1
        true_p90 = data_sorted[idx]

        est_p90 = await est.current_threshold()

        # allow 2 % of the data range as slack (typical P² error << 1 %)
        tol = (max(data) - min(data)) * 0.02
        assert true_p90 - tol <= est_p90 <= true_p90 + tol

async def test_multiple_quantiles_uniform():
    """
    Feed 50 000 uniform samples to three estimators (q = 0.1, 0.5, 0.9)
    and check each against the empirical value.
    """
    rng = random.Random(42)
    N = 50_000
    data = [rng.random() * 10_000 for _ in range(N)]

    qs = [0.1, 0.5, 0.9]
    ests = {q: QuantileEstimator(MockCounterView(), q) for q in qs}

    for x in data:
        _ = await asyncio.gather(*(e.add(x) for e in ests.values()))

    data_sorted = sorted(data)
    rng_span = max(data) - min(data)
    tol = rng_span * 0.012  # 1.2 % of range

    for q, est in ests.items():
        idx = math.ceil(q * N) - 1
        true_q = data_sorted[idx]
        est_q = await est.current_threshold()
        assert abs(est_q - true_q) <= tol, f"q={q}: {est_q} vs {true_q}"


async def test_heavy_tail_p99():
    """
    99-th percentile on a log-normal distribution (heavy tail).
    Slightly looser tolerance because p=0.99 is harder to nail.
    """
    rng = random.Random(7)
    N = 30_000
    data = [math.exp(rng.gauss(0, 1)) for _ in range(N)]  # lognormal σ=1
    est = QuantileEstimator(MockCounterView(), 0.99)

    for x in data:
        _ = await est.add(x)

    true_p99 = sorted(data)[math.ceil(0.99 * N) - 1]
    tol = true_p99 * 0.05            # allow 5 % relative error
    est_p99 = await est.current_threshold()

    assert abs(est_p99 - true_p99) <= tol


async def test_monotonic_threshold():
    """
    With monotonically increasing inputs, the quantile estimate should
    never decrease.
    """
    est = QuantileEstimator(MockCounterView(), 0.75)
    last = -float("inf")

    for x in range(1, 10_001):
        _ = await est.add(float(x))
        if x % 137 == 0:                   # check occasionally
            thr = await est.current_threshold()
            assert thr >= last
            last = thr


async def test_interleaved_queries():
    rng = random.Random(99)
    est = QuantileEstimator(MockCounterView(), 0.8)
    data = [rng.uniform(-100, 100) for _ in range(5_000)]

    for i, x in enumerate(data, 1):
        _ = await est.add(x)
        if i % 500 == 0:           # query every 500 inserts
            thr = await est.current_threshold()
            # proportion of seen samples above threshold ≈ (1-q)
            above = sum(1 for y in data[:i] if y >= thr)
            frac  = above / i
            assert abs(frac - 0.2) < 0.05   # within ±5 %