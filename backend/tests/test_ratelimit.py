from app.core.ratelimit import SlidingWindowLimiter


class FakeClock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t


def test_allows_up_to_limit_then_blocks_then_recovers():
    clock = FakeClock()
    rl = SlidingWindowLimiter(clock)
    assert all(rl.allow("k", 3, 60) for _ in range(3))
    assert not rl.allow("k", 3, 60)
    assert rl.retry_after("k", 60) >= 1
    clock.t += 61
    assert rl.allow("k", 3, 60)


def test_keys_are_independent_and_zero_disables():
    rl = SlidingWindowLimiter(FakeClock())
    assert rl.allow("a", 1, 60) and not rl.allow("a", 1, 60)
    assert rl.allow("b", 1, 60)
    assert all(rl.allow("c", 0, 60) for _ in range(50))


def test_is_limited_does_not_record():
    rl = SlidingWindowLimiter(FakeClock())
    assert not rl.is_limited("k", 2, 60)
    rl.record("k"); rl.record("k")
    assert rl.is_limited("k", 2, 60)
