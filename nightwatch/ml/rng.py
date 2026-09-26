"""A small, fast, seedable PRNG.

Nightwatch has no third-party dependencies, so it cannot use ``numpy.random``,
and ``random`` is not reproducible across interpreter versions for the
algorithms that matter here. Training a random forest with a 32-bit xorshift
keeps a run byte-for-byte reproducible, which is what makes the reported
metrics in the tests and the documentation trustworthy.

The generator is deliberately simple and identical on every platform:

* :class:`RNG` - xorshift32 bit generator plus the standard float transforms.
* :func:`shuffle` - Fisher-Yates over a list.
* :func:`choice` - uniform sampling with replacement.
* :func:`kfold` - deterministic index assignment for cross-validation.
* :func:`seeded_rng` - a :class:`RNG` derived from an arbitrary string or int,
  so "run 3 of the sweep" always produces the same forest.
"""

MASK32 = 0xFFFFFFFF


class RNG:
    """xorshift32 generator with the usual floating-point helpers."""

    def __init__(self, seed=12345):
        self._state = (int(seed) & MASK32) or 1

    def state(self):
        """The raw 32-bit state, for reproducible checkpointing."""
        return self._state

    def next_u32(self):
        """Next raw 32-bit value."""
        x = self._state
        x ^= (x << 13) & MASK32
        x ^= x >> 17
        x ^= (x << 5) & MASK32
        self._state = x & MASK32
        return self._state

    def random(self):
        """Uniform float in [0, 1) with 32 bits of resolution."""
        return self.next_u32() / 4294967296.0

    def randint(self, low, high):
        """Uniform integer in the inclusive range [low, high]."""
        if high < low:
            raise ValueError("high must be >= low")
        span = high - low + 1
        return low + int(self.random() * span) % span

    def uniform(self, low, high):
        return low + (high - low) * self.random()

    def normal(self, mu=0.0, sigma=1.0):
        """Box-Muller normal deviate (single value, second discarded)."""
        import math
        u1 = self.random()
        while u1 <= 1e-12:
            u1 = self.random()
        u2 = self.random()
        return mu + sigma * math.sqrt(-2.0 * math.log(u1)) * \
            math.cos(2.0 * math.pi * u2)

    def bernoulli(self, p=0.5):
        return self.random() < p

    def choice(self, seq):
        return seq[int(self.random() * len(seq)) % len(seq)]

    def shuffled(self, seq):
        out = list(seq)
        shuffle(out, self)
        return out

    def sample(self, seq, k):
        """``k`` distinct items from ``seq`` (or all of them if k is larger)."""
        pool = self.shuffled(seq)
        return pool[:max(0, min(k, len(pool)))]

    def __repr__(self):
        return f"<RNG state={self._state:#010x}>"


def seeded_rng(seed):
    """Build an :class:`RNG` from an int or an arbitrary string."""
    if isinstance(seed, int):
        return RNG(seed)
    digest = 0
    for index, char in enumerate(str(seed)):
        digest = ((digest << 5) - digest + ord(char) + index) & MASK32
    return RNG(digest or 12345)


def shuffle(items, rng=None):
    """In-place Fisher-Yates shuffle."""
    rng = rng or RNG()
    for i in range(len(items) - 1, 0, -1):
        j = int(rng.random() * (i + 1)) % (i + 1)
        items[i], items[j] = items[j], items[i]
    return items


def kfold(n, k, indices=None, shuffle_seed=None):
    """Split ``range(n)`` into ``k`` contiguous folds.

    Folds are contiguous rather than random so a time-ordered dataset is not
    silently shuffled across the train/test boundary, which would leak future
    events into training. Pass ``shuffle_seed`` to permute first when order
    carries no meaning.
    """
    if k < 2:
        raise ValueError("k must be at least 2")
    if k > n:
        raise ValueError(f"cannot build {k} folds from {n} samples")
    items = list(range(n)) if indices is None else list(indices)
    if shuffle_seed is not None:
        shuffle(items, seeded_rng(shuffle_seed))
    folds = [[] for _ in range(k)]
    for position, item in enumerate(items):
        folds[position % k].append(item)
    for fold in folds:
        fold.sort()
    return folds


def stratified_folds(labels, k, shuffle_seed=None):
    """K-fold split that preserves the class balance of each fold.

    Plain ``kfold`` can leave a fold with no positives on a rare class, which
    silently makes recall undefined for that fold.
    """
    by_class = {}
    for position, label in enumerate(labels):
        by_class.setdefault(label, []).append(position)
    folds = [[] for _ in range(k)]
    for label in sorted(by_class, key=repr):
        positions = list(by_class[label])
        if shuffle_seed is not None:
            shuffle(positions, seeded_rng(f"{shuffle_seed}:{label}"))
        for offset, position in enumerate(positions):
            folds[offset % k].append(position)
    for fold in folds:
        fold.sort()
    return folds
