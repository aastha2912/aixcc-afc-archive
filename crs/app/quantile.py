import asyncio
import math
from crs.app.counter_db import CounterView

class QuantileEstimator:
    """
    P-Square streaming quantile on top of a CounterView.
    Keeps five marker heights (h0-h4), their current positions (n0-n4)
    and desired positions (p0-p4), plus a total count `cnt`.
    Bootstrap uses v0-v4.
    """

    def __init__(self, db: CounterView, q: float):
        if not 0 < q < 1:
            raise ValueError("q must be in (0,1)")
        self.db   = db
        self.q    = q
        self.d    = [0, .5*q, q, .5*(1+q), 1]   # Δ for desired marker pos.
        self.lock = asyncio.Lock()

    # ─────────────────────────── public API ────────────────────────────
    async def add(self, x: float) -> bool:
        async with self.lock:
            n_prev = await self.db.fetch_add("cnt", 1.0)
            n = int(n_prev + 1)

            # 1‒5 : just cache raw samples
            if n <= 5:
                await self._set(f"v{n-1}", x)
                return x >= await self._bootstrap(n)

            # main phase -------------------------------------------------
            h  = [await self.db.get(f"h{i}")  for i in range(5)]
            n_ = [await self.db.get(f"n{i}")  for i in range(5)]
            p  = [await self.db.get(f"p{i}")  for i in range(5)]

            k = 0
            if x < h[0]:
                h[0] = x
            elif x >= h[4]:
                h[4] = x
                k = 3
            else:
                k = next((i for i in range(3) if h[i] <= x < h[i+1]), 3)


            # shift positions ≥ k+1
            for i in range(k+1,5):
                n_[i] += 1
            for i in range(5):
                p[i] += self.d[i]

            # adjust inner markers
            for i in range(1,4):
                d = p[i] - n_[i]
                if (d>=1 and n_[i+1]-n_[i]>1) or (d<=-1 and n_[i-1]-n_[i]<-1):
                    s = 1 if d>=1 else -1
                    hp = h[i] + s/(n_[i+1]-n_[i-1])*(
                          (n_[i]-n_[i-1]+s)*(h[i+1]-h[i])/(n_[i+1]-n_[i]) +
                          (n_[i+1]-n_[i]-s)*(h[i]-h[i-1])/(n_[i]-n_[i-1]) )
                    if not (h[i-1] < hp < h[i+1]):          # fall back linear
                        hp = h[i] + s*(h[i+s]-h[i])/(n_[i+s]-n_[i])
                    h[i]  = hp
                    n_[i] += s

            # persist everything in one shot
            _ = await asyncio.gather(*(
                self._set(f"h{i}", h[i])  for i in range(5)
            ), *(
                self._set(f"n{i}", n_[i]) for i in range(5)
            ), *(
                self._set(f"p{i}", p[i])  for i in range(5)
            ))
            return x >= h[2]                    # quantile estimate

    async def current_threshold(self) -> float:
        async with self.lock:
            n = int(await self.db.get("cnt"))
            if n == 0:
                return 0.0
            if n < 5:
                vals = sorted([await self.db.get(f"v{i}") for i in range(n)])
                return vals[max(0, math.ceil(self.q*n)-1)]
            return await self.db.get("h2")        # marker #2

    async def cnt(self) -> int:
        return int(await self.db.get("cnt"))

    async def _set(self, var: str, new: float):
        await self.db.set(var, new)

    async def _bootstrap(self, n: int) -> float:
        """When five samples collected, initialise P² markers."""
        if n < 5:               # simple exact quantile so far
            vals = [await self.db.get(f"v{i}") for i in range(n)]
            vals.sort()
            return vals[max(0, math.ceil(self.q*n)-1)]

        vals = sorted([await self.db.get(f"v{i}") for i in range(5)])
        _ = await asyncio.gather(*(
            self._set(f"h{i}",  vals[i])         for i in range(5)
        ), *(
            self._set(f"n{i}",  float(i+1))      for i in range(5)
        ), *(
            self._set(f"p{i}",  1 + self.d[i]*4) for i in range(5)
        ))
        return vals[2]                           # median of first five
