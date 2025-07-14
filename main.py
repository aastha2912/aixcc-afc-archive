import asyncio
import gc

from crs.app.app import CRS

if __name__ == "__main__":
    crs = CRS()
    gc.freeze()

    # note: defaults are 700, 10, 10; this is roughly 40x fewer gcs
    gc.set_threshold(8_000, 30, 60)

    asyncio.run(crs.loop())
