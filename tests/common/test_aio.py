from typing import Generator, Optional
from crs.common.aio import iterator

async def test_aio_iterator():
    def myiter(raises: Optional[Exception] = None) -> Generator[int, None, None]:
        for i in range(5):
            yield i
        if raises:
            raise raises

    async with iterator(myiter(raises=None)) as it:
        l = [x async for x in it]
        assert l == list(range(5))

    exc = Exception("test_aio_iterator exception")
    try:
        async with iterator(myiter(raises=exc)) as it:
            l = [x async for x in it]
            assert False, "unreachable because iterator should raise"
    except Exception as e:
        assert e is exc