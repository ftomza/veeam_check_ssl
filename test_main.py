from aiounittest import AsyncTestCase

from main import checker


class Test(AsyncTestCase):
    async def test_checker(self):
        r = await checker("github.com:80/index")
        self.assertEqual("BAD", r["result"])
        r = await checker("github.com:443/index")
        self.assertEqual("OK", r["result"])
