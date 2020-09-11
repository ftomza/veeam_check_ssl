import asyncio
import csv
import logging
import multiprocessing
import socket
import ssl
from concurrent.futures.thread import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict
from urllib.parse import urlparse


logging.basicConfig(level=logging.INFO)
pool = ThreadPoolExecutor(max_workers=multiprocessing.cpu_count())

async def checker(url: str) -> Dict[str, Any]:
    """
    Checking the URL for SSL validity

    :param url: Checked url
    :return: Dictionary result:
        - url: checked url,
        - hostname: hostname for check socket
        - port: port for check socket
        - result: OK or BAD status check
        - desc: Description status
        - validityExpires: timestamp expire cert
    """

    result = {
        "url": url,
        "hostname": "",
        "port": 0,
        "validityExpires": None
    }
    if not url:
        result.update({
            "result": "BAD",
            "desc": "URL not set"
        })
        return result

    if "://" not in url:
        url = f"https://{url}"

    parse_url = urlparse(url)
    hostname = parse_url.hostname
    port = parse_url.port or 443
    result.update({
        "hostname": hostname,
        "port": port,
    })
    if not hostname:
        result.update({
            "result": "BAD",
            "desc": "Hostname not set"
        })
        return result
    context = ssl.create_default_context()
    try:
        def sync_checker():
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")

        expire = await asyncio.get_event_loop().run_in_executor(pool, sync_checker)

    except ssl.SSLError as e:
        result.update({
            "result": "BAD",
            "desc": f"SSL Error: {e}",
        })
        return result
    except socket.gaierror as e:
        result.update({
            "result": "BAD",
            "desc": f"Connect Error: {e}",
        })
        return result
    except socket.timeout as e:
        result.update({
            "result": "BAD",
            "desc": f"Connect timeout",
        })
        return result

    if expire < datetime.now():
        result.update({
            "result": "BAD",
            "desc": f"Expire",
            "validityExpires": expire
        })
        return result
    result.update({
        "result": "OK",
        "desc": f"",
        "validityExpires": expire
    })
    return result


async def task(name, writer, queue: asyncio.Queue):
    while not queue.empty():
        url: str = await queue.get()
        url = url.strip()
        logging.info(f"Start check {url} on {name}")
        result = await checker(url)
        writer.writerow([
            result["url"],
            result["hostname"],
            result["port"],
            result["result"],
            result["desc"],
            result["validityExpires"]
        ])


async def main():
    queue = asyncio.Queue()
    with open("input.txt", "r") as f:
        for v in f:
            await queue.put(v)
    with open("output.csv", "w") as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow([
            "url",
            "hostname",
            "port",
            "result",
            "desc",
            "validityExpires"
        ])
        await asyncio.gather(
            asyncio.create_task(task("1", writer, queue)),
            asyncio.create_task(task("2", writer, queue)),
            asyncio.create_task(task("3", writer, queue)),
            asyncio.create_task(task("4", writer, queue)),
        )

if __name__ == '__main__':
    asyncio.run(main())


