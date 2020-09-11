import asyncio
import csv
import logging
import socket
import ssl
from datetime import datetime
from typing import Any, Dict
from urllib.parse import urlparse


logging.basicConfig(level=logging.INFO)


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

    logging.info(f"Start check {url}")

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
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expire = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
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


async def task(writer, queue: asyncio.Queue):
    while not queue.empty():
        url: str = await queue.get()
        result = await checker(url.strip())
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
            asyncio.create_task(task(writer, queue)),
            asyncio.create_task(task(writer, queue)),
            asyncio.create_task(task(writer, queue)),
            asyncio.create_task(task(writer, queue)),
        )

if __name__ == '__main__':
    asyncio.run(main())


