import httpx


async def _search_brave(query, headers, timeout):
    async with httpx.AsyncClient() as client:
        return await client.get(
            "https://fixed-search.example/api",
            params={"q": query},
            headers=headers,
            timeout=timeout,
        )
