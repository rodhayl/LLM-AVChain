from __future__ import annotations

from typing import Any

import httpx


class TaxiiClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._client = client

    async def publish_bundle(
        self,
        *,
        collection_id: str,
        bundle: dict[str, Any],
    ) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        path = f"/taxii2/collections/{collection_id}/objects/"
        if self._client is not None:
            response = await self._client.post(path, json=bundle, headers=headers)
            response.raise_for_status()
            return dict(response.json())
        async with httpx.AsyncClient(base_url=self.base_url, timeout=15.0) as client:
            response = await client.post(path, json=bundle, headers=headers)
        response.raise_for_status()
        return dict(response.json())

    async def fetch_collection_objects(
        self,
        *,
        collection_id: str,
    ) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        path = f"/taxii2/collections/{collection_id}/objects/"
        if self._client is not None:
            response = await self._client.get(path, headers=headers)
            response.raise_for_status()
            return dict(response.json())
        async with httpx.AsyncClient(base_url=self.base_url, timeout=15.0) as client:
            response = await client.get(path, headers=headers)
        response.raise_for_status()
        return dict(response.json())
