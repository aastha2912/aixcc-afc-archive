# aiohttp client for the competition API
# note: largely written by o1

import aiohttp
from types import TracebackType
from typing import Optional, Type
from pydantic import BaseModel

from crs.common.utils import shield_and_wait

from .models import (
    PingResponse,
    SarifAssessmentSubmission,
    SarifAssessmentResponse,
    BundleSubmission,
    BundleSubmissionResponse,
    BundleSubmissionResponseVerbose,
    FreeformSubmission,
    FreeformResponse,
    PatchSubmission,
    PatchSubmissionResponse,
    POVSubmission,
    POVSubmissionResponse,
    SARIFSubmission,
    SARIFSubmissionResponse,
)
JSON_HEADERS = {"Content-Type": "application/json"}

class CompetitionAPIClient:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.auth = aiohttp.BasicAuth(username, password)
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(auth=self.auth)
        return self

    async def __aexit__(self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]):
        if self._session:
            await shield_and_wait(self._session.close()) # noqa: ASYNC102; shield_and_wait behaves like a CancelScope(shield=True)

    async def _get_json(self, url: str):
        assert self._session is not None
        async with self._session.get(url) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def _post_json(self, url: str, payload: BaseModel):
        assert self._session is not None
        async with self._session.post(url, data=payload.model_dump_json(), headers=JSON_HEADERS) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def _patch_json(self, url: str, payload: BaseModel):
        assert self._session is not None
        async with self._session.patch(url, data=payload.model_dump_json(), headers=JSON_HEADERS) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def _delete_no_content(self, url: str):
        assert self._session is not None
        async with self._session.delete(url) as resp:
            resp.raise_for_status()
            # 204 returns no content, so no json

    async def ping(self) -> PingResponse:
        """
        GET /v1/ping/
        """
        url = f"{self.base_url}/v1/ping/"
        data = await self._get_json(url)
        return PingResponse(**data)

    async def submit_sarif_assessment(
        self, task_id: str, broadcast_sarif_id: str, payload: SarifAssessmentSubmission
    ) -> SarifAssessmentResponse:
        """
        POST /v1/task/{task_id}/broadcast-sarif-assessment/{broadcast_sarif_id}/
        """
        url = f"{self.base_url}/v1/task/{task_id}/broadcast-sarif-assessment/{broadcast_sarif_id}/"
        data = await self._post_json(url, payload)
        return SarifAssessmentResponse(**data)

    async def submit_bundle(
        self, task_id: str, payload: BundleSubmission
    ) -> BundleSubmissionResponse:
        """
        POST /v1/task/{task_id}/bundle/
        """
        url = f"{self.base_url}/v1/task/{task_id}/bundle/"
        data = await self._post_json(url, payload)
        return BundleSubmissionResponse(**data)

    async def delete_bundle(self, task_id: str, bundle_id: str) -> None:
        """
        DELETE /v1/task/{task_id}/bundle/{bundle_id}/
        """
        url = f"{self.base_url}/v1/task/{task_id}/bundle/{bundle_id}/"
        await self._delete_no_content(url)

    async def get_bundle(
        self, task_id: str, bundle_id: str
    ) -> BundleSubmissionResponseVerbose:
        """
        GET /v1/task/{task_id}/bundle/{bundle_id}/
        """
        url = f"{self.base_url}/v1/task/{task_id}/bundle/{bundle_id}/"
        data = await self._get_json(url)
        return BundleSubmissionResponseVerbose(**data)

    async def update_bundle(
        self, task_id: str, bundle_id: str, payload: BundleSubmission
    ) -> BundleSubmissionResponseVerbose:
        """
        PATCH /v1/task/{task_id}/bundle/{bundle_id}/
        """
        url = f"{self.base_url}/v1/task/{task_id}/bundle/{bundle_id}/"
        data = await self._patch_json(url, payload)
        return BundleSubmissionResponseVerbose(**data)

    async def submit_freeform(
        self, task_id: str, payload: FreeformSubmission
    ) -> FreeformResponse:
        """
        POST /v1/task/{task_id}/freeform/
        """
        url = f"{self.base_url}/v1/task/{task_id}/freeform/"
        data = await self._post_json(url, payload)
        return FreeformResponse(**data)

    async def submit_patch(
        self, task_id: str, payload: PatchSubmission
    ) -> PatchSubmissionResponse:
        """
        POST /v1/task/{task_id}/patch/
        """
        url = f"{self.base_url}/v1/task/{task_id}/patch/"
        data = await self._post_json(url, payload)
        return PatchSubmissionResponse(**data)

    async def get_patch(
        self, task_id: str, patch_id: str
    ) -> PatchSubmissionResponse:
        """
        GET /v1/task/{task_id}/patch/{patch_id}/
        """
        url = f"{self.base_url}/v1/task/{task_id}/patch/{patch_id}/"
        data = await self._get_json(url)
        return PatchSubmissionResponse(**data)

    async def submit_pov(
        self, task_id: str, payload: POVSubmission
    ) -> POVSubmissionResponse:
        """
        POST /v1/task/{task_id}/pov/
        """
        url = f"{self.base_url}/v1/task/{task_id}/pov/"
        data = await self._post_json(url, payload)
        return POVSubmissionResponse(**data)

    async def get_pov(
        self, task_id: str, pov_id: str
    ) -> POVSubmissionResponse:
        """
        GET /v1/task/{task_id}/pov/{pov_id}/
        """
        url = f"{self.base_url}/v1/task/{task_id}/pov/{pov_id}/"
        data = await self._get_json(url)
        return POVSubmissionResponse(**data)

    async def submit_submitted_sarif(
        self, task_id: str, payload: SARIFSubmission
    ) -> SARIFSubmissionResponse:
        """
        POST /v1/task/{task_id}/submitted-sarif/
        """
        url = f"{self.base_url}/v1/task/{task_id}/submitted-sarif/"
        data = await self._post_json(url, payload)
        return SARIFSubmissionResponse(**data)