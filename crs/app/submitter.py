import asyncio
from base64 import b64encode
from typing import Optional

from opentelemetry import trace

from .client import CompetitionAPIClient
from .models import *
from .products_db import ProductsDB

from crs import config
from crs.common.types import POVRunData, VulnReport, PatchRes

from crs_rust import logger

PING_PERIOD = 30
POLL_PERIOD = 1

class Submitter:
    """"
    Wrapper around CompetitionAPIClient which implements CRS type marshalling
    and some polling logic
    """
    def __init__(
        self,
        db: ProductsDB = ProductsDB(),
        url: str = config.CAPI_URL,
        username: str = config.CAPI_ID,
        password: str = config.CAPI_TOKEN
    ):
        self.db = db
        self.url = url
        self.username = username
        self.password = password
        self.products_db = ProductsDB()

    def _client(self) -> CompetitionAPIClient:
        return CompetitionAPIClient(self.url, self.username, self.password)

    @config.telem_tracer.start_as_current_span(
        "ping",
        attributes={"crs.action.category": "scoring_submission", "crs.action.name": "scoring.ping"},
        record_exception=False,
    )
    async def ping(self) -> bool:
        try:
            async with self._client() as client:
                resp = await client.ping()
                logger.info(f"got ping response: {resp.status=}")
            return True
        except Exception as e:
            logger.error(f"error pinging competition client: {e}")
            return False

    @config.telem_tracer.start_as_current_span(
        "submit_pov",
        attributes={"crs.action.category": "scoring_submission", "crs.action.name": "scoring.submit_pov"},
        record_exception=False,
    )
    async def submit_pov(self, task_id: UUID, pov_id: int, pov: POVRunData) -> POVSubmissionResponse:
        span = trace.get_current_span()
        span.set_attributes({'task.id': str(UUID), 'crs.debug.pov_id': pov_id})
        async with self._client() as client:
            response = await client.submit_pov(str(pov.task_uuid), POVSubmission(
                architecture="x86_64",
                engine=pov.engine,
                fuzzer_name=pov.harness,
                sanitizer=pov.sanitizer,
                testcase=b64encode(pov.input).decode()
            ))
            await self.db.put_submission(pov.task_uuid, response, 'povs', pov_id)
            logger.info(f"submitted POV: {task_id=} {pov_id=} {response.pov_id=} {response.status=}")
            span.add_event("pov_submitted", {'crs.debug.pov_id': str(response.pov_id)})
            return response

    @config.telem_tracer.start_as_current_span(
        "submit_patch",
        attributes={"crs.action.category": "scoring_submission", "crs.action.name": "scoring.submit_patch"},
        record_exception=False,
    )
    async def submit_patch(self, task_id: UUID, patch_id: int, patch: PatchRes) -> PatchSubmissionResponse:
        span = trace.get_current_span()
        span.set_attributes({'task.id': str(UUID), 'crs.debug.patch_id': patch_id})
        async with self._client() as client:
            response = await client.submit_patch(str(task_id), PatchSubmission(
                patch=b64encode(patch.diff.encode()).decode()
            ))
            await self.db.put_submission(task_id, response, 'patches', patch_id)
            logger.info(f"submitted patch: {task_id=} {patch_id=} {response.patch_id=} {response.status=}")
            span.add_event("patch_submitted", {'crs.debug.patch_id': str(response.patch_id)})
            return response

    @config.telem_tracer.start_as_current_span(
        "submit_sarif_assessment",
        attributes={"crs.action.category": "scoring_submission", "crs.action.name": "scoring.submit_sarif_assessment"},
        record_exception=False,
    )
    async def submit_sarif_assessment(self, task_id: UUID, vuln_id: Optional[int], sarif_id: UUID, correct: bool, reason: str) -> SarifAssessmentResponse:
        span = trace.get_current_span()
        if vuln_id is not None:
            span.set_attributes({'task.id': str(UUID), 'crs.debug.vuln_id': vuln_id})
        assessment = "correct" if correct else "incorrect"
        async with self._client() as client:
            response = await client.submit_sarif_assessment(str(task_id), str(sarif_id), SarifAssessmentSubmission(
                assessment=assessment,
                description=reason
            ))
            response.sarif_id = sarif_id # override default value because API doesn't return it
            await self.db.put_submission(task_id, response, 'vulns' if vuln_id else None, vuln_id)
            logger.info(f"submitted sarif assessment: {task_id=} {vuln_id=} {sarif_id=} {correct=}")
            span.add_event("sarif_assessment_submitted", {'crs.debug.sarif_id': str(sarif_id)})
            return response

    @config.telem_tracer.start_as_current_span(
        "submit_bundle",
        attributes={"crs.action.category": "scoring_submission", "crs.action.name": "scoring.submit_bundle"},
        record_exception=False,
    )
    async def submit_bundle(
        self,
        task_id: UUID,
        bundle_id: int,
        description: str,
        patch_id: Optional[UUID] = None,
        pov_id: Optional[UUID] = None,
        broadcast_sarif_id: Optional[UUID] = None,
        submitted_sarif_id: Optional[UUID] = None,
    ) -> BundleSubmissionResponseVerbose:
        span = trace.get_current_span()
        span.set_attributes({'task.id': str(UUID), 'crs.debug.bundle_id': bundle_id, 'crs.debug.vuln_desc': description})
        if patch_id:
            span.set_attribute('crs.debug.patch_id', str(patch_id))
        if pov_id:
            span.set_attribute('crs.debug.pov_id', str(pov_id))
        async with self._client() as client:
            response = await client.submit_bundle(str(task_id), BundleSubmission(
                description=description,
                patch_id=patch_id,
                pov_id=pov_id,
                broadcast_sarif_id=broadcast_sarif_id,
                submitted_sarif_id=submitted_sarif_id
            ))
            # immediately get bundle so we get the verbose reponse
            response = await client.get_bundle(str(task_id), str(response.bundle_id))
            await self.db.put_submission(task_id, response, 'bundles', bundle_id)
            logger.info(f"submitted bundle: {task_id=} {bundle_id=} {response.bundle_id=} {response.status=}")
            span.add_event("bundle_submitted", {'crs.debug.bundle_id': str(response.bundle_id)})
            return response


    @config.telem_tracer.start_as_current_span(
        "update_bundle",
        attributes={"crs.action.category": "scoring_submission", "crs.action.name": "scoring.update_bundle"},
        record_exception=False,
    )
    async def update_bundle(
        self,
        task_id: UUID,
        bundle_id: int,
        bundle_sub_id: UUID,
        description: str,
        patch_id: Optional[UUID] = None,
        pov_id: Optional[UUID] = None,
        broadcast_sarif_id: Optional[UUID] = None,
        submitted_sarif_id: Optional[UUID] = None,
    ) -> BundleSubmissionResponseVerbose:
        span = trace.get_current_span()
        span.set_attributes({
            'task.id': str(UUID),
            'crs.debug.bundle_id': bundle_id,
            'crs.debug.bundle_sub_id': str(bundle_sub_id),
            'crs.debug.vuln_desc': description
        })
        if patch_id:
            span.set_attribute('crs.debug.patch_id', str(patch_id))
        if pov_id:
            span.set_attribute('crs.debug.pov_id', str(pov_id))
        async with self._client() as client:
            response = await client.update_bundle(str(task_id), str(bundle_id), BundleSubmission(
                description=description,
                patch_id=patch_id,
                pov_id=pov_id,
                broadcast_sarif_id=broadcast_sarif_id,
                submitted_sarif_id=submitted_sarif_id
            ))
            await self.db.put_submission(task_id, response, 'bundles', bundle_id)
            logger.info(f"submitted bundle: {task_id=} {bundle_id=} {response.bundle_id=} {response.status=}")
            span.add_event("bundle_submitted", {'crs.debug.bundle_id': str(response.bundle_id)})
            return response

    @config.telem_tracer.start_as_current_span(
        "delete_bundle",
        attributes={"crs.action.category": "scoring_submission", "crs.action.name": "scoring.delete_bundle"},
        record_exception=False,
    )
    async def delete_bundle(
        self,
        task_id: UUID,
        bundle_id: int,
        bundle_sub_id: UUID,
    ):
        span = trace.get_current_span()
        span.set_attributes({
            'task.id': str(UUID),
            'crs.debug.bundle_id': bundle_id,
            'crs.debug.bundle_sub_id': str(bundle_sub_id),
        })
        async with self._client() as client:
            await client.delete_bundle(str(task_id), str(bundle_sub_id))
            await self.db.delete_bundle_submission(bundle_id)


    @config.telem_tracer.start_as_current_span(
        "poll_pov",
        attributes={"crs.action.category": "scoring_submission", "crs.action.name": "scoring.poll_pov"},
        record_exception=False,
    )
    async def poll_pov(self, task_id: UUID, pov_id: int, response: POVSubmissionResponse) -> POVSubmissionResponse:
        span = trace.get_current_span()
        span.set_attributes({'task.id': str(UUID), 'crs.debug.pov_id': pov_id})
        async with self._client() as client:
            # poll until status is not 'accepted'
            logger.info(f"polling POV... {task_id=} {pov_id=} {response.pov_id=} {response.status=}")
            while response.status == 'accepted':
                await asyncio.sleep(POLL_PERIOD)
                response = await client.get_pov(str(task_id), str(response.pov_id))
            await self.db.put_submission(task_id, response, 'povs', pov_id)
            logger.info(f"done polling POV: {task_id=} {pov_id=} {response.pov_id=} {response.status=}")
            span.add_event("poll_pov", attributes={"crs.debug.poll_result.pov": response.status})
            return response

    @config.telem_tracer.start_as_current_span(
        "poll_patch",
        attributes={"crs.action.category": "scoring_submission", "crs.action.name": "scoring.poll_patch"},
        record_exception=False,
    )
    async def poll_patch(self, task_id: UUID, patch_id: int, response: PatchSubmissionResponse) -> PatchSubmissionResponse:
        span = trace.get_current_span()
        span.set_attributes({'task.id': str(UUID), 'crs.debug.patch_id': patch_id})
        async with self._client() as client:
            # poll until status is not 'accepted'
            logger.info(f"polling patch... {task_id=} {patch_id=} {response.patch_id=} {response.status=}")
            while response.status == 'accepted':
                await asyncio.sleep(POLL_PERIOD)
                response = await client.get_patch(str(task_id), str(response.patch_id))
            await self.db.put_submission(task_id, response, 'patches', patch_id)
            logger.info(f"done polling patch: {task_id=} {patch_id=} {response.patch_id=} {response.status=}")
            trace.get_current_span().add_event("poll_patch", attributes={"crs.debug.poll_result.patch": response.status})
            return response

    async def submit_rejected_sarif_report(self, report: VulnReport, reason: str):
        if report.sarif_id is None:
            logger.error("reached submit_rejected_sarif_report with report.sarif_id=None")
            return

        try:
            _ = await self.submit_sarif_assessment(report.task_uuid, None, report.sarif_id, False, reason)
        except Exception:
            logger.exception(f"Error submitting rejected sarif {report.task_uuid=} {report.sarif_id=}")