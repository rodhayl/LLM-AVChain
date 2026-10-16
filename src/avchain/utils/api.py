from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


def attach_api_contract_handlers(app: FastAPI) -> FastAPI:
    @app.exception_handler(RequestValidationError)
    async def _validation_exception_handler(
        _: Request,
        __: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "error": "invalid_request",
                "message": "Request validation failed",
            },
        )

    return app
