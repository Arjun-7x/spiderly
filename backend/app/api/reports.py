from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse

from app.api.auth import Identity, can_access, require_api_key
from app.database import database as db
from app.reports.generator import generate_html_report

router = APIRouter(dependencies=[Depends(require_api_key)])

# Report content is escaped server-side; the CSP is defence in depth
# (no scripts, no external loads) since it embeds scanned-host-controlled text.
REPORT_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
}


@router.get("/reports/{scan_id}", response_class=HTMLResponse)
async def get_report(scan_id: str, ident: Identity = Depends(require_api_key)):
    results = await db.run(db._get_results, scan_id)
    if not results or not can_access(results["scan"], ident):
        raise HTTPException(status_code=404, detail="Scan not found.")
    return HTMLResponse(content=generate_html_report(results), headers=REPORT_HEADERS)
