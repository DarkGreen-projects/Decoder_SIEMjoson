from __future__ import annotations

from unittest.mock import patch

from decoder_siem.enrichers.abuseipdb import AbuseIPDBEnricher
from decoder_siem.enrichers.otx import OTXEnricher
from decoder_siem.enrichers.urlhaus import URLhausEnricher
from decoder_siem.enrichment_config import EnrichmentConfig
from decoder_siem.models import (
    Artifact,
    ArtifactReport,
    ArtifactScope,
    ArtifactType,
    EnrichmentResult,
    EnrichmentStatus,
)
from decoder_siem.pipeline import build_report_from_text
from decoder_siem.table_export import (
    TABLE_HEADERS,
    classify_artifact,
    enrichment_by_name,
    report_to_rows,
)


def _artifact(art_type: ArtifactType, value: str) -> Artifact:
    return Artifact(
        type=art_type,
        value=value,
        normalized_value=value,
        scope=ArtifactScope.PUBLIC,
        provenance=["test"],
    )


def test_abuseipdb_enrich_success():
    enricher = AbuseIPDBEnricher("test-key", requests_per_minute=1000)
    mock_response = {
        "data": {
            "abuseConfidenceScore": 87,
            "totalReports": 42,
            "countryCode": "US",
        }
    }
    with patch.object(
        enricher._http,
        "get_json",
        return_value=(200, mock_response, None),
    ):
        result = enricher.enrich(_artifact(ArtifactType.IP, "1.2.3.4"))

    assert result.status == EnrichmentStatus.SUCCESS
    assert result.data["abuse_confidence_score"] == 87
    assert AbuseIPDBEnricher.is_malicious(result.data)


def test_abuseipdb_not_found():
    enricher = AbuseIPDBEnricher("test-key", requests_per_minute=1000)
    with patch.object(
        enricher._http,
        "get_json",
        return_value=(404, None, "not found"),
    ):
        result = enricher.enrich(_artifact(ArtifactType.IP, "8.8.8.8"))

    assert result.status == EnrichmentStatus.NOT_FOUND


def test_otx_enrich_with_pulses():
    enricher = OTXEnricher("test-key", requests_per_minute=1000)
    mock_response = {"pulse_info": {"count": 5}, "country_name": "US"}
    with patch.object(
        enricher._http,
        "get_json",
        return_value=(200, mock_response, None),
    ):
        result = enricher.enrich(_artifact(ArtifactType.DOMAIN, "evil.example"))

    assert result.status == EnrichmentStatus.SUCCESS
    assert result.data["pulse_count"] == 5
    assert OTXEnricher.is_malicious(result.data)


def test_urlhaus_url_online():
    enricher = URLhausEnricher("auth-key", requests_per_minute=1000)
    mock_response = {
        "query_status": "ok",
        "url_status": "online",
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
        "tags": ["emotet"],
    }
    with patch.object(
        enricher._http,
        "post_form_json",
        return_value=(200, mock_response, None),
    ):
        result = enricher.enrich(
            _artifact(ArtifactType.URL, "http://evil.example/malware.exe")
        )

    assert result.status == EnrichmentStatus.SUCCESS
    assert URLhausEnricher.is_malicious(result.data)


def test_urlhaus_host_no_results():
    enricher = URLhausEnricher("auth-key", requests_per_minute=1000)
    with patch.object(
        enricher._http,
        "post_form_json",
        return_value=(200, {"query_status": "no_results"}, None),
    ):
        result = enricher.enrich(_artifact(ArtifactType.DOMAIN, "benign.example"))

    assert result.status == EnrichmentStatus.NOT_FOUND


def test_classify_vt_benign_abuseipdb_malicious():
    ar = ArtifactReport(
        artifact=_artifact(ArtifactType.IP, "1.2.3.4"),
        enrichments=[
            EnrichmentResult(
                enricher="virustotal",
                status=EnrichmentStatus.SUCCESS,
                data={"last_analysis_stats": {"malicious": 0, "harmless": 70}},
            ),
            EnrichmentResult(
                enricher="abuseipdb",
                status=EnrichmentStatus.SUCCESS,
                data={"abuse_confidence_score": 90, "total_reports": 10},
            ),
        ],
    )
    assert classify_artifact(ar) == "malicious"


def test_classify_otx_only_benign():
    ar = ArtifactReport(
        artifact=_artifact(ArtifactType.DOMAIN, "example.com"),
        enrichments=[
            EnrichmentResult(
                enricher="otx",
                status=EnrichmentStatus.NOT_FOUND,
                summary="assente",
            ),
        ],
    )
    assert classify_artifact(ar) == "benign"


def test_pipeline_urlhaus_without_vt():
    text = '{"HostIp": "8.8.8.8"}'
    config = EnrichmentConfig(
        vt_api_key=None,
        urlhaus_auth_key="fake-auth",
        osint_requests_per_minute=1000,
    )

    def fake_post(url, form, **kwargs):
        host = form.get("host", "")
        if host == "8.8.8.8":
            return (
                200,
                {
                    "query_status": "ok",
                    "url_count": "2",
                    "host": host,
                    "urlhaus_reference": f"https://urlhaus.abuse.ch/host/{host}/",
                },
                None,
            )
        return (200, {"query_status": "no_results"}, None)

    with patch(
        "decoder_siem.enrichers.urlhaus.HttpClient.post_form_json",
        side_effect=fake_post,
    ):
        report = build_report_from_text(text, enrich=True, config=config)

    enriched = [a for a in report.artifacts if a.enrichments]
    assert enriched
    uh = enrichment_by_name(enriched[0], "urlhaus")
    assert uh is not None
    assert uh.status == EnrichmentStatus.SUCCESS
    vt = enrichment_by_name(enriched[0], "virustotal")
    assert vt is not None
    assert vt.status == EnrichmentStatus.SKIPPED


def test_table_headers_include_osint_columns():
    assert len(TABLE_HEADERS) == 11
    assert "AbuseIPDB" in TABLE_HEADERS
    assert "URLhaus" in TABLE_HEADERS


def test_report_to_rows_osint_cells():
    ar = ArtifactReport(
        artifact=_artifact(ArtifactType.IP, "1.2.3.4"),
        enrichments=[
            EnrichmentResult(
                enricher="abuseipdb",
                status=EnrichmentStatus.SUCCESS,
                data={
                    "abuse_confidence_score": 50,
                    "permalink": "https://www.abuseipdb.com/check/1.2.3.4",
                },
                summary="AbuseIPDB score 50%",
            ),
        ],
    )
    from decoder_siem.models import IncidentReport, IncidentContext

    report = IncidentReport(
        source_file="test",
        context=IncidentContext(),
        artifacts=[ar],
    )
    rows = report_to_rows(report)
    assert rows[0][7] == "50%"
