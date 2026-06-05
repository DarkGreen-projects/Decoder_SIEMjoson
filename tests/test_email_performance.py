from decoder_siem.pipeline import build_report_from_text, _enrichable_for_report


def test_email_skips_generic_header_explosion():
    headers = (
        "From: sender@company.example\n"
        "To: user@corp.local\n"
        "Subject: Test\n"
        "Message-ID: <id@company.example>\n"
        "MIME-Version: 1.0\n"
        "Authentication-Results: mx.corp.local; spf=fail; dmarc=fail\n"
    )
    headers += "\n".join(
        f"Received: from hop{i}.evil.example ([203.0.113.{i}]) by mx{i}.corp.local;"
        for i in range(25)
    )
    report = build_report_from_text(headers, enrich=False)
    assert report.context.vendor == "EmailHeaders"
    assert len(report.artifacts) < 80
    assert not any(
        "root.headers" in p for ar in report.artifacts for p in ar.artifact.provenance
    )


def test_email_enrichment_cap():
    headers = (
        "From: a@b.example\n"
        "To: u@c.local\n"
        "Subject: T\n"
        "Message-ID: <x@b.example>\n"
        "MIME-Version: 1.0\n"
    )
    headers += "\n".join(
        f"Received: from r{i}.e.example ([8.8.{i // 250}.{i % 250}]) by mx{i}; Mon, 2 Jun 2025 10:00:00 +0000"
        for i in range(30)
    )
    report = build_report_from_text(headers, enrich=False)
    capped = _enrichable_for_report(report)
    assert len(report.enrichable_artifacts) > 20
    assert len(capped) == 20
