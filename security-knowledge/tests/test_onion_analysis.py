from app.workers.onion_analysis import extract_onion_findings


def test_extract_onion_findings_core_fields():
    sample = """
    <html><body>
      Victim: Acme Hospital
      Contact: ops@acme-hospital.example
      BTC: bc1qw4v3xgk7z0n53r6u2q2y3f3e5h6j7k8l9m0npq
      Ethereum: 0x1234567890abcdef1234567890ABCDEF12345678
      Binary package dropped as payload.exe and stage2.dll
      Hashes: d41d8cd98f00b204e9800998ecf8427e
      IOC: 185.199.108.153 and intranet.acme-hospital.example
      Demand: $1,500,000 payable in 3 BTC
      Mirror: abcdefghijklmnop.onion
    </body></html>
    """
    findings = extract_onion_findings(sample)

    assert "Acme Hospital" in findings["victims"]
    assert "ops@acme-hospital.example" in findings["emails"]
    assert "payload.exe" in findings["binaries"]
    assert "stage2.dll" in findings["binaries"]
    assert "d41d8cd98f00b204e9800998ecf8427e" in findings["hashes"]
    assert "185.199.108.153" in findings["ips"]
    assert "intranet.acme-hospital.example" in findings["domains"]
    assert "abcdefghijklmnop.onion" in findings["onion_links"]
    assert findings["summary"]["payment_address_count"] >= 2
    assert findings["summary"]["ioc_count"] >= 3

