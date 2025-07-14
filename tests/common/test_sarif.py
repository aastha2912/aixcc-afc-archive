import json

import crs.modules.sarif as sarif
from crs.modules.testing import TestProject

SAMPLE_SARIF = """{
    "runs": [
        {
            "artifacts": [
                {
                    "location": {
                        "index": 0,
                        "uri": "src/ui/user_input.c"
                    }
                }
            ],
            "automationDetails": {
                "id": "/"
            },
            "conversion": {
                "tool": {
                    "driver": {
                        "name": "GitHub Code Scanning"
                    }
                }
            },
            "results": [
                {
                    "correlationGuid": "9d13d264-74f2-48cc-a3b9-d45a8221b3e1",
                    "level": "error",
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "index": 0,
                                    "uri": "src/ui/user_input.c"
                                },
                                "region": {
                                    "endLine": 1447,
                                    "startColumn": 1,
                                    "startLine": 1421
                                }
                            }
                        }
                    ],
                    "message": {
                        "text": "Associated risk: CWE-121"
                    },
                    "partialFingerprints": {
                        "primaryLocationLineHash": "22ac9f8e7c3a3bd8:8"
                    },
                    "properties": {
                        "github/alertNumber": 2,
                        "github/alertUrl": "https://api.github.com/repos/aixcc-afc/round-precomp-libpng/code-scanning/alerts/2"
                    },
                    "rule": {
                        "id": "CWE-121",
                        "index": 0
                    },
                    "ruleId": "CWE-121"
                }
            ],
            "tool": {
                "driver": {
                    "name": "CodeScan++",
                    "rules": [
                        {
                            "defaultConfiguration": {
                                "level": "warning"
                            },
                            "fullDescription": {
                                "text": "vulnerable to #CWE-121"
                            },
                            "helpUri": "https://example.com/help/png_handle_iCCP",
                            "id": "CWE-121",
                            "properties": {},
                            "shortDescription": {
                                "text": "CWE #CWE-121"
                            }
                        }
                    ],
                    "version": "1.0.0"
                }
            },
            "versionControlProvenance": [
                {
                    "branch": "refs/heads/challenges/full-scan",
                    "repositoryUri": "https://github.com/aixcc-afc/round-precomp-libpng",
                    "revisionId": "0fae79bd451de3dbbce3e317573f43be30125dff"
                }
            ]
        }
    ],
    "$schema": "https://raw.githubusercontent.com/microsoft/sarif-python-om/refs/heads/main/sarif-schema-2.1.0.json",
    "version": "2.1.0"
}"""

async def test_sarif_to_vuln_report(project: TestProject):
    """
    Tests that our sarif_to_vuln_report() function can parse a raw sarif.
    """
    task = (await project.tasks()).unwrap()[0]
    sample_sarif = json.loads(SAMPLE_SARIF)
    res = await sarif.sarif_to_vuln_report(task, sample_sarif)
    assert "src/ui/user_input.c" in res.description
    assert "CWE-121" in res.description
