"""
mock_dspm.py — Mock DSPM server for local testing.
Run: python mock_dspm.py
API: http://localhost:5001/api/v1/findings
"""

from flask import Flask, jsonify

app = Flask(__name__)

# Mock DSPM findings including DLP profile details
SAMPLE_FINDINGS = [
    {
        "file_path": "/usr/dr_tester/automation updated file.pdf",
        "dlp_profiles": [
            {
                "type": "Email Addresses",
                "sensitivity": "Medium",
                "occurrence_count": 12
            },
            {
                "type": "Taxpayer IDs",
                "sensitivity": "High",
                "occurrence_count": 3
            }
        ]
    }
]


@app.get("/api/v1/findings")
def findings():

    response = {
        "success": True,
        "data": {
            "total": len(SAMPLE_FINDINGS),
            "results": []
        }
    }

    for i, file in enumerate(SAMPLE_FINDINGS, start=1):

        sensitive_types = []

        for profile in file["dlp_profiles"]:
            sensitive_types.append({
                "data_type": {
                    "name": profile["type"]
                },
                "occurence_count": profile["occurrence_count"],
                "sensitivity_level": {
                    "name": profile["sensitivity"]
                }
            })

        response["data"]["results"].append({
            "id": str(10000 + i),
            "file_path": file["file_path"],
            "sensitive_data_types": sensitive_types
        })

    return jsonify(response)


if __name__ == "__main__":
    print("Mock DSPM running on http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
