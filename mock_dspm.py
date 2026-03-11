"""
mock_dspm.py — Mock DSPM server for local testing.
Run: python mock_dspm.py  (port 5001)
"""

from flask import Flask, jsonify

app = Flask(__name__)

# These paths must match the normalised form of the upload event paths
# i.e. lowercase, forward slashes, prefix stripped
SAMPLE_FINDINGS = [
    {"file_path": "/usr/clients/acme/invoices/march_2024.csv"},
    {"file_path": "/usr/clients/acme/contracts/agreement.pdf"},
    {"file_path": "/usr/partners/xyz/employee_data.xlsx"},
    {"file_path": "/usr/internal/hr/salaries.csv"},         # internal — should NOT alert
]


@app.get("/api/v1/findings")
def findings():
    return jsonify({"findings": SAMPLE_FINDINGS})


if __name__ == "__main__":
    print("Mock DSPM running on http://localhost:5001")
    app.run(port=5001, debug=False)
