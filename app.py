import requests
from flask import Flask, request, render_template, send_file
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import io

app = Flask(__name__)

API_KEY = ""  # Replace with your VirusTotal API key
HEADERS = {"x-apikey": API_KEY}
BASE_URL = "https://www.virustotal.com/api/v3"


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


@app.route("/scan_file", methods=["POST"])
def scan_file():
    file = request.files.get("file")
    if not file:
        return "No file uploaded", 400

    files = {"file": (file.filename, file.stream, file.content_type)}
    response = requests.post(f"{BASE_URL}/files", headers=HEADERS, files=files).json()

    analysis_id = response["data"]["id"]
    report = requests.get(f"{BASE_URL}/analyses/{analysis_id}", headers=HEADERS).json()

    stats = report["data"]["attributes"]["stats"]
    results = report["data"]["attributes"]["results"]

    return render_template("report.html", stats=stats, results=results,
                           filename=file.filename, type="File")


@app.route("/scan_url", methods=["POST"])
def scan_url():
    url = request.form.get("url")
    if not url:
        return "No URL provided", 400

    data = {"url": url}
    response = requests.post(f"{BASE_URL}/urls", headers=HEADERS, data=data).json()

    analysis_id = response["data"]["id"]
    report = requests.get(f"{BASE_URL}/analyses/{analysis_id}", headers=HEADERS).json()

    stats = report["data"]["attributes"]["stats"]
    results = report["data"]["attributes"]["results"]

    return render_template("report.html", stats=stats, results=results,
                           filename=url, type="URL")


@app.route("/scan_ip", methods=["POST"])
def scan_ip():
    ip = request.form.get("ip")
    if not ip:
        return "No IP provided", 400

    response = requests.get(f"{BASE_URL}/ip_addresses/{ip}", headers=HEADERS).json()
    data = response["data"]["attributes"]

    return render_template("ip_domain_report.html", data=data, identifier=ip, type="IP Address")


@app.route("/scan_domain", methods=["POST"])
def scan_domain():
    domain = request.form.get("domain")
    if not domain:
        return "No domain provided", 400

    response = requests.get(f"{BASE_URL}/domains/{domain}", headers=HEADERS).json()
    data = response["data"]["attributes"]

    return render_template("ip_domain_report.html", data=data, identifier=domain, type="Domain")


@app.route("/download_report", methods=["POST"])
def download_report():
    """Generate a PDF report of scan results"""
    filename = request.form.get("filename")
    stats = eval(request.form.get("stats"))  # Convert string back to dict
    results = eval(request.form.get("results"))

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()

    # Title
    elements.append(Paragraph(f"VirusTotal Report for: {filename}", styles['Title']))
    elements.append(Spacer(1, 12))

    # Summary
    elements.append(Paragraph("<b>Scan Summary:</b>", styles['Heading2']))
    summary_data = [
        ["Malicious", stats["malicious"]],
        ["Suspicious", stats["suspicious"]],
        ["Harmless", stats["harmless"]],
        ["Undetected", stats["undetected"]],
    ]
    summary_table = Table(summary_data, hAlign="LEFT")
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))

    # Detailed Engine Results
    elements.append(Paragraph("<b>Engine Results:</b>", styles['Heading2']))
    data = [["Engine", "Category", "Result"]]
    for engine, details in results.items():
        data.append([engine, details["category"], details["result"] or "Clean"])

    table = Table(data, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.green),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
    ]))
    elements.append(table)

    doc.build(elements)
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name=f"{filename}_report.pdf", mimetype="application/pdf")


if __name__ == "__main__":
    app.run(debug=True)

