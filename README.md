# Phishing Email Detector

A beginner-friendly Python cybersecurity project that analyses local `.eml` files for common phishing indicators and generates a simple risk score.

## Features

- Parses email headers and body text
- Detects urgent or threatening wording
- Detects requests for sensitive information
- Compares sender and Reply-To domains
- Identifies SPF, DKIM and DMARC failures when present
- Extracts and evaluates URLs
- Flags suspicious attachments
- Produces Low, Medium or High risk ratings
- Optionally exports the report to JSON

## Project structure

```text
phishing-email-detector/
├── phishing_detector.py
├── sample_emails/
│   ├── sample_legitimate.eml
│   └── sample_phishing.eml
├── README.md
├── .gitignore
└── LICENSE
```

## Requirements

- Python 3.10 or later
- No external Python packages required

## Run the project

Open a terminal in the project folder.

Analyse the sample phishing email:

```bash
python phishing_detector.py sample_emails/sample_phishing.eml
```

On Windows, this path also works:

```bash
python phishing_detector.py sample_emails\sample_phishing.eml
```

Analyse the legitimate sample:

```bash
python phishing_detector.py sample_emails/sample_legitimate.eml
```

Save a JSON report:

```bash
python phishing_detector.py sample_emails/sample_phishing.eml --json phishing_report.json
```

## Example output

```text
=== Phishing Email Analysis Report ===
Risk score: 95/100
Risk level: High
Recommendation: Treat as likely phishing.
```

## Indicators checked

- Urgent or threatening language
- Requests for passwords, bank details or login credentials
- Sender and Reply-To domain mismatch
- SPF, DKIM and DMARC failures
- HTTP links
- Shortened URLs
- IP-based URLs
- Suspicious account-related domain names
- Dangerous attachment extensions

## Ethical use

This is a defensive learning project. It analyses local email files and does not send emails, collect credentials or interact with third-party accounts.

Do not open suspicious attachments or click suspicious links while testing.

## Limitations

This tool uses simple rule-based checks. It can produce false positives and false negatives. Real email security systems use additional threat intelligence, sandboxing, reputation checks and machine-learning models.

## Skills demonstrated

- Python scripting
- Email header analysis
- Phishing detection concepts
- Regular expressions
- URL parsing
- Risk scoring
- JSON report generation
- Git and GitHub documentation

## Future improvements

- Add a graphical interface
- Add CSV export
- Add domain-age and reputation checks through authorised APIs
- Add HTML email parsing
- Add a dashboard for analysing multiple emails
