from email_security.src.services.email_parser import EmailParserService

dummy_eml = b"From: badguy@evil.com\nTo: user@company.com\nSubject: Invoice\n\nPlease pay the invoice."
with open("dummy.eml", "wb") as f:
    f.write(dummy_eml)

parser = EmailParserService()
payload = parser.parse_file("dummy.eml")
print(payload)
