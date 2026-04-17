# Email Drop Full System Retest Summary

- Run Start (UTC): `2026-04-17T09:16:47.564873+00:00`
- Run End (UTC): `2026-04-17T09:18:54.155692+00:00`
- Email Count: `3`
- Total Run Seconds: `126.5908`

## Agent Timing Totals (s)
- `header_agent`: `2.1433`
- `content_agent`: `16.3397`
- `url_agent`: `89.1431`
- `attachment_agent`: `4.9938`
- `sandbox_agent`: `3.6829`
- `threat_intel_agent`: `9.9295`
- `user_behavior_agent`: `0.145`

## Per Email Verdicts and Durations
- `Dabur & Sony invite you to AINCAT'26.eml`: baseline=`likely_safe`, after=`likely_safe`, score `0.257` (delta `0.0194`), total_email_seconds=`97.2007`
- `IEEE ICNPCV 2026 - PAYMENT REMINDER.eml`: baseline=`suspicious`, after=`likely_safe`, score `0.4195` (delta `-0.0906`), total_email_seconds=`18.4277`
- `live_check_sample.eml`: baseline=`suspicious`, after=`suspicious`, score `0.435` (delta `0.0`), total_email_seconds=`10.9566`

## Reflection Checks
- `Dabur & Sony invite you to AINCAT'26.eml`: headers=True, body=True, urls=50, attachments=0
- `IEEE ICNPCV 2026 - PAYMENT REMINDER.eml`: headers=True, body=True, urls=5, attachments=0
- `live_check_sample.eml`: headers=True, body=True, urls=0, attachments=1
