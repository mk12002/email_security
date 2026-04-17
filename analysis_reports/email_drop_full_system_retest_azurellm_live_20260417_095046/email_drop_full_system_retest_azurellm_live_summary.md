# Email Drop Full System Retest (Azure LLM LIVE)

- Run Start (UTC): `2026-04-17T09:49:15.787550+00:00`
- Run End (UTC): `2026-04-17T09:50:46.191023+00:00`
- Email Count: `3`
- Total Run Seconds: `90.4035`

## Agent Timing Totals (s)
- `header_agent`: `0.5329`
- `content_agent`: `8.6673`
- `url_agent`: `68.4448`
- `attachment_agent`: `0.3839`
- `sandbox_agent`: `0.3174`
- `threat_intel_agent`: `1.9348`
- `user_behavior_agent`: `0.0797`

## Per Email Verdicts, Durations, LLM Mode
- `Dabur & Sony invite you to AINCAT'26.eml`: baseline=`likely_safe`, after=`likely_safe`, score `0.257` (delta `0.0194`), total_email_seconds=`68.139`, llm_fallback=`False`
- `IEEE ICNPCV 2026 - PAYMENT REMINDER.eml`: baseline=`suspicious`, after=`likely_safe`, score `0.4195` (delta `-0.0906`), total_email_seconds=`16.7766`, llm_fallback=`False`
- `live_check_sample.eml`: baseline=`suspicious`, after=`suspicious`, score `0.435` (delta `0.0`), total_email_seconds=`5.486`, llm_fallback=`False`

## Reflection Checks
- `Dabur & Sony invite you to AINCAT'26.eml`: headers=True, body=True, urls=50, attachments=0
- `IEEE ICNPCV 2026 - PAYMENT REMINDER.eml`: headers=True, body=True, urls=5, attachments=0
- `live_check_sample.eml`: headers=True, body=True, urls=0, attachments=1
