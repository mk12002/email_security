# Email Drop Full System Retest (Azure LLM)

- Run Start (UTC): `2026-04-17T09:44:56.854664+00:00`
- Run End (UTC): `2026-04-17T09:46:27.497426+00:00`
- Email Count: `3`
- Total Run Seconds: `90.6428`

## Agent Timing Totals (s)
- `header_agent`: `0.6308`
- `content_agent`: `7.2462`
- `url_agent`: `69.8073`
- `attachment_agent`: `0.3899`
- `sandbox_agent`: `0.3399`
- `threat_intel_agent`: `8.0635`
- `user_behavior_agent`: `0.0576`

## Per Email Verdicts, Durations, LLM Mode
- `Dabur & Sony invite you to AINCAT'26.eml`: baseline=`likely_safe`, after=`likely_safe`, score `0.257` (delta `0.0194`), total_email_seconds=`72.4253`, llm_fallback=`True`
- `IEEE ICNPCV 2026 - PAYMENT REMINDER.eml`: baseline=`suspicious`, after=`likely_safe`, score `0.4195` (delta `-0.0906`), total_email_seconds=`15.3013`, llm_fallback=`True`
- `live_check_sample.eml`: baseline=`suspicious`, after=`suspicious`, score `0.435` (delta `0.0`), total_email_seconds=`2.9148`, llm_fallback=`True`

## Reflection Checks
- `Dabur & Sony invite you to AINCAT'26.eml`: headers=True, body=True, urls=50, attachments=0
- `IEEE ICNPCV 2026 - PAYMENT REMINDER.eml`: headers=True, body=True, urls=5, attachments=0
- `live_check_sample.eml`: headers=True, body=True, urls=0, attachments=1
