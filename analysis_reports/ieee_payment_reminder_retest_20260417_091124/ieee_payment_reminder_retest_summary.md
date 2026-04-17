# IEEE Payment Reminder Retest

- Timestamp (UTC): `2026-04-17T09:11:24.541261+00:00`
- Email: `IEEE ICNPCV 2026 - PAYMENT REMINDER.eml`
- Baseline verdict/score: `suspicious` / `0.5101`
- After verdict/score: `likely_safe` / `0.4195`
- Score delta (after-baseline): `-0.0906`

## Agent Risk Deltas
- `attachment_agent`: baseline `0.0` -> after `0.0` (delta `0.0`)
- `content_agent`: baseline `0.9488` -> after `0.62` (delta `-0.3288`)
- `header_agent`: baseline `0.4856` -> after `0.4856` (delta `0.0`)
- `sandbox_agent`: baseline `0.0` -> after `0.0` (delta `0.0`)
- `threat_intel_agent`: baseline `0.0004` -> after `0.0004` (delta `0.0`)
- `url_agent`: baseline `0.8147` -> after `0.4481` (delta `-0.3666`)
- `user_behavior_agent`: baseline `0.8454` -> after `0.58` (delta `-0.2654`)

## Reflection Checks (After)
- `headers_extracted`: `True`
- `body_extracted`: `True`
- `urls_extracted_count`: `5`
- `attachments_extracted_count`: `0`
- `header_agent_has_output`: `True`
- `content_agent_has_output`: `True`
- `url_agent_reflects_url_presence`: `True`
- `attachment_agent_reflects_attachment_presence`: `True`
- `sandbox_agent_reflects_attachment_presence`: `True`
- `threat_intel_reflects_iocs_presence`: `True`
- `user_behavior_has_output`: `True`
