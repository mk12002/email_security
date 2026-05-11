import sys
import os
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, r'd:\Code_stuff\email_stuff\email_security')

from src.services.email_parser import EmailParserService
from src.agents.header_agent import analyze as header_analyze
from src.agents.content_agent import analyze as content_analyze
from src.agents.url_agent import analyze as url_analyze
from src.agents.attachment_agent import analyze as attachment_analyze
from src.agents.sandbox_agent import analyze as sandbox_analyze
from src.agents.threat_intel_agent import analyze as threat_intel_analyze
from src.agents.user_behavior_agent import analyze as user_behavior_analyze
from src.orchestrator.scoring_engine import calculate_threat_score
from src.orchestrator.threat_correlation import correlate_threats
from src.orchestrator.storyline_engine import generate_storyline

def main():
    eml_file = 'email_drop/test_malspam_invoice.eml'
    print(f'Testing complete system with {eml_file}...\n')
    
    # 1. Parse EML
    parser = EmailParserService()
    parsed_email = parser.parse_file(eml_file)
    print('EML Parsed Successfully.')
    print(f'  Sender: {parsed_email["headers"].get("sender")}')
    print(f'  Subject: {parsed_email["headers"].get("subject")}')
    print(f'  URLs found: {len(parsed_email.get("urls", []))}')
    print(f'  Attachments found: {len(parsed_email.get("attachments", []))}\n')

    # 2. Run Agents
    results = {}
    
    print('[Running Header Agent]')
    r = header_analyze(parsed_email)
    results['header_agent'] = r
    print(f'  => Risk: {r["risk_score"]:.4f}, Conf: {r["confidence"]:.4f}, Ind: {r["indicators"][:3]}')

    print('[Running Content Agent]')
    r = content_analyze(parsed_email)
    results['content_agent'] = r
    print(f'  => Risk: {r["risk_score"]:.4f}, Conf: {r["confidence"]:.4f}, Ind: {r["indicators"][:3]}')

    print('[Running URL Agent]')
    r = url_analyze(parsed_email)
    results['url_agent'] = r
    print(f'  => Risk: {r["risk_score"]:.4f}, Conf: {r["confidence"]:.4f}, Ind: {r["indicators"][:3]}')

    print('[Running Attachment Agent]')
    r = attachment_analyze(parsed_email)
    results['attachment_agent'] = r
    print(f'  => Risk: {r["risk_score"]:.4f}, Conf: {r["confidence"]:.4f}, Ind: {r["indicators"][:3]}')

    print('[Running Sandbox Agent]')
    r = sandbox_analyze(parsed_email)
    results['sandbox_agent'] = r
    print(f'  => Risk: {r["risk_score"]:.4f}, Conf: {r["confidence"]:.4f}, Ind: {r["indicators"][:3]}')

    print('[Running Threat Intel Agent]')
    r = threat_intel_analyze(parsed_email)
    results['threat_intel_agent'] = r
    print(f'  => Risk: {r["risk_score"]:.4f}, Conf: {r["confidence"]:.4f}, Ind: {r["indicators"][:3]}')

    print('[Running User Behavior Agent]')
    r = user_behavior_analyze(parsed_email)
    results['user_behavior_agent'] = r
    print(f'  => Risk: {r["risk_score"]:.4f}, Conf: {r["confidence"]:.4f}, Ind: {r["indicators"][:3]}\n')

    # 3. Orchestrator
    print('[Orchestrator Scoring & Correlation]')
    agent_results_list = list(results.values())
    score_data = calculate_threat_score(agent_results_list)
    correlation = correlate_threats(agent_results_list)
    overall = float(score_data.get('overall_score', 0.0))
    corr = float(correlation.get('correlation_score', 0.0))
    normalized = min(1.0, overall + (0.2 * corr))

    if normalized >= 0.8:
        verdict = 'malicious'
    elif normalized >= 0.6:
        verdict = 'high_risk'
    elif normalized >= 0.4:
        verdict = 'suspicious'
    else:
        verdict = 'likely_safe'

    storyline = generate_storyline(
        agent_results=agent_results_list,
        verdict=verdict,
        recommended_actions=['quarantine'] if verdict in ('malicious', 'high_risk') else ['review'],
    )

    print('==================================================')
    print('FINAL RESULT')
    print('==================================================')
    print(f'Overall Risk Score: {overall:.4f}')
    print(f'Correlation Boost:  +{corr * 0.2:.4f}')
    print(f'Final Normalized:   {normalized:.4f}')
    print(f'Verdict:            {verdict.upper()}')
    print('Storyline:')
    for phase in storyline:
        print(f"  - [{phase['phase']}] {phase['description']}")

if __name__ == '__main__':
    main()
