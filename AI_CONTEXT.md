# R Antivirus — AI Development Context

## Project
R Antivirus is an experimental Windows desktop antivirus application written in Python.

Repository:
https://github.com/Qaif95/R-Antivirus

## Project objective
Develop a reliable, privacy-conscious Windows antivirus application.

Security and reliability are more important than adding features.

## Technology
- Python
- PySide6
- ClamAV
- VirusTotal API
- Windows filesystem monitoring
- Windows Task Scheduler

## Development rules

1. Never rewrite the entire project without explicit approval.
2. Preserve existing functionality unless a change is necessary.
3. Never silently swallow security-related exceptions.
4. Never claim a security feature works without testing it.
5. Follow the principle of least privilege.
6. Protect quarantine operations against path traversal and file corruption.
7. Do not introduce unnecessary dependencies.
8. Explain changes in beginner-friendly language.
9. Provide complete replacement files when requested.
10. Include tests for security-critical changes.

## AI collaboration rules

- ChatGPT: Lead technical planning and implementation.
- Gemini: Independent review.
- DeepSeek: Independent debugging and review.
- All AI reviewers must examine the same proposed Git diff.
- No AI may independently merge untested changes into main.

## Current policy

Microsoft Defender remains enabled during development.

R Antivirus must not be represented as production-grade antivirus software until its security and reliability have been independently validated.
