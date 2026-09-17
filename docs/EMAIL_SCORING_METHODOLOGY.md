# Email scoring

Safety starts at 100. Sender identity mismatch costs 20, suspicious language 25, suspicious link indicators up to 30, HTML forms 10, and risky attachment metadata 15. Signals are grouped to avoid double counting. Confidence and completeness are 100% when all local checks execute; Gemini never changes the score.
