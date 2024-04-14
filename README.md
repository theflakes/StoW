# StoW - Sigma to Wazuh rule converter in GO

Reason for moving from Python3:  
- I want to learn GO.
- I don't like Python data structures.
- Fresh look at the problem by starting over.

Problem(s) this probably won't fix by moving to GO:
- Converting a more expressive logic (Sigma) to a less expressive logic (Wazuh)

## Current state:
- Skeleton PoC
- Working Sigma / Wazuh data structures and config moved to Yaml implemented
- Reads in all Sigma rules
- Creates skeleton Wazuh rules (no logic conversion)