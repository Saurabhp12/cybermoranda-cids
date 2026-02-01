# CyberMoranda CIDS

**CyberMoranda CIDS (Cognitive Intrusion Defense System)** is a behavior-based, ethical security prototype designed for modern web applications.  
It focuses on understanding **intent and behavior**, rather than relying only on static rules or instant blocking.

---

## Problem

Traditional firewalls and intrusion prevention systems often:
- Block traffic instantly
- Generate false positives
- Reveal defensive patterns to attackers
- Punish legitimate users for abnormal but valid behavior

This reactive approach creates noise, operational fatigue, and weak long-term defense.

---

## Solution

CyberMoranda CIDS follows an **observe → understand → contain** philosophy.

Instead of aggressive blocking, the system:
- Observes user behavior
- Assigns a dynamic risk score
- Applies **ethical, non-punitive containment**
- Uses deception to safely study attacker intent

The goal is to **waste attacker time**, protect real assets, and avoid harming legitimate users.

---

## Key Features

- **Behavioral Risk Analysis**  
  Detects intent using request patterns instead of signatures.

- **Explainable Security Decisions**  
  Every response is traceable and understandable (no black-box blocking).

- **Non-Punitive Containment**  
  Uses tarpitting and deception instead of immediate bans.

- **Decoy-Based Observation**  
  Honeypot paths (e.g. `/admin`) help identify malicious intent safely.

- **Professional SOC-Style Interface**  
  Clean, enterprise-grade dashboard for real-time visibility.

---

## Azure AI (Planned Architecture)

Azure AI is planned as a **post-analysis explanation layer**.

- Converts security events into human-readable summaries
- Helps explain *why* a session was classified as hostile
- **Live AI decision-making is intentionally disabled** in this MVP to avoid over-automation and false trust

---

## Demo

🎥 **Demo Video**  
A 60-second walkthrough demonstrating:
- Behavioral risk scoring  
- Ethical containment  
- Deception-based defense  
- Explainable security decisions  

---

## Disclaimer

This project is built **strictly for defensive security research and education**.

- No offensive use
- No exploitation tools
- No real-world attack facilitation

---

## Project Context

CyberMoranda CIDS is an MVP developed for:
- Learning and research
- Ethical cybersecurity experimentation
- Innovation challenges (e.g. Imagine Cup)

---

**CyberMoranda Research**  
*Cognitive Intrusion Defense System*