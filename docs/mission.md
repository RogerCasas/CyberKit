# CyberKit — Mission

## Vision

A unified, GUI-first cybersecurity learning platform that makes professional pen-testing techniques **visible, interactive, and approachable** — serving beginners, CTF players, and practitioners from a single polished desktop application.

## Mission Statement

CyberKit demystifies offensive and defensive security tooling by providing a modern graphical interface over the same techniques used by real-world professionals. Every module teaches the *what*, the *why*, and the *how* of a security concept — not just a button that runs a scan.

## Core Values

| Value | What it means in practice |
|---|---|
| **Educational first** | Every module includes context about what it does and why it matters. Results are categorised and explained, not just dumped. |
| **Honest tooling** | Techniques match what real tools (nmap, gobuster, hydra, etc.) do. No magic wrappers — learners understand the underlying protocol. |
| **Responsible use** | Every scan surface carries a clear disclaimer. The tool is scoped to targets the user owns or has explicit permission to test. |
| **Extensibility** | New modules drop into the sidebar with zero changes to the shell. One file = one tool. |
| **Polished UX** | Dark-themed, keyboard-friendly, never blocking. Results appear live. The UI teaches good security hygiene through its own design. |

## Primary Audiences

1. **Students & beginners** — Visual feedback and inline explanations lower the barrier to understanding network and web security concepts.
2. **CTF players** — Fast, reliable utility tools (encoder/decoder, hash identifier, port scanner) that are quicker to reach than installing separate CLI tools.
3. **Security professionals** — A lightweight desktop alternative to juggling a dozen terminal windows; useful for quick checks and demonstrations.

## Scope

CyberKit covers **reconnaissance, enumeration, analysis, and blue-team investigation** phases of security work. The v4.x roadmap expands into defensive tooling — log analysis, file metadata forensics, and integrity verification — to give learners visibility into both sides of the security picture. It deliberately stops short of exploitation frameworks (those belong in dedicated tools like Metasploit) to stay safe, legal, and educationally focused.

## Non-Goals

- Not a terminal emulator or script runner.
- Not a replacement for Burp Suite or Metasploit.
- Not a replacement for Wireshark — the v4.2 Packet Sniffer is an educational visualiser for understanding protocol structure, not a full capture-and-analysis suite.
- Not intended for automated mass-scanning of the public internet.
