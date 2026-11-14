# Two-minute demo script

Start the app first: `./run.sh`, then open http://127.0.0.1:8000.

Use the NIST case if its images have been examined. Otherwise use the practice case and say it is synthetic.

| Time | Show | Say |
|---|---|---|
| 0:00 | The case with an empty timeline, or the evidence list | "An employee is suspected of leaking files. We get disk images. Today this is days of manual work across separate tools, and the result is a slide nobody can check." |
| 0:15 | Press **Send all agents**. Watch the Activity log fill | "We send out six agents. Each one does a single forensic job and writes what it finds to a shared evidence ledger." |
| 0:30 | Timeline fills in. Point at the Cover-up lane | "Recovery brought back files from a formatted USB stick. Disguise found that these 'music' and 'photo' files are really Office documents. Wiper dated the format to the minute." |
| 0:50 | Files tab, pick a row. The thread draws across devices (switch to **By device**) | "This is one document. It starts on the company stick under its real name, shows up on the personal stick as `ringtone.amr`, and ends on a CD-R. Same bytes, proven by hash. Keyword search finds none of this." |
| 1:10 | Click a point, show the evidence panel, press **Download the recovered file** | "Every point is checkable: which image, which byte offset, which hash. A reviewer confirms or rejects each finding." |
| 1:25 | Press **Replay**, let two or three moments play. Optionally **3D view** | "For a jury, the same evidence plays back as a story, one moment at a time." |
| 1:45 | Score tab (NIST case) or the Narrative tab | "On the public NIST leak case we score ourselves against the published answer key. The agents never see it." |
| 1:55 | Open report | "And the prosecutor gets a cited report with an exhibit list. The model plans and writes. The tools compute. The ledger proves." |

## One-line pitch

Case Replay sends out agents that recover deleted files, expose files hiding under false names and flag wiping, then merges everything into one timeline where every point links to the bytes that prove it.

## Tracks

- Arlequin AI, Track 1: AI-Driven Forensics (main target)
- LangChain: best use of deepagents (lead investigator plus six specialist subagents, `casereplay/agents.py`)
- Main track: Science + Discovery

## Before recording

- [ ] `./run.sh test` passes
- [ ] The NIST images are downloaded and examined, or the practice case is clearly labelled synthetic on screen
- [ ] `ANTHROPIC_API_KEY` is set if you want to show the lead investigator writing the report
- [ ] Browser zoom at 90 to 100 percent so the three panels fit
