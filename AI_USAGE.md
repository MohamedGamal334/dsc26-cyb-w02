# AI usage: dsc26-cyb-w02

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

<!-- Which AI tools you used (or "none"), and for which parts of the task. -->
I used an AI assistant to help structure and debug the complex logic for the coverage_gaps function in core.py, ensuring it correctly iterates over all in-scope elements and required STRIDE categories without missing any combinations
## What AI got wrong

<!-- At least one thing an AI tool got wrong that you changed, and how you noticed:
     a test, the docs, running it. -->
     An AI tool initially suggested a policy check that looked for an explicit encrypted: true flag. However, when running pytest, I noticed it failed against standard protocols like tls or https, so I manually rewrote the check to inspect the allowed protocol list properly

## In my own words

<!-- One or two sentences each, written without AI. -->

1. Why does a data store have no Spoofing threats in STRIDE per element, and where does that threat go instead?
Because a data store is just storage and can't act on its own, so spoofing applies to the process or connection talking to it instead

2. Which of your eleven new threats would you fix first, and why that one?
I would fix threat t16 first because it protects the API Gateway, which is the main entry point for all external traffic