# Problem Statement

## Who is affected

Security operations analysts in defence and critical national infrastructure environments, and the
commanders who depend on their assessments. A tier-1 analyst on a twelve-hour watch is the specific
person this system is built for.

## The problem

A defence SOC aggregates alerts from systems that were never designed to interoperate: SIEM platforms,
network intrusion sensors, endpoint agents, satellite and geospatial feeds, cyber threat exchanges, and
human-authored intelligence reports. Each emits a different format with a different severity convention
and a different notion of what constitutes an event.

Three failures follow.

**Volume exceeds human capacity.** Alert counts run into the thousands per day. No analyst reads them
all, so triage collapses into whatever sorts to the top of the console — typically a vendor-assigned
severity field computed in isolation, with no knowledge of the asset involved or of the other alerts
occurring around it.

**The cost of error is asymmetric.** Investigating a false positive costs an analyst-hour. Missing a
genuine intrusion costs the mission. Yet the queue is ordered by neither of these; it is ordered by a
number a vendor picked.

**Correlation is the missing operation.** A real intrusion does not announce itself as one alert. It
appears as a phishing detection at 09:14, an anomalous process execution on the same host at 09:31,
and an outbound connection to an unfamiliar ASN at 09:47 — three alerts, three different tools, three
different consoles, three different analysts. Individually each is unremarkable. Together they are a
kill chain. The correlation exists in the data; nothing in the current workflow surfaces it.

## Why existing solutions fall short

SIEM correlation rules are deterministic and brittle. They catch attacks that have been seen before and
written down, which is precisely the set of attacks that matter least. They also generate their own
false-positive load, adding to the problem they were bought to solve.

SOAR platforms automate response but assume triage has already happened correctly. They accelerate
whatever decision the analyst made, including the wrong one.

Commercial AI triage tools are largely black boxes. In a defence context, an analyst who cannot see why
a system ranked something will not act on the ranking, and a commander cannot accept an assessment with
no visible evidence trail. Explainability is not a nice-to-have in this domain; it is a precondition for
adoption.

None of these produce the artefact the commander actually needs: a BLUF assessment stating what happened,
how confident we are, what to do next, and what we still do not know.

## Quantified pain

- Industry reporting consistently places SOC false-positive rates in the 40–60% band, meaning roughly
  half of all analyst investigation time produces nothing.
- Dwell time — intrusion to detection — is still measured in days to weeks across most sectors, despite
  the constituent alerts usually being present in the logs the whole time.
- Alert fatigue is a documented driver of SOC attrition, which compounds the problem: the analysts with
  the most pattern recognition are the ones who leave.

## Why now

Three things have changed. ATT&CK has matured into a comprehensive, machine-readable, freely available
taxonomy of adversary behaviour — a shared vocabulary that did not exist a decade ago. Embedding models
are now good enough and cheap enough to map unstructured alert text onto that taxonomy without a
hand-built rule for every case. And conversational agents such as IBM Bob make it possible for an
analyst to interrogate a reasoning system in natural language rather than learning a query DSL.

The pieces to solve this now exist independently. What is missing is the system that connects them.
