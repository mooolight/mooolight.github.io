---
title: Red Team Engagements
date: 2022-12-30 12:00:00 -500
categories: [Red Team Operator, Red Team Fundamentals Theory]
tags: [TryHackMe]
---

# Intro

- The key to a successful engagement is well-coordinated planning and communication through all parties involved.

<u>Engagements</u>:
- Tabletop exercises
- Adversary emulation
- Physical assessment

### Learning Objectives

 - Understand components and functions of a red team engagement.
 - Learn how to properly plan an engagement based of needs and resources available and TTPs.
 - Understand how to write engagement documentation in accordance to client objectives.

---------
# Defining Scope and Objectives

- Engagements can be very complex and bureaucratic.
- The key to a successful engagement is clearly defined `client objectives or goals`.
- Client objectives should be discussed between the client and red team to create a mutual understanding between both parties of what is expected and provided.
- Set objectives are the basis for the rest of the engagement documentation and planning.


- Without clear and concrete objectives and expectations, you are preparing for a very unstructured and unplanned campaign.
- `Objectives` set the tone for the rest of the engagement.

- When assessing a client's objectives and planning the engagement details, you will often need to decide how focused the assessment is.

- Engagements can be categorized between a `general internal/network penetration test` or a `focused adversary emulation`.

-> **Focused Adversary Emulation** : defines a specific APT group to emulate within an engagement.
- This will typically be determined based on groups that target the company's particular industries, i.e., financial institutions and APT38.

-> **Internal or network pentest** : follows a similar structure but will often be `less focused` and use more standard(known) TTPs.

- The specifics of the approach will depend on a case-by-case basis of the engagement defined by the client objectives.
- Client objectives will also affect the engagement's general Rules of Engagement and scope.
-> Expanded on task 6.


- The client objectives only set a basic definition of the client's goals of the engagement.
- The specific engagement plans will expand upon the client objectives and determine the specifics of the engagement.
- Engagement plans will be covered later within this room.


- The next `keystone` to a precise and transparent engagement is a `well-defined scope`.
- The `scope` of an engagement will vary by organization and what their infrastructure and posture look like.
- A client's scope will typically defined what you *can/cannot* do or target.
- While client objectives can be discussed and determined along with the providing team, a scope should only be set by the client.
- In some cases, the red team may discuss a grievance of the scope ifi t affects an engagement.
- They should have clear understanding of their network and the implications of an assessment.
- The specifics of the scope and the wording will always look different.
- Example of client's scope:

		- No exfiltration of data
		- Production servers are off-limits
		- 10.0.3.8/18 is out of scope.
		- 10.0.0.8/20 is in-scope.
		- System downtime is NOT permitted under ANY circumstances.
		- Exfiltration of PII is prohibited.

- When analyzing a client's objectives or scopes from a red team perspective, it is essential to understand the more profound meaning and implications.
- When analyzing, you should always have a dynamic understanding of how your team would approach the problems/objectives.
- If needed, you should write your engagement plans or start them from only a bare reading of the client objectives and scope.

<u>Example client objectives and scope for Global Enterprises</u>:

**Objectives**:
##### 1. Identify system misconfigurations and network weaknessses.
		- Focus on exterior systems.
##### 2. Determine the effectiveness of endpoint detection and response systems.
##### 3. Evaluate overall security posture and response:
		- SIEM and detection measures
		- Remediation
		- Segmentation of DMZ and internal servers.
##### 4. Use of `white cards` is permitted depending on downtime and length.
##### 5. Evaluate the impact of data exposure and exfiltration.

**Scope**:
##### 1. Systen downtime is not permitted under any circumstance.
		- Any form of DDoS or DoS is prohibited.
		- Use of any harmful malware is prohibited; this includes ransomware and other variations.
##### 2. Exfiltration of PII is prohibited. Use arbitrary exfiltration data.
##### 3. Attacks against systems within 10.0.4.0/22 are permitted.
##### 4. Attacks against systems within 10.0.12.0/22 are prohibited.
##### 5. Bean enterprises will closely monitor interactions with the DMZ and critical/production systems.
		- Any interaction with "*.bethechange.xyz*" is prohibited.
		- All interaction with "*.globalenterprises.htm*" is permitted.

------
# Rules of Engagement

- Rules of Engagement (RoE) are a legally binding outline of the client objectives and scope with further details of engagement expectations between both parties.
- This is the first "**official**" document in the engagement planning process and requires proper authorization between the client and the red team.
- This document often acts as the general contract between the two parties
- An external contract or other NDAs can also be used.


- The format and wording of RoE are critical since it is a legally binding contract and sets clear expectations.
- Each RoE structure will be determined by the client and red team can vary in content length and overall sections. Standard sections found in an RoE:
![](/assets/img/Pasted image 20221129085957.png)

-> Note that this is a summary:


----
# Campaign Planning
- Prior to this task, we have primarily focused on engagement planning and documentation from the business perspective.
- Campaign planning uses the information required and planned from the client objectives and RoE and applies it to various plans and documents to identify how and what the red team will do.


- Each internal red team will have its methodology and documentation for campaign planning.
- We will be showing one in-depth set of plans that allows for precise communication and detailed documentation.
- The campaign summary we will be using consists of four different plans varying in-depth and coverage adapted from military ops documents:
![](/assets/img/Pasted image 20221129091559.png)

-> Here's the checklist: https://redteam.guide/docs/checklists/red-team-checklist/

------
# Engagement Documentation

- Engagement documentation is an extension of campaign planning where ideas and thoughts of campaign planning are officially documented.
- In this context, the term "`document`" can be **deceiving** as some plans do NOT require proper documentation and can be as simple as an email.

<u>Engagement Plan</u>:
![](/assets/img/Pasted image 20221129092010.png)

<u>Operations Plan</u>:
![](/assets/img/Pasted image 20221129092540.png)

<u>Mission Plan</u>:
![](/assets/img/Pasted image 20221129092557.png)

<u>Remediation Plan(Optional)</u>:
![](/assets/img/Pasted image 20221129092616.png)

------
# Concept of Operations

- The **Concept of Operations** (CONOPS) is a part of engagement plan that details a `high-level overview` of the proceedings of an engagement.
- We can compare this to an executive summary of a pentest report.
- The document will serve as a business/client reference and a reference for the red cell to build off of and extend to further campaign plans.

- The CONOPS document should be written from a semi-technical summary perspective, assuming the target audience/reader has zero to minimal technical knowledge.
- Although the CONOPS should be written at a high-level, you should `not` omit details such as common tooling, target group,etc., as with most red team documents
- There is not a set standard of a CONOPS document
- Below is an outline of critical components that should be included in a CONOPS:

		- Client Name
		- Service Provider
		- Timeframe
		- General Objectives/Phases
		- Other Training Objectives(Exfiltration)
		- High-Level Tools/Techniques planned to be used
		- Threat group to emulate (if any)

- The key to writing and understanding a CONOPS is to provide just enough information to get a general understanding of all on-goings.
- The CONOPS should be easy to read and show clear definitions and points that readers can easily digest.

**Example CONOPS with Holo Enterprises**:

<u>CONOPS</u>:

- Holo Enterprises has hired TryHackMe as an external contractor to conduct a `month-long` network infrastructure assessment and security posture.
- The campaign will utilize an *assumed breach* model starting in `Tier 3 infrastructure`.
- Operators will progressively conduct recon and attempt to meet objectives to be determined.
- If defined goals are not met, the red cell will move and `escalate privileges` within the network `laterally`.
- Operators are also expected to `execute` and maintain `persistence` to sustain for a period of `three weeks`.
- A `trusted agent` is expected to intervene if the red cell is `identified or burned by blue cell` throughout the `entirety` of the engagement.
- The `last engagement` day is reserved for clean-up and remediation and consulation with the blue and white cell.


- The customer has requested the following training objectives:

		- Assess the blue team's ability to identify and defend against live intrusions and attacks.
		- Identify the risk of an adversary within the internal network.
		- The red cell will accomplish objectives by employing the use of Cobalt Strike as the primary red cell tool.
		- The red cell is permitted to use other standard tooling only identifiable to the target threat.
		- Uses the TTP of the threat group: FIN6 will be employed throughout the engagement.


---------
# Resource Plan
- The resource plan is the `second document` of the engagement plan, detailing a brief overview of dates, knowledge required (optional), resource requirements.
- The plan extends the CONOPS and includes specific details, such as `dates`, `knowledge required`, etc.


- Unlike CONOPS, the resource plan should not be written as a summary; instead, written as bulleted lists of subsections.
- As with most red team documents, there is no standard set of resource plan templates or documents.

**Outline of Resource Plan**:
- Header
		- Personnel Writing
		- Dates
		- Customer
- Engagement Dates
		- Recon Dates
		- Initial Compromise Dates
		- Post-Exploitation and Persistence Dates
		- Misc. Dates
- Knowledge Required(optional)
		- Recon
		- Initial Compromise
		- Post-Exploitation
- Resource Requirements
		- Personnel
		- Hardware
		- Cloud
		- misc.


-> The key to writing and understanding a resource plan is to provide enough information to gather what is required but not become overbearing.
-> The document should be straight to the point and define what is needed.

<u>Example</u>:
![](/assets/img/Pasted image 20221129095142.png)

--------------
# Operations Plan
- The operations plan is a flexible document(s) that provides specific details of the engagement and actions occurring.
- The plan expands upon the current CONOPS and should include a majority of specific engagement information; the **RoE** can also be placed here depending on the depth and structure of the RoE.


- The operations plan should follow a similar writing scheme to the resource plan, using bulleted lists and small sub-sections.
- As with other red team documents, there is no standard set of operation plan templates or documents;


<u>Example Subsections within an Operations Plan</u>:
- Header
		- Personnel Writing
		- Dates
		- Customer
- Halting/stopping conditions(can be placed in RoE depending on depth)
- Required/assigned personnel
- Specific TTPs and attacks planned
- Communications plan
- Rules Of Engagement(Optional)

- The most notable addition to this document is the **communications plan**.
- The **communications plan** should summarize how the red cell will communicate with other cells and the client overall.
- Each team will have its preferred method to communicate with clients.
- Samples:

		- vectr.io
		- Email
		- Slack

<u>Example of an Operations Plan</u>:
![](/assets/img/Pasted image 20221129095952.png)

-------
# Mission Plan

- The mission plan is a `cell-specific document` that details the `exact actions` to be completed by operators.
- The document uses information from previous plans and assigns actions to them.


- How the document is written and detailed will depend on the team.
- As this is an `internally used document`, the structure and detail have less impact.
- As with all the documents outlined in this room, presentation can vary
- This plan can be as simple as emailing all operators.
- List of details that cells should include in the plan:

		- Objectives
		- Operators
		- Exploits/Attacks
		- Targets (users/machines/objectives)
		- Execution plan variations

- Operations Plan: considered from a `business` and `client` perspective
- Missions Plan : from an `operator` and `red cell` perspective.

<u>Example</u>:
![](/assets/img/Pasted image 20221129100946.png)