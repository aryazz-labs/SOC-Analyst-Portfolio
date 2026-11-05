# SOC282 – Phishing Alert: Deceptive Mail Detected (LetsDefend)
 
## Overview / Objective
 
This writeup covers my investigation of **SOC282 – Phishing Alert – Deceptive Mail Detected**, a Security Analyst–level lab on the **LetsDefend** SOC simulation platform. The alert is triggered by the email gateway when a message looks like phishing, and the job is to work out whether the email is really malicious, whether the user interacted with it, and whether the endpoint was compromised.

> **A note on how this investigation unfolded:** I worked this case in two parts. After finishing my first pass, I scored the alert as a true positive with no execution. Questions in the LetsDefend module then showed me I had skipped a key step: I never checked Felix's endpoint itself. Part Two covers that follow-up and it changed the outcome of the case. I've kept both parts in this writeup because the mistake is a useful lesson on its own.

