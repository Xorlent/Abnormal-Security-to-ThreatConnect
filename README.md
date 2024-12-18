# Abnormal-Security-to-ThreatConnect
### A tool for publishing Abnormal email threat intelligence to ThreatConnect
## Summary
This Windows PowerShell tool Get-AbnormaltoTC.ps1 streamlines publishing legitimate [Abnormal Security](https://abnormalsecurity.com) email-based attack threat intel data to the [ThreatConnect](https://threatconnect.com) TI platform.  By default, this tool iterates through the following Abnormal threat types, presents each unique result to the analyst, and prompts to (I)nspect in browser, (F)ilter e-mail From Address, (Y)send, or (N)skip the result.  
- Invoice/Payment Fraud (BEC)
- Malware
- Extortion
- Phishing: Sensitive Data
- Scam
- Internal-to-Internal Attacks (Email Account Takeover)
- Social Engineering (BEC)
- Phishing: Credential
- Other

## Requirements
- A Windows host with PowerShell
- An Abnormal Security API key (Settings->Abnormal REST API)
- ThreatConnect API credentials (Access ID and secret key)

## Usage
1. In a PowerShell window, run Get-AbnormaltoTC.ps1
2. If no configuration file is present, the tool will prompt for necessary information:
   - ThreatConnect API Endpoint URL
   - Abnormal Security API key
   - ThreatConnect access ID
   - ThreatConnect secret key
   - Organization nickname or common abbreviation
   - Organization full name
   - Organization email domain name
   - Owner name for ThreatConnect intel records
   - Organization city, state
3. The tool then prompts for the number of days of data to retrieve
4. Each Abnormal threat result will return a prompt asking the analyst whether or not to send the item to ThreatConnect
   - This tool has basic redaction capabilities to help reduce the chance of data leakage
   - If you followed Abnormal's recommendation to prepend [SUSPICIOUS] to items identified as bulk mail, these will be skipped automatically
   - All threat results are submitted as [TLP:Amber](https://www.cisa.gov/news-events/news/traffic-light-protocol-tlp-definitions-and-usage)

## Notes, Limitations
- This tool has been running well in production for over a month now, but will receive significant refactoring before it becomes version 1.0.
- Currently the Abnormal API email FromAddress field is limited to 256 characters which can lead to truncated values and therefore invalid addresses being returned.  In the event an email address is truncated, this tool skips reporting the emailAddress indicator object to ThreatConnect, but the IP Address indictor will be published.
- The configuration file includes encrypted API details. The file is not portable between users/computers. Simply delete AbnormaltoTC-Config.xml and run Get-AbnormaltoTC.ps1 to build a new configuration file.
- AbnormaltoTC-Filters.txt, created on first run, can be edited freely, with each filtered from e-mail address per line.
  - The filter list allows partial matches.  Example: an entry of @pcmag.com will filter any email from a @pcmag.com email address.
- By default, all indicators submitted to ThreatConnect will have a confidence of 90 and a threat level of 3.  The script has guidance on how to change this if desired.
