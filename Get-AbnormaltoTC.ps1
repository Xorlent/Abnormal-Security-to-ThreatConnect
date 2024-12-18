<#
.NAME
    Abnormal Security Email Threat Feed to ThreatConnect
.VERSION
    0.2.0
.NOTES
    1.API connection ID and secrets are encrypted with the Windows Data Protection API.
        Encrypted config file fields within AbnormaltoTC-Config.xml are not portable between users/machines.
    2.If adjustments to the processed attack types is desired, edit/update the $InterestingAttackTypes array variable along with
        the corresponding $InterestingAttackThreatConfidence and $InterestingAttackThreatRating variables
        (see https://knowledge.threatconnect.com/docs/best-practices-indicator-threat-and-confidence-ratings)
.USAGE
    First run will prompt for all required configuration details and saves this information to an XML configuration file called, AbnormaltoTC-Config.xml
    This script will process the number of selected days of history, iterating through each attack type in $InterestingAttackTypes
#>

if ([System.Environment]::OSVersion.Platform -ne 'Win32NT'){
  Write-Host "Sorry, this tool is only intended for the Windows operating system." -ForegroundColor Red
  Exit 0
}

#Enable or disable debug logging (outputs to AbnormaltoTCDebug.log)
$Logging = $false

# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Set up runtime variables
$ConfigFile = "$PSScriptRoot\AbnormaltoTC-Config.xml"
$FilterFile = "$PSScriptRoot\AbnormaltoTC-Filters.txt"
$DefaultAPIURL = 'https://app.threatconnect.com'
$TargetOrg = ""
$TargetOrgFull = ""
$TargetOrgDomain = ""
$OwnerName = ""
$CityState = ""

# If the filter file does not exist, create it.
if (-not(Test-Path -Path $FilterFile -PathType Leaf)){[void](New-Item -Path $FilterFile -ItemType File)}

# If the config file does not exist, prompt for details and write the file.
if (-not(Test-Path -Path $ConfigFile -PathType Leaf)){
    Write-Host "Starting..." -ForegroundColor Yellow
    Write-Host "No configuration file found." -ForegroundColor Yellow
    Write-Host "Please complete the configuration data prompts below.  If you make a mistake filling out any values, you can simply CTRL-C and start over." -ForegroundColor Yellow
    Write-Host "..." -ForegroundColor Yellow
    $TCAPIURL = Read-Host -Prompt "Enter ThreatConnect API Endpoint URL.  Press enter to accept the default of [$($DefaultAPIURL)]"
    if ($TCAPIURL.Length -eq 0) {$TCAPIURL = $DefaultAPIURL}
    $APIBaseURL = $TCAPIURL
    $abnormalAPIKeyIn = Read-Host -Prompt 'Enter "Bearer " followed by your Abnormal Security API access token'
    $abnormalAPIKeySS = ConvertTo-SecureString $abnormalAPIKeyIn -AsPlainText -Force
    $apiUserIn = Read-Host -Prompt 'Enter your ThreatConnect access ID'
    $apiUserSS = ConvertTo-SecureString $apiUserIn -AsPlainText -Force
    $apiKeyIn = Read-Host -Prompt 'Enter your ThreatConnect secret key'
    $apiKeySS = ConvertTo-SecureString $apiKeyIn -AsPlainText -Force

    Remove-Variable abnormalAPIKeyIn
    Remove-Variable apiUserIn
    Remove-Variable apiKeyIn
    [System.GC]::Collect()

    $orgNick = Read-Host -Prompt "Enter your organization's nickname or its common abbreviation.  We will use this value to redact results fed to ThreatConnect."
    $TargetOrg = $orgNick
    $orgFull = Read-Host -Prompt "Enter your organization's full name.  We will use this value to redact results fed to ThreatConnect."
    $TargetOrgFull = $orgFull
    $orgDomain = Read-Host -Prompt "Enter your organization's top-level domain name in the format, "".domainname.tld"""
    $TargetOrgDomain = $orgDomain
    $TCOwnerName = Read-Host -Prompt "Enter the owner name you would like to appear in the ThreatConnect indicator object.  Example: ""XYZ Threat Feed"""
    $OwnerName = $TCOwnerName
    $TCCityState = Read-Host -Prompt "Enter your city, state in the format: ""Los Angeles, Ca"""
    $CityState = $TCCityState

    if ($TCAPIURL.Length -eq 0) {$TCAPIURL = $DefaultAPIURL}

    # Convert the input values to encrypted text
    $abnormalAPIKeyTxt = ConvertFrom-SecureString -SecureString $abnormalAPIKeySS
    $TCapiUserTxt = ConvertFrom-SecureString -SecureString $apiUserSS
    $TCapiKeyTxt = ConvertFrom-SecureString -SecureString $apiKeySS

    # Save the encrypted values and signature to an XML file
    $xml = New-Object System.Xml.XmlDocument
    $xml.AppendChild($xml.CreateXmlDeclaration("1.0", "UTF-8", $null))

    # Write API details
    $root = $xml.AppendChild($xml.CreateElement("APIDetails"))
    $root.AppendChild($xml.CreateElement("TCapiURL")).InnerText = $TCAPIURL
    $root.AppendChild($xml.CreateElement("TCapiUser")).InnerText = $TCapiUserTxt
    $root.AppendChild($xml.CreateElement("TCapiKey")).InnerText = $TCapiKeyTxt
    $root.AppendChild($xml.CreateElement("AbnormalapiKey")).InnerText = $abnormalAPIKeyTxt

    # Write Org details
    $root.AppendChild($xml.CreateElement("OrgNickname")).InnerText = $orgNick
    $root.AppendChild($xml.CreateElement("OrgFullname")).InnerText = $orgFull
    $root.AppendChild($xml.CreateElement("OrgDomain")).InnerText = $orgDomain
    $root.AppendChild($xml.CreateElement("OrgTCOwnerName")).InnerText = $TCOwnerName
    $root.AppendChild($xml.CreateElement("OrgTCCityState")).InnerText = $TCCityState

    $xml.Save($ConfigFile)
    Write-Host "..." -ForegroundColor Green
    Write-Host "Finished.  Encrypted API key data can only be retrieved when logged in as this active user on this host." -ForegroundColor Green
    Write-Host "If a plaintext configuration element needs to change, you can edit the unencrypted fields within $ConfigFile." -ForegroundColor Green
    Write-Host "If you need to edit/update encrypted elements, please delete $ConfigFile and re-run this script." -ForegroundColor Green
    }
else { # Config file exists, read API details from config.
    Write-Host "Starting..." -ForegroundColor Green
    # Load the XML file
    $xml = New-Object System.Xml.XmlDocument
    $xml.Load($ConfigFile)

    # Get API details
    $APIConfig = $xml.SelectSingleNode("//APIDetails")
    $APIBaseURL = $APIConfig.SelectSingleNode("TCapiURL").InnerText
    $TCapiUserTxt = $APIConfig.SelectSingleNode("TCapiUser").InnerText
    $TCapiKeyTxt = $APIConfig.SelectSingleNode("TCapiKey").InnerText
    $abnormalAPIKeyTxt = $APIConfig.SelectSingleNode("AbnormalapiKey").InnerText

    # Get Org details
    $TargetOrg = $APIConfig.SelectSingleNode("OrgNickname").InnerText
    $TargetOrgFull = $APIConfig.SelectSingleNode("OrgFullname").InnerText
    $TargetOrgDomain = $APIConfig.SelectSingleNode("OrgDomain").InnerText
    $OwnerName = $APIConfig.SelectSingleNode("OrgTCOwnerName").InnerText
    $CityState = $APIConfig.SelectSingleNode("OrgTCCityState").InnerText

    # Convert the API info to secure strings
    $apiUserSS = ConvertTo-SecureString $TCapiUserTxt
    $apiKeySS = ConvertTo-SecureString $TCapiKeyTxt
    $abnormalAPIKeySS = ConvertTo-SecureString $abnormalAPIKeyTxt

    Write-Host "..." -ForegroundColor Green
    Write-Host "Configuration data loaded." -ForegroundColor Green
    }

####### /Set up runtime variables 

# Abnormal Security API Endpoint URL (same for all customers)
$APIEndpoint = 'https://api.abnormalplatform.com/v1/'

#Decrypt Abnormal Credentials
$APIKey = [pscredential]::new('user',$abnormalAPIKeySS).GetNetworkCredential().Password

# These Abnormal Attack Types have been selected to present the most useful threat records for processing
$InterestingAttackTypes = 'Invoice/Payment Fraud (BEC)','Malware','Extortion','Phishing: Sensitive Data','Scam','Internal-to-Internal Attacks (Email Account Takeover)','Social Engineering (BEC)','Other','Phishing: Credential'

# For information about how to set Threat Confidence and Threat Rating values, see https://knowledge.threatconnect.com/docs/best-practices-indicator-threat-and-confidence-ratings
$InterestingAttackThreatConfidence = @(90,90,90,90,90,90,90,90,90) # You can update/adjust these ThreatConfidence values if desired; each entry corresponds to an InterestingAttackTypes value above
$InterestingAttackThreatRating = @(3,3,3,3,3,3,3,3,3) # You can update/adjust these Threat Rating values if desired; each entry corresponds to an InterestingAttackTypes value above

# ThreatConnect API request variables 
$APIURL = [uri]::EscapeUriString('/api/v3/indicators')
$URLMethod = 'POST'

#Decrypt ThreatConnect Credentials
$accessID = [pscredential]::new('user',$apiUserSS).GetNetworkCredential().Password
$secretKey = [pscredential]::new('user',$apiKeySS).GetNetworkCredential().Password

# Prompt user for number of days of backlog to process
$NumDays = Read-Host "How many days of history to process? Entering 0 will retrieve today's events only"
$DayOffset = [int]$NumDays
if($DayOffset -gt 0){$DayOffset *= -1}

# Build Abnormal Security API Request Header
$headers = @{}
$headers.Add('Authorization', $APIKey)
$Yesterday = (Get-Date).AddDays($DayOffset)
$DateSpecifier = $Yesterday.Year.ToString() + '-' + $Yesterday.Month.ToString() + '-' + $Yesterday.Day.ToString() + 'T00:00:00Z'
$FilterString = 'threats?filter=receivedTime gte ' + $DateSpecifier + '&attackType='

# Begin debug if so configured
if($Logging){Start-transcript -Path "$PSScriptRoot\AbnormaltoTCDebug.log"}

function Convert-ToAscii {
    param (
        [Parameter(Mandatory=$true)]
        [string]$InputString
    )
    
    # Cyrillic to Latin character mappings
    $cyrillicMap = @{
        # Lowercase (U+0430 through U+044F)
        "`u0430"='a';  "`u0431"='b';  "`u0432"='v';  "`u0433"='g';  "`u0434"='d';
        "`u0435"='e';  "`u0451"='yo'; "`u0436"='zh'; "`u0437"='z';  "`u0438"='i';
        "`u0439"='y';  "`u043A"='k';  "`u043B"='l';  "`u043C"='m';  "`u043D"='n';
        "`u043E"='o';  "`u043F"='p';  "`u0440"='r';  "`u0441"='s';  "`u0442"='t';
        "`u0443"='u';  "`u0444"='f';  "`u0445"='kh'; "`u0446"='ts'; "`u0447"='ch';
        "`u0448"='sh'; "`u0449"='sch';"`u044A"='';   "`u044B"='y';  "`u044C"='';
        "`u044D"='e';  "`u044E"='yu'; "`u044F"='ya';

        # Uppercase (U+0410 through U+042F)
        "`u0410"='A';  "`u0411"='B';  "`u0412"='V';  "`u0413"='G';  "`u0414"='D';
        "`u0415"='E';  "`u0401"='Yo'; "`u0416"='Zh'; "`u0417"='Z';  "`u0418"='I';
        "`u0419"='Y';  "`u041A"='K';  "`u041B"='L';  "`u041C"='M';  "`u041D"='N';
        "`u041E"='O';  "`u041F"='P';  "`u0420"='R';  "`u0421"='S';  "`u0422"='T';
        "`u0423"='U';  "`u0424"='F';  "`u0425"='Kh'; "`u0426"='Ts'; "`u0427"='Ch';
        "`u0428"='Sh'; "`u0429"='Sch';"`u042A"='';   "`u042B"='Y';  "`u042C"='';
        "`u042D"='E';  "`u042E"='Yu'; "`u042F"='Ya'
    }

    # Cyrillic character replacements
    foreach ($key in $cyrillicMap.Keys) {
        $InputString = $InputString.Replace($key, $cyrillicMap[$key])
    }

    # Normalize
    $normalizedString = $InputString.Normalize([Text.NormalizationForm]::FormKD)
    
    # Convert to ASCII
    $encodedBytes = [System.Text.Encoding]::UTF8.GetBytes($normalizedString)
    $asciiBytes = [System.Text.Encoding]::Convert(
        [System.Text.Encoding]::UTF8,
        [System.Text.Encoding]::ASCII,
        $encodedBytes
    )
    return [System.Text.Encoding]::ASCII.GetString($asciiBytes)
}

# Look up Abnormal Security threats
ForEach($Attack in $InterestingAttackTypes)
{
    # Grab the ThreatConfidence and ThreatRating values based on index matching each value with the $InterestingAttackTypes array
    $ThreatConfidence = $InterestingAttackThreatConfidence[$InterestingAttackTypes.IndexOf($Attack)]
    $ThreatRating = $InterestingAttackThreatRating[$InterestingAttackTypes.IndexOf($Attack)]
    $APIRequest = $APIEndpoint + [URI]::EscapeUriString($FilterString) + [URI]::EscapeUriString($Attack)

    $ThreatRecordIntro = '############################### ---------- Processing ' + $Attack + ' Threats ------------ ##############################'
    Write-Host $ThreatRecordIntro -ForegroundColor Magenta

    # Perform the Abnormal API request for all events matching the current AttackType value
    $Response1 = Invoke-RestMethod -Uri $APIRequest -Method GET -Headers $headers

    ForEach($Threat in $Response1.threats)
    {
        # Get each threat, display the result and ask the operator if they would like to submit the presented event to ThreatConnect
        $APIRequest2 = $APIEndpoint + 'threats/' + $Threat.threatId
        $Response2 = Invoke-RestMethod -Uri $APIRequest2 -Method GET -Headers $headers

        ForEach($Message in $Response2.messages)
        {
            if(!$Message.subject.Contains('[SUSPICIOUS]'))
            {
                # Check to see if the from address is a valid email address format
                try{
                    $null = [mailaddress]$Message.fromAddress
                    $FromAddress = $Message.fromAddress
                    }
                catch{
                    # If from address is invalid, swap the replyToEmails[0] value in
                    if([string]::IsNullOrEmpty($Message.replyToEmails[0])){
                        $FromAddress = $Message.returnPath
                        }
                    else{
                        $FromAddress = $Message.replyToEmails[0]
                        }
                    }

                $filterMatch = 0

                ForEach($FilterAddress in Get-Content $FilterFile)
                {
                    if($FromAddress.Contains($FilterAddress))
                    {
                        $filterMatch = 1
                        break
                    }
                }

                if($filterMatch -eq 0)
                {
                    Write-Host '############################### ------------------------------------------------------------ ##############################' -ForegroundColor Cyan
                    Write-Host 'Subject: '-ForegroundColor Gray -NoNewline
                    $SanitizedSubject1 = $Message.subject -iReplace $TargetOrg,'-redacted-'
                    $SanitizedSubject = $SanitizedSubject1 -iReplace $TargetOrgFull,'-redacted-'
                    if(![string]::IsNullOrEmpty($SanitizedString)){$SanitizedSubject = Convert-ToAscii($SanitizedSubject)}
                    $SanitizedSubject

                    $FromString = [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($Message.fromName))
                    $SanitizedFrom1 = $FromString -iReplace $TargetOrg,'-redacted-'
                    $SanitizedFrom = $SanitizedFrom1 -iReplace $TargetOrgFull,'-redacted-'
                    if(![string]::IsNullOrEmpty($SanitizedFrom)){$SanitizedFrom = Convert-ToAscii($SanitizedFrom)}

                    $AttributeArray = @(
                        @{
                        'type' = 'Description'
                        'default' = 'true'
                        'value' = 'FROM: ' + $SanitizedFrom + ' | IP: ' + $Message.senderIpAddress + ' | RETURN PATH: ' + $Message.returnPath.Replace($TargetOrg,'redacted') + ' | SUBJECT: ' + $SanitizedSubject + ' | ATTACK TYPE: ' + $Message.attackType + ' | STRATEGY: ' + $Message.attackStrategy + ' | VECTOR: ' + $Message.attackVector + ' | INSIGHTS: ' + $Message.summaryInsights
                        }
                    )

                    Write-Host 'Message Received at: '-ForegroundColor Gray -NoNewline
                    Write-Host $Message.receivedTime

                    Write-Host 'Attack Type: '-ForegroundColor Gray -NoNewline
                    $Message.attackType

                    Write-Host 'Attack Strategy: '-ForegroundColor Gray -NoNewline
                    $Message.attackStrategy

                    Write-Host 'Attack Vector: '-ForegroundColor Gray -NoNewline
                    $Message.attackVector

                    Write-Host 'Sender IP: '-ForegroundColor Gray -NoNewline
                    $Message.senderIpAddress

                    Write-Host 'From: '-ForegroundColor Gray -NoNewline
                    $FromAddress

                    Write-Host 'Return Path: '-ForegroundColor Gray -NoNewline
                    $Message.returnPath

                    if ($Message.replyToEmails.Count -gt 0)
                    {
                        Write-Host 'Reply-to Emails:'-ForegroundColor Gray
                    }
                    ForEach($Email in $Message.replyToEmails)
                    {
                        $ReplyTmp = $Email.ToString()
                        $ReplyTmp
                        $AttributeArray += @{
                            'type' = 'Reply-To Email Address'
                            'value' = $ReplyTmp -iReplace $TargetOrg,'redacted'
                            }
                    }

                    Write-Host 'Email Insights:'-ForegroundColor Gray
                    $Message.summaryInsights

                    if ($Message.attachmentCount -gt 0)
                    {
                        Write-Host 'Attachments:'-ForegroundColor Gray
                    }

                    ForEach($Attachment in $Message.attachmentNames)
                    {
                        $AttachmentTmp = $Attachment.ToString()
                        $AttachmentTmp
                        $AttributeArray += @{
                            'type' = 'Attachment Name'
                            'value' = $AttachmentTmp -iReplace $TargetOrg,'-redacted-'
                            }
                    }

                    if ($Message.urlCount -gt 0)
                    {
                        Write-Host 'URLs:'-ForegroundColor Gray
                    }

                    ForEach($URL in $Message.urls)
                    {
                        $StringURL = $URL.ToString()
                        if(-Not ($StringURL.Contains('https://aka.ms/LearnAboutSenderIdentification') -or $StringURL.Contains($TargetOrgDomain)))
                        {
                            $ShortURL = $URL.Split("?")
                            $ShortURL[0]
                            $AttributeArray += @{
                                'type' = 'Full URL if Truncated for Summary'
                                'value' = $ShortURL[0]
                                }
                        }
                    }

                    Write-Host '############################### ------------------------------------------------------------ ##############################' -ForegroundColor Cyan

                    # Prompt user to decide whether or not to submit the displayed result.
                    Write-Host '====> ' -ForegroundColor Green -NoNewline
                    $SendRecord = Read-Host -Prompt 'Send this email to ThreatConnect (Y)es, (N)o, (F)ilter this From Address, or (I)nspect in browser?  Only submit confirmed attacks.  (Default = Y)'

                    # See if user wants to inspect the Abnormal threat entry in a browser for a more detailed look at the email
                    if($SendRecord -ieq 'I'){
                        $InspectSwitch = '--new-window ' + $message.abxPortalUrl
                        Start-Process msedge.exe $InspectSwitch
                        Write-Host '===============================================> ' -ForegroundColor Green -NoNewline
                        $SendRecord = Read-Host -Prompt 'Based on your inspection, send this email to ThreatConnect?  (Default = Y)'
                    }

                    # Add the From Address to the filter configuration file
                    if($SendRecord -ieq 'F'){
                        Add-Content -Path $FilterFile -Value $FromAddress
                        Write-Host "<<<<<<<<<<<<<<<<<<<<<<<<<Email From Address added to filter list located at $FilterFile>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
                        }
                
                    if ([string]::IsNullOrWhiteSpace($SendRecord)){$SendRecord = 'Y'}

                    # If 'Y/y' is selected, publish the record to ThreatConnect
                    if($SendRecord -eq 'Y')
                        {

                        $DTS = (Get-Date).ToUniversalTime() | Get-Date -UFormat %s
                        $timestamp = $DTS.Split(".")

                        $EncPayload = $APIURL + ':' + $URLMethod + ':' + $timestamp[0]

                        $APIURL2 = $APIBaseURL + $APIURL

                        $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
                        $hmacsha.key = [Text.Encoding]::ASCII.GetBytes($secretKey)
                        $signature = $hmacsha.ComputeHash([Text.Encoding]::ASCII.GetBytes($EncPayload))
                        $signature = [Convert]::ToBase64String($signature)
                        $authorization = 'TC ' + $accessID + ':' + $signature

                        $headerData = @{
                           'Timestamp' = $timestamp[0]
                           'Authorization' = $authorization
                           'Accept' = 'application/json'
                           }
                        $bodyData = @{
                        }
                        $IPbodyData = @{
                            'type' = 'Address'
                            'ownerName' = $OwnerName
                            'ip' = $Message.senderIpAddress
                            'lastSeen' = $Message.receivedTime
                            'attributes' = @{
                                'data' = @(
                                        @{
                                        'type' = 'Description'
                                        'default' = 'true'
                                        'value' = 'EMAIL FROM: ' + $FromAddress.Replace($TargetOrg,'redacted') + ' (' + $SanitizedFrom + ') | IP: ' + $Message.senderIpAddress + ' | RETURN PATH: ' + $Message.returnPath.Replace($TargetOrg,'redacted') + ' | SUBJECT: ' + $SanitizedSubject + ' | ATTACK TYPE: ' + $Message.attackType + ' | STRATEGY: ' + $Message.attackStrategy + ' | VECTOR: ' + $Message.attackVector + ' | INSIGHTS: ' + $Message.summaryInsights
                                        }
                                    )
                                }
                            'active' = 'true'
                            'tags' = @{
                                'data' = @(
                                        @{
                                        'name' = $Message.attackType
                                        },
                                        @{
                                        'name' = $TargetOrg.ToUpper()
                                        },
                                        @{
                                        'name' = $CityState
                                        }
                                    )
                                }
                            'securityLabels' = @{
                                'data' = @(
                                        @{
                                        'name' = 'TLP:AMBER'
                                        }
                                    )
                                }
                            'confidence' = $ThreatConfidence
                            'rating' = $ThreatRating
                        }
                        # Send the IP (Address) indicator first before we create the emailAddress indicator
                        try{
                            $responseIP = Invoke-RestMethod -Uri $APIURL2 -Header $headerData -ContentType 'application/json' -Method $URLMethod -Body ($IPbodyData | ConvertTo-Json -Depth 4)
                            # If the IP indicator API call was successful, add its ID to the associatedIndicators list for the emailAddress indicator API call
                            $bodyData = @{
                                'type' = 'EmailAddress'
                                'ownerName' = $OwnerName
                                'address' = $FromAddress -iReplace $TargetOrg,'redacted'
                                'lastSeen' = $Message.receivedTime
                                'attributes' = @{
                                    'data' = $AttributeArray
                                    }
                                'associatedIndicators' = @{
                                    'data' = @(
                                            @{
                                            'id' = $responseIP.data.id
                                            }
                                        )
                                    }
                                'active' = 'true'
                                'tags' = @{
                                    'data' = @(
                                            @{
                                            'name' = $Message.attackType
                                            },
                                            @{
                                            'name' = $TargetOrg.ToUpper()
                                            },
                                            @{
                                            'name' = $CityState
                                            }
                                        )
                                    }
                                'securityLabels' = @{
                                    'data' = @(
                                            @{
                                            'name' = 'TLP:AMBER'
                                            }
                                        )
                                    }
                                'confidence' = $ThreatConfidence
                                'rating' = $ThreatRating
                                }
                            }
                        catch{
                            # If it did not accept our IP indicator, do not send the associatedIndicators list to the emailAddress indicator API call
                            $bodyData = @{
                                'type' = 'EmailAddress'
                                'ownerName' = $OwnerName
                                'address' = $FromAddress -iReplace $TargetOrg,'redacted'
                                'lastSeen' = $Message.receivedTime
                                'attributes' = @{
                                    'data' = $AttributeArray
                                    }
                                'active' = 'true'
                                'tags' = @{
                                    'data' = @(
                                            @{
                                            'name' = $Message.attackType
                                            },
                                            @{
                                            'name' = $TargetOrg.ToUpper()
                                            },
                                            @{
                                            'name' = $CityState
                                            }
                                        )
                                    }
                                'securityLabels' = @{
                                    'data' = @(
                                            @{
                                            'name' = 'TLP:AMBER'
                                            }
                                        )
                                    }
                                'confidence' = $ThreatConfidence
                                'rating' = $ThreatRating
                                }
                            }
                        finally {
                            # Now send the emailaddress indicator
                            try{
                                # If Abnormal's API truncated the email address, we won't have a valid emailAddress indicator to submit, so skip it
                                if($FromAddress.Length -lt 255)
                                    {
                                    $response = Invoke-RestMethod -Uri $APIURL2 -Header $headerData -ContentType 'application/json' -Method $URLMethod -Body ($bodyData | ConvertTo-Json -Depth 4)
                                    Write-Output $response.data
                                    }
                                }
                            catch{
                                $err=$_.Exception
                                # If we got a 403 error, the likely cause is a filtered/whitelisted email address.  Swap the email address with the reply-to address and re-submit the indicator.
                                if($err -like "*(403)*"){
                                    $bodyData.address = $ReplyTmp -iReplace $TargetOrg,'redacted'
                                    $response403 = Invoke-RestMethod -Uri $APIURL2 -Header $headerData -ContentType 'application/json' -Method $URLMethod -Body ($bodyData | ConvertTo-Json -Depth 4)
                                    Write-Output $response403.data
                                    }
                                else{
                                    Write-Host "*************************** UNHANDLED EXCEPTION SENDING EMAILADDRESS INDICATOR TO THREATCONNECT.  DETAILS BELOW: ***************************" -ForegroundColor Red
                                    Write-Output $err
                                    $ExceptionAction = Read-Host "Hit ENTER to continue processing records or Q to quit"
                                    if ($ExceptionAction -ieq 'Q'){
                                        # Remove unencrypted API variables from memory
                                        Remove-Variable APIKey
                                        Remove-Variable accessID
                                        Remove-Variable secretKey
                                        [System.GC]::Collect()
                                        Write-Host 'Secrets unloaded, garbage collection completed.' -ForegroundColor Green
                                        # End debug logging
                                        if($Logging){Stop-transcript}
                                        # Bail out
                                        exit 1
                                        }
                                    }
                                }
                            }
                        Remove-Variable SendRecord
                        break #Don't process any more copies of this message
                        }
                    Remove-Variable SendRecord
                    break #Don't process any more copies of this message
                } # /Message FromAddress matched in $FilterFile
            } # /Subject not contains [SUSPICIOUS]
        } # /Foreach message
    }
}

# Remove unencrypted API variables from memory
Remove-Variable APIKey
Remove-Variable accessID
Remove-Variable secretKey
[System.GC]::Collect()
Write-Host 'Secrets unloaded, garbage collection completed.' -ForegroundColor Green
# End debug logging
if($Logging){Stop-transcript}
exit 0
