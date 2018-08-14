#IdentityNow Identity Management Module by Shane Zabel
#Eventually plan to have a function for each API method
#Need to have a complete list of possible attributes for whitelist
#Need to write help for each cmdlet
#Add functionality for getting or setting multiple attributes at once, and multiple identities or accounts at once

#must run this first for rest of module to work
Function Set-IDNCredentials{
    #example Set-IDNCredentials -"sourceID" 11111
    param
    (
        [parameter(Position=0)]
        $ClientID,
        [parameter(Position=1)]
        $ClientSecret,
        [parameter(Position=2)]
        $org,
        [parameter(Position=3)]
        $UserSourceId,
        [parameter(Position=4)]
        $sourceId
    )
    $script:ClientID = $ClientID
    $script:ClientSecret = $ClientSecret
    $script:org = $org
    $script:UserSourceId = $UserSourceId
    $script:CredPair = $ClientID + ":" + $ClientSecret,
    $script:EncodedPair = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($CredPair))
    $script:sourceId = $sourceId
}

Set-IDNCredentials

Function New-IDNUSer
{
        #Param will prompt user for all mandatory prompts and set lifestylestate to inactive and enddate to 12/31/9999 unless the user calls New-IDNUser -lifecyclestate "" -enddate ""
        #Previous comment no longer true, now must specify all parameters in call as no parameters will prompt for input
        param(
        [parameter(Mandatory=$false,Position=0,ValueFromPipeline=$true)]
        $id,
        [parameter(Mandatory=$false,Position=1,ValueFromPipeline=$true)]
        $email,
        [parameter(Mandatory=$false,Position=2,ValueFromPipeline=$true)]
        $alternateEmail,
        [parameter(Mandatory=$false,Position=3,ValueFromPipeline=$true)]
        $lastName,
        [parameter(Mandatory=$false,Position=4,ValueFromPipeline=$true)]
        $firstName,
        [parameter(Mandatory=$false,Position=5,ValueFromPipeline=$true)]
        $middleInit,
        [parameter(Mandatory=$false,Position=6,ValueFromPipeline=$true)]
        $phone,
        [parameter(Mandatory=$false,Position=7,ValueFromPipeline=$true)]
        $workLoc,
        [parameter(Mandatory=$false,Position=8,ValueFromPipeline=$true)]
        $jobTitle,
        [parameter(Mandatory=$false,Position=9,ValueFromPipeline=$true)]
        $department,
        [parameter(Mandatory=$false,Position=10,ValueFromPipeline=$true)]
        $companyName,
        [parameter(Mandatory=$false,Position=11,ValueFromPipeline=$true)]
        $supervisorEmail,
        [parameter(Mandatory=$false,Position=12,ValueFromPipeline=$true)]
        $startDate,
        [parameter(Mandatory=$false,Position=13,ValueFromPipeline=$true)]
        $endDate = "12/31/9999",
        [parameter(Mandatory=$false,Position=14,ValueFromPipeline=$true)]
        $lifecycleState = "inactive",
        [parameter(Mandatory=$false,Position=15,ValueFromPipeline=$true)]
        ${Personal Email},
        [parameter(Mandatory=$false,Position=16,ValueFromPipeline=$true)]
        $Supervisor,
        [parameter(Mandatory=$false,Position=17,ValueFromPipeline=$true)]
        $Company,
        [parameter(Mandatory=$false,Position=18,ValueFromPipeline=$true)]
        $Location,
        [parameter(Mandatory=$false,Position=19,ValueFromPipeline=$true)]
        $positionNumber
        )
    #building web request
    $headers = @{Authorization = "Basic $EncodedPair"; Accept = "application/json"}
    #create hash table then convert to json
    $Hash = @{}
    $parameters = (Get-Command New-IDNUSer).Parameters
    Foreach($parameter in $parameters.keys)
    {
        if((Test-IDNAttributeValid $parameter) -ne "Invalid Attribute")
        {
            if(!($NULL -eq (Get-Variable -Name "$parameter" -ValueOnly)))
            {
                $Hash.add("$parameter",(Get-Variable -Name "$parameter" -ValueOnly))
            }
        }
    }
    $Body = $Hash | ConvertTo-Json
    #Will create user and show http response to confirm
    $APIURL = "https://$org.api.identitynow.com/v2/accounts?sourceId=$UserSourceId&org=$org"
    Invoke-WebRequest -Uri $APIURL -Method "post" -Headers $headers -ContentType "application/json" -Body $Body
    #Need to edit this to only show on correct http response code, can then not need to show full response for confimation
    #do this by putting web request response in variable and calling variable.responsecode and if statements
    Write-Host "Creating account for $firstName $lastName"
<#
    .SYNOPSIS
    Creates a new Identity Now user.
    .DESCRIPTION
    The New-IDNUser cmdlet creates a new entry in a given flat file source which is then used by Identity Now to create a new Identity.
    .INPUTS
    Strings
    .OUTPUTS
    HTTP Web Response Confirming Creation
    .EXAMPLE
    New-IDNUser -ID user@domain.com
    .LINK
    api.identitynow.com
    Get-IDNUser
    Set-IDNUser
    Remove-IDNUser
#>
}

Function Remove-IDNUser
{
    param(
    [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
    $ID
    )
    #Checks to make sure you are only deleting one user, may want to add a get-user and a are you sure check
    $UserID = Get-IDNID $ID

    if($UserID -eq "You received more than one response please check input")
    {
        $UserID
    }
    elseif($UserID -eq "No results found")
    {
        $UserID
    }
    else
    {
        $headers = @{Authorization = "Basic $EncodedPair"; Accept = "application/json"}
        $APIURL = "https://$org.api.identitynow.com/v2/accounts/${UserID}?org=$org"
        Invoke-WebRequest -Uri $APIURL -Method "Delete" -Headers $headers
        #Same as new idnuser, use response code so only shows ... has been removed on successful removal
        Write-Host "$ID has been removed."
    }
<#
    .SYNOPSIS
    Removes an Identity Now user.
    .DESCRIPTION
    The Remove-IDNUser Deletes an Identity Now Identity.
    .INPUTS
    Identity
    .OUTPUTS
    HTTP Web Response Confirming Deletion
    .EXAMPLE
    Remove-IDNUser -ID user
    .LINK
    api.identitynow.com
    Get-IDNUser
    Set-IDNUser
    New-IDNUser
#>
}

Function Get-IDNUser
{
    param
    (
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        $ID,
        [String]
        [parameter(Mandatory=$false,Position=1)]
        $Attribute = ""
    )
    #Takes ID param and finds the id, if 0 or more than 1 IDs found throw error
    $UserID = Get-IDNID $ID
    if($UserID -eq "You received more than one response please check input")
    {
        $UserID
    }
    elseif($UserID -eq "No results found")
    {
        $UserID
    }
    else
    {
        #Send attribute to attribute whitelist, throws error if attribute not found
        $Attribute = Test-IDNAttributeValid $Attribute

        if($Attribute -ne "Invalid Attribute")
        {

            #Building Web Request
            #as noted elsewhere need to modify for multiple attributes but not all
            #probably easiest to see attributes as a list of strings and a foreach attribute in attributes {results.attributes.attribute}
            $headers = @{Authorization = "Basic $EncodedPair"}
            $APIURL = "https://$org.api.identitynow.com/v2/accounts/${UserID}?org=$org"
            #Takes web response and puts the response content into $results as json content
            $JSONResponse = Invoke-WebRequest -Uri $APIURL -Method GET -Headers $headers -ContentType "application/json"
            (Invoke-WebRequest -Uri $APIURL -Method GET -Headers $headers -ContentType "application/json").content > Jsonout.json

            $results = $JSONResponse.Content | ConvertFrom-Json
            #if "" or * returns a powershell object with all attributes, otherwise just returns the one attribute
            if(($Attribute -eq "*") -or ($Attribute -eq ""))
            {
                return $results.attributes
            }
            else
            {
                return $results.attributes.$Attribute
            }

        }
        else
        {
            $Attribute
        }
    }
}

Function Set-IDNUser
{
    param
    (
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        $ID,
        [String]
        [parameter(Position=1)]
        $Attribute,
        [String]
        [parameter(Position=2)]
        $Value
    )
    #Takes ID param and finds the id, if 0 or more than 1 IDs found throw error
    $UserID = Get-IDNID $ID
    if($UserID -eq "You received more than one response please check input")
    {
        $UserID
    }
    elseif($UserID -eq "No results found")
    {
        $UserID
    }
    else
    {
        #Send attribute to attribute whitelist, throws error if attribute not found
        $Attribute = Test-IDNAttributeValid $Attribute
    
        if($Attribute -ne "Invalid Attribute")
        {
            #building web request
            $headers = @{Authorization = "Basic $EncodedPair"; Accept = "application/json"}
            #could modify this to change multiple attributes at once 
            $Hash = 
            @{
                $Attribute = $Value;
             }

            $Body = $Hash | ConvertTo-Json

            $APIURL = "https://$org.api.identitynow.com/v2/accounts/${UserID}?org=$org"
            Invoke-WebRequest -Uri $APIURL -Method "patch" -Headers $headers -ContentType "application/json" -Body $Body
            #See new-idnuser and remove-idnuser for this, use response code to show success or failure message
            Write-Host "Set $Attribute to $Value for $ID"
    
        }
        else
        {
            $Attribute
        }
    }
    
    

}

function Get-IDNID 
{
    param($Query)
    #Building api request
    $headers = @{Authorization = "Basic $EncodedPair"}
    $APIURL = "https://$org.api.identitynow.com/v2/search?types=identity&query=$Query&org=$org"
    
    #Receive API response
    $JSONResponse = Invoke-WebRequest -Uri $APIURL -Method GET -Headers $headers -ContentType "application/json"

    #convert from JSON to PowerShell Object (be sure to grab response content)
    $results = $JSONResponse.Content | ConvertFrom-Json
    
    #look for ID of user based on source ID.
    if ($results.identity.Count -eq 1) 
    { #ensure only one response
        foreach($searchAccounts in $results.identity[0].accounts)
        { #iterate through all accounts
            if ($searchAccounts.source.id -eq $sourceId) 
            { #verify source ID
                return $searchAccounts.id
            }
        }
    }
    #Error text if multiple accounts are found from query or no accounts are found
    elseif( $results.identity.Count -eq 0)
    {
        return "No results found"
    }
    else
    {
        return "You received more than one response please check input"
    }
}

#access profile functions
function Get-IDNAccessProfileList
{

}

function New-IDNAccessProfile
{

}

function Remove-IDNAccessProfile
{

}

function Get-IDNAccessProfile
{

}

function Set-IDNAccessProfile
{

}

function Get-IDNAccessProfileAttribute
{

}

function Set-IDNAccessProfileAttribute
{

}

function Get-IDNAccessProfileEntitlement
{

}

#access request function
function Get-IDNAccessRequest
{

}


#two accounts functions not already written, existing IDNUSer functions need to be IDNAccount functions
function Get-IDNAccountList
{

}

#Updates an existing account from a flat-file source. The body represents all the values to be defined on the account. 
#Attributes that are not present in the body will be removed from the account.
function Redo-IDNAccount
{

}

#approvals functions
function Get-IDNApprovalList
{

}

function Approve-IDNRequest
{

}

#forwards approval request
function Submit-IDNRequest
{

}

function Deny-IDNRequest
{

}

#launchers functions
function Get-IDNLauncher
{

}

function Set-IDNLauncher
{

}

function Register-IDNLauncherClick
{

}

#org functions
function Get-IDNOrg
{

}

function Set-IDNOrg
{

}

#provisioning functions
function Get-IDNProvisioningActivityList
{

}

function Get-IDNProvisioningActivity
{

}

#task results function
function Get-IDNTaskResult
{

}

#identities functions
function Get-IDNIdentityList
{

}

function New-IDNIdentity
{

}

function Remove-IDNIdentity
{

}

function Get-IDNIdentity
{

}

function Set-IDNIdentity
{

}

function Get-IDNIdentityApprovals
{

}

function Get-IDNIdentityApps
{

}

function Get-IDNIdentityLaunchers
{

}

function New-IDNIdentityLauncher
{

}

function Remove-IDNIdentityLauncher
{

}

#resetting password unlocks
function Lock-IDNIdentity
{

}

#search functions
function Find-IDNEntitlement
{

}

function Find-IDNEvent
{

}

#currently get-idnid
function Find-IDNIdentity
{

}

function Find-IDNIndexMapping
{

}

function Find-IDNMapping
{

}



function Test-IDNAttributeValid
{
    param($Attribute)
    #Whitelist of attributes we use for IDN, can be modified depending on what attributes your implementation uses
    #Need a full list of attributes currently just have the ones we selected
    $result = switch($Attribute)
    {
        id{$Attribute}
        email{$Attribute}
        alternateEmail{$Attribute}
        lastName{$Attribute}
        firstName{$Attribute}
        middleInit{$Attribute}
        phone{$Attribute}
        workLoc{$Attribute}
        jobTitle{$Attribute}
        department{$Attribute}
        companyName{$Attribute}
        supervisorEmail{$Attribute}
        startDate{$Attribute}
        endDate{$Attribute}
        lifecycleState{$Attribute}
        supervisor{$Attribute}
        company{$Attribute}
        positionNumber{$Attribute}
        "Personal Email"{$Attribute}
        location{$Attribute}
        *{$Attribute}
        ""{$Attribute}
        default{"Invalid Attribute"}
    }
    return $result
}
