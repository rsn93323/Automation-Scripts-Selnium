# Connect to Azure AD using Connect-MsolService if not already connected
if (!(Get-Module MSOnline)) {
    Connect-MsolService
}

# Connect to Exchange Online using Connect-ExchangeOnline if not already connected
if (!(Get-Module ExchangeOnlineManagement)) {
    Connect-ExchangeOnline -ShowProgress $true
}

#Prompt the user to input the user's user principal name (UPN)
$userUPN = Read-Host "Enter the user's user principal name (UPN). Example: user@companydomain.com"

#Prompt the user to input the output directory path
$outputDir = Read-Host "Enter the output directory path to save user license information. Example: \\SomeServer\SomeDriveLetter$\SomeFolder\SomeSubFolder"

#Retrieve the user object from Azure AD
$user = Get-MsolUser -UserPrincipalName $userUPN

#Convert the user to a shared mailbox
$sharedMailbox = Set-Mailbox $userUPN -Type Shared
if ($sharedMailbox -eq $null) {
    Write-Output "Failed to convert the mailbox to a shared mailbox for $userUPN"
} else {
    Write-Output "The mailbox has been converted to a shared mailbox for $userUPN"
}

#Output the user's licensed products to a file
$licenseInfo = @()
foreach ($license in $user.Licenses) {
    $licenseName = (Get-MsolAccountSku | Where-Object {$_.AccountSkuId -eq $license.AccountSkuId}).SkuPartNumber
    switch ($licenseName) {
        "ENTERPRISEPACK" {
            $licenseName = "Office 365 E3"
            break
        }
        "ENTERPRISEPREMIUM" {
            $licenseName = "Office 365 E5"
            break
        }
        "POWERAPPS_INDIVIDUAL_USER" {
            $licenseName = "Power Apps and Logic Flows"
            break
        }
        "ATP_ENTERPRISE" {
            $licenseName = "Microsoft Defender for Office 365 (Plan 1)"
            break
        }
        "VISIOCLIENT" {
            $licenseName = "Visio Online Plan 2"
            break
        }
        "FLOW_FREE" {
            $licenseName = "Microsoft Power Automate Free"
            break
        }
        "POWERAPPS_VIRAL" {
            $licenseName = "Microsoft Power Apps Plan 2 Trial"
            break
        }
        "MCOEV" {
            $licenseName = "Microsoft Teams Phone Standard"
            break
        }
        "MCOPSTN2" {
            $licenseName = "Microsoft Teams Domestic and International Calling Plan/Skype for Business PSTN Domestic and International Calling"
            break
        }
        "DYN365_ENTERPRISE_P1_IW" {
            $licenseName = "Dynamics 365 P1 Trial for Information Workers"
            break
        }
        "MCOMEETADV" {
            $licenseName = "Microsoft 365 Audio Conferencing"
            break
        }
        "MICROSOFT_BUSINESS_CENTER" {
            $licenseName = "Microsoft Business Center"
            break
        }
        "POWER_BI_STANDARD" {
            $licenseName = "Power BI (free)"
            break
        }
    }
    $licenseInfo += "$userUPN is licensed for $licenseName"
}

#Save license information to a file
$licenseFile = "$outputDir\$($userUPN.Replace('@', '_')).txt"
$licenseInfo | Out-File $licenseFile -Append
if (Test-Path $licenseFile) {
    Write-Output "License information has been saved to $licenseFile"
} else {
    Write-Output "Failed to save license information to $licenseFile"
}

#Remove the user's assigned licenses
$removedLicenses = Set-MsolUserLicense -UserPrincipalName $userUPN -RemoveLicenses $user.Licenses.AccountSkuId
if ($removedLicenses -eq $null) {
    Write-Output "Failed to remove licenses for $userUPN in Office 365"
} else {
    Write-Output "Licenses have been removed for $userUPN in Office 365"
}

#Output completion message
Write-Output 'The following tasks have been completed for $userUPN:'
if ($sharedMailbox -ne $null) {
    Write-Output "1. The mailbox has been converted to a shared mailbox."
} else {
    Write-Output "1. Failed to convert the mailbox to a shared mailbox."
}
if (Test-Path $licenseFile) {
    Write-Output "2. License information has been saved to $licenseFile."
} else {
    Write-Output "2. Failed to save license information to $licenseFile."
}
if ($removedLicenses -ne $null) {
    Write-Output "3. Licenses have been removed for $userUPN in Office 365."
} else {
    Write-Output "3. Failed to remove licenses for $userUPN in Office 365."
}

#rename verizon Phone

#Re name Navision account to Disabled Account

#Disable Navision account

#if freindly licnese name does not match Office 365. Vist https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference or see Excel file