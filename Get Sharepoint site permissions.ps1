# Check if the user is already connected to SharePoint Online
if (-not (Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' -and $_.State -eq 'Opened' })) {
    # If not connected, prompt the user to sign in and connect to SharePoint Online
    Connect-SPOService -Url https://SomeWebsite.com/
}

# Prompt the user for the SharePoint site URL
$siteUrl = Read-Host "Enter the URL of the SharePoint site"

Get-SPOSiteGroup -Site $siteUrl | Where-Object { $_.LoginName -notlike "*SharingLinks*" -and $_.LoginName -notlike "*Limited Access*" }