#Prompt user for username
$username = Read-Host "Please enter the username of the user to disable and move"

#Get the user object from Active Directory
$user = Get-ADUser -Identity $username

#Change the user's password
$user | Set-ADAccountPassword -Reset -NewPassword (Read-Host "Enter the new password for $username" -AsSecureString)

#Get the user's Get-ADUser, job title, department, company, and manager
$userInfo = Get-ADUser $username -Properties Title, Department, Company, Manager

#Create the directory path
$dirPath = "\\SomeServer\SomeDriveLetter$\SomeFolder\$username"
if (-not (Test-Path $dirPath)) {
    New-Item -ItemType Directory -Path $dirPath | Out-Null
}

#Save "member of" into a text file
$memberOf = $user | Get-ADPrincipalGroupMembership | Where-Object {$_.Name -ne "Domain Users"} | select -Expand name
$memberOf | Out-File -FilePath "\\SomeServer\SomeDriveLetter$\SomeFolder\$username\$username-MemberOf.txt"

#Create an output string for the user information
$output = "User: $($userInfo.Name)`n" +
          "Job Title: $($userInfo.Title)`n" +
          "Department: $($userInfo.Department)`n" +
          "Company: $($userInfo.Company)`n`n" + 
          "Manager: $($userInfo.Manager)`n`n"

#Write the user information to a file
$output | Out-File -FilePath "$dirPath\$username-UserInfo.txt"

#Disable the user's account
$user | Disable-ADAccount

#Remove the user from all groups except Domain Users
$groups = Get-ADPrincipalGroupMembership $user | Where-Object {$_.Name -ne "Domain Users"}
foreach ($group in $groups) {
    Remove-ADGroupMember -Identity $group -Members $user -Confirm:$false
}

#Remove the manager value
Set-ADUser -Identity $user -Clear manager

#Move the user's account to the Disabled Accounts OU
$disabledOU = "OU=SomeOrganizationUnit,DC=SomeDomain,DC=com"
$user | Move-ADObject -TargetPath $disabledOU

#Show progress
Write-Host "The following tasks have been completed for $username"
Write-Host "- Password has been changed"
Write-Host "- Account has been disabled"
Write-Host "- Account has been moved to the Disabled Accounts OU"
Write-Host "- Account has removed manager"
Write-Host "- User information has been saved to $dirPath\$username-UserInfo.txt"
Write-Host "- Member Of information has been saved to $dirPath\$username-MemberOf.txt"
