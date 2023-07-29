#Logging data
$dateToday = (Get-Date).tostring("MM-dd-yyyy-hh-mm-ss")

#initialize connections & variables
Connect-MsolService ; Connect-ExchangeOnline
$currentUser = $env:UserName
$defaultTerminationFolder = "SomePath" 
$deafultTicketDocumentFolder = "SomePath"

#check if logging is necessary
if($? -eq 'True'){
Start-Transcript -Path "C:\Users\$currentUser\PowershellScripts\log\Transcript-$dateToday.txt"
} 

#imports
Import-Module -Name ActiveDirectory
Import-Module ExchangeOnlineManagement
import-module Hyper-V

echo "               ____  ______                   ";
echo "              / __ \/ ____/                   ";
echo "             / / / / / __                     ";
echo "            / /_/ / /_/ /                     ";
echo "           /_____/\____/                      ";
echo "                                              ";
echo "      D   I   A   M   O   N   D               ";
echo "             G  A  M  E                       ";
echo "                                              ";
echo "         By: Rupert Navarro                   ";

Pause

while($true) {
  Echo "Main Menu:
    [1]   Search all Locked out AD Users
    [2]   UnLock all Locked out AD Users
    [3]   Get password expiration date/additoinal account information
    [3a]  Get user group membership
    [4]   Get user manager
    [5]   Disable AD user
    [6]   Enable AD user
    [7]   Disable/Remove MFA for single User
    [8]   Generate list of all licensed user's MFA status
    [8a]  Generate list of all licensed user's MFA status methods
    [9]   Find user(s) logged into machine
    [10]  Reset password for user 
    [11]  Get AD Description of machine
    [12]  List members of AD Group
    [12a] List members of Office 365 Group
    [13]  Search AD Computer description
    [14]  Get orginization tab properties of AD user
    [14a] Get Description of single Computer Object 
    [15]  Convert to Shared mailbox
    [16]  Add user to Dist/Security Group - Using AD
    [17]  View user loginscript path
    [17a] Edit logon script for user
    [18]  Remove all Office 365 license for user
    [19]  Get VM hypervisor host
    [20]  List all ad computers starting with
    [21]  List all Hyper V Host VMs



    [logoff] Log off selected user from specific Machine
    [a] create User Termination Folder
    [b] create ticket folder 
    [q] quit
  "

  $selection = Read-Host "Please make a selection "

  if($selection -eq 'q' -OR $selection -eq 'Q') {
    Echo "Selected: $selection"
    Echo "Selected: $selection exiting...."
    Pause
    Exit
  }

  if($selection -eq 'a' -OR $selection -eq 'A') {
    $TerminatingUser = Read-Host -prompt "Please Enter Full name of user being Terminated"
    MKDIR -p "$defaultTerminationFolder\$TerminatingUser"
    start "$defaultTerminationFolder\$TerminatingUser"
  }

  if($selection -eq 'b' -OR $selection -eq 'B') {
    $folderName = Read-Host -prompt "Enter name of folder"
    MKDIR -p "$deafultTicketDocumentFolders\$folderName"
    start "$deafultTicketDocumentFolders\$folderName"
  }

  elseif($selection -eq '1') { #Search all Locked out AD Users
    Echo "Selected: $selection"
    Search-ADAccount -LockedOut

  } elseif($selection -eq '2') { #UnLock all Locked out AD Users
    Echo "Selected: $selection"
    Search-ADAccount -LockedOut | Unlock-ADAccount
  } 

  elseif($selection -eq '3') { #Get password expiration date/additoinal account information
    $username = Read-Host -prompt "Please Enter Username"

    Net user $username /domain
  } 

  elseif($selection -eq '3a') { #Get user group membership
    $username = Read-Host -prompt "Please Enter Username"

    Get-ADPrincipalGroupMembership $username | select -Expand name
  } 

  elseif($selection -eq '4') { #Get user manager
    $user = Read-Host "Please Enter Username"
    $Manager = get-aduser $user -properties * | Select -ExpandProperty Manager
    get-aduser $Manager -properties * | Select SamAccountName,DisplayName
  }

  elseif($selection -eq '5') { #Disable AD user

    $user = Read-Host "Please Enter Username"
    Disable-ADAccount -Identity $user
    Echo "User account sucessfully disabled status: $?"
  }

  elseif($selection -eq '6') { #Enable AD user

    $user = Read-Host "Please Enter Username"
    Enable-ADAccount -Identity $user
    Echo "User account sucessfully enabled status: $?"
  }

  elseif($selection -eq '7') { #Disable/Remove MFA for single User

    $user = Read-Host "Please Enter email of user you want to disable MFA"
    Get-MsolUser -UserPrincipalName $user | Set-MsolUser -StrongAuthenticationRequirements @()
    Echo "User account MFA sucessfully disabled status: $?"
  }


  elseif($selection -eq '8') { #Generate list of all licensed user's MFA status
    Echo "Selected: Generate list of all licensed user's MFA status"
    $folderName = (Get-Date).tostring("MM-dd-yyyy-hh-mm-ss")  
    Get-MsolUser -all | Where {$_.islicensed -like "True"} | Select DisplayName,UserPrincipalName,@{Name='MFAStatus'; Expression= {If($_.StrongAuthenticationRequirements.Count -ne 0) {$_.StrongAuthenticationRequirements[0].State} Else {'Disabled'}}} | Export-Csv -NoTypeInformation C:\export\MFAStatus-$folderName.csv

    start C:\export
  }

  elseif($selection -eq "8a") { #Generate list of all licensed user's MFA status methods
    echo "Generate list of all licensed user's MFA status methods"
    $dateAndTime = (Get-Date).tostring("MM-dd-yyyy-hh-mm-ss")  
    #Connect-MsolService
    Get-MsolUser -all | where {$_.isLicensed -eq $true} | select DisplayName,UserPrincipalName,@{N="MFA Status"; E={ if( $_.StrongAuthenticationMethods.IsDefault -eq $true) {($_.StrongAuthenticationMethods | Where IsDefault -eq $True).MethodType} else { "Disabled"}}} | Export-Csv -NoTypeInformation C:\export\MFAStatusMethods-$dateAndTime.csv
    start C:\export
  }


  elseif($selection -eq '9') { #Find user(s) logged into machine

    $machineName = Read-Host -Prompt "Enter Computer Name"
    query user /server:$machineName
  }

  elseif($selection -eq '10') { #Reset password for user 
    $user = Read-Host -Prompt "Enter username"
    $newPass = Read-Host -Prompt "Enter new password"
    Set-ADAccountPassword -Identity $user -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$newPass" -Force)
    Echo "Password change status: $?"
  }

  elseif($selection -eq '11') { #Get AD Description of machine
    $deviceName = Read-Host -Prompt "Enter computer name"
    Get-ADComputer $deviceName -Properties * | ft Name,Description
  }


  elseif($selection -eq '12') { #List members of AD Group
    $ADGroup = Read-Host -Prompt "Enter AD group name"
    Get-ADGroupMember -Identity "$ADGroup" | Select-Object Name | Sort-Object Name
  }

  elseif($selection -eq '12a') { #List members of Office 365 Group
    
    $officeGroup = Read-Host -Prompt "Enter Office 365 group name"
    Get-Group -Identity "$officeGroup" | Format-List -Property Members
  }

  elseif($selection -eq '13') { #Search AD Computer description
    $ADDescription = Read-Host -Prompt "Enter Description"
    Get-ADComputer -Filter "description -like `"*$ADDescription*`""
  }

  elseif($selection -eq '14') { #Get orginization tab properties of AD user
    $user = Read-Host -Prompt "Enter user"
    Get-ADUser $user -Properties * | Ft -autosize -wrap title, Department, Company, Manager
  }

  elseif($selection -eq '14a') { #Get Description of single Computer Object
    $computerObject = Read-Host -Prompt "Enter user"
    Get-ADComputer -Filter {name -Like $computerObject} -Properties description
  }


  elseif($selection -eq '15') { #Convert to Shared mailbox
    $userEmail = Read-Host -Prompt "Enter email of user you want to convert to share mailbox"
    Set-Mailbox $userEmail -Type Shared
    Echo "User account sucessfully converted to shared mailbox status: $?"
  }

  elseif($selection -eq '16') { #View Users in a Group then, Add user to Dist/Security Group - Using AD
    $Group = Read-Host -Prompt "Enter name of group"
    Get-ADGroupMember -Identity $Group -Recursive

    Pause
 
    $user = Read-Host -Prompt "Enter username of user to add to: $Group"
    Add-ADGroupMember -Identity $Group -Members $user
    Echo "User account sucesfully added to $Group : $?"
  }


  elseif($selection -eq '17') { #View user loginscript path
    $username = Read-Host -Prompt "Enter name of user"
    Get-ADUser -Identity $username -Properties Scriptpath | fl Scriptpath

  }

  elseif($selection -eq '17a') { #Edit user LoginPath
    $username = Read-Host -Prompt "Enter name of user"
    echo "current ScriptPath: "
    Get-ADUser -Identity $username -Properties Scriptpath | fl Scriptpath
    $newScriptPath = Read-Host -Prompt "Enter name of new script path"
    Get-ADUser -Identity $username | Set-ADUser -ScriptPath $newScriptPath
    Echo "Login change status: $?"
  }

  elseif($selection -eq '18') { #Remove all Office 365 license for user
    $username = Read-Host -Prompt "Enter email of user"
    Echo "List of licences removed"
    (Get-MsolUser -UserPrincipalName $username).licenses.AccountSkuId
    (Get-MsolUser -UserPrincipalName $username).licenses.AccountSkuId | foreach {Set-MsolUserLicense -UserPrincipalName $username -RemoveLicenses $_}
    Echo "Verify licenses removed"
    (Get-MsolUser -UserPrincipalName $username).licenses.AccountSkuId
  }

  elseif($selection -eq '19') { #Get VM's hypervisor host
   $vm = Read-Host -Prompt "Enter name of VM(s)"
   Invoke-Command -ComputerName $vm -ScriptBlock {Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"}  | Select-Object HostName
  }

  elseif($selection -eq '20') { #List all ad computers starting with
  $startingWithName = Read-Host -Prompt "Enter starting with name"
  Get-ADComputer -Filter "Name -like '$startingWithName*'" -Properties IPv4Address | FT Name,DNSHostName,IPv4Address -A
  }

  elseif($selection -eq '21') { #List all Hyper V Host VMs
  $hypervHost = Read-Host -Prompt "Enter HyperV host"
  Get-VM -ComputerName $hypervHost
  }



  elseif($selection -eq 'logoff') { #Log off selected user from specific Machine
    $machineName = Read-Host -Prompt "Enter machine to view current users"
    Start-Process quser /server:$machineName -Wait -NoNewWindow
    $ID = Read-Host -Prompt "Enter ID you want to log off"
    logoff $ID /server:$machineName 
    Echo "Selection: $ID sucessfully signed out status: $?"
  }

  else {
    Echo "Selected: $selection"
    Echo "Not valid entry. Try again."
    Pause
  }

} # End of While Loop

Stop-Transcript

stop-process -Id $PID