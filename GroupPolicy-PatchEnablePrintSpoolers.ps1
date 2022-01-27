# Created by packet for https://www.parceu.com

# Specify how to re-enable printspoolers and/or Remoteprint and/or Point-and-Print
# Must be run on a DC

# Note: Non-functional due to GPO download source deletion.

#========#
# ^^^^^^ #
# README #
#========#

########################################################################################################################################################################################################################


#Detects if the script is run in admin context, if it is not, the script will exit after letting the user know.
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false)
{
    cls
    write-warning "Script needs to be run as admin."
    break
}

#Sets the TLS settings to allow downloads via HTTP
#Downloads, installs, and imports neccesary modules
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = "SilentlyContinue"
#====================================#
# Please add neccesary modules below #
# VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV #
#====================================#


#Import-module AdmPwd.PS
# is done later due to dependency issues

#install-module PSAppDeployToolkit
# Put in for use in later version.

#import-module PSAppDeployToolkit  
# Put in for use in later version.


#====================================#
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #
# Please add neccesary modules above #
#====================================#

#Shows the startup banner main menu.
$MainMenu01 = 
{
    sleep 1
    cls
    write-host "";
    write-host "                                       " -BackGroundColor Black -NoNewLine; write-host "By packet" -ForeGroundColor Red -BackGroundColor Black -NoNewLine; write-host "                                     " -BackGroundColor Black
    write-host "         " -BackGroundColor Black -NoNewLine; write-host " █████╗ ██╗   ██╗████████╗ ██████╗ ██╗      █████╗ ██████╗ ███████╗" -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host "         " -BackGroundColor Black
    write-host "         " -BackGroundColor Black -NoNewLine; write-host "██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██║     ██╔══██╗██╔══██╗██╔════╝" -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host "         " -BackGroundColor Black
    write-host "         " -BackGroundColor Black -NoNewLine; write-host "███████║██║   ██║   ██║   ██║   ██║██║     ███████║██████╔╝███████╗" -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host "         " -BackGroundColor Black
    write-host "         " -BackGroundColor Black -NoNewLine; write-host "██╔══██║██║   ██║   ██║   ██║   ██║██║     ██╔══██║██╔═══╝ ╚════██║" -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host "         " -BackGroundColor Black
    write-host "         " -BackGroundColor Black -NoNewLine; write-host "██║  ██║╚██████╔╝   ██║   ╚██████╔╝███████╗██║  ██║██║     ███████║" -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host "         " -BackGroundColor Black
    write-host "         " -BackGroundColor Black -NoNewLine; write-host "╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝" -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host "         " -BackGroundColor Black
    write-host "                                                                                     " -BackGroundColor Black
    write-host "+---FUNCTIONS------------------------+" -BackGroundColor Black -NoNewLine; write-host "---README-------------------------------------+" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|1. (Deploy) Deploy LAPS             |" -BackGroundColor Black -NoNewLine; write-host " This script deploys or removes Microsoft LAPS|" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|                                    |" -BackGroundColor Black -NoNewLine; write-host " across an organisations domain.              |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|------------------------------------|" -BackGroundColor Black -NoNewLine; write-host "                                              |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|2. (Remove) Removes LAPS deployments|" -BackGroundColor Black -NoNewLine; write-host "                                              |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|            made with this script   |" -BackGroundColor Black -NoNewLine; write-host "                             (CTRL+C to exit) |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "+------------------------------------+" -BackGroundColor Black -NoNewLine; write-host "----------------------------------------------+" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host ""
    $MainMenuFunction01 = read-host "Select function (1/2)"
    
    #If neither function 1 or function 2 is selected, the user is returned to the main menu. This forces the user to make a valid choice.
    if ($MainMenuFunction01 -ne "1" -and $MainMenuFunction01 -ne "2")
    {
        &@MainMenu01
    }

    #If function 2 is selected, everything generated by function 1 will be removed:
    if ($MainMenuFunction01 -eq "2")
    {
        #Detects Group policies that follow the scripts naming convention
        $ExistingLAPS01 = Get-GPO -All | Where-Object {$_.displayname -like "Parceu_AutoLAPS_*"}
        
        #If any are found, they will be removed
        if ($ExistingLAPS01 -ne $null)
        {
            Remove-GPO -Name Parceu_AutoLAPS_DeviceInstallation
            Remove-GPO -Name Parceu_AutoLAPS_Configuration
        }

        #If none are found, a variable will be set for later
        else
        {
            $ExistingLAPSResult01 = $false
        }

        #Detects the generated folder
        $ExistingLAPS02 = Test-Path -Path C:\Parceu_AutoLAPS\

        #If found, it will be removed
        if ($ExistingLAPS02 -eq $true)
        {
            Remove-Item –path C:\Parceu_AutoLAPS\ –recurse -Force
        }

        #If not found, a variable will be set for later
        else
        {
            $ExistingLAPSResult02 = $false
        }

        #If neither any GPOs or the folder is found, it will let the user know and then return to main menu.
        if ($ExistingLAPSResult01 -eq $false -and $ExistingLAPSResult02 -eq $false)
        {
            cls
            write-host ""
            write-host "No existing deployment by this script detected" -ForegroundColor Red
            write-host "Returning to main menu..."
            write-host ""
            sleep 1
            &@MainMenu01
        }
        #If either is found and therefor removed, it will let the user know and then return to the main menu.
        cls
        write-host ""
        write-host "Existing deployment has now been removed" -ForegroundColor Green
        write-warning "Any existing installations of the LAPS software will NOT be automatically uninstalled anywhere"
        pause
        cls
        &@MainMenu01
    }
    #If function 1 is selected, the code breaks out of the main menu and will continue from the below point.
}
&@MainMenu01
cls
#Function 1 starts here
#===================================#
# Please add functional code  below #
# VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV #
#===================================#

#Creates the folder where the LAPS files will be stored
New-Item -ItemType "directory" -Path "C:\ITR_AutoLAPS"

#Creates the folder where the LAPS GPO files will be temporarily stored
New-Item -ItemType "directory" -Path "C:\ITR_AutoLAPSInstall"

#Downloads the LAPS MSI installer to the previously generated AutoLAPS folder
Invoke-WebRequest -Uri https://download.microsoft.com/download/C/7/A/C7AAD914-A8A6-4904-88A1-29E657445D03/LAPS.x64.msi -OutFile C:\ITR_AutoLAPS\LAPS.x64.msi

#Downloads the AutoLAPS GPOs to the temporary AutoLAPS folder
$GPOURL = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cHM6Ly9naXRodWIuY29tL3Bja3RzL1ByaW50TmlnaHRtYXJlV29ya2Fyb3VuZC9yYXcvbWFpbi9HUE9zLnppcA=="))
Invoke-WebRequest -Uri $GPOURL -OutFile C:\ITR_AutoLAPSInstall\GPOs.zip
sleep 1
 
#Installs LAPS including the management tools
msiexec.exe /i C:\ITR_AutoLAPS\LAPS.x64.msi ADDLOCAL=CSE,Management,Management.UI,Management.PS,Management.ADMX /quiet

#Makes the AutoLAPS folder shared and allowing everyone to have read access. The only content of this folder is the publicly-available LAPS msi installer file.
New-SmbShare -Name LAPS -Path C:\ITR_AutoLAPS | Grant-SmbShareAccess -AccountName Everyone -AccessRight Read

#Imports the LAPS module for powershell. This isn't done until this point due to being dependent on an installation of the management tools.
Import-module AdmPwd.PS

#Updates the AD Schema to make the newly installed LAPS features available.
Update-AdmPwdADSchema

#Imports the GPOs and links them at domain root and every inheritence blocked OU.
#The links will also be enforced.
$Partition01 = Get-ADDomainController | Select DefaultPartition
$GPOSource01 = "C:\ITR_AutoLAPS\"
import-gpo -BackupId 6A1B280F-82A9-484D-AE16-3D278EDD65E7 -TargetName ITR_AutoLAPS_DeviceInstallation -path $GPOSource01 -CreateIfNeeded
import-gpo -BackupId FA0E159B-5892-4D0B-B6A1-90FABC0ED38B -TargetName ITR_AutoLAPS_Configuration -path $GPOSource01 -CreateIfNeeded
Get-GPO -Name "PrintSpoolerDisable" | New-GPLink -Target $Partition01.DefaultPartition
Get-GPO -Name "PrintSpoolerEnable" | New-GPLink -Target $Partition01.DefaultPartition
$Blocked01 = Get-ADOrganizationalUnit -Filter * | Get-GPInheritance | Where-Object {$_.GPOInheritanceBlocked} | select-object Path 
Foreach ($B01 in $Blocked01) 
{
    New-GPLink -Name "ITR_AutoLAPS_Configuration" -Target $B01.Path
    New-GPLink -Name "ITR_AutoLAPS_DeviceInstallation" -Target $B01.Path
    Set-GPLink -Name "ITR_AutoLAPS_Configuration" -Enforced Yes -Target $B01.Path
    Set-GPLink -Name "ITR_AutoLAPS_DeviceInstallation" -Enforced Yes -Target $B01.Path
}

#Sets permissions so that Domain Admins can read the password computers that LAPS is deployed to.
cls
write-host "Do you have multiple or custom OUs that contain computers?"
$MoreComputers = read-host -Prompt 'Yes/No?'
if ($MoreComputers = "yes" -or "y")
{
    $ComputerRAWs = Get-ADComputer -filter * | Select-Object DistinguishedName
    foreach ($ComputerRAW in $ComputerRAWs)
    {
        $ComputerOU = $ComputerRAW | ForEach-Object{($_ -split "," | Select-Object -Skip 1) -join ","}
        $ComputerDN = $ComputerOU.Substring(0,$ComputerOU.Length-1)
        $PermsGiven = Find-AdmPwdExtendedRights -Identity "$ComputerDN"
        if ($PermsGiven = "")
        {
            Set-AdmPwdComputerSelfPermission $ComputerDN
            Set-AdmPwdReadPasswordPermission $ComputerDN -AllowedPrincipals "Domain Admins"
            cls
        }
    }
}
else
{
    Set-AdmPwdComputerSelfPermission CN=Computers,$domainDN
    Set-AdmPwdComputerSelfPermission OU=Domain Controllers,$domainDN
    Set-AdmPwdReadPasswordPermission CN=Computers,$domainDN -AllowedPrincipals "Domain Admins"
    Set-AdmPwdReadPasswordPermission OU=Domain Controllers,$domainDN -AllowedPrincipals "Domain Admins"
    cls
}

#===================================#
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #
# Please add functional code  above #
#===================================#


#Checks if run as admin
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false)
{
    cls
    write-host "Please run as admin..."
    sleep 1
    break
}

#Sets the TLS settings to allow downloads via HTTP
#Downloads, installs, and imports neccesary modules
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = "SilentlyContinue"
import-module activedirectory | out-null

#Tries to import before installing, as installing takes a long time.
try
{
    import-module Microsoft.powershell.archive | out-null
}
catch
{
    install-module Microsoft.powershell.archive | out-null
}

#Shows the startup banner main menu.
$banner = 
{
    sleep 1
    cls
    write-host "";
    write-host "                                       " -BackGroundColor Black -NoNewLine; write-host "By packet" -ForeGroundColor Red -BackGroundColor Black -NoNewLine; write-host "                                      " -BackGroundColor Black
    write-host "  " -BackGroundColor Black -NoNewLine; write-host "██████╗ ██████╗ ██╗███╗   ██╗████████╗██████╗ ██████╗ ███████╗ █████╗ ███╗   ███╗" -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host "  " -BackGroundColor Black
    write-host "  " -BackGroundColor Black -NoNewLine; write-host "██╔══██╗██╔══██╗██║████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔══██╗████╗ ████║" -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host "  " -BackGroundColor Black
    write-host "  " -BackGroundColor Black -NoNewLine; write-host "██████╔╝██████╔╝██║██╔██╗ ██║   ██║   ██║  ██║██████╔╝█████╗  ███████║██╔████╔██║" -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host "  " -BackGroundColor Black
    write-host "  " -BackGroundColor Black -NoNewLine; write-host "██╔═══╝ ██╔══██╗██║██║╚██╗██║   ██║   ██║  ██║██╔══██╗██╔══╝  ██╔══██║██║╚██╔╝██║" -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host "  " -BackGroundColor Black
    write-host "  " -BackGroundColor Black -NoNewLine; write-host "██║     ██║  ██║██║██║ ╚████║   ██║   ██████╔╝██║  ██║███████╗██║  ██║██║ ╚═╝ ██║" -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host "  " -BackGroundColor Black
    write-host "  " -BackGroundColor Black -NoNewLine; write-host "╚═╝     ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝" -ForeGroundColor Darkyellow -BackGroundColor Black -NoNewLine; write-host "  " -BackGroundColor Black
    write-host "                                                                                     " -BackGroundColor Black
    write-host "+---FUNCTIONS------------------------+" -BackGroundColor Black -NoNewLine; write-host "---README-------------------------------------+" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|1. (deploy) Rolls back workarounds  |" -BackGroundColor Black -NoNewLine; write-host " This script is used to roll back workarounds |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|and deploys chosen remediation GPO  |" -BackGroundColor Black -NoNewLine; write-host " deployed with PrintParalysis (Formerly       |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|------------------------------------|" -BackGroundColor Black -NoNewLine; write-host " PrintNightmareAutomated) or deployments that |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|2. (cleanup) Deletes previously     |" -BackGroundColor Black -NoNewLine; write-host " otherwise follow the same naming conventions.|" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "|deployed remediation GPOs           |" -BackGroundColor Black -NoNewLine; write-host " (CTRL+C to exit)                             |" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host "+------------------------------------+" -BackGroundColor Black -NoNewLine; write-host "----------------------------------------------+" -ForeGroundColor DarkGray -BackGroundColor Black
    write-host ""
    $WantedFunction = read-host "Select function (1/2)"
    
    #If neither 1 or 2 is selected, user is forced to stay on main menu
    if ($WantedFunction -ne "1" -and $WantedFunction -ne "2")
    {
        &@banner
    }
    #If function 2 is selected, GPO from previous deployment(s) are detected and deleted, user is then returned to main menu.
    if ($WantedFunction -eq "2")
    {
        $PreviousGPOs = Get-GPO -All | Where-Object {$_.displayname -like "Parceu_*"}
        foreach ($PreviousGPO in $PreviousGPOs)
        {
            $PGPO = $PreviousGPO.Displayname
            Remove-GPO -Name $PGPO
        }
        cls
        write-host "CLEANUP COMPLETE" -ForegroundColor Green
        sleep 1
        &@banner
    }
}
&@banner
$bannerexit

#Detects if GPO(s) stemming from a previous run of this script exists. If it does, it will warn the user and refuse to continue.
#It will display a warning message and then after acknowledgement from the user, return them to the main menu.
$HasRunBefore = Get-GPO -All | Where-Object {$_.displayname -like "Parceu_*"}
if ($HasRunBefore -ne $null)
{
    sleep 1
    cls
    write-host ""
    write-host "===" -ForegroundColor DarkGray -NoNewLine; write-host "ERROR" -ForegroundColor Red -NoNewLine; write-host "===" -ForegroundColor DarkGray -NoNewLine; write-host "ERROR" -ForegroundColor Red -NoNewLine; write-host "===" -ForegroundColor DarkGray -NoNewLine; write-host "ERROR" -ForegroundColor Red -NoNewLine; write-host "===" -ForegroundColor DarkGray -NoNewLine; write-host "ERROR" -ForegroundColor Red -NoNewLine; write-host "===" -ForegroundColor DarkGray;
    write-host ""
    write-host "A previous run of the script has been detected!" 
    write-host "You can not proceed until you've run a cleanup."
    write-host ""
    pause
    &@banner
}

#Detects and deletes all GPOs stemming from workaround deployments with PrintNightmareAutomated as well as most manual deployments.
#It will display the list to the user and ask for them to verify, to ensure no production GPOs are affected.
#If no GPOs are detected, it will simply proceed without deleting anything. (After telling the user briefly)
$SpoolerGPOs = Get-GPO -All | Where-Object {$_.displayname -like "*spool*" -or $_.displayname -like "*nightmare*"} | Select displayname
if ($SpoolerGPOs -ne $null)
{
    cls
    $SpoolerGPOs | out-host
    echo "" | out-host
    echo "Please verify these are only related to PrintNightmare" | out-host
    echo "" | out-host
    $DeleteSpoolerGPOs = read-host "Continue? (Y/N)"
    
    #If the user does not choose to continue, they will be adviced to manually clean up the policies, and exit the script.
    if ($DeleteSpoolerGPOs -ne "y")
    {
        cls
        write-host "Please manually clean up policies."
        pause
        cls
        break
    }
    #If the user chooses to proceed, all previously listed GPOs will be deleted.
    foreach ($SpoolerGPO in $SpoolerGPOs)
    {
        $Spooler = $SpoolerGPO.Displayname
        Remove-GPO -Name $Spooler
    }
}
else
{
    cls
    write-host "No GPOs relating to a PrintNightmare workaround has been found" -ForegroundColor Red
    sleep 1
}
#Detects if a previous download of dependecies exist, if it does, it will delete it, as a new and ensured complete package is downloaded.
$DoesDependsExist = Test-Path -Path C:\PrintNightmareTemp
if ($DoesDependsExist -eq $true)
{
    Remove-Item –path C:\PrintNightmareTemp –recurse -Force
}

#Downloads dependencies
New-Item -ItemType "directory" -Path C:\PrintNightmareTemp
sleep 1
$GPOURL = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cHM6Ly9naXRodWIuY29tL3Bja3RzL1ByaW50TmlnaHRtYXJlV29ya2Fyb3VuZC9yYXcvbWFpbi9HUE9zLnppcA=="))
Invoke-WebRequest -Uri $GPOURL -OutFile C:\PrintNightmareTemp\GPOs.zip
sleep 1

#Attempts to unzip the downloaded archive of dependencies, if this fails it will be because WMF 5.1 is not installed.
#The script will inform the user about this and give an option to open the download page for them.
#Regardless of which option is chosen, the script will exit, as it is impossible to continue without these dependencies.
#(It is possible to proceed without this dependency by manually unzipping and manually running this script in parts, but it is highly inadvisable)
Try
{
    Expand-Archive -LiteralPath 'C:\PrintNightmareTemp\GPOs.zip' -DestinationPath C:\PrintNightmareTemp
}
catch
{
    cls
    write-host "Powershell version is outdated and does not contain required functionality."
    write-host "Please download and install Windows Management Framework 5.1"
    write-host "You can not continue until this is installed."
    write-host ""
    $DownloadWMF = read-host "Do you want to go to the download page before closing? (Y/N)"
    if ($DownloadWMF = "y")
    {
        Start-Process "https://www.microsoft.com/en-us/download/details.aspx?id=54616"
        cls
        break
    }
    else
    {
        break
    }
}
#Presents a series of choices to the user. The sum of these choices will determine which GPO will be deployed.
#None of the choices can be bypassed and require a valid input, and will not proceed otherwise.

#The first choice being if they want to enable or disable the printspooler.
$SpoolerChoice = 
{
    cls
    write-host "Do you want to enable or disable the printspooler?"
    $DesiredSpoolerState = read-host "(E)nable/(D)isable"
    if ($DesiredSpoolerState -ne "d" -and $DesiredSpoolerState -ne "e")
    {
        &@SpoolerChoice
    }
    else
    {
        #The second choice being if they want to enable or disable remote printing functionality
        $RemoteChoice = 
        {
            cls
            write-host "Do you want to enable or disable remote printing?"
            $DesiredRemoteState = read-host "(E)nable/(D)isable"
            if ($DesiredRemoteState -ne "d" -and $DesiredRemoteState -ne "e")
            {
                &@RemoteChoice
            }
            else
            {
                #The third and final choice being if they want to enable or disable "Point and Print" functionality
                $PAPChoice = 
                {
                    cls
                    write-host "Do you want to enable or disable Point and Print?"
                    $DesiredPAPState = read-host "(E)nable/(D)isable"
                    if ($DesiredPAPState -ne "d" -and $DesiredPAPState -ne "e")
                    {
                        &@PAPChoice
                    }
                    else
                    {
                        #Creates variables for the GPO GUIDs for convenience
                        $111 = "23E036C2-B247-4717-9A43-41F3212F8DC0"
                        $110 = "D73E9B1F-1906-4382-A650-B4C1DC7B5E7E"
                        $101 = "2885612A-32D1-4CAA-B730-F5C9C6F1B2E7"
                        $100 = "77F9D898-8EB1-437D-B1C2-91E04E14996D"
                        $011 = "9EB906D5-2E15-4091-A790-450E03449E1B"
                        $010 = "CA478F98-53BD-4C7C-920E-4C76F2E0485C"
                        $001 = "96599A76-E0AA-45D7-B1C2-577F974E7D6A"
                        $000 = "6BCBC833-D657-4F04-AEE7-EEA92CA99395"

                        #Scriptblock that will be used to select what versions of devices to target.
                        #This code is not run at first appearance but is called in later.
                        $ServerVersionChoice =
                        {
                                                        
                            #Gets all devices of a certain OS version and creates an array of these.

                            #Server versions
                            $SRV2019 = (Get-ADcomputer -filter {operatingsystem -like "*2019*"} -Properties Name, OperatingSystem).name
                            $SRV2016 = (Get-ADcomputer -filter {operatingsystem -like "*2016*"} -Properties Name, OperatingSystem).name
                            $SRV2012 = (Get-ADcomputer -filter {operatingsystem -like "*2012*"} -Properties Name, OperatingSystem).name
                            $SRVOLD  = (Get-ADcomputer -filter {operatingsystem -like "*200*"}  -Properties Name, OperatingSystem).name

                            #Client versions
                            $WIN10  = (Get-ADcomputer -filter {operatingsystem -like "Windows 10*"} -Properties Name, OperatingSystem).name
                            $WINOLD = (Get-ADcomputer -filter {operatingsystem -notlike "Windows 10*" -and operatingsystem -notlike "*Server*"} -Properties Name, OperatingSystem).name

                            #Presents the possible options to the user and lets them choose the combination of device versions they desire
                            #This will loop until it is exited on purpose. It is not possible to pick the same option twice. (nothing will happen after first time)
                            $AddedDeviceGroups = {$hostname}.Invoke()
                            while ($AddedDeviceGroup -ne "done")
                            {
                                sleep 1
                                cls
                                write-host "Possible groups of target devices:" -ForegroundColor Green
                                write-host ""
                                write-host "(1). Server 2019"
                                write-host "(2). Server 2016"
                                write-host "(3). Server 2012 and 2012R2"
                                write-host "(4). Server 2008R2 and earlier"
                                write-host ""
                                write-host "(5). Windows 10"
                                write-host "(6). Windows 8.1 and earlier"
                                write-host ""
                                write-host ""
                                write-host "Targetted devices:" -ForegroundColor Red
                                $AddedDeviceGroups
                                write-host;
                                write-host ""
                                write-host "--------------------------------------------------------" -ForegroundColor DarkGray
                                write-host ""
                                write-host "Please input what devices you want to apply the changes to, one at a time."
                                write-host "Please be absolutely sure of the devices you add, as the only easy way to add or remove devices later is to start over."
                                write-host "If you accidentally add an unintended group, you can 'add' it again to remove it"
                                write-host ""
                                write-host "Type 'done' when you do not want to add any more device groups"
                                $AddedDeviceGroup = Read-Host "Option"

                                #Detects if a valid input is selected and lists the option as "picked" on the screen. The handling of duplicate choices is also here.
                                #In a later instance, the devices belonging to the chosen group, will be added to an array that is used later for actual deployment.
                                #If you pick an existing option, it will be removed
                                #A "block" exists for each group of devices, they function identically.
                                if ($AddedDeviceGroup -eq "1")
                                {
                                    if ($AddedDeviceGroups.Contains("Server 2019") -ne $true)
                                    {
                                        $AddedDeviceGroups.Add("Server 2019")
                                    }
                                    else
                                    {
                                        $AddedDeviceGroups.Remove("Server 2019")
                                    }
                                }
                                if ($AddedDeviceGroup -eq "2")
                                {
                                    if ($AddedDeviceGroups.Contains("Server 2016") -ne $true)
                                    {
                                        $AddedDeviceGroups.Add("Server 2016")
                                    }
                                    else
                                    {
                                        $AddedDeviceGroups.Remove("Server 2016")
                                    }
                                }
                                if ($AddedDeviceGroup -eq "3")
                                {
                                    if ($AddedDeviceGroups.Contains("Server 2012 and 2012R2") -ne $true)
                                    {
                                        $AddedDeviceGroups.Add("Server 2012 and 2012R2")
                                    }
                                    else
                                    {
                                        $AddedDeviceGroups.Remove("Server 2012 and 2012R2")
                                    }
                                }
                                if ($AddedDeviceGroup -eq "4")
                                {
                                    if ($AddedDeviceGroups.Contains("Server 2008R2 and earlier") -ne $true)
                                    {
                                        $AddedDeviceGroups.Add("Server 2008R2 and earlier")
                                    }
                                    else
                                    {
                                        $AddedDeviceGroups.Remove("Server 2008R2 and earlier")
                                    }
                                }
                                if ($AddedDeviceGroup -eq "5")
                                {
                                    if ($AddedDeviceGroups.Contains("Windows 10") -ne $true)
                                    {
                                        $AddedDeviceGroups.Add("Windows 10")
                                    }
                                    else
                                    {
                                        $AddedDeviceGroups.Remove("Windows 10")
                                    }
                                }
                                if ($AddedDeviceGroup -eq "6")
                                {

                                    if ($AddedDeviceGroups.Contains("Windows 8.1 and earlier") -ne $true)
                                    {
                                        $AddedDeviceGroups.Add("Windows 8.1 and earlier")
                                    }
                                    else
                                    {
                                        $AddedDeviceGroups.Remove("Windows 8.1 and earlier")
                                    }
                                }
                            }
                            $AddedDeviceGroups.RemoveAt(0)
                            $AddedDeviceGroups.Remove("done")

                            #Adds the devices from respective groups to the array used for actual deployment
                            if ($AddedDeviceGroups.Contains("Server 2019") -eq $true)
                            {
                                $DesiredDevices += $SRV2019
                            }
                            if ($AddedDeviceGroups.Contains("Server 2016") -eq $true)
                            {
                                $DesiredDevices += $SRV2016
                            }
                            if ($AddedDeviceGroups.Contains("Server 2012 and 2012R2") -eq $true)
                            {
                                $DesiredDevices += $SRV2012
                            }
                            if ($AddedDeviceGroups.Contains("Server 2008R2 and earlier") -eq $true)
                            {
                                $DesiredDevices += $SRVOLD
                            }
                            if ($AddedDeviceGroups.Contains("Windows 10") -eq $true)
                            {
                                $DesiredDevices += $WIN10
                            }
                            if ($AddedDeviceGroups.Contains("Windows 8.1 and earlier") -eq $true)
                            {
                                $DesiredDevices += $WINOLD
                            }
                            if ($AddedDeviceGroups.Contains("Server 2019") -ne $true -and $AddedDeviceGroups.Contains("Server 2016") -ne $true -and $AddedDeviceGroups.Contains("Server 2012 and 2012R2") -ne $true -and $AddedDeviceGroups.Contains("Server 2008R2 and earlier") -ne $true -and $AddedDeviceGroups.Contains("Windows 10") -ne $true -and $AddedDeviceGroups.Contains("Windows 8.1 and earlier") -ne $true)
                            {
                                write-warning "ERROR! - You have not picked any groups"
                                write-warning "Undoing changes and returning to main menu..."
                                sleep 2
                                $PreviousGPOs = Get-GPO -All | Where-Object {$_.displayname -like "Parceu_*"}
                                foreach ($PreviousGPO in $PreviousGPOs)
                                {
                                    $PGPO = $PreviousGPO.Displayname
                                    Remove-GPO -Name $PGPO
                                }
                                Remove-Item –path C:\PrintNightmareTemp –recurse -Force
                                cls
                                &@banner
                            }

                            cls
                            Write-host "The chosen policies will now be applied to the chosen device groups..."
                            sleep 2                                  
                                
                            #Applies the previously chosen GPO to the chosen groups of devices and finally exits.. by returning to the main menu
                            ForEach ($DesiredDevice in $DesiredDevices) 
                            {
                                Set-GPPermission -name $DesiredGPO -Targetname "$DesiredDevice" -TargetType Computer -PermissionLevel GpoApply
                            }
                            cls
                            write-host ""
                            write-host "DONE." -ForegroundColor Red
                            sleep 3
                            break
                        }
                        #The next 8 blocks of code are almost identical
                        #The blocks select a GPO based on previous choices and deploys and links it in the domain.
                        #Afterwards the user will be directed to the previous block that lets them choose what devices to target    
                        if ($DesiredSpoolerState -eq "e" -and $DesiredRemoteState -eq "e" -and $DesiredPAPState -eq "e")
                        {
                            $GPOName = "Parceu_SpoolerEnable-RemoteEnable-PAPEnable"
                            $Partition = Get-ADDomainController | Select DefaultPartition
                            $GPOSource = "C:\PrintNightmareTemp\"
                            import-gpo -BackupId $111 -TargetName $GPOName -path $GPOSource -CreateIfNeeded
                            Get-GPO -Name $GPOName | New-GPLink -Target $Partition.DefaultPartition
                            Set-GPLink -Name $GPOName -Enforced Yes -Target $Partition.DefaultPartition
                            $Blocked = Get-ADOrganizationalUnit -Filter * | Get-GPInheritance | Where-Object {$_.GPOInheritanceBlocked} | select-object Path 
                            foreach ($B in $Blocked) 
                            {
                                New-GPLink -Name $GPOName -Target $B.Path
                                Set-GPLink -Name $GPOName -Enforced Yes -Target $B.Path
                            }
                            Set-GPPermission -name $GPOName -Targetname "Authenticated Users" -TargetType Group -PermissionLevel None -Replace
                            $DesiredGPO = $GPOName
                            &@ServerVersionChoice     
                        }
                        if ($DesiredSpoolerState -eq "e" -and $DesiredRemoteState -eq "e" -and $DesiredPAPState -eq "d")
                        {
                            $GPOName = "Parceu_SpoolerEnable-RemoteEnable-PAPDisable"
                            $Partition = Get-ADDomainController | Select DefaultPartition
                            $GPOSource = "C:\PrintNightmareTemp\"
                            import-gpo -BackupId $110 -TargetName $GPOName -path $GPOSource -CreateIfNeeded
                            Get-GPO -Name $GPOName | New-GPLink -Target $Partition.DefaultPartition
                            Set-GPLink -Name $GPOName -Enforced Yes -Target $Partition.DefaultPartition
                            $Blocked = Get-ADOrganizationalUnit -Filter * | Get-GPInheritance | Where-Object {$_.GPOInheritanceBlocked} | select-object Path 
                            foreach ($B in $Blocked) 
                            {
                                New-GPLink -Name $GPOName -Target $B.Path
                                Set-GPLink -Name $GPOName -Enforced Yes -Target $B.Path
                            }
                            Set-GPPermission -name $GPOName -Targetname "Authenticated Users" -TargetType Group -PermissionLevel None -Replace
                            $DesiredGPO = $GPOName
                            &@ServerVersionChoice    
                        }
                        if ($DesiredSpoolerState -eq "e" -and $DesiredRemoteState -eq "d" -and $DesiredPAPState -eq "e")
                        {
                            $GPOName = "Parceu_SpoolerEnable-RemoteDisable-PAPEnable"
                            $Partition = Get-ADDomainController | Select DefaultPartition
                            $GPOSource = "C:\PrintNightmareTemp\"
                            import-gpo -BackupId $101 -TargetName $GPOName -path $GPOSource -CreateIfNeeded
                            Get-GPO -Name $GPOName | New-GPLink -Target $Partition.DefaultPartition
                            Set-GPLink -Name $GPOName -Enforced Yes -Target $Partition.DefaultPartition
                            $Blocked = Get-ADOrganizationalUnit -Filter * | Get-GPInheritance | Where-Object {$_.GPOInheritanceBlocked} | select-object Path 
                            foreach ($B in $Blocked) 
                            {
                                New-GPLink -Name $GPOName -Target $B.Path
                                Set-GPLink -Name $GPOName -Enforced Yes -Target $B.Path
                            }
                            Set-GPPermission -name $GPOName -Targetname "Authenticated Users" -TargetType Group -PermissionLevel None -Replace
                            $DesiredGPO = $GPOName
                            &@ServerVersionChoice 
                        }
                        if ($DesiredSpoolerState -eq "e" -and $DesiredRemoteState -eq "d" -and $DesiredPAPState -eq "d")
                        {
                            $GPOName = "Parceu_SpoolerEnable-RemoteDisable-PAPDisable"
                            $Partition = Get-ADDomainController | Select DefaultPartition
                            $GPOSource = "C:\PrintNightmareTemp\"
                            import-gpo -BackupId $100 -TargetName $GPOName -path $GPOSource -CreateIfNeeded
                            Get-GPO -Name $GPOName | New-GPLink -Target $Partition.DefaultPartition
                            Set-GPLink -Name $GPOName -Enforced Yes -Target $Partition.DefaultPartition
                            $Blocked = Get-ADOrganizationalUnit -Filter * | Get-GPInheritance | Where-Object {$_.GPOInheritanceBlocked} | select-object Path 
                            foreach ($B in $Blocked) 
                            {
                                New-GPLink -Name $GPOName -Target $B.Path
                                Set-GPLink -Name $GPOName -Enforced Yes -Target $B.Path
                            }
                            Set-GPPermission -name $GPOName -Targetname "Authenticated Users" -TargetType Group -PermissionLevel None -Replace
                            $DesiredGPO = $GPOName
                            &@ServerVersionChoice 
                        }
                        if ($DesiredSpoolerState -eq "d" -and $DesiredRemoteState -eq "e" -and $DesiredPAPState -eq "e")
                        {
                            $GPOName = "Parceu_SpoolerDisable-RemoteEnable-PAPEnable"
                            $Partition = Get-ADDomainController | Select DefaultPartition
                            $GPOSource = "C:\PrintNightmareTemp\"
                            import-gpo -BackupId $011 -TargetName $GPOName -path $GPOSource -CreateIfNeeded
                            Get-GPO -Name $GPOName | New-GPLink -Target $Partition.DefaultPartition
                            Set-GPLink -Name $GPOName -Enforced Yes -Target $Partition.DefaultPartition
                            $Blocked = Get-ADOrganizationalUnit -Filter * | Get-GPInheritance | Where-Object {$_.GPOInheritanceBlocked} | select-object Path 
                            foreach ($B in $Blocked) 
                            {
                                New-GPLink -Name $GPOName -Target $B.Path
                                Set-GPLink -Name $GPOName -Enforced Yes -Target $B.Path
                            }
                            Set-GPPermission -name $GPOName -Targetname "Authenticated Users" -TargetType Group -PermissionLevel None -Replace
                            $DesiredGPO = $GPOName
                            &@ServerVersionChoice 
                        }
                        if ($DesiredSpoolerState -eq "d" -and $DesiredRemoteState -eq "e" -and $DesiredPAPState -eq "d")
                        {
                            $GPOName = "Parceu_SpoolerDisable-RemoteEnable-PAPEnable"
                            $Partition = Get-ADDomainController | Select DefaultPartition
                            $GPOSource = "C:\PrintNightmareTemp\"
                            import-gpo -BackupId $010 -TargetName $GPOName -path $GPOSource -CreateIfNeeded
                            Get-GPO -Name $GPOName | New-GPLink -Target $Partition.DefaultPartition
                            Set-GPLink -Name $GPOName -Enforced Yes -Target $Partition.DefaultPartition
                            $Blocked = Get-ADOrganizationalUnit -Filter * | Get-GPInheritance | Where-Object {$_.GPOInheritanceBlocked} | select-object Path 
                            foreach ($B in $Blocked) 
                            {
                                New-GPLink -Name $GPOName -Target $B.Path
                                Set-GPLink -Name $GPOName -Enforced Yes -Target $B.Path
                            }
                            Set-GPPermission -name $GPOName -Targetname "Authenticated Users" -TargetType Group -PermissionLevel None -Replace
                            $DesiredGPO = $GPOName
                            &@ServerVersionChoice 
                        }
                        if ($DesiredSpoolerState -eq "d" -and $DesiredRemoteState -eq "d" -and $DesiredPAPState -eq "e")
                        {
                            $GPOName = "Parceu_SpoolerDisable-RemoteEnable-PAPEnable"
                            $Partition = Get-ADDomainController | Select DefaultPartition
                            $GPOSource = "C:\PrintNightmareTemp\"
                            import-gpo -BackupId $001 -TargetName $GPOName -path $GPOSource -CreateIfNeeded
                            Get-GPO -Name $GPOName | New-GPLink -Target $Partition.DefaultPartition
                            Set-GPLink -Name $GPOName -Enforced Yes -Target $Partition.DefaultPartition
                            $Blocked = Get-ADOrganizationalUnit -Filter * | Get-GPInheritance | Where-Object {$_.GPOInheritanceBlocked} | select-object Path 
                            foreach ($B in $Blocked) 
                            {
                                New-GPLink -Name $GPOName -Target $B.Path
                                Set-GPLink -Name $GPOName -Enforced Yes -Target $B.Path
                            }
                            Set-GPPermission -name $GPOName -Targetname "Authenticated Users" -TargetType Group -PermissionLevel None -Replace
                            $DesiredGPO = $GPOName
                            &@ServerVersionChoice 
                        }
                        if ($DesiredSpoolerState -eq "d" -and $DesiredRemoteState -eq "d" -and $DesiredPAPState -eq "d")
                        {
                            $GPOName = "Parceu_SpoolerDisable-RemoteEnable-PAPEnable"
                            $Partition = Get-ADDomainController | Select DefaultPartition
                            $GPOSource = "C:\PrintNightmareTemp\"
                            import-gpo -BackupId $000 -TargetName $GPOName -path $GPOSource -CreateIfNeeded
                            Get-GPO -Name $GPOName | New-GPLink -Target $Partition.DefaultPartition
                            Set-GPLink -Name $GPOName -Enforced Yes -Target $Partition.DefaultPartition
                            $Blocked = Get-ADOrganizationalUnit -Filter * | Get-GPInheritance | Where-Object {$_.GPOInheritanceBlocked} | select-object Path 
                            foreach ($B in $Blocked) 
                            {
                                New-GPLink -Name $GPOName -Target $B.Path
                                Set-GPLink -Name $GPOName -Enforced Yes -Target $B.Path
                            }
                            Set-GPPermission -name $GPOName -Targetname "Authenticated Users" -TargetType Group -PermissionLevel None -Replace
                            $DesiredGPO = $GPOName
                            &@ServerVersionChoice 
                        }
                    }
                }
                &@PAPChoice
            }
        }
        &@RemoteChoice 
    }
}
&@SpoolerChoice
