## In order to retrieve and/or install Windows Optional Features this script needs to run with admin privileges
#Requires -RunAsAdministrator
function Install-WSLFeature{
    ## First we need to make sure the WSL feature is installed, if not install and reboot afterwards 
    if($null -eq (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux)){
        ## Enable WSL and Virtual Machine Platform features
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
        
        ## Create temp directory if it does not exist
        $tmp = "C:\temp"
        if($null -eq (Test-Path $tmp)){
            
            New-Item $tmp
        
        }
        else{}
        
        ## Copy the script to the temp directory
        Copy-Item -Path ".\install-wsl.ps1" -Destination $tmp 

        ## Create a run once registry key in order for this script to be able to continue after reboot
        Set-Location HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce
        New-Itemproperty . InstallWSL -propertytype String -value "Powershell $tmp\install-wsl.ps1"
        
        ## Wait a bit and reboot the machine, continue on 
        Restart-Computer -Wait 1
    }
}
Install-WSLFeature


function Get-WSLDistribution{
    ## Then we bootstrap the host and install WSL and Ansible
    ## We can check if the correct distro is already installed, if not we run the install command
    $wsl = wsl -l | Where-Object {$_.Replace("`0","") -match '20.04'}
    $distro = "Ubuntu-20.04"
}
Get-WSLDistribution
function Set-WSLUsernamePassword{
    ## Set username and password (if existing install please enter your current user credentials otherwise create a new one)
    Write-Host "Please fill in your username"
    $script:username = Read-Host # Change this (update to commandline switch)
    Write-Host "Please fill in your password"
    $password = Read-Host -asSecureString

    ## Decode the password so it can be used inside the bash shell
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $script:plainpassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}
Set-WSLUsernamePassword

function Install-WSLDistribution{
    ## If WSL is not installed we install it
    if($null -eq $wsl){
        ## Install the distro as root so we can create a user
        wsl --install --d $distro
        ## Set WSL2 as default
        wsl --set-default-version 2
        ## Now we got to wait a few minutes in order for the distro to install before we can continue on
        Start-Sleep -Seconds 60
        ## Add new user
        wsl -u root -d $distro useradd -m "$username"
        ## Set the password
        wsl -u root -d $distro /bin/bash -c "echo '${username}:${plainpassword}' | chpasswd"
        ## Change login shell to bash
        wsl -u root -d $distro chsh -s /bin/bash "$username"
        ## Set the privileges
        wsl -u root -d $distro usermod -aG adm,cdrom,sudo,dip,plugdev "$username"
    }
}
Install-WSLDistribution

function Set-WSLDefaults{
    ## Set WSL2 as default and set the Ubuntu-20.04 distro as default (if this is not yet the case already)
    wsl --set-default-version 2
    wsl --setdefault $distro
}
Set-WSLDefaults

function Install-WSLPackages{
    ## Let's make sure all our packages are up-to-date
    wsl -u $username /bin/bash -c "echo $plainpassword | sudo -S apt update -y && sudo -S apt upgrade -y"
    ## In order for Ansible to work openSSH Server needs to be installed
    wsl -u $username /bin/bash -c "echo $plainpassword | sudo -S apt install openssh-server -y && sudo -S service ssh start"
    ## Now install Ansible for the second stage of this deployment
    wsl -u $username /bin/bash -c "echo $plainpassword | sudo -S apt install ansible -y"
}
Install-WSLPackages

function Set-AnsibleConfig{
    ## Import System.Web Assembly
    Add-Type -AssemblyName System.Web
    ## Now we are going to create a service account under which our Ansible Playbook can run
    ## First we are going to generate a random password for this account.
    $ansibleuser = "svc_ansible"
    $ansiblepassword = [System.Web.Security.Membership]::GeneratePassword(16,4)

    ## Now we create the user inside
    wsl -u root -d $distro useradd -m "$ansibleuser"
    ## Set the password
    wsl -u root -d $distro /bin/bash -c "echo '${ansibleuser}:${ansiblepassword}' | chpasswd"
    ## Change login shell to bash
    wsl -u root -d $distro chsh -s /bin/bash "$ansibleuser"
    ## Set the privileges
    wsl -u root -d $distro usermod -aG adm,sudo "$ansibleuser"
}

Set-AnsibleConfig



