<#
$Metadata = @{
	Title = "Install WSL"
	Filename = "scripts\install-wsl.ps1"
	Description = "This script installs and configures WSL and installs Ansible for the second stage configuration"
	Tags = "Automation, Powershell, WSL, Ubuntu, Ansible"
	Project = "wsl-config"
	Author = "Roel de Cort"
	Url = "https://github.com/deCort-tech/wsl-config"
	Version = "1.0.0"
	License = ""
}
#>

## In order to check and/or install Windows Optional Features this script needs to run with admin privileges
#equires -RunAsAdministrator
function Install-WSL {
    <#
    .SYNOPSIS
        This script installs WSL (if needed) and configures it and prepares for stage 2 configuration via Ansible.
    .DESCRIPTION
        This script installs WSL if not yet installed and installs a Ubuntu 20.04 LTS image. After installing a user is created that can be used to login. 
        The Ubuntu image is updated and Ansible is installed, an ansible service account is created and a ansible vault so we can reference the service account password
        in the Ansible playbook as a secure variable. 
    .PARAMETER Username
        Username used to login on the WSL instance
    .EXAMPLE
        PS C:\wsl-config\scripts> Install-WSL.ps1 -Username roelc
    .INPUTS
        System.String
    .LINK
        https://github.com/deCort-tech/wsl-config
    #>

    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true)]
        [string]$Username
    )

    function Start-Sleep($seconds) {
        $sleepdate = (Get-Date).AddSeconds($seconds)
        
        while ($sleepdate -gt (Get-Date)) {
            $secondsLeft = $sleepdate.Subtract((Get-Date)).TotalSeconds
            $percent = ($seconds - $secondsLeft) / $seconds * 100
            Write-Progress -Activity "Waiting" -Status "Waiting..." -SecondsRemaining $secondsLeft -PercentComplete $percent
            [System.Threading.Thread]::Sleep(500)
        }
        Write-Progress -Activity "Waiting" -Status "Waiting..." -SecondsRemaining 0 -Completed
    }

    function Get-Password {
        ## Function to get the Password and compare it
        do {
            $password = Read-Host -AsSecureString -Prompt "Please fill in your password"
            $password_confirm = Read-Host -AsSecureString -Prompt "Please Re-enter your password"

            $script:plainpassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
            $plainpassword_confirm = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password_confirm))

        } until ($plainpassword -eq $plainpassword_confirm)
    }
    Get-Password

    function Install-WSLFeature {
        ## First we need to make sure the WSL feature is installed, if not install and reboot afterwards 
        if ($null -eq (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux)) {
            ## Enable WSL and Virtual Machine Platform features
            Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
            Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
            
            ## Create temp directory if it does not exist
            $tmp = "C:\temp"
            if ($null -eq (Test-Path $tmp)) {
                
                New-Item $tmp
            
            }
            else {}
            
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

    function Get-WSLDistribution {
        ## Then we bootstrap the host and install WSL and Ansible
        ## We can check if the correct distro is already installed, if not we run the install command
        Write-Host "Checking if the correct distribution is installed" -BackgroundColor Green
        $script:wsldistro = wsl -l | Where-Object { $_.Replace("`0", "") -match '20.04' }
        $script:distro = "Ubuntu-20.04"
    }
    Get-WSLDistribution
    
    function Install-WSLDistribution {
        ## If WSL is not installed we install it
        if ($null -eq $wsldistro) {
            ## Install the distro as root so we can create a user
            wsl --install --d $distro
            
            ## Now we got to wait a few minutes in order for the distro to install before we can continue on
            Write-Host "Waiting 1 minute before continuing on" -BackgroundColor Green
            Start-Sleep(60)
            
            ## Add new user
            Write-Host "Creating new user $username" -BackgroundColor Green
            wsl -u root -d $distro useradd -m "$username"
            
            ## Set the password
            Write-Host "Setting password for user $username" -BackgroundColor Green
            wsl -u root -d $distro /bin/bash -c "echo '${username}:${plainpassword}' | chpasswd"
            
            ## Change login shell to bash
            Write-Host "Changing login shell to /bin/bash for user $username" -BackgroundColor Green
            wsl -u root -d $distro chsh -s /bin/bash "$username"
            
            ## Set the privileges
            Write-Host "Setting user permissions for user $username" -BackgroundColor Green
            wsl -u root -d $distro usermod -aG adm, cdrom, sudo, dip, plugdev "$username"
        }
    }
    Install-WSLDistribution

    function Set-WSLDefaults {
        ## Set WSL2 as default and set the Ubuntu-20.04 distro as default (if this is not yet the case already)
        Write-Host "Setting WSL Defaults" -BackgroundColor Green
        wsl --set-default-version 2
        wsl --setdefault $distro
    }
    Set-WSLDefaults

    function Install-WSLPackages {
        ## Let's make sure all our packages are up-to-date
        Write-Host "Installing updates" -BackgroundColor Green
        wsl -u $username /bin/bash -c "echo $plainpassword | sudo -S apt update -y && sudo -S apt upgrade -y"
        
        ## Reboot WSL
        Write-Host "Rebooting WSL" -BackgroundColor Green
        wsl --shutdown

        ## Clean up unneeded packages
        Write-Host "Cleaning up packages" -BackgroundColor Green
        wsl -u $username /bin/bash -c "echo $plainpassword | sudo -S apt autoremove -y"

        ## In order for Ansible to work openSSH Server needs to be installed
        Write-Host "Installing OpenSSH Server" -BackgroundColor Green
        wsl -u $username /bin/bash -c "echo $plainpassword | sudo -S apt install openssh-server -y && sudo -S service ssh start"

        ## Now install Ansible for the second stage of this deployment
        Write-Host "Installing Ansible" -BackgroundColor Green
        wsl -u $username /bin/bash -c "echo $plainpassword | sudo -S apt install ansible -y"
    }
    Install-WSLPackages

    function Set-AnsibleConfig {
        ## Import System.Web Assembly
        Add-Type -AssemblyName System.Web

        ## Now we are going to create a service account under which our Ansible Playbook can run
        ## First we are going to generate a random password for this account.
        $ansibleuser = "svc_ansible"
        $script:ansiblepassword = [System.Web.Security.Membership]::GeneratePassword(16, 4)
        $script:vaultpassword = [System.Web.Security.Membership]::GeneratePassword(16, 4)

        ## Now we create the user inside
        Write-Host "Creating Ansible Service Account" -BackgroundColor Green
        wsl -u root useradd -m "$ansibleuser"

        ## Set the password
        Write-Host "Setting password for $ansibleuser" -BackgroundColor Green
        wsl -u root /bin/bash -c "echo '${ansibleuser}:${ansiblepassword}' | chpasswd"

        ## Change login shell to bash
        Write-Host "Changing login shell to /bin/bash for $ansibleuser" -BackgroundColor Green
        wsl -u root chsh -s /bin/bash "$ansibleuser"

        ## Set the privileges
        Write-Host "Setting user permissions for $ansibleuser" -BackgroundColor Green
        wsl -u root usermod -aG adm, sudo "$ansibleuser"

        ## Create Ansible Vault password file
        Write-Host "Creating Ansible Vault password file" -BackgroundColor Green
        wsl -u $ansibleuser /bin/bash -c "cd ~/ && echo '$vaultpassword' > .vault_password.txt && chmod 600 .vault_password.txt"
        
        ## Create Ansible Vault encrypted variable file
        Write-Host "Creating Ansible Vault encrypted variable file" -BackgroundColor Green
        wsl -u $ansibleuser /bin/bash -c "cd ../group_vars/localhost && echo ansible_password: `"$ansiblepassword`" > vault && ansible-vault encrypt vault --vault-password-file=~/.vault_password.txt --encrypt-vault-id default"

        ## Update Ansible vars file for the configure_wsl role by setting the username variable
        Write-Host "Creating username vars file ..\roles\configure_wsl\vars\username.yaml" -BackgroundColor Green
        New-Item -Path "..\roles\configure_wsl\vars\username.yaml"
        Add-Content -Path "..\roles\configure_wsl\vars\username.yaml" -Value "username: $username"
        
        ## Copy the Ansible.cfg file to the svc_ansible's home directory
        Write-Host "Copy the ansible.cfg to the svc_ansible's home directory" -BackgroundColor Green
        wsl -u $ansibleuser /bin/bash -c "cp ../ansible_config/ansible.cfg ~/ansible.cfg && chown '${ansibleuser}:${ansibleuser}' ~/ansible.cfg && chmod 0644 ~/ansible.cfg"

    }
    Set-AnsibleConfig
}
Install-WSL