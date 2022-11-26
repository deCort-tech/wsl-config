## First we need to make sure the WSL feature is installed, if not install and reboot afterwards 
if($null -eq (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux)){
    ## Enable WSL Feature
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
    Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
    ## Create temp directory if it does not exist
    $tmp = "C:\temp"
    if($null -eq (Test-Path $tmp)){
        New-Item $tmp
    }else{}
    ## Copy the script to the temp directory
    Copy-Item -Path ".\install-wsl.ps1" -Destination $tmp 

    ## Create a run once registry key in order for this script to be able to continue after reboot
    Set-Location HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce
    New-Itemproperty . InstallWSL -propertytype String -value "Powershell $tmp\install-wsl.ps1"
    ## Wait a bit and reboot the machine, continue on 
    Restart-Computer -Wait 1
}

## Then we bootstrap the host and install WSL and Ansible
## We can check if the correct distro is already installed, if not we run the install command
$wsl = wsl -l | Where-Object {$_.Replace("`0","") -match '22.04'}
$distro = Ubuntu-20.04

$username = "roelc" # Change this (update to commandline switch)


## If WSL is not installed we install it
if($null -eq $wsl){
    ## Install the distro as root so we can create a user
    wsl --install --d $distro --root
    ## Set WSL2 as default
    wsl --set-default-version 2
    ## Set our ubuntu 20.04 image as default
    wsl --setdefault Ubuntu-20.04
    ## Add new user
    wsl -u root -d $distro useradd -m "$username"
    ## Set the password
    wsl -u root -d $distro sh -c "echo "${username}:${password}" | chpasswd"
    ## Change login shell to bash
    wsl -u root -d $distro chsh -s /bin/bash "$username"
    ## Set the privileges
    wsl -u root -d $distro usermod -aG adm,cdrom,sudo,dip,plugdev "$username"
}

## Set WSL2 as default and set the Ubuntu-20.04 distro as default (if this is not yet the case already)
wsl --set-default-version 2
wsl --setdefault Ubuntu-20.04


$decodedpassword = ConvertFrom-SecureString -SecureString $password -AsPlainText
wsl -u $username "echo ($password | sudo apt update -y"
wsl -u $username echo $password | sudo apt upgrade -y









