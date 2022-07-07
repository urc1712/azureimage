#installing DSC modules

Install-Module -Name SecurityPolicyDsc
Install-Module -Name ComputerManagementDsc
Install-Module -Name  AuditPolicyDsc

$fpath = "c:\buildActions"
$dscfileuri = "https://urcstorage.blob.core.windows.net/imagebuilder/DemoImageConfv1.ps1?sp=r&st=2022-06-30T04:07:37Z&se=2022-06-30T12:07:37Z&spr=https&sv=2021-06-08&sr=b&sig=ek25nJ2s6s5lftOY%2Bl4kMMcm7iOKv68%2FrgxJSv5ueVU%3D"

Write-Host  "Azure-Image-Builder-Was-Here" | Out-File $fpath\buildActionsOutput.txt


New-Item -Path $fpath -ItemType Directory

Invoke-WebRequest $dscuri -OutFile $fpath\DemoImageConfv1.ps1

cd $fpath 

Powershell.exe -File $fpath\DemoImageConfv1.ps1

Start-DscConfiguration -Path $fpath\DemoImageConfv1


