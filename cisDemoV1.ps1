#installing DSC modules

Install-Module -Name SecurityPolicyDsc
Install-Module -Name ComputerManagementDsc
Install-Module -Name  AuditPolicyDsc

$fpath = "c:\buildActions"
$dscfileuri = "https://raw.githubusercontent.com/urc1712/azureimage/main/DemoImageConfv1.ps1"

Write-Host  "Azure-Image-Builder-Was-Here" | Out-File $fpath\buildActionsOutput.txt


New-Item -Path $fpath -ItemType Directory

Invoke-WebRequest $dscuri -OutFile $fpath\DemoImageConfv1.ps1

cd $fpath 

Powershell.exe -File $fpath\DemoImageConfv1.ps1

Start-DscConfiguration -Path $fpath\DemoImageConfv1


