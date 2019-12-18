# Design pattern for heartbeat-based VM rebuild with same OS boot volume and data disks

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fzhjuve%2Fdesignpatterns%2Fmaster%2F001-vmrebuilddata%2Fazuredeploy.json" target="_blank"><img src="https://raw.githubusercontent.com/azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.png"/></a>

Deploy or use existing Log Analytics workspace, deploy a Linux VM within a new or existing Virtual Network (static IP), Storage and connect VM to workspace, then create an action group and alert rule to initiate a created runbook when heartbeats are lost for VM. VM gets rebuilt with same NIC and all disks (OS + data) which were present on malfunctioning VM.

