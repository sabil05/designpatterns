# Design pattern for heartbeat-based VM rebuild with same OS boot volume

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fzhjuve%2Fazure-quickstart-templates%2Fmaster%2F201-vm-new-or-existing-conditions%2Fazuredeploy.json" target="_blank"><img src="https://raw.githubusercontent.com/zhjuve/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.png"/></a>

Deploy or use existing Log Analytics workspace, deploy a Linux VM within a new or exsiting Virtual Network, Storage and connect VM to workspace, then create an action group and alert rule to initiate a created runbook when heartbeats are lost for VM

`Tags: new, existing, resource, vm, condition, conditional`
