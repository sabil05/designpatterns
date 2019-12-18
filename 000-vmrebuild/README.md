# Design pattern for heartbeat-based VM rebuild with same OS boot volume

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fzhjuve%2Fdesignpatterns%2Fmaster%2F000-vmrebuild%2Fazuredeploy.json" target="_blank"><img src="https://raw.githubusercontent.com/zhjuve/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.png"/></a>

Deploy or use existing Log Analytics workspace, deploy a Linux VM within a new or existing Virtual Network (dynamically assigned IP address), Storage and connect VM to workspace, then create an action group and alert rule to initiate a created runbook when heartbeats are lost for VM
