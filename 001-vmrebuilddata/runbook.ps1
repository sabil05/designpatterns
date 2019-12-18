[OutputType("PSAzureOperationResponse")]
param
(
    [Parameter (Mandatory=$false)]
    [object] $WebhookData
)
$ErrorActionPreference = "stop"

if ($WebhookData)
{
    # Get the data object from WebhookData
    $WebhookBody = (ConvertFrom-Json -InputObject $WebhookData.RequestBody)

    # Get the info needed to identify the VM (depends on the payload schema)
    $schemaId = $WebhookBody.schemaId
    Write-Verbose "schemaId: $schemaId" -Verbose
    if ($schemaId -eq "azureMonitorCommonAlertSchema") {
        # This is the common Metric Alert schema (released March 2019)
        $Essentials = [object] ($WebhookBody.data).essentials
        $AlertContext = [object] ($WebhookBody.data).alertContext
        # Get the first target only as this script doesn't handle multiple
        $alertTargetIdArray = (($Essentials.alertTargetIds)[0]).Split("/")
        $SubId = ($alertTargetIdArray)[2]
        $ResourceGroupName = ($alertTargetIdArray)[4]
        $ResourceType = ($alertTargetIdArray)[6] + "/" + ($alertTargetIdArray)[7]
        $ResourceName = ($alertTargetIdArray)[-1]
        $status = $Essentials.monitorCondition
        $alertRule = $Essentials.alertRule
        $alertCI = (($alertRule).Split("-"))[-1]
        #Write-Verbose "Configuration Item: $alertCIs" -Verbose
        Write-Verbose "Configuration Item: $alertCI" -Verbose
        $alertCI
    }
    elseif ($schemaId -eq "AzureMonitorMetricAlert") {
        # This is the near-real-time Metric Alert schema
        $AlertContext = [object] ($WebhookBody.data).context
        $SubId = $AlertContext.subscriptionId
        $ResourceGroupName = $AlertContext.resourceGroupName
        $ResourceType = $AlertContext.resourceType
        $ResourceName = $AlertContext.resourceName
        $status = ($WebhookBody.data).status
    }
    elseif ($schemaId -eq "Microsoft.Insights/activityLogs") {
        # This is the Activity Log Alert schema
        $AlertContext = [object] (($WebhookBody.data).context).activityLog
        $SubId = $AlertContext.subscriptionId
        $ResourceGroupName = $AlertContext.resourceGroupName
        $ResourceType = $AlertContext.resourceType
        $ResourceName = (($AlertContext.resourceId).Split("/"))[-1]
        $status = ($WebhookBody.data).status
    }
    elseif ($schemaId -eq $null) {
        # This is the original Metric Alert schema
        $AlertContext = [object] $WebhookBody.context
        $SubId = $AlertContext.subscriptionId
        $ResourceGroupName = $AlertContext.resourceGroupName
        $ResourceType = $AlertContext.resourceType
        $ResourceName = $AlertContext.resourceName
        $status = $WebhookBody.status
    }
    else {
        # Schema not supported
        Write-Error "The alert data schema - $schemaId - is not supported."
    }

    Write-Verbose "status: $status" -Verbose
    if (($status -eq "Activated") -or ($status -eq "Fired"))
    {
        Write-Verbose "resourceType: $ResourceType" -Verbose
        Write-Verbose "resourceName: $ResourceName" -Verbose
        Write-Verbose "resourceGroupName: $ResourceGroupName" -Verbose
        Write-Verbose "subscriptionId: $SubId" -Verbose

        # Determine code path depending on the resourceType
        if ($ResourceType -eq "microsoft.operationalinsights/workspaces")
        {
            Write-Verbose "This is log search query-based alert parsing..." -Verbose

            # Authenticate to Azure with service principal and certificate and set subscription
            Write-Verbose "Authenticating to Azure with service principal and certificate" -Verbose
            $ConnectionAssetName = "AzureRunAsConnection"
            Write-Verbose "Get connection asset: $ConnectionAssetName" -Verbose
            $Conn = Get-AutomationConnection -Name $ConnectionAssetName
            if ($Conn -eq $null)
            {
                throw "Could not retrieve connection asset: $ConnectionAssetName. Check that this asset exists in the Automation account."
            }
            Write-Verbose "Authenticating to Azure with service principal." -Verbose
            Add-AzureRMAccount -ServicePrincipal -Tenant $Conn.TenantID -ApplicationId $Conn.ApplicationID -CertificateThumbprint $Conn.CertificateThumbprint | Write-Verbose
            Write-Verbose "Setting subscription to work against: $SubId" -Verbose
            Set-AzureRmContext -SubscriptionId $SubId -ErrorAction Stop | Write-Verbose

            # Find out VM name from Affected Configuration Items array
            #Stop-AzureRmVM -Name $ResourceName -ResourceGroupName $ResourceGroupName -Force
            #Start-AzureRmVM -Name $ResourceName -ResourceGroupName $ResourceGroupName
            if (!($alertCI -eq $null)) {
                #disable alert rule to avoid false positives
                Write-Verbose "Disanling Alert Rule = $alertRule" -Verbose
                $context = Get-AzureRmContext
		$SubscriptionId = $context.Subscription
		$cache = $context.TokenCache
		$cacheItem = $cache.ReadItems()
		$AccessToken=$cacheItem[$cacheItem.Count -1].AccessToken
		$headerParams = @{'Authorization'="Bearer $AccessToken"}
		$url="https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.insights/scheduledQueryRules/$alertRule"+"?api-version=2018-04-16"
		$rBody = @{
			'properties' = @{
				'enabled' = 'false'
			}
		}
		$json = $rBody | ConvertTo-Json
		$results=Invoke-RestMethod -Uri $url -Headers $headerParams -Method Patch -Body $json -ContentType 'application/json'
		$results
                #get old VM config
                Write-Verbose "Getting the VM = $alertCI" -Verbose
                $oldvm = Get-AzureRmVm -Name $alertCI -ResourceGroupName $ResourceGroupName
                $oldvm
                Write-Verbose "Deleting old VM ($oldvm.Name)" -Verbose
                Remove-AzureRmVM -Name $oldvm.Name -ResourceGroupName $ResourceGroupName -Force
                $osDisk = Get-AzureRmDisk -DiskName $oldvm.StorageProfile.OsDisk.Name -ResourceGroupName $oldvm.ResourceGroupName
                $osDisk
                $vmConfig = New-AzureRmVMConfig -VMName $oldvm.Name -VMSize $oldvm.HardwareProfile.VmSize
                $vmConfig
                $vm = Add-AzureRmVMNetworkInterface -VM $vmConfig -Id $oldvm.NetworkProfile.NetworkInterfaces.Id
                $vm
                $vm = Set-AzureRmVMOSDisk -VM $vm -ManagedDiskId $osDisk.Id -CreateOption Attach -Linux
                $vm
		Foreach ($datadisk in $oldvm.StorageProfile.DataDisks) {
		   $vm = Add-AzureRmVMDataDisk -VM $vm -CreateOption Attach -Lun $datadisk.Lun -ManagedDiskId $datadisk.Id
		}
                New-AzureRmVM -VM $vm -ResourceGroupName $oldvm.ResourceGroupName -Location $oldvm.Location
            } elseif (!((Get-AzureRmVm -Name "RebuildableVM01" -ResourceGroupName "RG-WE-RebuildableVMs") -eq $null )) {
                # test use only
                Write-Verbose "Taking default VM = RebuidableVM01test" -Verbose
                $oldvm = Get-AzureRmVm -Name "RebuildableVM01test" -ResourceGroupName "RG-WE-RebuildableVMs"
                $oldvm
                Write-Verbose "Deleting old VM ($oldvm.Name)" -Verbose
                Remove-AzureRmVM -Name $oldvm.Name -ResourceGroupName "RG-WE-RebuildableVMs" -Force
            } else {
                Write-Error "NO VM TO REBUILD"
            }
            #$azureLocation              = $vm.Location
            #$azureResourceGroup         = $vm.ResourceGroupName
            #$azureVmName                = $vm.Name
            #$azureVmOsDiskName          = $vm.StorageProfile.OsDisk.Name
            #$azureVmSize                = $vm.HardwareProfile.VmSize

        }
        elseif ($ResourceType -eq "Microsoft.Compute/virtualMachines")
        {
            # This is an Resource Manager VM
            Write-Verbose "This is an Resource Manager VM." -Verbose
            #future use
        }
        else {
            # ResourceType not supported
            Write-Error "$ResourceType is not a supported resource type for this runbook."
        }
    }
    else {
        # The alert status was not 'Activated' or 'Fired' so no action taken
        Write-Verbose ("No action taken. Alert status: " + $status) -Verbose
    }
}
else {
    # Error
    Write-Error "This runbook is meant to be started from an Azure alert webhook only."
}
