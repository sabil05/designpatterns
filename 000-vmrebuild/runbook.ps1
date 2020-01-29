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
    #$schemaId
    Write-Verbose "schemaId: $schemaId" -Verbose
    if ($schemaId -eq "azureMonitorCommonAlertSchema") {
        # This is the common Metric Alert schema (released March 2019)
        $Essentials = [object] ($WebhookBody.data).essentials
        #$Essentials
        $AlertContext = [object] ($WebhookBody.data).alertContext
        #$AlertContext
        $alertQuery = $AlertContext.SearchQuery
        #$alertQuery
        # Get the first target only as this script doesn't handle multiple
        $alertTargetIdArray = (($Essentials.alertTargetIds)[0]).Split("/")
        $ResourceType = ($alertTargetIdArray)[6] + "/" + ($alertTargetIdArray)[7]
        #$ResourceType
        $status = $Essentials.monitorCondition
        #$status
        #$alertTargetIdArray
        $SubId = ($alertTargetIdArray)[2]
        #$SubId
        #$ResourceGroupName = ($alertTargetIdArray)[4]
        $ResourceGroupName = (($alertQuery).Split("//"))[2]
        Write-Output "RG = $ResourceGroupName"
        $AzureAlertCIUUID = (($alertQuery).Split("//"))[4]
        $OSAlertCIUUID = (($alertQuery).Split("//"))[-1]
        Write-Output "Azure VM BIOS GUID = $AzureAlertCIUUID"
        Write-Output "OS VM BIOS GUID    = $OSAlertCIUUID"
        $alertRule = $Essentials.alertRule
        #$alertCI = (($alertRule).Split("-"))[-1]
        #Write-Verbose "Configuration Item: $alertCIs" -Verbose
        #Write-Verbose "Configuration Item: $alertCI" -Verbose
        #$alertCI
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
            #if (!($alertCI -eq $null)) {
            if (!($AzureAlertCIUUID -eq $null)) {
                #disable alert rule to avoid false positives
                #Write-Verbose "Disanling Alert Rule = $alertRule" -Verbose
                #$context = Get-AzureRmContext
                #$SubscriptionId = $context.Subscription
				#$cache = $context.TokenCache
				#$cacheItem = $cache.ReadItems()
				#$AccessToken=$cacheItem[$cacheItem.Count -1].AccessToken
				#$headerParams = @{'Authorization'="Bearer $AccessToken"}
				#$url="https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.insights/scheduledQueryRules/$alertRule"+"?api-version=2018-04-16"
				#$rBody = @{
				#	'properties' = @{
				#		'enabled' = 'false'
				#	}
				#}
				#$json = $rBody | ConvertTo-Json
				#$results=Invoke-RestMethod -Uri $url -Headers $headerParams -Method Patch -Body $json -ContentType 'application/json'
				#$results

                #check VM activity logs for write actions (meaning that VM has been e.g. rebuilt)
                $oldVm = Get-AzureRmVm -ResourceGroupName $ResourceGroupName | where-object {$_.VmId -eq $AzureAlertCIUUID}
                Write-Output "Old VM config captured:"
                Write-Output "<<<<<<<<<<<<<<<<<<<<<<START OLD VM>>>>>>>>>>>>>>>>>>>>>>"
                $oldvm
                Write-Output "<<<<<<<<<<<<<<<<<<<<<<END OF OLD VM>>>>>>>>>>>>>>>>>>>>>"
                $vmlog = Get-AzureRmLog -ResourceGroupName $ResourceGroupName -starttime (get-date).addminutes(-10) | where-object {($_.Authorization.Action -eq "microsoft.compute/virtualmachines/write") -and (($_.ResourceId).Split("/")[-1] -eq $oldVm.Name)}
                $logcount = $vmlog.Count
                Write-Output "Write events in Activity Log Count = $logcount"
                if ($vmlog.Count -eq 0) {
                    Write-Output "<<<<<<<<<<<<<<<<<<<<<<DELETING VM:"
                    Remove-AzureRmVM -Name $oldvm.Name -ResourceGroupName $ResourceGroupName -Force
                    Write-Output "||VM DELETED! >>>>>>>>>>>>>>>>>>>>>"
                    $osDisk = Get-AzureRmDisk -DiskName $oldvm.StorageProfile.OsDisk.Name -ResourceGroupName $oldvm.ResourceGroupName
                    #$osDisk
                    $vmConfig = New-AzureRmVMConfig -VMName $oldvm.Name -VMSize $oldvm.HardwareProfile.VmSize
                    #$vmConfig
                    $vm = Add-AzureRmVMNetworkInterface -VM $vmConfig -Id $oldvm.NetworkProfile.NetworkInterfaces.Id
                    #$vm
                    $vm = Set-AzureRmVMOSDisk -VM $vm -ManagedDiskId $osDisk.Id -CreateOption Attach -Linux
                    #$vm
                    $tags = $oldvm.Tags
                    Write-Output "<<<<<<<<<<<<<<<<<<<<<<VM TAGS>>>>>>>>>>>>>>>>>>>>>>"
                    $tags
                    Write-Output "<<<<<<<<<<<<<<<<<<<<<<END TAGS>>>>>>>>>>>>>>>>>>>>>"
                    Write-Output "<<<<<<<<<<<<<<<<<<<<<<RE-CREATING VM:"
                    New-AzureRmVM -VM $vm -ResourceGroupName $oldvm.ResourceGroupName -Location $oldvm.Location -Tag $tags
                    Write-Output "///////// VM CREATION FINISHED >>>>>>>>>>>>>>>>>>>>>"
                    #Alert Rule need to be updated because VM has been rebuilt
                    Write-Output "///////// Alert Rule Update START >>>>>>>>>>>>>>>>>>>>>"
                    $context = Get-AzureRmContext
                    $SubscriptionId = $context.Subscription
			        $cache = $context.TokenCache
			        $cacheItem = $cache.ReadItems()
			        $AccessToken=$cacheItem[$cacheItem.Count -1].AccessToken
			        $headerParams = @{'Authorization'="Bearer $AccessToken"}
			        $url="https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.insights/scheduledQueryRules/$alertRule"+"?api-version=2018-04-16"
			        $results=Invoke-RestMethod -Uri $url -Headers $headerParams -Method Get -ContentType 'application/json'
                    write-output "Old alert: /////////////////////"
                    $results
                    $oldq = $results.properties.source.query
			        write-output "Old Query: $oldq"
                    $recreatedVm = Get-AzureRmVm -ResourceGroupName $oldvm.ResourceGroupName | where-object {$_.Name -eq $oldVm.Name}
                    $newalertCIUUID = $recreatedVm.VmId
			        write-output "New VM ID: $newalertCIUUID"
                    $olds = $AzureAlertCIUUID+"//"+$OSAlertCIUUID
			        write-output "Old end: $old"
                    $news = $newalertCIUUID+"//"+$OSAlertCIUUID
			        write-output "New end: $new"
                    $newq = $oldq -replace $old,$new
                    write-output "New Query: $newq"
                    $results.properties.source.query = $newq
                    $results.PSObject.Properties.Remove('id')
                    $results.PSObject.Properties.Remove('name')
                    $results.PSObject.Properties.Remove('type')
                    $results.PSObject.Properties.Remove('kind')
                    $results.PSObject.Properties.Remove('etag')
                    write-output "New alert req body: /////////////////////"
			        $json = $results | ConvertTo-Json -Depth 5
                    $json
                    write-output "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
   			        $updates=Invoke-RestMethod -Uri $url -Headers $headerParams -Method Put -Body $json -ContentType 'application/json'
                    write-output "New alert results: /////////////////////"
                    $updates                   
                }
            } elseif (!((Get-AzureRmVm -Name "RebuildableVM01test" -ResourceGroupName "RG-WE-RebuildableVMstest") -eq $null )) {
                # test use only
                Write-Verbose "Taking default VM = RebuidableVM01test" -Verbose
                $oldvm = Get-AzureRmVm -Name "RebuildableVM01test" -ResourceGroupName "RG-WE-RebuildableVMstest"
                $oldvm
                Write-Verbose "Deleting old VM ($oldvm.Name)" -Verbose
                Remove-AzureRmVM -Name $oldvm.Name -ResourceGroupName "RG-WE-RebuildableVMs" -Force
            } else {
                Write-Error "NO VM TO REBUILD"
            }
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
