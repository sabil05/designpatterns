[OutputType("PSAzureOperationResponse")]
param
(
    [Parameter (Mandatory = $false)]
    [object] $WebhookData
)
$ErrorActionPreference = "stop"

if ($WebhookData) {
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
        $ResourceGroupName = (($alertQuery).Split('//'))[2]
        Write-Output "RG = $ResourceGroupName"
        $AzureAlertCIUUID = (($alertQuery).Split('//'))[4]
        $OSAlertCIUUID = (($alertQuery).Split('//'))[6]
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
    if (($status -eq "Activated") -or ($status -eq "Fired")) {
        Write-Verbose "resourceType: $ResourceType" -Verbose
        Write-Verbose "resourceName: $ResourceName" -Verbose
        Write-Verbose "resourceGroupName: $ResourceGroupName" -Verbose
        Write-Verbose "subscriptionId: $SubId" -Verbose

        # Determine code path depending on the resourceType
        if ($ResourceType -eq "microsoft.operationalinsights/workspaces") {
            Write-Verbose "This is log search query-based alert parsing..." -Verbose

            # Authenticate to Azure with service principal and certificate and set subscription
            Write-Verbose "Authenticating to Azure with service principal and certificate" -Verbose
            $ConnectionAssetName = "AzureRunAsConnection"
            Write-Verbose "Get connection asset: $ConnectionAssetName" -Verbose
            $Conn = Get-AutomationConnection -Name $ConnectionAssetName
            if ($Conn -eq $null) {
                throw "Could not retrieve connection asset: $ConnectionAssetName. Check that this asset exists in the Automation account."
            }
            Write-Verbose "Authenticating to Azure with service principal." -Verbose
            Add-AzureRMAccount -ServicePrincipal -Tenant $Conn.TenantID -ApplicationId $Conn.ApplicationID -CertificateThumbprint $Conn.CertificateThumbprint | Write-Verbose
            Write-Verbose "Setting subscription to work against: $SubId" -Verbose
            Set-AzureRmContext -SubscriptionId $SubId -ErrorAction Stop | Write-Verbose

            if (!($AzureAlertCIUUID -eq $null)) {
                #disable alert rule to avoid false positives
                Write-Verbose "Disanling Alert Rule for runbook execution time = $alertRule" -Verbose
                $context = Get-AzureRmContext
                $SubscriptionId = $context.Subscription
                $cache = $context.TokenCache
                $cacheItem = $cache.ReadItems()
                $AccessToken = $cacheItem[$cacheItem.Count - 1].AccessToken
                $headerParams = @{'Authorization' = "Bearer $AccessToken" }
                $durl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.insights/scheduledQueryRules/$alertRule" + "?api-version=2018-04-16"
                $drBody = @{
                    'properties' = @{
                        'enabled' = 'false'
                    }
                }
                $djson = $drBody | ConvertTo-Json
                try {
                    $dresults = Invoke-RestMethod -Uri $durl -Headers $headerParams -Method Patch -Body $djson -ContentType 'application/json'
                    Write-Output "Res length =" $dresults.length
                    #$results
                }
                catch {
                    Write-Output "Rule disable failed. It is not critical. Retrying 2 times..."
                    for ($i = 1; $i -le 2; $i++) {
                        Start-Sleep -s 2
                        $dresults = Invoke-RestMethod -Uri $durl -Headers $headerParams -Method Patch -Body $djson -ContentType 'application/json'
                        Write-Output "Res length =" $dresults.length
                        if (!($dresults.length -eq 0)) {
                            Break
                        }
                    }
                }

                #check VM activity logs for write actions (meaning that VM has been e.g. rebuilt)
                $oldVm = Get-AzureRmVm -ResourceGroupName $ResourceGroupName | where-object { $_.VmId -eq $AzureAlertCIUUID }
                Write-Output "Old VM config captured:"
                Write-Output "<<<<<<<<<<<<<<<<<<<<<<START OLD VM>>>>>>>>>>>>>>>>>>>>>>"
                $oldvm
                Write-Output "<<<<<<<<<<<<<<<<<<<<<<END OF OLD VM>>>>>>>>>>>>>>>>>>>>>"
                $vmlog = Get-AzureRmLog -ResourceGroupName $ResourceGroupName -starttime (get-date).addminutes(-15) | where-object { ($_.Authorization.Action -eq "microsoft.compute/virtualmachines/write") -and (($_.ResourceId).Split("/")[-1] -eq $oldVm.Name) }
                $logcount = $vmlog.Count
                Write-Output "Write events in Activity Log Count = $logcount"
                #If write count is 0 then proceeed with VM rebuild
                if ($vmlog.Count -eq 0) {
                    Write-Output "<<<<<<<<<<<<<<<<<<<<<<DELETING VM:"
                    Remove-AzureRmVM -Name $oldvm.Name -ResourceGroupName $ResourceGroupName -Force
                    Write-Output "||VM DELETED! >>>>>>>>>>>>>>>>>>>>>"
                    $osDisk = Get-AzureRmDisk -DiskName $oldvm.StorageProfile.OsDisk.Name -ResourceGroupName $oldvm.ResourceGroupName
                    $vmConfig = New-AzureRmVMConfig -VMName $oldvm.Name -VMSize $oldvm.HardwareProfile.VmSize
                    $vm = Add-AzureRmVMNetworkInterface -VM $vmConfig -Id $oldvm.NetworkProfile.NetworkInterfaces.Id
                    $vm = Set-AzureRmVMOSDisk -VM $vm -ManagedDiskId $osDisk.Id -CreateOption Attach -Linux
                    $tags = $oldvm.Tags
                    Write-Output "<<<<<<<<<<<<<<<<<<<<<<VM TAGS>>>>>>>>>>>>>>>>>>>>>>"
                    $tags
                    Write-Output "<<<<<<<<<<<<<<<<<<<<<<END TAGS>>>>>>>>>>>>>>>>>>>>>"
                    Write-Output "<<<<<<<<<<<<<<<<<<<<<<RE-CREATING VM:"
                    New-AzureRmVM -VM $vm -ResourceGroupName $oldvm.ResourceGroupName -Location $oldvm.Location -Tag $tags
                    Write-Output "///////// VM CREATION FINISHED >>>>>>>>>>>>>>>>>>>>>"
                    #Alert Rule need to be updated because VM has been rebuilt
                    Write-Output "///////// Alert Rule Update START >>>>>>>>>>>>>>>>>>>>>"
                    $url = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.insights/scheduledQueryRules/$alertRule" + "?api-version=2018-04-16"
                    try {
                        $results = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Get -ContentType 'application/json'
                        Write-Output "Rule disable success. Proceeding..."
                    }
                    catch {
                        Write-Output "Rule GET failed. It is critical. Retrying 5 times..."
                        for ($i = 1; $i -le 5; $i++) {
                            Start-Sleep -s 2
                            $results = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Get -ContentType 'application/json'
                            if (!($results.length -eq 0)) {
                                Write-Output "Rule disable success. Proceeding..."
                                Break
                            }
                        }
                    }
                    write-output "Old alert: /////////////////////"
                    $results
                    $oldq = $results.properties.source.query
                    write-output "Old Query: $oldq"
                    $recreatedVm = Get-AzureRmVm -ResourceGroupName $oldvm.ResourceGroupName | where-object { $_.Name -eq $oldVm.Name }
                    $newalertCIUUID = $recreatedVm.VmId
                    write-output "New VM ID: $newalertCIUUID"
                    $olds = $AzureAlertCIUUID + "//" + $OSAlertCIUUID
                    $news = $newalertCIUUID + "//" + $OSAlertCIUUID
                    $newq = $oldq -replace $olds, $news
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
                    Write-Output "///////// Alert Rule Update END >>>>>>>>>>>>>>>>>>>>>"
                    write-output "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
                    try {
                        $updates = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Put -Body $json -ContentType 'application/json'
                        write-output "Success:" $updates
                    }
                    catch {
                        Write-Output "$_"
                        Write-Output "Rule update failed. It is critical. Retrying 5..."
                        for ($i = 1; $i -le 5; $i++) {
                            Start-Sleep -s 2
                            $updates = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Put -Body $json -ContentType 'application/json'
                            if (!($updates.length -eq 0)) {
                                Write-Output "Rule update success. Proceeding..."
                                Break
                            }
                        }
                    }
                    write-output "New alert results: /////////////////////"
                    $updates                   
                    Write-Verbose "Enabling Alert Rule back after runbook execution time = $alertRule" -Verbose
                    $eurl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.insights/scheduledQueryRules/$alertRule" + "?api-version=2018-04-16"
                    $erBody = @{
                        'properties' = @{
                            'enabled' = 'true'
                        }
                    }
                    $ejson = $erBody | ConvertTo-Json
                    try {
                        $eresults = Invoke-RestMethod -Uri $eurl -Headers $headerParams -Method Patch -Body $ejson -ContentType 'application/json'
                    }
                    catch {
                        Write-Output "Rule enablement failed. It is critical. Retrying 5 times..."
                        for ($i = 1; $i -le 5; $i++) {
                            Start-Sleep -s 2
                            $eresults = Invoke-RestMethod -Uri $eurl -Headers $headerParams -Method Patch -Body $ejson -ContentType 'application/json'
                            if (!($eresults.length -eq 0)) {
                                Write-Output "Rule enablement success. Proceeding..."
                                Break
                            }
                        }
                    }
                }
            }
            elseif (!((Get-AzureRmVm -Name "RebuildableVM01test" -ResourceGroupName "RG-WE-RebuildableVMstest") -eq $null )) {
                # test use only
                Write-Verbose "Taking default VM = RebuidableVM01test" -Verbose
                $oldvm = Get-AzureRmVm -Name "RebuildableVM01test" -ResourceGroupName "RG-WE-RebuildableVMstest"
                $oldvm
                Write-Verbose "Deleting old VM ($oldvm.Name)" -Verbose
                Remove-AzureRmVM -Name $oldvm.Name -ResourceGroupName "RG-WE-RebuildableVMs" -Force
            }
            else {
                Write-Error "NO VM TO REBUILD"
            }
        }
        elseif ($ResourceType -eq "Microsoft.Compute/virtualMachines") {
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
