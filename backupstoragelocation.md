# Backup Storage Location

The following sample Azure `BackupStorageLocation` YAML shows all of the configurable parameters. The items under `spec.config` can be provided as key-value pairs to the `velero install` command's `--backup-location-config` flag -- for example, `storageAccount=my-sa,...`.

```yaml
apiVersion: velero.io/v1
kind: BackupStorageLocation
metadata:
  name: default
  namespace: velero
spec:
  # Name of the object store plugin to use to connect to this location.
  #
  # Required.
  provider: velero.io/azure

  objectStorage:
    # The bucket/blob container in which to store backups.
    #
    # Required.
    bucket: my-bucket

    # The prefix within the bucket under which to store backups.
    #
    # Optional.
    prefix: my-prefix

  config:
    # Name of the storage account for this backup storage location.
    #
    # Required.
    storageAccount: my-backup-storage-account

    # Name of the environment variable in $AZURE_CREDENTIALS_FILE that contains storage account key for this backup storage location.
    #
    # Required if using a storage account access key to authenticate rather than a service principal.
    storageAccountKeyEnvVar: MY_BACKUP_STORAGE_ACCOUNT_KEY_ENV_VAR

    # The block size, in bytes, to use when uploading objects to Azure blob storage.
    # See https://docs.microsoft.com/en-us/rest/api/storageservices/understanding-block-blobs--append-blobs--and-page-blobs#about-block-blobs
    # for more information on block blobs.
    #
    # Optional (defaults to 104857600, i.e. 100MB).
    blockSizeInBytes: "104857600"

    # When service principal or managed identity is used the plugin has the option to access the blob storage directly without fetching a storage access key. This feature is enabled if resourceGroup or subscriptionId isn't set.
    # Requirements to enable direct access:
    # - subscriptionId and resourceGroup needs to be removed from backup-location-config.
    # - The identity accessing the storage account additionally needs the role "Storage Blob Data Contributor", else you will get this error in the velero log: `AuthorizationPermissionMismatch`.
    # Using direct access is recommended as it will be the default in a future release.

    # Name of the resource group containing the storage account for this backup storage location.
    #
    # Deprecated
    resourceGroup: my-backup-resource-group

    # ID of the subscription for this backup storage location.
    #
    # Deprecated
    subscriptionId: my-subscription
```
