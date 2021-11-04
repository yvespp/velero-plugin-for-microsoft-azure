/*
Copyright the Velero contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azidentity "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	veleroplugin "github.com/vmware-tanzu/velero/pkg/plugin/framework"
)

const (
	storageAccountConfigKey          = "storageAccount"
	storageAccountKeyEnvVarConfigKey = "storageAccountKeyEnvVar"
	subscriptionIDConfigKey          = "subscriptionId"
	blockSizeConfigKey               = "blockSizeInBytes"

	// blocks must be less than/equal to 100MB in size
	// ref. https://docs.microsoft.com/en-us/rest/api/storageservices/put-block#uri-parameters
	defaultBlockSize = 100 * 1024 * 1024
)

type containerGetter interface {
	getContainer(bucket string) (container, error)
}

type azureContainerGetter struct {
	serviceClient *azblob.ServiceClient
}

func (cg *azureContainerGetter) getContainer(bucket string) (container, error) {
	containerClient := cg.serviceClient.NewContainerClient(bucket)

	return &azureContainer{
		containerClient: &containerClient,
	}, nil
}

type container interface {
	ListBlobs(params *azblob.ContainerListBlobFlatSegmentOptions) *azblob.ContainerListBlobFlatSegmentPager
}

type azureContainer struct {
	containerClient *azblob.ContainerClient
}

func (c *azureContainer) ListBlobs(params *azblob.ContainerListBlobFlatSegmentOptions) *azblob.ContainerListBlobFlatSegmentPager {
	return c.containerClient.ListBlobsFlat(params)
}

type blobGetter interface {
	getBlob(bucket, key string) (blob, error)
}

type azureBlobGetter struct {
	serviceClient *azblob.ServiceClient
}

func (bg *azureBlobGetter) getBlob(bucket, key string) (blob, error) {
	containerClient := bg.serviceClient.NewContainerClient(bucket)
	blobClient := containerClient.NewBlockBlobClient(key)
	return &azureBlob{
		blobClient: &blobClient,
	}, nil
}

type blob interface {
	PutBlock(blockID string, chunk []byte, options *azblob.StageBlockOptions) (azblob.BlockBlobStageBlockResponse, error)
	PutBlockList(blocks []string, options *azblob.CommitBlockListOptions) (azblob.BlockBlobCommitBlockListResponse, error)
	Exists() (bool, error)
	Get(options *azblob.DownloadBlobOptions) (*azblob.DownloadResponse, error)
	Delete(options *azblob.DeleteBlobOptions) (azblob.BlobDeleteResponse, error)
}

type azureBlob struct {
	blobClient *azblob.BlockBlobClient
}

type nopCloser struct {
	io.ReadSeeker
}

func (n nopCloser) Close() error {
	return nil
}

// NopCloser returns a ReadSeekCloser with a no-op close method wrapping the provided io.ReadSeeker.
func NopCloser(rs io.ReadSeeker) io.ReadSeekCloser {
	return nopCloser{rs}
}

func (b *azureBlob) PutBlock(blockID string, chunk []byte, options *azblob.StageBlockOptions) (azblob.BlockBlobStageBlockResponse, error) {
	return b.blobClient.StageBlock(context.TODO(), blockID, NopCloser(bytes.NewReader(chunk)), options)
}
func (b *azureBlob) PutBlockList(blocks []string, options *azblob.CommitBlockListOptions) (azblob.BlockBlobCommitBlockListResponse, error) {
	return b.blobClient.CommitBlockList(context.TODO(), blocks, options)
}

func (b *azureBlob) Exists() (bool, error) {
	response, err := b.blobClient.GetProperties(context.TODO(), nil)

	if response.RawResponse == nil {
		return false, err
	}
	if response.RawResponse.StatusCode == 200 {
		return true, nil
	}
	if response.RawResponse.StatusCode == 404 {
		return false, nil
	}

	return false, err
}

func (b *azureBlob) Get(options *azblob.DownloadBlobOptions) (*azblob.DownloadResponse, error) {
	return b.blobClient.Download(context.TODO(), options)
}

func (b *azureBlob) Delete(options *azblob.DeleteBlobOptions) (azblob.BlobDeleteResponse, error) {
	return b.blobClient.Delete(context.TODO(), options)
}

// func (b *azureBlob) GetSASURI(options *storage.BlobSASOptions) (string, error) {
// 	b.blobClient.GetSASToken()
// 	return b.blob.GetSASURI(*options)
// }

type ObjectStore struct {
	log             logrus.FieldLogger
	containerGetter containerGetter
	blobGetter      blobGetter
	blockSize       int
}

func newObjectStore(logger logrus.FieldLogger) *ObjectStore {
	return &ObjectStore{log: logger}
}

// getSubscriptionID gets the subscription ID from the 'config' map if it contains
// it, else from the AZURE_SUBSCRIPTION_ID environment variable.
func getSubscriptionID(config map[string]string) string {
	if subscriptionID := config[subscriptionIDConfigKey]; subscriptionID != "" {
		return subscriptionID
	}

	return os.Getenv(subscriptionIDEnvVar)
}

func getServiceClient(config map[string]string) (*azblob.ServiceClient, error) {
	var credential azcore.Credential

	credentialsFile, err := selectCredentialsFile(config)
	if err != nil {
		return nil, err
	}

	if err := loadCredentialsIntoEnv(credentialsFile); err != nil {
		return nil, err
	}

	// get Azure cloud from AZURE_CLOUD_NAME, if it exists. If the env var does not
	// exist, parseAzureEnvironment will return azure.PublicCloud.
	_, err = parseAzureEnvironment(os.Getenv(cloudNameEnvVar))
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse azure cloud name environment variable")
	}

	// get storage account key from env var whose name is in config[storageAccountKeyEnvVarConfigKey].
	// If the config does not exist, continue obtaining the storage key using API
	if secretKeyEnvVar := config[storageAccountKeyEnvVarConfigKey]; secretKeyEnvVar != "" {
		storageKey := os.Getenv(secretKeyEnvVar)
		if storageKey == "" {
			return nil, errors.Errorf("no storage account key found in env var %s", secretKeyEnvVar)
		}

		credential, err = azblob.NewSharedKeyCredential("accountName", storageKey)
		if err == nil {
			return nil, err
		}
	} else {
		// get authorizer from environment in the following order:
		// 1. client credentials (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
		// 2. client certificate (AZURE_CERTIFICATE_PATH, AZURE_CERTIFICATE_PASSWORD)
		// 3. username and password (AZURE_USERNAME, AZURE_PASSWORD)
		// 4. MSI (managed service identity)
		credential, err = azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, errors.Wrap(err, "error getting authorizer from environment")
		}
	}

	serviceClient, err := azblob.NewServiceClient("https://<myAccountName>.blob.core.windows.net/", credential, nil)
	if err != nil {
		return nil, err
	}
	//containerClient := serviceClient.NewContainerClient("velero")
	//blobClient := containerClient.NewBlobClient("velero")

	return &serviceClient, nil

}

func mapLookup(data map[string]string) func(string) string {
	return func(key string) string {
		return data[key]
	}
}

func (o *ObjectStore) Init(config map[string]string) error {
	if err := veleroplugin.ValidateObjectStoreConfigKeys(config,
		resourceGroupConfigKey,
		storageAccountConfigKey,
		subscriptionIDConfigKey,
		blockSizeConfigKey,
		storageAccountKeyEnvVarConfigKey,
		credentialsFileConfigKey,
	); err != nil {
		return err
	}

	serviceClient, err := getServiceClient(config)
	if err != nil {
		return err
	}

	if _, err := getRequiredValues(mapLookup(config), storageAccountConfigKey); err != nil {
		return errors.Wrap(err, "unable to get all required config values")
	}

	o.containerGetter = &azureContainerGetter{
		serviceClient: serviceClient,
	}
	o.blobGetter = &azureBlobGetter{
		serviceClient: serviceClient,
	}

	o.blockSize = getBlockSize(o.log, config)

	return nil
}

func getBlockSize(log logrus.FieldLogger, config map[string]string) int {
	val, ok := config[blockSizeConfigKey]
	if !ok {
		// no alternate block size specified in config, so return with the default
		return defaultBlockSize
	}

	blockSize, err := strconv.Atoi(val)
	if err != nil {
		log.WithError(err).Warnf("Error parsing config.blockSizeInBytes value %v, using default block size of %d", val, defaultBlockSize)
		return defaultBlockSize
	}

	if blockSize <= 0 || blockSize > defaultBlockSize {
		log.WithError(err).Warnf("Value provided for config.blockSizeInBytes (%d) is outside the allowed range of 1 to %d, using default block size of %d", blockSize, defaultBlockSize, defaultBlockSize)
		return defaultBlockSize
	}

	return blockSize
}

func (o *ObjectStore) PutObject(bucket, key string, body io.Reader) error {
	blob, err := o.blobGetter.getBlob(bucket, key)
	if err != nil {
		return err
	}

	// Azure requires a blob/object to be chunked if it's larger than 256MB. Since we
	// don't know ahead of time if the body is over this limit or not, and it would
	// require reading the entire object into memory to determine the size, we use the
	// chunking approach for all objects.

	var (
		block    = make([]byte, o.blockSize)
		blockIDs []string
	)

	for {
		n, err := body.Read(block)
		if n > 0 {
			// blockID needs to be the same length for all blocks, so use a fixed width.
			// ref. https://docs.microsoft.com/en-us/rest/api/storageservices/put-block#uri-parameters
			blockID := fmt.Sprintf("%08d", len(blockIDs))

			o.log.Debugf("Putting block (id=%s) of length %d", blockID, n)
			if _, putErr := blob.PutBlock(blockID, block[0:n], nil); putErr != nil {
				return errors.Wrapf(putErr, "error putting block %s", blockID)
			}

			blockIDs = append(blockIDs, blockID)
		}

		// got an io.EOF: we're done reading chunks from the body
		if err == io.EOF {
			break
		}
		// any other error: bubble it up
		if err != nil {
			return errors.Wrap(err, "error reading block from body")
		}
	}

	o.log.Debugf("Putting block list %v", blockIDs)
	if _, err := blob.PutBlockList(blockIDs, nil); err != nil {
		return errors.Wrap(err, "error putting block list")
	}

	return nil
}

func (o *ObjectStore) ObjectExists(bucket, key string) (bool, error) {
	blob, err := o.blobGetter.getBlob(bucket, key)
	if err != nil {
		return false, err
	}

	exists, err := blob.Exists()
	if err != nil {
		return false, errors.WithStack(err)
	}

	return exists, nil
}

func (o *ObjectStore) GetObject(bucket, key string) (io.ReadCloser, error) {
	blob, err := o.blobGetter.getBlob(bucket, key)
	if err != nil {
		return nil, err
	}

	res, err := blob.Get(nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return res.Body(azblob.RetryReaderOptions{}), nil
}

func (o *ObjectStore) ListCommonPrefixes(bucket, prefix, delimiter string) ([]string, error) {
	// container, err := o.containerGetter.getContainer(bucket)
	// if err != nil {
	// 	return nil, err
	// }

	// params := azblob.ContainerListBlobFlatSegmentOptions{
	// 	Prefix: &prefix,
	// 			Delimiter: delimiter,
	// }

	// var prefixes []string
	// for {
	// 	res := container.ListBlobs(&params)
	// 	if err != nil {
	// 		return nil, errors.WithStack(err)
	// 	}
	// 	prefixes = append(prefixes, res.BlobPrefixes...)
	// 	if res.NextMarker == "" {
	// 		break
	// 	}
	// 	params.Marker = res.NextMarker
	// }

	return nil, nil
}

func (o *ObjectStore) ListObjects(bucket, prefix string) ([]string, error) {
	container, err := o.containerGetter.getContainer(bucket)
	if err != nil {
		return nil, err
	}

	params := azblob.ContainerListBlobFlatSegmentOptions{
		Prefix: &prefix,
	}

	var objects []string
	res := container.ListBlobs(&params)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	for {
		for _, blob := range res.PageResponse().Segment.BlobItems {
			objects = append(objects, *blob.Name)
		}
		if !res.NextPage(context.TODO()) {
			break
		}
	}

	return objects, nil
}

func (o *ObjectStore) DeleteObject(bucket string, key string) error {
	blob, err := o.blobGetter.getBlob(bucket, key)
	if err != nil {
		return err
	}

	_, err = blob.Delete(nil)
	return errors.WithStack(err)
}
