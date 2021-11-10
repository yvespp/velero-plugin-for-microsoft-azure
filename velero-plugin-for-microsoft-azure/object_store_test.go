/*
Copyright 2018, 2019 the Velero contributors.

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
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestObjectExists(t *testing.T) {
	tests := []struct {
		name           string
		getBlobError   error
		exists         bool
		errorResponse  error
		expectedExists bool
		expectedError  string
	}{
		{
			name:           "getBlob error",
			exists:         false,
			errorResponse:  errors.New("getBlob"),
			expectedExists: false,
			expectedError:  "getBlob",
		},
		{
			name:           "exists",
			exists:         true,
			errorResponse:  nil,
			expectedExists: true,
		},
		{
			name:           "doesn't exist",
			exists:         false,
			errorResponse:  nil,
			expectedExists: false,
		},
		{
			name:           "error checking for existence",
			exists:         false,
			errorResponse:  errors.New("bad"),
			expectedExists: false,
			expectedError:  "bad",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blobGetter := new(mockBlobGetter)
			defer blobGetter.AssertExpectations(t)

			o := &ObjectStore{
				blobGetter: blobGetter,
			}

			bucket := "b"
			key := "k"

			blob := new(mockBlob)
			defer blob.AssertExpectations(t)
			blobGetter.On("getBlob", bucket, key).Return(blob, tc.getBlobError)

			blob.On("Exists").Return(tc.exists, tc.errorResponse)

			exists, err := o.ObjectExists(bucket, key)

			if tc.expectedError != "" {
				assert.EqualError(t, err, tc.expectedError)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tc.expectedExists, exists)
		})
	}
}

type mockBlobGetter struct {
	mock.Mock
}

func (m *mockBlobGetter) getBlob(bucket string, key string) (blob, error) {
	args := m.Called(bucket, key)
	return args.Get(0).(blob), args.Error(1)
}

type mockBlob struct {
	mock.Mock
}

func (m *mockBlob) PutBlock(blockID string, chunk []byte, options *azblob.StageBlockOptions) (azblob.BlockBlobStageBlockResponse, error) {
	args := m.Called(blockID, chunk, options)
	return args.Get(0).(azblob.BlockBlobStageBlockResponse), args.Error(1)
}
func (m *mockBlob) PutBlockList(blocks []string, options *azblob.CommitBlockListOptions) (azblob.BlockBlobCommitBlockListResponse, error) {
	args := m.Called(blocks, options)
	return args.Get(0).(azblob.BlockBlobCommitBlockListResponse), args.Error(1)
}

func (m *mockBlob) Exists() (bool, error) {
	args := m.Called()
	return args.Bool(0), args.Error(1)
}

func (m *mockBlob) Get(options *azblob.DownloadBlobOptions) (*azblob.DownloadResponse, error) {
	args := m.Called(options)
	return args.Get(0).(*azblob.DownloadResponse), args.Error(1)
}

func (m *mockBlob) Delete(options *azblob.DeleteBlobOptions) (azblob.BlobDeleteResponse, error) {
	args := m.Called(options)
	return args.Get(0).(azblob.BlobDeleteResponse), args.Error(1)
}

func (m *mockBlob) GetSASURI(storageEndpointSuffix, storageAccount string, ttl time.Duration, useDelegationSAS bool) (string, error) {
	args := m.Called(storageEndpointSuffix, storageAccount, ttl, useDelegationSAS)
	return args.String(0), args.Error(1)
}

type mockContainerGetter struct {
	mock.Mock
}

func (m *mockContainerGetter) getContainer(bucket string) (container, error) {
	args := m.Called(bucket)
	return args.Get(0).(container), args.Error(1)
}

type mockContainer struct {
	mock.Mock
}

func (m *mockContainer) ListBlobs(params *azblob.ContainerListBlobFlatSegmentOptions) *azblob.ContainerListBlobFlatSegmentPager {
	args := m.Called(params)
	return args.Get(0).(*azblob.ContainerListBlobFlatSegmentPager)
}

func (m *mockContainer) ListBlobsHierarchy(delimiter string, listOptions *azblob.ContainerListBlobHierarchySegmentOptions) *azblob.ContainerListBlobHierarchySegmentPager {
	args := m.Called(delimiter, listOptions)
	return args.Get(0).(*azblob.ContainerListBlobHierarchySegmentPager)
}
