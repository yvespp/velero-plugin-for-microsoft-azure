package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

type KeyInfo struct {
	Start  string
	Expiry string
}

type UserDelegationKey struct {
	SignedOid     string
	SignedTid     string
	SignedStart   string
	SignedExpiry  string
	SignedService string
	SignedVersion string
	Value         string
}

func main() {

	userDelegationKey, _ := getUserDelegationKey("aksvelerocrttestst", os.Getenv("TENANTID"))
	fmt.Println(userDelegationKey)
	CreateSignedURL("aksvelerocrttestst", "velero", "test", userDelegationKey, time.Hour*1)
}

func CreateSignedURL(account, container, blob string, key *UserDelegationKey, ttl time.Duration) (string, error) {
	sas := BlobDelegationSASSignatureValues{
		KeyObjectId:           key.SignedOid,
		KeyTenantId:           key.SignedTid,
		KeyStart:              key.SignedStart,
		KeyExpiry:             key.SignedExpiry,
		KeyService:            key.SignedService,
		KeyVersion:            key.SignedVersion,
		Protocol:              "https",
		Start:                 key.SignedStart,
		Expiry:                time.Now().UTC().Add(ttl).Format(time.RFC3339),
		Version:               "2020-12-06",
		Permissions:           "r",
		Resource:              "b",
		CanonicalizedResource: getCanonicalName(account, container, blob),
	}

	sig, err := ComputeHMACSHA256(sas.StringToSign(), []byte(key.Value))
	if err != nil {
		log.Fatal(err)
	}
	sas.Signature = sig
	url := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s?%s", account, container, blob, sas.ToURL())
	fmt.Println(url)
	fmt.Println(sas.StringToSign())

	return url, nil
}

func ComputeHMACSHA256(message string, key []byte) (string, error) {
	h := hmac.New(sha256.New, key)
	_, err := h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), err
}

// https://docs.microsoft.com/en-gb/rest/api/storageservices/get-user-delegation-key
func getUserDelegationKey(account, tenantID string) (*UserDelegationKey, error) {
	baseUrl := fmt.Sprintf("https://%s.blob.core.windows.net/", account)
	cred, _ := azidentity.NewDefaultAzureCredential(nil)
	token, _ := cred.GetToken(context.TODO(), policy.TokenRequestOptions{Scopes: []string{baseUrl}, TenantID: tenantID})

	keyInfo := KeyInfo{
		Start:  time.Now().UTC().Format(time.RFC3339),
		Expiry: time.Now().UTC().Add(time.Hour * 2).Format(time.RFC3339),
	}
	fmt.Println(keyInfo)
	client := &http.Client{}
	body, err := xml.Marshal(&keyInfo)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, baseUrl+"/?restype=service&comp=userdelegationkey", bytes.NewBuffer(body))
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Add("Authorization", "Bearer "+token.Token)
	req.Header.Add("x-ms-version", "2020-12-06")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Errored when sending request to the server")
		return nil, err
	}
	if resp.StatusCode != 200 {
		log.Fatal(resp.Status)
	}

	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	userDelegationKey := &UserDelegationKey{}

	xml.Unmarshal(responseBody, userDelegationKey)
	if err != nil {
		log.Fatal(err)
	}

	return userDelegationKey, nil
}

// For more information, see https://docs.microsoft.com/en-gb/rest/api/storageservices/create-user-delegation-sas
type BlobDelegationSASSignatureValues struct {
	Version                  string `param:"sv"` // Indicates the version of the service used to construct the signature field, and also specifies the service version that handles a request made with this shared access signature.
	Resource                 string `param:"sr"` // Specifies which blob resources are accessible via the shared access signature.
	CanonicalizedResource    string
	Start                    string `param:"st"`    // Not specified if IsZero. Optional. The time at which the shared access signature becomes valid, expressed in one of the accepted ISO 8601 UTC formats. If omitted, the current UTC time is used as the start time.
	Expiry                   string `param:"se"`    // The time at which the shared access signature becomes invalid, expressed in one of the accepted ISO 8601 UTC formats.
	Permissions              string `param:"sp"`    // Indicates which operations a client who possesses the SAS may perform on the resource. Permissions may be combined.
	IP                       string `param:"sip"`   // Specifies an IP address or an inclusive range of IP addresses from which to accept requests.
	Protocol                 string `param:"spr"`   // Specifies the protocol permitted for a request made with the SAS. Include this field to require that requests made with the SAS token use HTTPS.
	KeyObjectId              string `param:"skoid"` // Identifies an Azure AD security principal.
	KeyTenantId              string `param:"sktid"` // Specifies the Azure AD tenant in which a security principal is defined.
	KeyStart                 string `param:"skt"`   // Not specified if IsZero. Value is returned by the Get User Delegation Key operation. Indicates the start of the lifetime of the user delegation key, expressed in one of the accepted ISO 8601 UTC formats. If omitted, the current time is assumed.
	KeyExpiry                string `param:"ske"`   // Not specified if IsZero. Value is returned by the Get User Delegation Key operation. Indicates the end of the lifetime of the user delegation key, expressed in one of the accepted ISO 8601 UTC formats.
	KeyService               string `param:"sks"`   // Indicates the service for which the user delegation key is valid. Currently only the Blob service is supported.
	KeyVersion               string `param:"skv"`   // The Get User Delegation Key operation returns this value as part of the response. The signed key version field specifies the storage service version used to get the user delegation key. This field must specify version 2018-11-09 or later.
	AuthorizedUserObjectId   string `param:"saoid"` // Specifies the object ID for an Azure AD security principal that is authorized by the owner of the user delegation key to perform the action granted by the SAS token. No additional permission check on POSIX ACLs is performed.
	UnauthorizedUserObjectId string `param:"suoid"` // Specifies the object ID for an Azure AD security principal when a hierarchical namespace is enabled. Azure Storage performs a POSIX ACL check against the object ID before authorizing the operation.
	CorrelationId            string `param:"scid"`  // Correlate the storage audit logs with the audit logs used by the principal generating and distributing SAS.
	DirectoryDepth           string `param:"sdd"`   // Indicates the number of directories beneath the root folder of the directory specified in the canonicalizedResource field of the string-to-sign.
	SnapshotTime             string
	EncryptionScope          string `param:"ses"` // Indicates the encryption scope to use to encrypt the request contents.
	Identifier               string `param:"si"`
	Signature                string `param:"sig"`
	CacheControl             string // rscc Azure Storage sets the Cache-Control response header to the value specified on the SAS token.
	ContentDisposition       string // rscd Azure Storage sets the Content-Disposition response header to the value specified on the SAS token.
	ContentEncoding          string // rsce Azure Storage sets the Content-Encoding response header to the value specified on the SAS token.
	ContentLanguage          string // rscl Azure Storage sets the Content-Language response header to the value specified on the SAS token.
	ContentType              string // rsct Azure Storage sets the Content-Type response header to the value specified on the SAS token.
}

// getCanonicalName computes the canonical name for a container or blob resource for SAS signing.
func getCanonicalName(account string, containerName string, blobName string) string {
	// Container: "/blob/account/containername"
	// Blob:      "/blob/account/containername/blobname"
	elements := []string{"/blob/", account, "/", containerName}
	if blobName != "" {
		elements = append(elements, "/", strings.Replace(blobName, "\\", "/", -1))
	}
	return strings.Join(elements, "")
}

func (b BlobDelegationSASSignatureValues) ToURL() string {
	v := reflect.ValueOf(b)
	t := reflect.TypeOf(b)
	values := url.Values{}

	for i := 0; i < v.NumField(); i++ {
		field_v := v.Field(i)
		field_t := t.Field(i)

		param := field_t.Tag.Get("param")
		if param == "" {
			continue
		}
		value := field_v.String()
		if value != "" {
			values.Add(param, value)
		}
	}

	return values.Encode()
}

func (b BlobDelegationSASSignatureValues) StringToSign() string {

	stringToSign := strings.Join([]string{
		b.Permissions,
		b.Start,
		b.Expiry,
		b.CanonicalizedResource,
		b.KeyObjectId,
		b.KeyTenantId,
		b.KeyStart,
		b.KeyExpiry,
		b.KeyService,
		b.KeyVersion,
		b.AuthorizedUserObjectId,
		b.UnauthorizedUserObjectId,
		b.CorrelationId,
		b.IP,
		b.Protocol,
		b.Version,
		b.Resource,
		b.SnapshotTime,
		b.EncryptionScope,
		b.CacheControl,
		b.ContentDisposition,
		b.ContentEncoding,
		b.ContentLanguage,
		b.ContentType,
	}, "\n")

	return stringToSign
}
