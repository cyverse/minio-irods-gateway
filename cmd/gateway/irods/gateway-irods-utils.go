/*
 * MinIO Object Storage (c) 2021 MinIO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package irods

import (
	"strings"

	"github.com/minio/minio-go/v7/pkg/s3utils"
	minio "github.com/minio/minio/cmd"
)

const (
	// Minio meta bucket.
	minioMetaBucket = ".minio.sys"

	// Minio Tmp meta prefix.
	minioMetaTmpBucket = minioMetaBucket + "/tmp"

	// Minio reserved bucket name.
	minioReservedBucket = "minio"
)

// Ignores all reserved bucket names or invalid bucket names.
func isReservedOrInvalidBucket(bucketEntry string, strict bool) bool {
	bucketEntry = strings.TrimSuffix(bucketEntry, minio.SlashSeparator)
	if strict {
		if err := s3utils.CheckValidBucketNameStrict(bucketEntry); err != nil {
			return true
		}
	} else {
		if err := s3utils.CheckValidBucketName(bucketEntry); err != nil {
			return true
		}
	}
	return isMinioMetaBucket(bucketEntry) || isMinioReservedBucket(bucketEntry)
}

// Returns true if input bucket is a reserved minio meta bucket '.minio.sys'.
func isMinioMetaBucket(bucketName string) bool {
	return bucketName == minioMetaBucket
}

// Returns true if input bucket is a reserved minio bucket 'minio'.
func isMinioReservedBucket(bucketName string) bool {
	return bucketName == minioReservedBucket
}
