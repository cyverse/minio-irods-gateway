/*
 * Copyright (c) 2010-2021, The Arizona Board of Regents on behalf of The University of Arizona
 * All rights reserved.
 * Developed by: CyVerse as a collaboration between participants at BIO5 at The University of Arizona (the primary hosting institution), Cold Spring Harbor Laboratory, The University of Texas at Austin, and individual contributors. Find out more at http://www.cyverse.org/.
 */

package irods

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/minio/cli"
	"github.com/minio/madmin-go"
	"github.com/minio/minio-go/v7/pkg/s3utils"
	minio "github.com/minio/minio/cmd"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/pkg/bucket/policy"
	"github.com/minio/pkg/bucket/policy/condition"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
)

const (
	irodsClientName                      string        = "minio-irods-gateway"
	defaultIRODSOperationTimeout         time.Duration = 5 * time.Minute
	defaultIRODSConnectionIdleTimeout    time.Duration = 5 * time.Minute
	defaultIRODSConnectionMax            int           = 10
	defaultIRODSMetadataCacheTimeout     time.Duration = 5 * time.Minute
	defaultIRODSMetadataCacheCleanupTime time.Duration = 5 * time.Minute
	defaultIRODSStartNewTransaction      bool          = true

	irodsSeparator = minio.SlashSeparator
)

func init() {
	const irodsGatewayTemplate = `NAME:
			   {{.HelpName}} - {{.Usage}}
			
		   USAGE:
			   {{.HelpName}} {{if .VisibleFlags}}[FLAGS]{{end}} [ENDPOINT]
		   {{if .VisibleFlags}}
		   FLAGS:
			   {{range .VisibleFlags}}{{.}}
			   {{end}}{{end}}
		   ENDPOINT:
			   iRODS server endpoint. An example ENDPOINT is irods://data.cyverse.org:1247/iplant/home/<username>
			
		   EXAMPLES:
			 1. Start minio gateway server for iRODS backend.
			   {{.Prompt}} {{.EnvVarSetCommand}} MINIO_ACCESS_KEY{{.AssignmentOperator}}username
			   {{.Prompt}} {{.EnvVarSetCommand}} MINIO_SECRET_KEY{{.AssignmentOperator}}password
			   {{.Prompt}} {{.HelpName}}
			
			 2. Start minio gateway server for iRODS backend with edge caching enabled
			   {{.Prompt}} {{.EnvVarSetCommand}} MINIO_ACCESS_KEY{{.AssignmentOperator}}username
			   {{.Prompt}} {{.EnvVarSetCommand}} MINIO_SECRET_KEY{{.AssignmentOperator}}password
			   {{.Prompt}} {{.EnvVarSetCommand}} MINIO_CACHE_DRIVES{{.AssignmentOperator}}"/mnt/drive1,/mnt/drive2,/mnt/drive3,/mnt/drive4"
			   {{.Prompt}} {{.EnvVarSetCommand}} MINIO_CACHE_EXCLUDE{{.AssignmentOperator}}"bucket1/*,*.png"
			   {{.Prompt}} {{.EnvVarSetCommand}} MINIO_CACHE_QUOTA{{.AssignmentOperator}}90
			   {{.Prompt}} {{.EnvVarSetCommand}} MINIO_CACHE_AFTER{{.AssignmentOperator}}3
			   {{.Prompt}} {{.EnvVarSetCommand}} MINIO_CACHE_WATERMARK_LOW{{.AssignmentOperator}}75
			   {{.Prompt}} {{.EnvVarSetCommand}} MINIO_CACHE_WATERMARK_HIGH{{.AssignmentOperator}}85
			   {{.Prompt}} {{.HelpName}}
			`

	minio.RegisterGatewayCommand(cli.Command{
		Name:               minio.IRODSBackendGateway,
		Usage:              "iRODS",
		Action:             irodsGatewayMain,
		CustomHelpTemplate: irodsGatewayTemplate,
		HideHelpCommand:    true,
	})
}

// Handler for 'minio gateway irods' command line.
func irodsGatewayMain(ctx *cli.Context) {
	args := ctx.Args()
	if !ctx.Args().Present() {
		logger.FatalIf(fmt.Errorf("ENDPOINT is not given"), "ENDPOINT is not given")
	}

	logger.Info("Parsing iRODS Endpoint URL - %s", args.First())
	irodsAccount, err := parseIRODSURL(args.First())
	if err != nil {
		logger.FatalIf(err, "ENDPOINT is not correct URL format")
	}

	// Start the gateway..
	minio.StartGateway(ctx, irodsAccount)
}

// parseIRODSURL parses iRODS Access URL string and returns IRODS struct
func parseIRODSURL(inputURL string) (*IRODS, error) {
	u, err := url.Parse(inputURL)
	if err != nil {
		return nil, err
	}

	user := ""
	password := ""

	if u.User != nil {
		uname := u.User.Username()
		if len(uname) > 0 {
			user = uname
		}

		if pwd, ok := u.User.Password(); ok {
			password = pwd
		}
	}

	host := ""
	host = u.Hostname()

	port := 1247
	if len(u.Port()) > 0 {
		port64, err := strconv.ParseInt(u.Port(), 10, 32)
		if err != nil {
			return nil, err
		}
		port = int(port64)
	}

	fullpath := path.Clean(u.Path)
	zone := ""
	irodsPath := "/"
	if len(fullpath) == 0 || fullpath[0] != '/' {
		err = fmt.Errorf("path (%s) must contain an absolute path", u.Path)
		return nil, err
	}

	pos := strings.Index(fullpath[1:], "/")
	if pos > 0 {
		zone = strings.Trim(fullpath[1:pos+1], "/")
		irodsPath = fullpath // starts with zone
	} else if pos == -1 {
		// no path
		zone = strings.Trim(fullpath[1:], "/")
		irodsPath = fullpath
	}

	if len(zone) == 0 || len(irodsPath) == 0 {
		err = fmt.Errorf("path (%s) must contain an absolute path", inputURL)
		return nil, err
	}

	if irodsPath == "/" {
		err = fmt.Errorf("path (%s) must not be a root", inputURL)
		return nil, err
	}

	irodsPath = strings.TrimSuffix(irodsPath, "/")

	bucketName := path.Base(irodsPath)
	irodsParentPath := path.Dir(irodsPath)

	return &IRODS{
		host:   host,
		port:   port,
		zone:   zone,
		path:   irodsParentPath,
		bucket: bucketName,

		username: user,
		password: password,
	}, nil
}

// IRODS implements Gateway.
type IRODS struct {
	host   string
	port   int
	zone   string
	path   string
	bucket string

	username string
	password string
}

// Name implements Gateway interface.
func (g *IRODS) Name() string {
	return minio.IRODSBackendGateway
}

// NewGatewayLayer returns iRODS ObjectLayer.
func (g *IRODS) NewGatewayLayer(creds madmin.Credentials) (minio.ObjectLayer, error) {
	if len(g.username) == 0 {
		g.username = creds.AccessKey
	}

	if len(g.password) == 0 {
		g.password = creds.SecretKey
	}

	account, err := irodsclient_types.CreateIRODSAccount(g.host, g.port,
		g.username, g.zone, irodsclient_types.AuthSchemeNative, g.password, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create an IRODS Account - %v", err)
	}

	fsconfig := irodsclient_fs.NewFileSystemConfig(
		irodsClientName,
		defaultIRODSOperationTimeout, defaultIRODSConnectionIdleTimeout,
		defaultIRODSConnectionMax, defaultIRODSMetadataCacheTimeout,
		defaultIRODSMetadataCacheCleanupTime,
		defaultIRODSStartNewTransaction,
	)

	irodsfsclient, err := irodsclient_fs.NewFileSystem(account, fsconfig)
	if err != nil {
		return nil, err
	}

	irodsObjects := irodsObjects{
		client:   irodsfsclient,
		zone:     g.zone,
		path:     g.path,
		bucket:   g.bucket,
		username: g.username,
		listPool: minio.NewTreeWalkPool(time.Minute * 30),
	}

	return &irodsObjects, nil
}

// irodsObjects - Implements Object layer for Irods blob storage.
type irodsObjects struct {
	minio.GatewayUnsupported
	client   *irodsclient_fs.FileSystem
	zone     string
	path     string
	bucket   string
	username string
	listPool *minio.TreeWalkPool
}

func irodsToObjectErr(ctx context.Context, err error, params ...string) error {
	if err == nil {
		return nil
	}

	bucket := ""
	object := ""
	switch len(params) {
	case 2:
		object = params[1]
		fallthrough
	case 1:
		bucket = params[0]
	}

	switch {
	case irodsclient_types.IsFileNotFoundError(err):
		if object != "" {
			return minio.ObjectNotFound{Bucket: bucket, Object: object}
		}
		return minio.BucketNotFound{Bucket: bucket}
	case irodsclient_types.IsCollectionNotEmptyError(err):
		if object != "" {
			return minio.PrefixAccessDenied{Bucket: bucket, Object: object}
		}
		return minio.BucketNotEmpty{Bucket: bucket}
	default:
		logger.LogIf(ctx, err)
		return err
	}
}

// irodsIsValidBucketName verifies whether a bucket name is valid.
func irodsIsValidBucketName(bucket string) bool {
	return s3utils.CheckValidBucketNameStrict(bucket) == nil
}

func (l *irodsObjects) irodsPathJoin(args ...string) string {
	return minio.PathJoin(append([]string{l.path, irodsSeparator}, args...)...)
}

// GetMetrics returns this gateway's metrics
func (l *irodsObjects) GetMetrics(ctx context.Context) (*minio.BackendMetrics, error) {
	metrics := l.client.Session.GetTransferMetrics()
	minioMetrics := minio.NewMetrics()

	minioMetrics.IncBytesReceived(metrics.BytesReceived)
	minioMetrics.IncBytesSent(metrics.BytesSent)

	return minioMetrics, nil
}

// Shutdown saves any gateway metadata to disk
// if necessary and reload upon next restart.
func (l *irodsObjects) Shutdown(ctx context.Context) error {
	l.client.Release()
	return nil
}

// StorageInfo is not relevant to iRODS backend.
func (l *irodsObjects) StorageInfo(ctx context.Context) (si minio.StorageInfo, _ []error) {
	si.Backend.Type = madmin.Gateway
	si.Backend.GatewayOnline = true

	return si, nil
}

// ListBuckets lists iRODS collections
func (l *irodsObjects) ListBuckets(ctx context.Context) (buckets []minio.BucketInfo, err error) {
	// logger.Info("ListBuckets")

	// Ignore all reserved bucket names and invalid bucket names.
	if isReservedOrInvalidBucket(l.bucket, false) {
		err := fmt.Errorf("bucket name %s is invalid or reserved", l.bucket)
		logger.LogIf(ctx, err)
		return nil, irodsToObjectErr(ctx, err)
	}

	entry, err := l.client.StatDir(l.irodsPathJoin(l.bucket))
	if err != nil {
		logger.LogIf(ctx, err)
		return nil, irodsToObjectErr(ctx, err)
	}

	buckets = append(buckets, minio.BucketInfo{
		Name:    entry.Name,
		Created: entry.CreateTime,
	})

	return buckets, nil
}

func (l *irodsObjects) isLeafDir(bucket, leafPath string) bool {
	return l.isObjectDir(context.Background(), bucket, leafPath)
}

func (l *irodsObjects) isLeaf(bucket, leafPath string) bool {
	return !strings.HasSuffix(leafPath, irodsSeparator)
}

func (l *irodsObjects) listDirFactory() minio.ListDirFunc {
	// listDir - lists all the entries at a given prefix and given entry in the prefix.
	listDir := func(bucket, prefixDir, prefixEntry string) (emptyDir bool, entries []string, delayIsLeaf bool) {
		// irodsPath := l.irodsPathJoin(bucket, prefixDir)
		// logger.Info("listDir - %s", irodsPath)

		irodsEntries, err := l.client.List(l.irodsPathJoin(bucket, prefixDir))
		if err != nil {
			logger.LogIf(minio.GlobalContext, err)
			if irodsclient_types.IsFileNotFoundError(err) {
				err = nil
			}
			return
		}

		if len(irodsEntries) == 0 {
			return true, nil, false
		}

		for _, fi := range irodsEntries {
			if fi.Type == irodsclient_fs.DirectoryEntry {
				entries = append(entries, fi.Name+irodsSeparator)
			} else {
				entries = append(entries, fi.Name)
			}
		}
		entries, delayIsLeaf = minio.FilterListEntries(bucket, prefixDir, entries, prefixEntry, l.isLeaf)
		return false, entries, delayIsLeaf
	}

	// Return list factory instance.
	return listDir
}

// GetBucketInfo gets bucket metadata
func (l *irodsObjects) GetBucketInfo(ctx context.Context, bucket string) (bi minio.BucketInfo, err error) {
	// logger.Info("GetBucketInfo - %s", bucket)

	irodsPath := l.irodsPathJoin(bucket)
	irodsPath = strings.TrimSuffix(irodsPath, "/")

	fi, err := l.client.StatDir(irodsPath)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			return bi, minio.BucketNotFound{Bucket: bucket}
		}

		return bi, irodsToObjectErr(ctx, err, bucket)
	}

	return minio.BucketInfo{
		Name:    bucket,
		Created: fi.CreateTime,
	}, nil
}

// MakeBucketWithLocation creates a new bucket (not allowed)
func (l *irodsObjects) MakeBucketWithLocation(ctx context.Context, bucket string, opts minio.BucketOptions) error {
	return minio.NotImplemented{}
}

// DeleteBucket deletes a bucket (not allowed)
func (l *irodsObjects) DeleteBucket(ctx context.Context, bucket string, opts minio.DeleteBucketOptions) error {
	return minio.NotImplemented{}
}

// ListObjects lists all blobs in iRODS bucket (collection) filtered by prefix
func (l *irodsObjects) ListObjects(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (loi minio.ListObjectsInfo, err error) {
	// logger.Info("ListObjects - bucket %s, prefix %s", bucket, prefix)

	irodsPath := l.irodsPathJoin(bucket, prefix)
	irodsSafePath := strings.TrimSuffix(irodsPath, "/")

	stat, err := l.client.Stat(irodsSafePath)
	if err != nil {
		return loi, irodsToObjectErr(ctx, err, bucket, prefix)
	}

	// If the user is trying to list a single file, bypass the entire directory-walking code below
	// and just return the single file's information.
	if stat.Type == irodsclient_fs.FileEntry {
		if strings.HasSuffix(irodsPath, "/") {
			// the path is for a file and ends with "/"
			return minio.ListObjectsInfo{
				IsTruncated: false,
				Objects:     []minio.ObjectInfo{},
				Prefixes:    []string{},
			}, nil
		}

		return minio.ListObjectsInfo{
			IsTruncated: false,
			Objects: []minio.ObjectInfo{
				fileInfoToObjectInfo(bucket, prefix, stat),
			},
			Prefixes: []string{},
		}, nil
	}

	getObjectInfo := func(ctx context.Context, bucket, entry string) (minio.ObjectInfo, error) {
		irodsFilePath := l.irodsPathJoin(bucket, entry)
		// logger.Info("getObjectInfo - %s", irodsFilePath)

		irodsSafeFilePath := strings.TrimSuffix(irodsFilePath, "/")

		fi, err := l.client.Stat(irodsSafeFilePath)
		if err != nil {
			return minio.ObjectInfo{}, irodsToObjectErr(ctx, err, bucket, entry)
		}

		if fi.Type == irodsclient_fs.FileEntry && strings.HasSuffix(irodsFilePath, "/") {
			// file but ends with "/"
			return minio.ObjectInfo{}, nil
		}

		return fileInfoToObjectInfo(bucket, entry, fi), nil
	}

	return minio.ListObjects(ctx, l, bucket, prefix, marker, delimiter, maxKeys, l.listPool, l.listDirFactory(), l.isLeaf, l.isLeafDir, getObjectInfo, getObjectInfo)
}

// ListObjectsV2 lists all blobs in iRODS bucket filtered by prefix
func (l *irodsObjects) ListObjectsV2(ctx context.Context, bucket, prefix, continuationToken, delimiter string, maxKeys int, fetchOwner bool, startAfter string) (loi minio.ListObjectsV2Info, err error) {
	// logger.Info("ListObjectsV2 - bucket %s, prefix %s", bucket, prefix)

	// fetchOwner is not supported and unused.
	marker := continuationToken
	if marker == "" {
		marker = startAfter
	}

	resultV1, err := l.ListObjects(ctx, bucket, prefix, marker, delimiter, maxKeys)
	if err != nil {
		return loi, err
	}

	return minio.ListObjectsV2Info{
		Objects:               resultV1.Objects,
		Prefixes:              resultV1.Prefixes,
		ContinuationToken:     continuationToken,
		NextContinuationToken: resultV1.NextMarker,
		IsTruncated:           resultV1.IsTruncated,
	}, nil
}

func fileInfoToObjectInfo(bucket string, entry string, fi *irodsclient_fs.Entry) minio.ObjectInfo {
	return minio.ObjectInfo{
		Bucket:  bucket,
		Name:    entry,
		ModTime: fi.ModifyTime,
		Size:    fi.Size,
		IsDir:   fi.Type == irodsclient_fs.DirectoryEntry,
		// iRODS doesn't have access time, we will use modify time
		AccTime: fi.ModifyTime,
		ETag:    fmt.Sprintf("%d-%s", fi.ID, fi.CheckSum),
	}
}

func (l *irodsObjects) isObjectDir(ctx context.Context, bucket, object string) bool {
	irodsPath := l.irodsPathJoin(bucket, object)
	entry, err := l.client.Stat(irodsPath)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			return false
		}
		logger.LogIf(ctx, err)
		return false
	}

	return entry.Type == irodsclient_fs.DirectoryEntry
}

func (l *irodsObjects) GetObjectInfo(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	irodsPath := l.irodsPathJoin(bucket, object)
	// logger.Info("GetObjectInfo - %s", irodsPath)

	irodsPath = strings.TrimSuffix(irodsPath, "/")

	fi, err := l.client.Stat(irodsPath)
	if err != nil {
		return objInfo, irodsToObjectErr(ctx, err, bucket, object)
	}

	return fileInfoToObjectInfo(bucket, object, fi), nil
}

func (l *irodsObjects) GetObjectNInfo(ctx context.Context, bucket, object string, rs *minio.HTTPRangeSpec, h http.Header, lockType minio.LockType, opts minio.ObjectOptions) (gr *minio.GetObjectReader, err error) {
	// irodsPath := l.irodsPathJoin(bucket, object)
	// logger.Info("GetObjectNInfo - %s", irodsPath)

	objInfo, err := l.GetObjectInfo(ctx, bucket, object, opts)
	if err != nil {
		return nil, err
	}

	var startOffset, length int64
	startOffset, length, err = rs.GetOffsetLength(objInfo.Size)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	go func() {
		nerr := l.getObject(ctx, bucket, object, startOffset, length, pw, objInfo.ETag, opts)
		pw.CloseWithError(nerr)
	}()

	// Setup cleanup function to cause the above go-routine to
	// exit in case of partial read
	pipeCloser := func() { pr.Close() }
	return minio.NewGetObjectReaderFromReader(pr, objInfo, opts, pipeCloser)
}

func (l *irodsObjects) getObject(ctx context.Context, bucket, key string, startOffset, length int64, writer io.Writer, etag string, opts minio.ObjectOptions) error {
	irodsPath := l.irodsPathJoin(bucket, key)
	// logger.Info("getObject - %s", irodsPath)

	irodsPath = strings.TrimSuffix(irodsPath, "/")

	if _, err := l.client.Stat(irodsPath); err != nil {
		return irodsToObjectErr(ctx, err, bucket, key)
	}

	fh, err := l.client.OpenFile(irodsPath, "", "r")
	if err != nil {
		return irodsToObjectErr(ctx, err, bucket, key)
	}

	rw := NewIRODSFileRW(fh)
	defer rw.Close()

	_, err = io.Copy(writer, io.NewSectionReader(rw, startOffset, length))
	return irodsToObjectErr(ctx, err, bucket, key)
}

func (l *irodsObjects) PutObject(ctx context.Context, bucket string, object string, r *minio.PutObjReader, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	irodsPath := l.irodsPathJoin(bucket, object)
	// logger.Info("PutObject - %s", irodsPath)

	irodsPath = strings.TrimSuffix(irodsPath, "/")

	_, err = l.client.Stat(l.irodsPathJoin(bucket))
	if err != nil {
		return objInfo, irodsToObjectErr(ctx, err, bucket)
	}

	// If its a directory create a prefix {
	if strings.HasSuffix(object, irodsSeparator) && r.Size() == 0 {
		if err = l.client.MakeDir(irodsPath, true); err != nil {
			l.deleteObject(l.irodsPathJoin(bucket), irodsPath)
			return objInfo, irodsToObjectErr(ctx, err, bucket, object)
		}
	} else {
		dir := path.Dir(irodsPath)
		if dir != "" {
			if err = l.client.MakeDir(dir, true); err != nil {
				return objInfo, irodsToObjectErr(ctx, err, bucket, object)
			}
		}

		fh, err := l.client.CreateFile(irodsPath, "")
		if err != nil {
			return objInfo, irodsToObjectErr(ctx, err, bucket, object)
		}

		rw := NewIRODSFileRW(fh)

		if _, err = io.Copy(rw, r); err != nil {
			rw.Close()
			return objInfo, irodsToObjectErr(ctx, err, bucket, object)
		}

		rw.Close()
	}

	fi, err := l.client.Stat(irodsPath)
	if err != nil {
		return objInfo, irodsToObjectErr(ctx, err, bucket, object)
	}

	return fileInfoToObjectInfo(bucket, object, fi), nil
}

func (l *irodsObjects) CopyObject(ctx context.Context, srcBucket, srcObject, dstBucket, dstObject string, srcInfo minio.ObjectInfo, srcOpts, dstOpts minio.ObjectOptions) (minio.ObjectInfo, error) {
	srcIrodsPath := l.irodsPathJoin(srcBucket, srcObject)
	destIrodsPath := l.irodsPathJoin(dstBucket, dstObject)
	srcIrodsPath = strings.TrimSuffix(srcIrodsPath, "/")
	destIrodsPath = strings.TrimSuffix(destIrodsPath, "/")

	cpSrcDstSame := minio.IsStringEqual(srcIrodsPath, destIrodsPath)
	if cpSrcDstSame {
		return l.GetObjectInfo(ctx, srcBucket, srcObject, minio.ObjectOptions{})
	}

	return l.PutObject(ctx, dstBucket, dstObject, srcInfo.PutObjReader, minio.ObjectOptions{
		ServerSideEncryption: dstOpts.ServerSideEncryption,
		UserDefined:          srcInfo.UserDefined,
	})
}

func (l *irodsObjects) DeleteObject(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (minio.ObjectInfo, error) {
	irodsPath := l.irodsPathJoin(bucket, object)
	// logger.Info("DeleteObject - %s", irodsPath)

	err := l.deleteObject(l.irodsPathJoin(bucket), irodsPath)
	if err != nil {
		return minio.ObjectInfo{}, irodsToObjectErr(ctx, err, bucket, object)
	}

	return minio.ObjectInfo{
		Bucket: bucket,
		Name:   object,
	}, nil
}

// deleteObject deletes a file path if its empty. If it's successfully deleted,
// it will recursively move up the tree, deleting empty parent directories
// until it finds one with files in it. Returns nil for a non-empty directory.
func (l *irodsObjects) deleteObject(basePath, deletePath string) error {
	if basePath == deletePath {
		return nil
	}

	// Attempt to remove path.
	f, err := l.client.Stat(deletePath)
	if err != nil {
		return err
	}

	if f.Type == irodsclient_fs.FileEntry {
		err = l.client.RemoveFile(deletePath, true)
		if err != nil {
			return err
		}
	} else {
		// dir?
		err = l.client.RemoveDir(deletePath, false, false)
		if err != nil {
			if irodsclient_types.IsCollectionNotEmptyError(err) {
				// Ignore errors if the directory is not empty. The server relies on
				// this functionality, and sometimes uses recursion that should not
				// error on parent directories.
				return nil
			}
			return err
		}
	}

	// Trailing slash is removed when found to ensure
	// slashpath.Dir() to work as intended.
	deletePath = strings.TrimSuffix(deletePath, irodsSeparator)
	deletePath = path.Dir(deletePath)

	// Delete parent directory. Errors for parent directories shouldn't trickle down.
	l.deleteObject(basePath, deletePath)

	return nil
}

func (l *irodsObjects) DeleteObjects(ctx context.Context, bucket string, objects []minio.ObjectToDelete, opts minio.ObjectOptions) ([]minio.DeletedObject, []error) {
	// irodsPath := l.irodsPathJoin(bucket)
	// logger.Info("DeleteObjects - %s", irodsPath)

	errs := make([]error, len(objects))
	dobjects := make([]minio.DeletedObject, len(objects))
	for idx, object := range objects {
		_, errs[idx] = l.DeleteObject(ctx, bucket, object.ObjectName, opts)
		if errs[idx] == nil {
			dobjects[idx] = minio.DeletedObject{
				ObjectName: object.ObjectName,
			}
		}
	}
	return dobjects, errs
}

// GetBucketPolicy will get policy on bucket
func (l *irodsObjects) GetBucketPolicy(ctx context.Context, bucket string) (bucketPolicy *policy.Policy, err error) {
	// irodsPath := l.irodsPathJoin(bucket)
	// logger.Info("GetBucketPolicy - %s", irodsPath)

	return &policy.Policy{
		Version: policy.DefaultVersion,
		Statements: []policy.Statement{
			policy.NewStatement(
				policy.Allow,
				policy.NewPrincipal("*"),
				policy.NewActionSet(
					policy.GetBucketLocationAction,
					policy.ListBucketAction,
					policy.GetObjectAction,
				),
				policy.NewResourceSet(
					policy.NewResource(bucket, ""),
					policy.NewResource(bucket, "*"),
				),
				condition.NewFunctions(),
			),
		},
	}, nil
}

// IsCompressionSupported returns whether compression is applicable for this layer.
func (l *irodsObjects) IsCompressionSupported() bool {
	return false
}

// IsEncryptionSupported returns whether server side encryption is implemented for this layer.
func (l *irodsObjects) IsEncryptionSupported() bool {
	return false
}

func (l *irodsObjects) IsTaggingSupported() bool {
	return false
}
