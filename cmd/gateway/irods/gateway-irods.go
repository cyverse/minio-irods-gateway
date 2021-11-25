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
	"sort"
	"strconv"
	"strings"
	"sync"
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

/*
 import (
	 "context"
	 "crypto/md5"
	 "crypto/rand"
	 "encoding/hex"
	 "encoding/json"
	 "fmt"
	 "io"
	 "mime"
	 "net/http"
	 "path/filepath"
	 "sort"
	 "strconv"
	 "strings"
	 "time"

	 humanize "github.com/dustin/go-humanize"
	 gorods "github.com/jjacquay712/GoRODS"
	 "github.com/minio/cli"
	 "github.com/minio/minio/cmd"
	 "github.com/minio/minio/cmd/logger"
	 "github.com/minio/minio/pkg/auth"
	 "github.com/minio/minio/pkg/policy"
	 "github.com/minio/minio/pkg/policy/condition"

	 minio "github.com/minio/minio/cmd"
 )

 const (
	 irodsBlockSize             = 100 * humanize.MiByte
	 irodsS3MinPartSize         = 5 * humanize.MiByte
	 metadataObjectNameTemplate = "multipart_v1_%s_%x_irods.json"
	 irodsMarkerPrefix          = "{minio}"
	 irodsIQuestQuery           = "minio_list_objects"
	 irodsMultipartSubCol       = "multiparts"
	 irodsObjMetaAttr           = "minio_obj"
	 irodsMultipartMetaAttr     = "minio_multipart"
	 irodsBucketMetaAttr        = "minio_loc"
	 irodsConPoolSize           = 4
 )
*/

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

	return &IRODS{
		host: host,
		port: port,
		zone: zone,
		path: irodsPath,

		username: user,
		password: password,
	}, nil
}

// IRODS implements Gateway.
type IRODS struct {
	host string
	port int
	zone string
	path string

	username string
	password string
}

// Name implements Gateway interface.
func (g *IRODS) Name() string {
	return minio.IRODSBackendGateway
}

// NewGatewayLayer returns iRODS ObjectLayer.
func (g *IRODS) NewGatewayLayer(creds madmin.Credentials) (minio.ObjectLayer, error) {
	metrics := minio.NewMetrics()

	/*
		 TODO: Use this for reporting metrics
		 t := &minio.MetricsTransport{
			 Transport: minio.NewGatewayHTTPTransport(),
			 Metrics:   metrics,
		 }
	*/

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
		username: g.username,
		metrics:  metrics,
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
	username string
	metrics  *minio.BackendMetrics
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
	return l.metrics, nil
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

// ListBuckets lists all iRODS buckets (collections)
func (l *irodsObjects) ListBuckets(ctx context.Context) (buckets []minio.BucketInfo, err error) {
	entries, err := l.client.List(l.irodsPathJoin())
	if err != nil {
		logger.LogIf(ctx, err)
		return nil, irodsToObjectErr(ctx, err)
	}

	for _, entry := range entries {
		// Ignore all non-collections
		if entry.Type != irodsclient_fs.DirectoryEntry {
			continue
		}

		// Ignore all reserved bucket names and invalid bucket names.
		if isReservedOrInvalidBucket(entry.Name, false) {
			continue
		}
		buckets = append(buckets, minio.BucketInfo{
			Name:    entry.Name,
			Created: entry.CreateTime,
		})
	}

	// Sort bucket infos by bucket name.
	sort.Sort(byBucketName(buckets))
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
	fi, err := l.client.StatDir(l.irodsPathJoin(bucket))
	if err != nil {
		return bi, irodsToObjectErr(ctx, err, bucket)
	}

	return minio.BucketInfo{
		Name:    bucket,
		Created: fi.CreateTime,
	}, nil
}

// MakeBucket creates a new container on iRODS backend
func (l *irodsObjects) MakeBucketWithLocation(ctx context.Context, bucket string, opts minio.BucketOptions) error {
	if opts.LockEnabled || opts.VersioningEnabled {
		return minio.NotImplemented{}
	}

	if !irodsIsValidBucketName(bucket) {
		return minio.BucketNameInvalid{Bucket: bucket}
	}

	return irodsToObjectErr(ctx, l.client.MakeDir(l.irodsPathJoin(bucket), true), bucket)
}

// DeleteBucket deletes a bucket (collection) on iRODS
func (l *irodsObjects) DeleteBucket(ctx context.Context, bucket string, opts minio.DeleteBucketOptions) error {
	if !irodsIsValidBucketName(bucket) {
		return minio.BucketNameInvalid{Bucket: bucket}
	}

	if opts.Force {
		return irodsToObjectErr(ctx, l.client.RemoveDir(l.irodsPathJoin(bucket), true, true), bucket)
	}

	return irodsToObjectErr(ctx, l.client.RemoveDir(l.irodsPathJoin(bucket), false, false), bucket)
}

// ListObjects lists all blobs in iRODS bucket (collection) filtered by prefix
func (l *irodsObjects) ListObjects(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (loi minio.ListObjectsInfo, err error) {
	var mutex sync.Mutex
	fileInfos := make(map[string]*irodsclient_fs.Entry)
	targetPath := l.irodsPathJoin(bucket, prefix)

	var targetFileInfo *irodsclient_fs.Entry

	if targetFileInfo, err = l.populateDirectoryListing(targetPath, fileInfos); err != nil {
		return loi, irodsToObjectErr(ctx, err, bucket)
	}

	// If the user is trying to list a single file, bypass the entire directory-walking code below
	// and just return the single file's information.
	if targetFileInfo.Type == irodsclient_fs.FileEntry {
		return minio.ListObjectsInfo{
			IsTruncated: false,
			NextMarker:  "",
			Objects: []minio.ObjectInfo{
				fileInfoToObjectInfo(bucket, prefix, targetFileInfo),
			},
			Prefixes: []string{},
		}, nil
	}

	getObjectInfo := func(ctx context.Context, bucket, entry string) (minio.ObjectInfo, error) {
		mutex.Lock()
		defer mutex.Unlock()

		filePath := path.Clean(l.irodsPathJoin(bucket, entry))
		fi, ok := fileInfos[filePath]

		// If the file info is not known, this may be a recursive listing and filePath is a
		// child of a sub-directory. In this case, obtain that sub-directory's listing.
		if !ok {
			parentPath := path.Dir(filePath)

			if _, err := l.populateDirectoryListing(parentPath, fileInfos); err != nil {
				return minio.ObjectInfo{}, irodsToObjectErr(ctx, err, bucket)
			}

			fi, ok = fileInfos[filePath]
			if !ok {
				err = fmt.Errorf("could not get FileInfo for path '%s'", filePath)
				return minio.ObjectInfo{}, irodsToObjectErr(ctx, err, bucket, entry)
			}
		}

		objectInfo := fileInfoToObjectInfo(bucket, entry, fi)

		delete(fileInfos, filePath)

		return objectInfo, nil
	}

	return minio.ListObjects(ctx, l, bucket, prefix, marker, delimiter, maxKeys, l.listPool, l.listDirFactory(), l.isLeaf, l.isLeafDir, getObjectInfo, getObjectInfo)
}

// ListObjectsV2 lists all blobs in iRODS bucket filtered by prefix
func (n *irodsObjects) ListObjectsV2(ctx context.Context, bucket, prefix, continuationToken, delimiter string, maxKeys int, fetchOwner bool, startAfter string) (loi minio.ListObjectsV2Info, err error) {
	// fetchOwner is not supported and unused.
	marker := continuationToken
	if marker == "" {
		marker = startAfter
	}

	resultV1, err := n.ListObjects(ctx, bucket, prefix, marker, delimiter, maxKeys)
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
	}
}

// Lists a path's direct, first-level entries and populates them in the `fileInfos` cache which maps
// a path entry to an `*irodsclient_fs.Entry`. It also saves the listed path's `*irodsclient_fs.Entry` in the cache.
func (l *irodsObjects) populateDirectoryListing(filePath string, fileInfos map[string]*irodsclient_fs.Entry) (*irodsclient_fs.Entry, error) {
	dirStat, err := l.client.StatDir(filePath)
	if err != nil {
		return nil, err
	}

	if dirStat.Type != irodsclient_fs.DirectoryEntry {
		return dirStat, nil
	}

	entries, err := l.client.List(filePath)
	if err != nil {
		return nil, err
	}

	key := path.Clean(filePath)

	fileInfos[key] = dirStat
	for _, entry := range entries {
		fileInfos[entry.Path] = entry
	}

	return dirStat, nil
}

func (l *irodsObjects) isObjectDir(ctx context.Context, bucket, object string) bool {
	entry, err := l.client.Stat(l.irodsPathJoin(bucket, object))
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			return false
		}
		logger.LogIf(ctx, err)
		return false
	}

	if entry.Type != irodsclient_fs.DirectoryEntry {
		return false
	}

	entries, err := l.client.List(entry.Path)
	if err != nil {
		logger.LogIf(ctx, err)
		return false
	}

	return len(entries) == 0
}

func (l *irodsObjects) GetObjectInfo(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	_, err = l.client.Stat(l.irodsPathJoin(bucket))
	if err != nil {
		return objInfo, irodsToObjectErr(ctx, err, bucket)
	}

	if strings.HasSuffix(object, irodsSeparator) && !l.isObjectDir(ctx, bucket, object) {
		p := l.irodsPathJoin(bucket, object)
		return objInfo, irodsToObjectErr(ctx, irodsclient_types.NewFileNotFoundError(p+" not found"), bucket, object)
	}

	fi, err := l.client.Stat(l.irodsPathJoin(bucket, object))
	if err != nil {
		return objInfo, irodsToObjectErr(ctx, err, bucket, object)
	}
	return minio.ObjectInfo{
		Bucket:  bucket,
		Name:    object,
		ModTime: fi.ModifyTime,
		Size:    fi.Size,
		IsDir:   fi.Type == irodsclient_fs.DirectoryEntry,
		AccTime: fi.ModifyTime,
	}, nil
}

func (l *irodsObjects) GetObjectNInfo(ctx context.Context, bucket, object string, rs *minio.HTTPRangeSpec, h http.Header, lockType minio.LockType, opts minio.ObjectOptions) (gr *minio.GetObjectReader, err error) {
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
	if _, err := l.client.Stat(l.irodsPathJoin(bucket)); err != nil {
		return irodsToObjectErr(ctx, err, bucket)
	}

	fh, err := l.client.OpenFile(l.irodsPathJoin(bucket, key), "", "r")
	if err != nil {
		return irodsToObjectErr(ctx, err, bucket, key)
	}

	rw := NewIRODSFileRW(fh)
	defer rw.Close()

	_, err = io.Copy(writer, io.NewSectionReader(rw, startOffset, length))
	return irodsToObjectErr(ctx, err, bucket, key)
}

func (l *irodsObjects) PutObject(ctx context.Context, bucket string, object string, r *minio.PutObjReader, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	_, err = l.client.Stat(l.irodsPathJoin(bucket))
	if err != nil {
		return objInfo, irodsToObjectErr(ctx, err, bucket)
	}

	name := l.irodsPathJoin(bucket, object)

	// If its a directory create a prefix {
	if strings.HasSuffix(object, irodsSeparator) && r.Size() == 0 {
		if err = l.client.MakeDir(name, true); err != nil {
			l.deleteObject(l.irodsPathJoin(bucket), name)
			return objInfo, irodsToObjectErr(ctx, err, bucket, object)
		}
	} else {
		tmpname := l.irodsPathJoin(minioMetaTmpBucket, minio.MustGetUUID())

		fh, err := l.client.CreateFile(tmpname, "")
		if err != nil {
			return objInfo, irodsToObjectErr(ctx, err, bucket, object)
		}

		rw := NewIRODSFileRW(fh)

		defer l.deleteObject(l.irodsPathJoin(minioMetaTmpBucket), tmpname)

		if _, err = io.Copy(rw, r); err != nil {
			rw.Close()
			return objInfo, irodsToObjectErr(ctx, err, bucket, object)
		}

		dir := path.Dir(name)
		if dir != "" {
			if err = l.client.MakeDir(dir, true); err != nil {
				rw.Close()
				l.deleteObject(l.irodsPathJoin(bucket), dir)
				return objInfo, irodsToObjectErr(ctx, err, bucket, object)
			}
		}
		rw.Close()

		if err = l.client.RenameFile(tmpname, name); err != nil {
			return objInfo, irodsToObjectErr(ctx, err, bucket, object)
		}
	}

	fi, err := l.client.Stat(name)
	if err != nil {
		return objInfo, irodsToObjectErr(ctx, err, bucket, object)
	}

	return minio.ObjectInfo{
		Bucket:  bucket,
		Name:    object,
		ETag:    r.MD5CurrentHexString(),
		ModTime: fi.ModifyTime,
		Size:    fi.Size,
		IsDir:   fi.Type == irodsclient_fs.DirectoryEntry,
		AccTime: fi.ModifyTime,
	}, nil
}

func (l *irodsObjects) CopyObject(ctx context.Context, srcBucket, srcObject, dstBucket, dstObject string, srcInfo minio.ObjectInfo, srcOpts, dstOpts minio.ObjectOptions) (minio.ObjectInfo, error) {
	cpSrcDstSame := minio.IsStringEqual(l.irodsPathJoin(srcBucket, srcObject), l.irodsPathJoin(dstBucket, dstObject))
	if cpSrcDstSame {
		return l.GetObjectInfo(ctx, srcBucket, srcObject, minio.ObjectOptions{})
	}

	return l.PutObject(ctx, dstBucket, dstObject, srcInfo.PutObjReader, minio.ObjectOptions{
		ServerSideEncryption: dstOpts.ServerSideEncryption,
		UserDefined:          srcInfo.UserDefined,
	})
}

func (l *irodsObjects) DeleteObject(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (minio.ObjectInfo, error) {
	err := irodsToObjectErr(ctx, l.deleteObject(l.irodsPathJoin(bucket), l.irodsPathJoin(bucket, object)), bucket, object)
	return minio.ObjectInfo{
		Bucket: bucket,
		Name:   object,
	}, err
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
func (a *irodsObjects) GetBucketPolicy(ctx context.Context, bucket string) (bucketPolicy *policy.Policy, err error) {
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
