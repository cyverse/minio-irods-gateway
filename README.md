# minio-irods-gateway
iRODS Gateway for MinIO

## Build Docker Image
```
docker build -t minio-irods-gateway:latest .
```

This will build a docker image `minio-irods-gateway:latest`.

## Run MinIO-iRODS-Gateway
```
export IRODS_USER_NAME=<username>
export IRODS_USER_PASSWORD=<password>

docker run -p 9001:9001 \
	-e "MINIO_ROOT_USER=${IRODS_USER_NAME}" \
	-e "MINIO_ROOT_PASSWORD=${IRODS_USER_PASSWORD}" \
	minio-irods-gateway:latest gateway --console-address :9001 irods \
	irods://data.cyverse.org:1247/iplant/home/iychoi
```

This will run the MinIO-iRODS-Gateway on port 9001.
MinIO Gateway Console Login Username will be `<username>`, and password will be `<password>`.
The MinIO-iRODS-Gateway will connect to CyVerse DataStore using following information.

- iRODS Host: data.cyverse.org
- iRODS Port: 1247
- iRODS Zone: iplant
- iRODS Collection Path to Mount: /iplant/home/iychoi

To access the gateway console, open up a web browser and access `localhost:9001`.


## References

Following MinIO Gateway implementations were used as references:

- [MinIO-HDFS-Gateway](https://github.com/minio/minio/tree/master/cmd/gateway/hdfs)


## License

Copyright (c) 2010-2021, The Arizona Board of Regents on behalf of The University of Arizona

All rights reserved.

Developed by: CyVerse as a collaboration between participants at BIO5 at The University of Arizona (the primary hosting institution), Cold Spring Harbor Laboratory, The University of Texas at Austin, and individual contributors. Find out more at http://www.cyverse.org/.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of CyVerse, BIO5, The University of Arizona, Cold Spring Harbor Laboratory, The University of Texas at Austin, nor the names of other contributors may be used to endorse or promote products derived from this software without specific prior written permission.


Please check [LICENSE](https://github.com/cyverse/minio-irods-gateway/tree/master/LICENSE) file.

