#! /usr/bin/env python3

import os
from minio import Minio

irods_user = os.environ.get('IRODS_USER_NAME', '')
irods_password = os.environ.get('IRODS_USER_PASSWORD', '')

client = Minio("127.0.0.1:9000",
            access_key=irods_user,
            secret_key=irods_password,
            secure=False)

objects = client.list_objects("iychoi")
for obj in objects:
    print(obj.object_name)
