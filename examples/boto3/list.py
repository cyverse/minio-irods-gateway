#! /usr/bin/env python3

import os
import boto3

irods_user = os.environ.get('IRODS_USER_NAME', '')
irods_password = os.environ.get('IRODS_USER_PASSWORD', '')

s3 = boto3.resource('s3',
        endpoint_url="http://127.0.0.1:9000",
        aws_access_key_id=irods_user, 
        aws_secret_access_key=irods_password)

bucket = s3.Bucket('iychoi')
for my_bucket_object in bucket.objects.all():
    print(my_bucket_object.key)