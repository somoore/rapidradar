import os
import boto3

def check_if_file_exists(bucket_name, object_key) -> bool:
    s3 = boto3.client('s3')
    base_kwargs = {
        'Bucket': bucket_name,
        'Prefix': object_key
    }
    try:
        result = s3.list_objects_v2(**base_kwargs)
        if result['KeyCount'] == 0:
            return False
        return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
        return False

def store_report(file_path, bucket_name, object_key) -> bool:
    s3_res = boto3.resource('s3')
    try:
        s3_res.meta.client.upload_file(file_path, bucket_name, object_key)
    except Exception as error:
        print(f"[ERROR] Could not upload CSV to S3 Bucket: {str(error)}")
        return False
    return True

def get_s3_files(bucket_name, prefix) -> str:
    s3 = boto3.client('s3')
    next_token = ''
    base_kwargs = {
        'Bucket': bucket_name,
        'Prefix': prefix,
    }
    keys = []
    folders = []
    try:
        while next_token is not None:
            kwargs = base_kwargs.copy()
            if next_token != '':
                kwargs.update({'ContinuationToken': next_token})
            results = s3.list_objects_v2(**kwargs)
            if 'Contents' in results:
                contents = results['Contents']
                for i in contents:
                    k = i['Key']
                    if k[-1] != '/':
                        keys.append(k)
                    else:
                        folders.append(k)
                if 'NextContinuationToken' in results:
                    next_token = results['NextContinuationToken']
                else:
                    next_token = None
            else:
                next_token = None
        for folder in folders:
            dest_pathname = os.path.join('/tmp/', folder)
            if not os.path.exists(os.path.dirname(dest_pathname)):
                os.makedirs(os.path.dirname(dest_pathname))
        for obj in keys:
            dest_pathname = os.path.join('/tmp/', obj)
            if not os.path.exists(os.path.dirname(dest_pathname)):
                os.makedirs(os.path.dirname(dest_pathname))
            s3.download_file(bucket_name, obj, dest_pathname)
    except Exception as error:
        print(f"[ERROR] {str(error)}")
        return False, keys
    return True, keys
