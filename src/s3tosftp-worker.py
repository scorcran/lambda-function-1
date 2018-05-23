import errno
import json
import os
import sys
import urllib
import logging

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

# We need to package pysftp with the Lambda function so add it to path
here = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(here, "vendored"))

import pysftp
import gnupg

# Lambda Environment Variables
success_topic_arn = os.environ['success_topic_arn']

# Other global variables
TMP_DIR = '/tmp'

# Initiate Logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Main Lambda Function

def lambda_handler(event, context):
    logger.info(event)

    if 'Records' in event and event['Records'][0]['EventSource'] == "aws:sns":
        message_body = json.loads(event['Records'][0]['Sns']['Message'])

        if message_body['Records'][0]['eventSource'] == "aws:s3":
            s3_event = message_body['Records'][0]['s3']
            s3_bucket = s3_event['bucket']['name']
            s3_key = s3_event['object']['key']
            event_time = message_body['Records'][0]['eventTime']

            s3_key = urllib.unquote(s3_key).decode('utf8').replace("+", " ")

            new_s3_object(s3_bucket, s3_key)

            send_success_notification(context, s3_bucket, s3_key, event_time)

            response = {
                "statusCode": 200,
                "body": "Uploaded {}".format(s3_key)
            }
            return response
    else:
        retry_failed_messages()

# AWS SNS Functions

def _publish_sns_message(context, sns_parameters, success_topic_arn):
    logger.info('Publishing SNS Notification to {}'.format(success_topic_arn))
    try:
        # AWS SNS Settings
        sns = boto3.client('sns')

        response = sns.publish(
            TopicArn=success_topic_arn,
            Message=json.dumps(sns_parameters),
            MessageStructure='string'
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            logger.info('Message published to {} successfully'.format(success_topic_arn))
    except ClientError as err:
        logger.error(str(err))
        raise

def _compile_sns_message(context, s3_bucket, s3_key, event_time):
    logger.info('Compiling SNS Message Attributes...')
    sns_parameters = {
        "request_id": context.aws_request_id,
        "event_time": event_time,
        "source_function": context.function_name,
        "object_bucket": s3_bucket,
        "object_key": s3_key,
        "message_attributes": {
            "footer": "S3-to-SFTP Pipeline",
            "title_link": "",
            "source": "S3 Bucket: {}".format(s3_bucket),
            "destination": "SFTP Location: {}".format(os.environ['SFTP_LOCATION'])
        }
    }
    return sns_parameters

def send_success_notification(context, s3_bucket, s3_key, event_time):
    """
    Sends success notification via AWS SNS
    """
    logger.info('Sending SNS success message...')
    sns_parameters = _compile_sns_message(context, s3_bucket, s3_key, event_time)
    # Send success Notification
    _publish_sns_message(context, sns_parameters, success_topic_arn)

# AWS SSM Parameter Store Functions

def _write_private_key(contents, private_key_path):
    try:
        logger.info('Creating Private Key file from SSM secure parameter store value...')
        private_key_file = open(private_key_path, 'w')
        private_key_file.write(contents)
        private_key_file.close()
    except Exception as err:
        logger.error(str(err))
        raise

def _secure_delete(path, passes=1):
    try:
        with open(path, "ab+") as delfile:
            length = delfile.tell()
            for i in range(passes):
                delfile.seek(0)
                delfile.write(os.urandom(length))
        os.remove(path)
    except Exception as err:
        logger.error(str(err))
        raise

def _get_ssm_parameter(name):
    logger.info('Retrieving {} SSM secure parameter value...'.format(name))
    try:
        # Initiate AWS SSM Client
        ssm = boto3.client('ssm', 'us-east-1')

        response = ssm.get_parameters(
            Names=[name],
            WithDecryption=True
        )
        for parameter in response['Parameters']:
            return parameter['Value']
    except Exception as err:
        logger.error(str(err))
        raise

def _create_key_file(file_path, parameter_name):
    # Local Lambda directory path to private key
    key_path = file_path
    # Get private key from SSM Parameter Store
    key = _get_ssm_parameter(parameter_name)
    # Write private key to file
    _write_private_key(key, key_path)

    return key_path

# AWS S3 Functions

def _download_s3_object(s3_bucket, s3_key):
    s3_object = os.path.basename(s3_key)
    logger.info('Downloading {} object to Lambda {} directory...'.format(s3_object, TMP_DIR))
    local_object_dir = '{}/{}'.format(TMP_DIR, os.path.dirname(s3_key))
    _create_local_tmp_dirs(local_object_dir)

    try:
        s3 = boto3.resource('s3', config=Config(signature_version='s3v4'))
        bucket = s3.Bucket(s3_bucket)
        bucket.download_file(s3_key, '{}/{}'.format(TMP_DIR, s3_key))

    except ClientError:
        logger.error('{} not found in {}'.format(s3_key, s3_bucket))
        raise

    except IOError:
        logger.error('Unable to download {}'.format(s3_key))
        raise

# SFTP Functions

def _upload_file(file_path):
    host = os.environ['SFTP_HOST']
    port = int(os.environ['SFTP_PORT'])
    user = os.environ['SFTP_USER']
    sftp_location = os.environ['SFTP_LOCATION']
    create_dir_structure = os.environ['SFTP_CREATE_DIR_STRUCTURE']

    if os.environ['PGP_ENCRYPT'] == "True":
        file_path = _encrypt_file(file_path)

    private_key = _create_key_file('{}/private_key.pem'.format(TMP_DIR), os.environ['SFTP_SSH_KEY_PARAM'])

    cnopts = pysftp.CnOpts()
    cnopts.hostkeys = None

    try:
        with pysftp.Connection(host=host, port=port,
                               username=user,
                               private_key=private_key,
                               cnopts=cnopts) as sftp:
            with sftp.cd(sftp_location):
                if create_dir_structure == "True":
                    sftp.makedirs(os.path.dirname(file_path))
                    sftp.put('{}/{}'.format(TMP_DIR, file_path), file_path)
                    logger.info('File {} uploaded successfully'.format(os.path.basename(file_path)))
                else:
                    filename = os.path.split(file_path)[1]
                    sftp.put('{}/{}'.format(TMP_DIR, file_path), filename)
                    logger.info('File {} uploaded successfully'.format(filename))

    except (pysftp.ConnectionException, pysftp.CredentialException,
            pysftp.SSHException, pysftp.AuthenticationException):
        logger.error('SFTP connection error')
        raise

    except IOError:
        logger.error('Failed to upload {}'.format(file_path))
        raise

    # Securely delete private key from Lambda
    _secure_delete(private_key, passes=1)

# Other Functions

def new_s3_object(s3_bucket, s3_key):
    try:
        _download_s3_object(s3_bucket, s3_key)
        _upload_file(s3_key)
    except Exception as err:
        logger.error(str(err))
        raise

def _create_local_tmp_dirs(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def retry_failed_messages():
    logger.info('Retrying failed messages in SQS Queue')
    queue_name = os.environ['QUEUE_NAME']

    sqs = boto3.resource('sqs')
    queue = sqs.get_queue_by_name(QueueName=queue_name)

    for message in queue.receive_messages(MaxNumberOfMessages=10):
        lambda_handler(json.loads(message.body), 'context')
        message.delete()

def _encrypt_file(file_path):
    logger.info('Encrypting {} before upload to SFTP destination...'.format(os.path.basename(file_path)))

    gpg = gnupg.GPG(gnupghome='{}/gpghome'.format(TMP_DIR))

    key_path = '{}/pgp_key.pub'.format(TMP_DIR)
    public_key = _create_key_file(key_path, os.environ['PGP_PUB_KEY_PARAM'])
    key_data = open(public_key).read()
    import_result = gpg.import_keys(key_data)

    keys = []

    for key in import_result.results:
        keys.append(key['fingerprint'])

    encrypted_file_path = '{}.{}'.format(file_path, ".enc")

    with open(file_path, 'rb') as f:
        encryption = gpg.encrypt_file(
            f, recipients=json.dumps(keys),
            output=encrypted_file_path, always_trust=True)

    if encryption.ok != True:
        raise

    return encrypted_file_path
