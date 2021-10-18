import sys
import os
import boto3
from secrets import choice
import psycopg2 as psycopg2
from psycopg2 import extensions
from botocore.exceptions import ClientError
import logging

logging.basicConfig(format='%(asctime)s %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

CONNECTOR_USERS_TABLE = os.environ.get('ConnectorUsersSchema') + '.' + os.environ.get('ConnectorUsersTable')
PROXY_PREFIX = os.environ.get('ProxyUsersPrefix')


def handler(event, context):
    logger.info('-----Starting the Utility-----')

    redshift_connection, aws_region = get_db_connection()

    cursor = redshift_connection.cursor()
    users = get_connector_users(cursor)

    logger.info('Number of users to be updated: {}'.format(len(users)))

    if len(users) != 0:
        # get asm clients
        for ar in users:
            corp_id = ar[0]
            aws_account_id = ar[1].replace('-', '').rstrip()
            is_active_user = ar[2]

            if is_active_user:
                logger.info('Running the utility for corp id: {}'.format(corp_id))
                # create a temp password
                temp_password = generate_dynamic_password()

                # get redshift groups for each user
                groups = get_redshift_groups(cursor, corp_id)

                # get select permissions on schemas for each user
                schemas = get_redshift_schemas(cursor, corp_id)

                # get select permissions on tables for each user
                tables = get_create_permissions(cursor, corp_id)

                proxy_user = PROXY_PREFIX + corp_id

                # check if proxy user exists in redshift
                if is_proxy_user_in_redshift(proxy_user, cursor):
                    # reset the password
                    reset_proxy_user_password(proxy_user, temp_password, cursor)
                else:
                    # create a new proxy user
                    if not create_redshift_proxy_user(cursor, corp_id, temp_password):
                        logger.error('Proxy user {} not created'.format(corp_id))
                        continue

                # add proxy user to group, grant select access to schemas
                add_proxy_user_group(cursor, groups, proxy_user)
                grant_select_access_schemas(cursor, schemas, proxy_user)
                grant_select_access_tables(cursor, tables, proxy_user)

                # get the asm client only once per
                asm_client = get_aws_secret_manager_client(aws_account_id, aws_region)

                # check if user exists in AWS Secrets Manager, if not, add
                if is_user_in_secrets_manager(asm_client, proxy_user) is False:
                    add_user_creds_secrets_manager(asm_client, proxy_user, temp_password)
                else:
                    # user already exists in AWS Secrets Manager, update the password
                    update_secrets_manager_password(asm_client, proxy_user, temp_password)

                # update the last_updated_date column of the Redshift table
                update_last_updated_date(cursor, corp_id)
                logger.info('Proxy user {} set up for user {}'.format(proxy_user, corp_id))

                # TODO: email log file to DBAs if new users were created
            else:
                asm_client = get_aws_secret_manager_client(aws_account_id, aws_region)
                remove_inactive_users(corp_id, asm_client, cursor)

        cursor.close()

    else:
        logger.info('No new users added to the {} table'.format(CONNECTOR_USERS_TABLE))

    logger.info('-----Utility run completed-----')

    return 0


def is_proxy_user_in_redshift(proxy_user, cursor):
    """
    Check if the proxy user is already created in Amazon Redshift
    """
    check_user_sql = "SELECT * from pg_user WHERE usename = '" + proxy_user + "'"
    try:
        cursor.execute(check_user_sql)
        user_list = cursor.fetchall()
    except Exception as e:
        logger.error('Error checking if proxy user {} exist in Amazon Redshift: '.format(proxy_user))
        raise e

    if len(user_list) == 1:
        logger.info('Proxy user {} exists in Amazon Redshift'.format(proxy_user))
        return True
    return False


def reset_proxy_user_password(proxy_user, password, cursor):
    """
    Reset the password of the proxy user
    """
    reset_password_sql = "ALTER USER " + proxy_user + " PASSWORD '" + password + "'"
    try:
        cursor.execute(reset_password_sql)
    except Exception as e:
        logger.error('Error resetting Amazon Redshift password for proxy user {} table'.format(proxy_user))
        raise e


def remove_inactive_users(inactive_user, asm_client, cursor):
    """
    Deletes the inactive proxy user from the Amazon Redshift connector users table and the AWS Secrets Manager
    """
    # remove user from connector_users table
    delete_user_sql = "DELETE FROM " + CONNECTOR_USERS_TABLE + " WHERE corp_id = '" + inactive_user + "'"
    try:
        cursor.execute(delete_user_sql)
    except Exception as e:
        logger.error('Error deleting inactive user from {} table: '.format(CONNECTOR_USERS_TABLE))
        raise e
    logger.info('Deleted inactive user {} from the Amazon Redshift {} table '.format(inactive_user,
                                                                                     CONNECTOR_USERS_TABLE))

    # remove the user from AWS Secrets Manager
    proxy_user = PROXY_PREFIX + inactive_user
    if is_user_in_secrets_manager(asm_client, proxy_user):
        if delete_user_in_asm(asm_client, proxy_user):
            logger.info('Deleted inactive user {} from AWS Secrets Manager '.format(proxy_user))
        else:
            logger.info('Error deleting user {} from AWS Secrets Manager '.format(proxy_user))
    else:
        logger.info('Secret does not exist in AWS Secrets Manager for user {}'.format(inactive_user))


def delete_user_in_asm(client, shadow_user):
    """
    Deletes the inactive proxy user from the AWS Secrets Manager
    """
    try:
        response = client.delete_secret(SecretId=shadow_user, ForceDeleteWithoutRecovery=True)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return True
        else:
            return False

    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.info("Secrets Manager can't decrypt the protected secret text using the provided KMS key")
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.info("Server side error")
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.info("You provided an invalid value for a parameter.")
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.info("You provided a parameter value that is not valid for the current state of the resource.")
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.info('User {} does not exist in AWS Secrets Manager'.format(shadow_user))
            raise e


def update_last_updated_date(cursor, user):
    """
    Updates the column in the Amazon Redshift connector Users table.
    """
    update_timestamp_sql = "UPDATE " + CONNECTOR_USERS_TABLE + " SET last_updated = SYSDATE WHERE corp_id  = '" + user + "'"
    try:
        cursor.execute(update_timestamp_sql)
        logger.info(
            'Updated the last_updated column of the user {} in the {} table'.format(user, CONNECTOR_USERS_TABLE))
    except Exception as e:
        logger.error('Error updating last_updated for user {}'.format(user))
        raise e


def convert_to_list(list_tuple):
    flat_list = [item for x in list_tuple for item in x]
    return flat_list


def update_secrets_manager_password(client, shadow_user, password):
    """
    Updates the password for the shadow user in AWS Secrets Manager
    """
    logger.info('User {} exists in AWS Secrets Manger, resetting the password'.format(shadow_user))
    try:
        client.update_secret(SecretId=shadow_user, SecretString=password)
    except Exception as e:
        logger.error('Error in resetting the Secret for user {}'.format(shadow_user))
        raise e


def add_user_creds_secrets_manager(client, shadow_user, password):
    """
    Adds the shadow user credentials in AWS Secrets Manager
    """
    try:
        response = client.create_secret(Name=shadow_user, SecretString=password)
        if response['ResponseMetadata']['HTTPStatusCode'] != 200:
            raise Exception(
                'Error in getting the AWS Secrets Manager client in add_user_creds_secrets_manager function')

    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.info("Secrets Manager can't decrypt the protected secret text using the provided KMS key")
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.info("Server side error")
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.info("You provided an invalid value for a parameter.")
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.info("You provided a parameter value that is not valid for the current state of the resource.")
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.info("User does not exist in AWS Secrets Manager")

    logger.info('User {} added to AWS Secrets Manager'.format(shadow_user))


def is_user_in_secrets_manager(client, shadow_user):
    """
    for a CORP User ID, checks if the shadow user already exists in AWS Secrets Manager
    """
    try:
        logger.info('Checking if user {} exist in AWS Secrets Manager'.format(shadow_user))

        response = client.get_secret_value(SecretId=shadow_user)

        if response['ResponseMetadata']['HTTPStatusCode'] != 200:
            raise Exception('Error in getting the AWS Secrets Manager client')

    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.info("Secrets Manager can't decrypt the protected secret text using the provided KMS key")
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.info("Server side error")
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.info("You provided an invalid value for a parameter.")
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.info("You provided a parameter value that is not valid for the current state of the resource.")
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            logger.info('User {} does not exist in AWS Secrets Manager'.format(shadow_user))
            return False
    return True


def get_aws_secret_manager_client(account_num, aws_region):
    """
    Assume a cross account IAM Role and get Amazon Secrets Manager boto3 client
    """
    sts_connection = boto3.client('sts')
    try:
        client = boto3.client(
            'secretsmanager',
            region_name=aws_region
        )

    except Exception as e:
        logger.error('Error in getting the AWS Secrets Manger client: {}'.format(e))
        raise e

    return client


def grant_select_access_tables(cursor, tables, user):
    if len(tables) > 0:
        for table in tables:
            grant_select_access_sql = "GRANT SELECT ON TABLE " + table + " TO " + user + "; "
            try:
                cursor.execute(grant_select_access_sql)
            except Exception as e:
                logger.error("Error executing SQL: {}".format(e))
                raise e
            logger.info("Granted SELECT to user {} on the table {}".format(user, table))


def grant_select_access_schemas(cursor, schemas, user):
    """
    Grant proxy user access to schemas that the corp user has access to.
    """
    if len(schemas) > 0:
        for schema in schemas:
            grant_usage_schema_sql = "GRANT USAGE ON SCHEMA " + schema + " TO " + user + ";"
            try:
                cursor.execute(grant_usage_schema_sql)
            except Exception as e:
                logger.error('Error granting schema access: {}'.format(e))
                raise e
            logger.info('Granted USAGE Access to user {} on schema {}'.format(user, schema))


def add_proxy_user_group(cursor, groups, user):
    """
    Add the proxy user to all the Amazon Redshift groups that the corp user belongs to.
    """
    if len(groups) > 0:
        for group in groups:
            add_group_sql = "ALTER GROUP " + group + " ADD USER " + user.lstrip().rstrip() + "; "
            try:
                cursor.execute(add_group_sql)
            except Exception as e:
                logger.error("Error executing SQL: {}".format(add_group_sql))
                raise e
            logger.info("Added user {} to Amazon Redshift group {}".format(user, group))


def create_redshift_proxy_user(cursor, user, temp_password):
    """
    Creates the proxy user in Amazon Redshift with passed password
    """
    logger.info('Creating proxy user {} for CorpID {}'.format(PROXY_PREFIX + user, user))
    create_proxy_user_sql = "CREATE USER " + PROXY_PREFIX + user.lstrip().rstrip() + " password '" + temp_password + "';"
    try:
        cursor.execute(create_proxy_user_sql)
    except Exception as e:
        logger.error('Error creating proxy user: {}'.format(e))
        raise e
    if str(cursor.statusmessage).lower() == 'create user':
        return True
    return False


def get_create_permissions(cursor, user):
    get_create_permissions_sql = "SELECT " \
                                 "t.tablename " \
                                 "FROM pg_user u " \
                                 "CROSS JOIN pg_tables t " \
                                 "WHERE " \
                                 "has_table_privilege(u.usename,t.tablename,'select') = true " \
                                 "AND u.usename = '" + user + "' " \
                                                              "AND t.schemaname NOT LIKE '%pg_%' " \
                                                              "AND t.schemaname NOT LIKE '%information_schema%'; "
    try:
        cursor.execute(get_create_permissions_sql)
        tables_create_permissions = cursor.fetchall()
    except Exception as e:
        logger.error('Error in executing SQL: {}'.format(get_create_permissions_sql))
        raise e

    return convert_to_list(tables_create_permissions)


def get_redshift_schemas(cursor, user):
    """
    Get all the Amazon Redshift schemas on which the user has create permissions
    """
    get_schemas_sql = "SELECT s.schemaname " \
                      "FROM pg_user u " \
                      "CROSS JOIN " \
                      "(SELECT DISTINCT schemaname FROM pg_tables) s " \
                      "WHERE has_schema_privilege(u.usename,s.schemaname,'create') = true " \
                      "AND u.usename = '" + user + "' " \
                                                   "AND s.schemaname NOT LIKE '%pg_%' " \
                                                   "AND s.schemaname NOT LIKE '%information_schema%' ;"
    try:
        cursor.execute(get_schemas_sql)
        schemas = cursor.fetchall()
    except Exception as e:
        logger.error('Error in executing SQL: {}'.format(get_schemas_sql))
        raise e
    return convert_to_list(schemas)


def get_redshift_groups(cursor, user):
    """
    Get all the Amazon Redshift groups that the user belongs to
    """
    get_groups_sql = "SELECT pg_group.groname " \
                     "FROM pg_group, pg_user " \
                     "WHERE pg_user.usesysid = ANY(pg_group.grolist) " \
                     "AND pg_user.usename IN ( '" + user + "' ) " \
                                                           "GROUP BY 1 " \
                                                           "ORDER BY 1"
    try:
        cursor.execute(get_groups_sql)
        list_groups = cursor.fetchall()
    except Exception as e:
        logger.error('Error in executing SQL: {}'.format(get_groups_sql))
        raise e
    return convert_to_list(list_groups)


def generate_dynamic_password():
    """
    Dynamically generates a password for the shadow user
    :return: Password
    """
    alphabet = '!$()*0123456789@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]_abcdefghijklmnopqrstuvwxyz{}~'
    while True:
        password = ''.join(choice(alphabet) for i in range(8))
        if any(c.islower() for c in password) and any(c.isupper() for c in password) \
                and sum(c.isdigit() for c in password) >= 2:
            break
    return password


def get_connector_users(cursor):
    """
    Get the list of users who need to be created, synced or deleted
    """
    get_connector_users_sql = "SELECT corp_id, aws_account, is_active FROM " + \
                              CONNECTOR_USERS_TABLE + " WHERE last_updated IS NULL " + \
                              " OR date(SYSDATE) - date(last_updated) > 29" + \
                              " OR is_active = False" + \
                              " ORDER BY aws_account, is_active"

    try:
        cursor.execute(get_connector_users_sql)
        users = cursor.fetchall()
    except Exception as e:
        logger.error('Error in executing SQL: {}'.format(get_connector_users_sql))
        raise e
    return users


def get_redshift_client(aws_region):
    sts_connection = boto3.client('sts')

    try:
        acct = sts_connection.assume_role(
            RoleArn="arn:aws:iam::431584782610:role/serverlessrepo-SyncRedshiftUse-ConnectorConfigRole-I78Q1Z1JQNY6",
            RoleSessionName="cgde_role"
        )

        ACCESS_KEY = acct['Credentials']['AccessKeyId']
        SECRET_KEY = acct['Credentials']['SecretAccessKey']
        SESSION_TOKEN = acct['Credentials']['SessionToken']

        client = boto3.client(
            'redshift',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN,
            region_name=aws_region
        )

    except Exception as ERROR:
        logger.error('Error in getting Amazon Redshift Cluster Credentials: {}'.format(ERROR))
        sys.exit(1)
    return client


def get_db_connection():
    """
    Get the Amazon Redshift client and connect to Redshift using the psycopg2 library
    """
    RS_PORT = os.environ.get('RedshiftPort')
    RS_USER = os.environ.get('RedshiftDBUser')
    DATABASE = os.environ.get('RedshiftDBName')
    CLUSTER_ID = os.environ.get('RedshiftClusterId')
    RS_HOST = os.environ.get('RedshiftDBUrl')
    REGION_NAME = os.environ.get('AWSRegion')

    client = boto3.client('redshift', region_name=REGION_NAME)

    try:

        cluster_creds = client.get_cluster_credentials(DbUser=RS_USER,
                                                       DbName=DATABASE,
                                                       ClusterIdentifier=CLUSTER_ID,
                                                       DurationSeconds=3600,
                                                       AutoCreate=False)

    except Exception as ERROR:
        logger.error('Error in getting Amazon Redshift Cluster Credentials: {}'.format(ERROR))
        sys.exit(1)

    try:

        conn = psycopg2.connect(
            host=RS_HOST,
            port=RS_PORT,
            user=cluster_creds['DbUser'],
            password=cluster_creds['DbPassword'],
            database=DATABASE
        )
        logger.info('HERE: {}, {}, {} '.format(conn, RS_PORT, cluster_creds['DbUser']))
    except Exception as ERROR:
        logger.error('Error in connecting to Amazon Redshift: {}'.format(ERROR))
        sys.exit(1)

    autocommit = extensions.ISOLATION_LEVEL_AUTOCOMMIT
    logger.info("ISOLATION_LEVEL_AUTOCOMMIT: {}".format(extensions.ISOLATION_LEVEL_AUTOCOMMIT))

    # set the isolation level for the connection's cursors
    # will raise ActiveSqlTransaction exception otherwise
    conn.set_isolation_level(autocommit)

    logger.info('Connected to Redshift!')

    return conn, REGION_NAME