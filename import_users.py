"""Pull IAM users and create local accounts for them with ssh keys from IAM as well.

Not Implemented:
removing old users
check IsTruncated/Pagination

Improvements:
stable uid/gid's
"""
import os
import pwd

import boto3

from botocore.exceptions import ClientError


def get_ssh_keys(iam, username):
    """Fetch ssh public keys from IAM and lay them down.

    iam - open connection to iam for fetching ssh pub keys
    """
    keys = iam.list_ssh_public_keys(UserName=username)
    for key in keys['SSHPublicKeys']:
        # print(key)
        keyinfo = iam.get_ssh_public_key(UserName=username,
                                         SSHPublicKeyId=key['SSHPublicKeyId'],
                                         Encoding='SSH')['SSHPublicKey']
        # print(keyinfo)
        if keyinfo['Status'] != 'Active':
            continue
        # add pub key to accepted_keys if not there
        try:
            osinfo = pwd.getpwnam(username)
            # no exception, the user already exists locally, update ssh pub keys
            akeys_file = "{}/.ssh/accepted_keys".format(osinfo.pw_dir)
            with open(akeys_file, 'a+') as afp:
                if keyinfo['SSHPublicKeyBody'] not in afp.read():
                    afp.write('# Added from AWS IAM\n{}\n\n'.format(keyinfo['SSHPublicKeyBody']))

        except Exception as exc:
            # we bubble this back up to the caller so it can add the user
            raise exc


def create_local_user(username):
    """Create a local Unix user."""
    os.system('adduser {}'.format(username))
    os.system('usermod -aG sudo {}'.format(username))


def main():
    """Get a list of users and add to the system."""
    iam = boto3.client('iam')
    iamr = boto3.resource('iam')

    for user in iamr.users.all():
        profile = user.LoginProfile()
        try:
            profile.load()
            # Do something with the profile
            # print(user.name, "has a profile", profile)
            try:
                get_ssh_keys(iam, user.name)
            except KeyError:
                # User doesn't exist locally, add user and then get ssh keys
                print("Adding user: {}".format(user.name))
                create_local_user(user.name)
                get_ssh_keys(iam, user.name)
        except ClientError:
            # They don't have a profile, so we ignore them... this means the account is disabled
            pass


if __name__ == '__main__':
    main()
