# import argparse
import datetime
import time
import json
import random
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# ignore the SSL server Certificate error
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# parser = argparse.ArgumentParser(description='Get the new license and apply it to your vthunder')
# parser.add_argument('-u', '--glm_username', help='the username for login to your GLM account.)
# parser.add_argument('-p', '--glm_password', help='the password for login to your GLM account.)
# parser.add_argument('-H', '--a10_host', help='the IP address for login to your vthunder.)
# parser.add_argument('-U', '--a10_username', help='the username for login to your vthunder.)
# parser.add_argument('-P', '--a10_password', help='the password for login to your vthunder.)

    glm_username = y.takamoto@scsk.jp
    glm_password = p4ssw0rD
    a10_host = 172.31.31.31
    a10_username = admin
    a10_password = PAsSwORd12345

def glm_login():
    '''
    Description: Method to log into glm.a10networks.com and return the auth token for follow up api calls.
    '''
    try:
        url = 'https://glm.a10networks.com/users/sign_in.json'
        json_header = {'Content-Type': 'application/json'}
        values = """
              {
                "user": {
                  "email": "%s",
                  "password": "%s"
                }
              }
            """ % (glm_username, glm_password)
        r = requests.post(url, headers=json_header, data=values, verify=False)
        content = r.content
        parsed_json = json.loads(content)
        user_token = parsed_json['user_token']
        glm_req_header = {
            'Content-Type': 'application/json',
            'X-User-Email': glm_username,
            'X-User-Token': user_token
        }
        return glm_req_header

    except Exception as e:
        print('Error in glm_login: ', e)


def create_new_license_token(glm_req_header):
    '''
    Description: create the new trial license and get the value.
    '''
    try:
        date = datetime.date.today()
        url = 'https://glm.a10networks.com/licenses.json'
        r = requests.get(url, headers=glm_req_header)
        content = r.content
        parsed_json = json.loads(content)
        org_id = parsed_json[0]['organization_id']
        values = """
              {
                "license": {
                  "name": "trial-flexpool-%s",
                  "license_type": "cfw_cap_sub_trial",
                  "organization_id": "%s"
                }
              }
            """ % (date, org_id)
        r = requests.post(url, headers=glm_req_header,data=values, verify=False)
        content = r.content
        parsed_json = json.loads(content)
        new_token = parsed_json['token']
        return new_token

    except Exception as e:
        print('Error in get_new_license_token: ', e)


def get_available_license_token(glm_req_header):
    '''
    Description: get the available license token-id the bandwidths of which still remain.
    '''
    try:
        license_prefix = 'trial-flexpool'
        url = 'https://glm.a10networks.com/licenses.json'
        r = requests.get(url, headers=glm_req_header)
        content = r.content
        parsed_json = json.loads(content)
        available_tokens = [e['token'] for e in parsed_json if e['name'].startswith(license_prefix) and
                  e['remaining_bandwidth'] > 0]
        return available_tokens

    except Exception as e:
        print('Error in get_available_license_token: ', e)


def revoke_and_delete_expired_license(glm_req_header):
    '''
    Description: revoke the expired licenses and then clear them all.
    '''
    try:
        today = datetime.datetime.now()
        today_txt = today.strftime("%Y-%m-%d")
        today_txt2 = today_txt.replace('-', '')

        license_prefix = 'trial-flexpool'
        url = 'https://glm.a10networks.com/licenses.json'
        r = requests.get(url, headers=glm_req_header)
        content = r.content
        parsed_json = json.loads(content)
        expired_license_ids = [e['id'] for e in parsed_json
                                    if e['name'].startswith(license_prefix)
                                    and e['expires_at'][:10].replace('-', '') < today_txt2]
        print('check whether to exist the remaining expired licenses...')
        time.sleep(2)
        if not expired_license_ids:
            print("...licenses that should be revoked doesn't exist")
            return
        else:
            for expired_license_id in expired_license_ids:
                url = 'https://glm.a10networks.com/activations.json'
                r = requests.get(url, headers=glm_req_header)
                content = r.content
                parsed_json = json.loads(content)
                expired_ids = [{'id': e['id'], 'host_name': e['host_name']} for e in parsed_json
                              if e['license_id'] == expired_license_id ]

            # at first revoke the licenses
            for expired_id in expired_ids:
                url = 'https://glm.a10networks.com/activations/{}/revoke_activation.json'.format(expired_id['id'])
                r = requests.post(url, headers=glm_req_header, verify=False)
                content = r.content
                parsed_json = json.loads(content)
                print(expired_id['host_name'] + ": " + parsed_json['message'])

            # finally delete the licenses
            for expired_license_id in expired_license_ids:
                url = 'https://glm.a10networks.com/licenses/{}.json'.format(expired_license_id)
                requests.delete(url, headers=glm_req_header, verify=False)
                print("revoked licenses's completely deleted...!!")

    except Exception as e:
        print('Error in revoke_and_delete_expired_license: ', e)


# from here: aXAPI function
def a10_login():
    '''
    Description: Login to your vthunder and get the signature ID.
    '''
    try:
        url = 'https://{}/axapi/v3/auth'.format(a10_host)
        payload = {'credentials': {
            'username': a10_username,
            'password': a10_password}
        }
        headers = {'Content-Type': 'application/json'}
        r = requests.post(url, headers=headers, json=payload, verify=False)
        r_payload = json.loads(r.text)
        signature = r_payload['authresponse']['signature']
        if r.status_code == 200:
            print('Successfully logged in!')
            return signature

    except Exception as e:
        print('Error in a10_login: ', e)


def a10_logoff(sign):
    '''
    Description: Logoff from your vthunder.
    '''
    try:
        url = 'https://{}/axapi/v3/logoff'.format(a10_host)
        headers = {'Authorization': 'A10 {}'.format(sign)}
        r = requests.post(url, headers=headers, verify=False)
        if r.status_code == 200:
            print('Successfully logged out!')
            return

    except Exception as e:
        print('Error in a10_logoff: ', e)


def a10_write_memory(sign):
    '''
    Description: write memory.
    '''
    try:
        url = 'https://{}/axapi/v3/write/memory'.format(a10_host)
        headers = {'Authorization': 'A10 {}'.format(sign),
                   'Content-Type': 'application/json'}
        r = requests.post(url, headers=headers, verify=False)
        if r.status_code == 200:
            print('Successfully saved!')
            return

    except Exception as e:
        print('Error in a10_write_memory: ', e)


# clideploy: run some CLI commands and then export as a file
def a10_clideploy(sign, glm_token):
    '''
    Description: re-set the glm-commands and send GLM server the new license request.
    '''
    try:
        file_date = datetime.date.today()
        file_suffix = random.randrange(111111, 999999)
        url = 'https://{}/axapi/v3/clideploy'.format(a10_host)
        headers = {'Authorization': 'A10 {}'.format(sign),
                   'Content-Type': 'application/json'}
        payload1 = {'commandList':
                        ['glm enable-requests', 'glm allocate-bandwidth 2',
                            'glm token {}'.format(glm_token)]}
        requests.post(url, headers=headers, json=payload1, verify=False)
        print('thunder configuration...')
        time.sleep(1)
        payload2 = {'commandList':
                        ['glm send license-request']}
        requests.post(url, headers=headers, json=payload2, verify=False)
        print('sending license-request...')
        time.sleep(2)
        payload3 = {'commandList':
                        ['show license-info']}
        r = requests.post(url, headers=headers, json=payload3, verify=False)
        print('output license-info...')
        if r.status_code == 200:
            with open('show_license-info_{0}_{1}.txt'.format(file_date, file_suffix), 'w') as f:
                f.write(r.text)
                print('Successfully done!')

    except Exception as e:
        print('Error in a10_clideploy: ', e)


if __name__ == '__main__':
    glm_req_header = glm_login()
    revoke_and_delete_expired_license(glm_req_header)
    token_list = get_available_license_token(glm_req_header)
    if token_list:
        glm_token = random.choice(token_list)
    else:
        glm_token = create_new_license_token(glm_req_header)
    print('glm token:{} will be attached...'.format(glm_token))
    sign = a10_login()
    a10_clideploy(sign, glm_token)
    a10_write_memory(sign)
    a10_logoff(sign)