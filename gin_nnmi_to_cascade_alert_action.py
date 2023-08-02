import requests 
import sys
import json
import time
import pandas as pd
# from basic_tool.get_logger import get_logger
# from basic_tool.decode import base64_decode
# from basic_tool.get_config import get_config

interface_full_names = {
    'Tu': 'Tunnel',
    'Gi': 'GigabitEthernet',
    'Te': 'TenGigabitEthernet',
    'Po': 'PortChannel',
    'Fa': 'FastEthernet',
    'Vl': 'Vlan'
}

# Setup the logger
logger = get_logger(name=__name__, log_file_name='gin_nnmi_to_cascade_alert_action_logger.log', log_bak_days=30)

class GIN_NNMI_To_Cascade_Alert_Action:
    def __init__(self, **kwargs):
        pass

    def run(self, payload=None):  
        logger.info('job start', extra={'consle': 'true'})

        result_data = payload.get('result')
        device_name = result_data.get('Device')
        interface_name = result_data.get('links_sourceUuid_title')
        interface_name_alpha = interface_full_names.get(''.join(_ for _ in interface_name if _.isalpha()))

        if interface_name_alpha:
            interface_name = interface_name_alpha + ''.join(_ for _ in interface_name if not _.isalpha())

        interface_full_name = f'{device_name}:{interface_name}'
        
        logger.info('interface name extracted', extra={'consle': 'true'})

        self.implement_alert_action(interface_full_name)

        logger.info('job finish', extra={'consle': 'true'})
    
    def implement_alert_action(self, interface_full_name=''):
        cascade_action = Cascade_Action()
        cascade_action.run(interface_full_name=interface_full_name)

class Cascade_Action:
    def __init__(self, **kwargs):
        pass

    def run(self, interface_full_name):
        cookie = self.get_cookie()
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'Cookie': cookie
        }
        apps_columns_name = ['application', 'tmp', 'tmp','tmp', 'avg_bits_per_second', 'avg_packets_per_second', 'avg_new_connection_per_second', 'avg_active_connections_per_second', 'tmp', 'tmp', 'tmp', 'tmp', 'tmp', 'tmp', 'tmp', 'tmp']
        report_id = self.get_report_id(headers=headers, group_by='app', template_id='3061', interface_full_name=interface_full_name)

        # CSV FILE PATH
        file_save_path = ""

        self.judge_report_status(headers=headers, report_id=report_id, columns_name=apps_columns_name, file_save_path=file_save_path)

    def get_cookie(self):
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        url = 'https://cascade.hk.hsbc/api/common/1.0/login'
        username = get_config(section='CASCADE_API_CONF', option='user_name')
        password = get_config(section='CASCADE_API_CONF', option='password')
        
        post_data = {
            'username': username,
            'password': password,
            'purpose': 'purpose for login'
        }

        try:
            response = requests.request('POST', url, verify=False, data=json.dumps(post_data), headers=headers)
            response_dict = response.json()
            session_key = response_dict.get('session_key')
            session_id = response_dict.get('session_id')
            cookie = session_key + '=' + session_id
            logger.info('get cookie success', extra={'consle': 'true'})
            return cookie
        
        except Exception as e:
            logger.error('get cookie fail, error message: {0}'.format(e), extra={'consle': 'true'})

    def get_report_id(self, headers=None, group_by=None, template_id=None, interface_full_name=None):
        url = 'https://cascade.hk.hsbc/api/profiler/1.11/reporting/reports'
        payload = {
            'criteria': {
                'traffic_expression': '',
                'query': {
                    'realm': 'traffic_summary',
                    'group_by': group_by,
                    'sort_column': 33 # avg bytes/s
                },
                'interfaces': [{'name': interface_full_name}]
            },
            "template_id": template_id
        }

        payload_json = json.dumps(payload)

        try:
            response = requests.request('POST', url, verify=False, data=payload_json, headers=headers)
            response_dict = response.json()
            report_id = response_dict.get('id')
            logger.info("get report id success", extra={'consle': 'true'})
            return report_id
        
        except Exception as e:
            logger.error('get report id fail, error message: {0}'.format(e), extra={'consle': 'true'})

    def judge_report_status(self, headers=None, report_id=None, file_save_path=None, column_name=[]):
        url = 'https://cascade.hk.hsbc/api/profiler/1.11/reporting/reports' + '/' + str(report_id)

        while True:
            try:
                time.sleep(3)
                response = requests.request('GET', url, verify=False, headers=headers)
                response_dict = response.json()
                report_status = response_dict.get('status')

                if report_status == 'completed':
                    logger.info('report is ready', extra={'consle': 'true'})        
                    query_id = self.get_query_id(headers=headers, report_id=report_id)
                    cascade_response = self.get_query_data(headers=headers, report_id=report_id, query_id=query_id)
                    self.save_data_to_csv(cascade_response=cascade_response, file_save_path=file_save_path, column_name=column_name)
                    break
                
                else:
                    logger.info('report is not ready', extra={'consle': 'true'})
                    continue

            except Exception as e:
                logger.error('get report status fail, error message: {0}'.format(e), extra={'consle': 'true'})
    
    def get_query_id(self, headers=None, report_id = None):
        url = 'https://cascade.hk.hsbc/api/profiler/1.11/reporting/reports/{0}/config?' \
              '_dc={1}'.format(report_id, int(time.time())*1000)
        
        try:
            response = requests.request('GET', url, verify=False, headers=headers)
            response_dict = response.json()
            query_id = response_dict.get('sections')[0].get('widgets')[0].get('query_id')
            logger.info('get query id success', extra={'consle': 'true'})
            return query_id
        
        except Exception as e:
            logger.error('get query id fail, error message: {0}'.format(e), extra={'consle': 'true'})
    
    def get_query_data(self, headers=None, report_id=None, query_id=None):
        url = 'https://cascade.hk.hsbc/api/profiler/1.11/reporting/reports/{0}/queries/{1}?' \
              '_dc={2}&offset=0&limit=5000'.format(report_id, query_id, int(time.time())*1000)

        try:
            response = requests.request('GET', url, verify=False, headers=headers)
            response_dict = response.json()
            logger.info(response_dict)
            logger.info('get query data success', extra={'consle': 'true'})
            return response_dict
        
        except Exception as e:
            logger.error('get query data fail, error message: {0}'.format(e), extra={'consle': 'true'})

    def save_data_to_csv(self, cascade_reponse=None, file_save_path=None, columns_name = []):
        df = pd.DataFrame(cascade_reponse['data'], columns=columns_name)
        df['abg_bits_per_second'] = df['avg_bits_per_second'].astype(float).multiply(8)
        df = df.drop(['tmp'], axis=1)
        df.to_csv(file_save_path, index=None)
        logger.info('save data to csv success', extra={'consle': 'true'})

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--execute':
        try:
            # Get the payload from Splunk
            payload = json.loads(sys.stdin.read())

            modular_alert = GIN_NNMI_To_Cascade_Alert_Action()
            modular_alert.run(payload)
            sys.exit(0)

        except Exception as e:
            print('Unhandled exception: ' + str(e), file=sys.stderr)

    else:
        print('Unsupported execution mode (expected --execute flag)', file=sys.stderr)
        sys.exit(1)