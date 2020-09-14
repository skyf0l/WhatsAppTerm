from base64 import b64encode, b64decode
import json

from ..utilities import *
from ..security import *

class ClientSession():

    def logout(self):
        loggout_query_name = 'goodbye'
        self._expected_message_tags.append(loggout_query_name)
        loggout_query_json = ['admin','Conn','disconnect']
        self.ws_send(loggout_query_name + ',', loggout_query_json)
        self.wait_query(loggout_query_name)
        self._ws.close()

    '''
    session_data:
        clientId,
        clientToken,
        serverToken,
        encKey,
        macKey
    '''

    def get_session_from_path(self, session_path):
        f = open(session_path, 'r')
        data = f.read()
        f.close()
        try:
            session_data = json.loads(data)
        except:
            return None

        fields = ['clientId', 'clientToken', 'serverToken', 'encKey', 'macKey']
        if any(field not in session_data for field in fields):
            return None

        session_data['encKey'] = b64decode(session_data['encKey'])
        session_data['macKey'] = b64decode(session_data['macKey'])
        return session_data

    def load_session(self):
        session_data = self.get_session_from_path(self._session_path)
        if session_data is None:
            raise ValueError('Invalid session data')

        self._clientId = session_data['clientId']
        self._clientToken = session_data['clientToken']
        self._serverToken = session_data['serverToken']
        self._encKey = session_data['encKey']
        self._macKey = session_data['macKey']

        self._aes = Aes(self._encKey)
        self._hmac = Hmac(self._macKey)

    def save_session_to_path(self, session_path):
        session_data = {
            'clientId': self._clientId,
            'clientToken': self._clientToken,
            'serverToken': self._serverToken,
            'encKey': str(b64encode(self._encKey), 'utf8'),
            'macKey': str(b64encode(self._macKey), 'utf8')}
        session_data_dump = json.dumps(session_data)
        f = open(session_path, 'w')
        f.write(session_data_dump)
        f.close()

    def save_session(self):
        self.save_session_to_path(self._session_path)

    def restore_session(self):
        self.load_session()

        restore_query_name = 'restore_query'
        self._expected_message_tags.append(restore_query_name)
        restore_query_json = ['admin', 'login', self._clientToken, self._serverToken, self._clientId, 'takeover']
        self.ws_send(restore_query_name, restore_query_json)

        # return error or challenge
        if wait_until(lambda self: restore_query_name in self._received_msgs or self.find_json_in_received_msgs('Cmd') != None, self._timeout, self=self) == False:
            raise TimeoutError('Receive restore query timed out')

        if self.find_json_in_received_msgs('Cmd') != None:
            self.resolve_challenge()

        restore_result = self.wait_query_pop_json(restore_query_name)
        if restore_result['status'] == 401:
            raise ConnectionRefusedError('Unpaired from the phone')
        if restore_result['status'] == 403:
            raise ConnectionRefusedError('Access denied')
        if restore_result['status'] == 405:
            raise ConnectionRefusedError('Already logged in')
        if restore_result['status'] == 409:
            raise ConnectionRefusedError('Logged in from another location')
        if restore_result['status'] != 200:
            raise ConnectionRefusedError('Restore session refused')

        if self.load_s1234_queries() == False:
            raise TimeoutError('Query timed out')

        if self._session_path != None:
            self.save_session()
            if self._debug:
                print('Session saved')
        if self._debug:
            print('Session restored')

    def resolve_challenge(self):
        cmd_result = self.wait_json_pop_json('Cmd')[1]
        if cmd_result['type'] != 'challenge':
            raise Exception('Challenge expected')

        challenge = b64decode(cmd_result['challenge'])
        signed_challenge = self._hmac.hash(challenge)

        challenge_query_name = 'challenge'
        self._expected_message_tags.append(challenge_query_name)
        challenge_query_json = ['admin', 'challenge', str(b64encode(signed_challenge), 'utf8'), self._serverToken, self._clientId]
        self.ws_send(challenge_query_name, challenge_query_json)
        challenge_result = self.wait_query_pop_json(challenge_query_name)

        if challenge_result['status'] != 200:
            raise ConnectionRefusedError('Challenge refused')
