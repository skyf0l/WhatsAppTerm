from base64 import b64encode, b64decode

import json

def load_session(session_path):
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

def save_session(client, session_path):
    session_data = {
        'clientId': client._clientId,
        'clientToken': client._clientToken,
        'serverToken': client._serverToken,
        'encKey': str(b64encode(client._encKey), 'utf8'),
        'macKey': str(b64encode(client._macKey), 'utf8')}
    session_data_dump = json.dumps(session_data)
    f = open(session_path, 'w')
    f.write(session_data_dump)
    f.close()