def dict_in(subset, list):
    return subset.items() <= list.items()

class ClientPayloadAction():

    def set_battery(self, battery):
        self._battery['value'] = battery['value']
        self._battery['live'] = battery['live'] == 'true'
        self._battery['powersave'] = battery['powersave'] == 'true'

    def sub_action(self, name, content, data):
        if name == 'battery' and data == None:
            self.set_battery(content)
            return True

        elif name == 'contacts' and content == {'type': 'frequent'}:
            self.add_frequent_contacts(data)
            self._frequent_contacts_loaded = True
            return True

        return False

    def action(self, content, data):
        if content == None:
            sub_payload = data[0]
            sub_name = sub_payload[0]
            sub_content = sub_payload[1]
            sub_data = sub_payload[2]
            return self.sub_action(sub_name, sub_content, sub_data)

        elif (content == {'add': 'last'} or
            content == {'add': 'relay'} or
            content == {'add': 'update'} or
            content == {'add': 'before', 'last': 'true'}):
            self.add_messages(data)
            return True

        return False

    def response(self, content, data):
        if content == {'type': 'chat'}:
            self.add_chats(data)
            return True

        if dict_in({'type': 'contacts'}, content) and 'checksum' in content:
            self.add_contacts(data)
            self._contacts_loaded = True
            return True

        return False

    def payload_action(self, payload):
        name = payload[0]
        if len(payload) == 2:
            content = payload[1]
            pass
        elif len(payload) == 3:
            content = payload[1]
            data = payload[2]
            if name == 'action':
                return self.action(content, data)
            elif name == 'response':
                return self.response(content, data)
        return False