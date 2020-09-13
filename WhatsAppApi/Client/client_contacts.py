from ..utilities import *

class ClientContacts:

    def add_frequent_contacts(self, contacts):
        for contact in contacts:
            frequent_contact = {
                'jid': contact[1]['jid'],
                'type': contact[0]
            }
            self._frequent_contacts.append(frequent_contact)

    def add_contact(self, contact):
        try:
            if contact[0] == 'user' and contact[2] == None:
                data = contact[1]
                new_contact = {
                    'jid': data['jid'],
                    'type': 'user' if '@c.us' in data['jid'] else 'group',
                    'notify': data['notify'] if 'notify' in data else None,
                    'name': data['name'] if 'name' in data else (data['vname'] if 'vname' in data else None),
                    'short': data['short'] if 'short' in data else None
                    # unused data['verify']
                }
                self._contacts.append(new_contact)
            else:
                eprint_report('Unknown contact: {}'.format(contact))
        except Exception as e:
            eprint_report('Invalid contact: {}'.format(contact), add_traceback=True)

    def add_contacts(self, contacts):
        for contact in contacts:
            self.add_contact(contact)