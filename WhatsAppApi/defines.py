from .BinaryMessages.whatsapp_protobuf_pb2 import WebMessageInfo

import json
from google.protobuf import json_format

"""
WebMessage, Tags, ByteTokens and Metrics are inspired by
    https://github.com/sigalor/whatsapp-web-reveng/blob/master/backend/whatsapp_defines.py
"""

class WebMessage:

    @staticmethod
    def decode(data):
        msg = WebMessageInfo()
        msg.ParseFromString(data)
        return json.loads(json_format.MessageToJson(msg))

    @staticmethod
    def encode(msg):
        data = json_format.Parse(json.dumps(msg), WebMessageInfo(), ignore_unknown_fields=True)
        return data.SerializeToString()

class Tags:
    LIST_EMPTY      = 0
    STREAM_END      = 2
    DICTIONARY_0    = 236
    DICTIONARY_1    = 237
    DICTIONARY_2    = 238
    DICTIONARY_3    = 239
    LIST_8          = 248
    LIST_16         = 249
    JID_PAIR        = 250
    HEX_8           = 251
    BINARY_8        = 252
    BINARY_20       = 253
    BINARY_32       = 254
    NIBBLE_8        = 255
    SINGLE_BYTE_MAX = 256
    PACKED_MAX      = 254

ByteTokens = [
    None, None, None, '200', '400', '404', '500', '501', '502', 'action', 'add',
    'after', 'archive', 'author', 'available', 'battery', 'before', 'body',
    'broadcast', 'chat', 'clear', 'code', 'composing', 'contacts', 'count',
    'create', 'debug', 'delete', 'demote', 'duplicate', 'encoding', 'error',
    'false', 'filehash', 'from', 'g.us', 'group', 'groups_v2', 'height', 'id',
    'image', 'in', 'index', 'invis', 'item', 'jid', 'kind', 'last', 'leave',
    'live', 'log', 'media', 'message', 'mimetype', 'missing', 'modify', 'name',
    'notification', 'notify', 'out', 'owner', 'participant', 'paused',
    'picture', 'played', 'presence', 'preview', 'promote', 'query', 'raw',
    'read', 'receipt', 'received', 'recipient', 'recording', 'relay',
    'remove', 'response', 'resume', 'retry', 's.whatsapp.net', 'seconds',
    'set', 'size', 'status', 'subject', 'subscribe', 't', 'text', 'to', 'true',
    'type', 'unarchive', 'unavailable', 'url', 'user', 'value', 'web', 'width',
    'mute', 'read_only', 'admin', 'creator', 'short', 'update', 'powersave',
    'checksum', 'epoch', 'block', 'previous', '409', 'replaced', 'reason',
    'spam', 'modify_tag', 'message_info', 'delivery', 'emoji', 'title',
    'description', 'canonical-url', 'matched-text', 'star', 'unstar',
    'media_key', 'filename', 'identity', 'unread', 'page', 'page_count',
    'search', 'media_message', 'security', 'call_log', 'profile', 'ciphertext',
    'invite', 'gif', 'vcard', 'frequent', 'privacy', 'blacklist', 'whitelist',
    'verify', 'location', 'document', 'elapsed', 'revoke_invite', 'expiration',
    'unsubscribe', 'disable', 'vname', 'old_jid', 'new_jid', 'announcement',
    'locked', 'prop', 'label', 'color', 'call', 'offer', 'call-id',
    'quick_reply', 'sticker', 'pay_t', 'accept', 'reject', 'sticker_pack',
    'invalid', 'canceled', 'missed', 'connected', 'result', 'audio',
    'video', 'recent']

class Metrics:
    DEBUG_LOG               = 1
    QUERY_RESUME            = 2
    QUERY_RECEIPT           = 3
    QUERY_MEDIA             = 4
    QUERY_CHAT              = 5
    QUERY_CONTACTS          = 6
    QUERY_MESSAGES          = 7
    PRESENCE                = 8
    PRESENCE_SUBSCRIBE      = 9
    GROUP                   = 10
    READ                    = 11
    CHAT                    = 12
    RECEIVED                = 13
    PIC                     = 14
    STATUS                  = 15
    MESSAGE                 = 16
    QUERY_ACTIONS           = 17
    BLOCK                   = 18
    QUERY_GROUP             = 19
    QUERY_PREVIEW           = 20
    QUERY_EMOJI             = 21
    QUERY_MESSAGE_INFO      = 22
    SPAM                    = 23
    QUERY_SEARCH            = 24
    QUERY_IDENTITY          = 25
    QUERY_URL               = 26
    PROFILE                 = 27
    CONTACT                 = 28
    QUERY_VCARD             = 29
    QUERY_STATUS            = 30
    QUERY_STATUS_UPDATE     = 31
    PRIVACY_STATUS          = 32
    QUERY_LIVE_LOCATIONS    = 33
    LIVE_LOCATION           = 34
    QUERY_VNAME             = 35
    QUERY_LABELS            = 36
    CALL                    = 37
    QUERY_CALL              = 38
    QUERY_QUICK_REPLIES     = 39
    QUERY_CALL_OFFER        = 40
    QUERY_RESPONSE          = 41
    QUERY_STICKER_PACKS     = 42
    QUERY_STICKERS          = 43
    ADD_OR_REMOVE_LABELS    = 44
    QUERY_NEXT_LABEL_COLOR  = 45
    QUERY_LABEL_PALETTE     = 46
    CREATE_OR_DELETE_LABELS = 47
    EDIT_LABELS             = 48

class MessageStatus:
    Error       = 0
    Pending     = 1
    ServerAck   = 2
    DeliveryAck = 3
    Read        = 4
    Played      = 5

    keys = ['ERROR', 'PENDING', 'SERVER_ACK', 'DELIVERY_ACK', 'READ', 'PLAYED']

    def get(value):
        for key_id in range(len(MessageStatus.keys)):
            if value == MessageStatus.keys[key_id]:
                return key_id
        raise ValueError('MessageStatus {} unexist'.format(value))

    def to_string(value):
        if value < 0 or value >= len(MessageStatus.keys):
            raise ValueError('MessageStatus key_id {} unexist'.format(value))
        return MessageStatus.keys[value]

class MessageType:
    NoMessage                                  = -1
    Conversation                               = 0
    SenderKeyDistributionMessage               = 1
    ImageMessage                               = 2
    ContactMessage                             = 3
    LocationMessage                            = 4
    ExtendedTextMessage                        = 5
    DocumentMessage                            = 6
    AudioMessage                               = 7
    VideoMessage                               = 8
    Call                                       = 9
    Chat                                       = 10
    ProtocolMessage                            = 11
    ContactsArrayMessage                       = 12
    HighlyStructuredMessage                    = 13
    FastRatchetKeySenderKeyDistributionMessage = 14
    SendPaymentMessage                         = 15
    LiveLocationMessage                        = 16
    RequestPaymentMessage                      = 17
    DeclinePaymentRequestMessage               = 18
    CancelPaymentRequestMessage                = 19
    TemplateMessage                            = 20
    StickerMessage                             = 21

    keys = ['noMessage', 'conversation', 'senderKeyDistributionMessage', 'imageMessage', 'contactMessage', 'locationMessage', 'extendedTextMessage', 'documentMessage', 'audioMessage', 'videoMessage', 'call', 'chat', 'protocolMessage', 'contactsArrayMessage', 'highlyStructuredMessage', 'fastRatchetKeySenderKeyDistributionMessage', 'sendPaymentMessage', 'liveLocationMessage', 'requestPaymentMessage', 'declinePaymentRequestMessage', 'cancelPaymentRequestMessage', 'templateMessage', 'stickerMessage']

    def get(value):
        for key_id in range(len(MessageType.keys)):
            if value == MessageType.keys[key_id]:
                return key_id - 1
        raise ValueError('MessageType {} unexist'.format(value))

    def to_string(value):
        value += 1
        if value < 0 or value >= len(MessageType.keys):
            raise ValueError('MessageType key_id {} unexist'.format(value - 1))
        return MessageType.keys[value]

class MessageStubType:
    Unknown                                            = 0
    Revoke                                             = 1
    Ciphertext                                         = 2
    Futureproof                                        = 3
    NonVerifiedTransition                              = 4
    UnverifiedTransition                               = 5
    VerifiedTransition                                 = 6
    VerifiedLowUnknown                                 = 7
    VerifiedHigh                                       = 8
    VerifiedInitialUnknown                             = 9
    VerifiedInitialLow                                 = 10
    VerifiedInitialHigh                                = 11
    VerifiedTransitionAnyToNone                        = 12
    VerifiedTransitionAnyToHigh                        = 13
    VerifiedTransitionHighToLow                        = 14
    VerifiedTransitionHighToUnknown                    = 15
    VerifiedTransitionUnknownToLow                     = 16
    VerifiedTransitionLowToUnknown                     = 17
    VerifiedTransitionNoneToLow                        = 18
    VerifiedTransitionNoneToUnknown                    = 19
    GroupCreate                                        = 20
    GroupChangeSubject                                 = 21
    GroupChangeIcon                                    = 22
    GroupChangeInviteLink                              = 23
    GroupChangeDescription                             = 24
    GroupChangeRestrict                                = 25
    GroupChangeAnnounce                                = 26
    GroupParticipantAdd                                = 27
    GroupParticipantRemove                             = 28
    GroupParticipantPromote                            = 29
    GroupParticipantDemote                             = 30
    GroupParticipantInvite                             = 31
    GroupParticipantLeave                              = 32
    GroupParticipantChangeNumber                       = 33
    BroadcastCreate                                    = 34
    BroadcastAdd                                       = 35
    BroadcastRemove                                    = 36
    GenericNotification                                = 37
    E2EIdentityChanged                                 = 38
    E2EEncrypted                                       = 39
    CallMissedVoice                                    = 40
    CallMissedVideo                                    = 41
    IndividualChangeNumber                             = 42
    GroupDelete                                        = 43
    GroupAnnounceModeMessageBounce                     = 44
    CallMissedGroupVoice                               = 45
    CallMissedGroupVideo                               = 46
    PaymentCiphertext                                  = 47
    PaymentFutureproof                                 = 48
    PaymentTransactionStatusUpdateFailed               = 49
    PaymentTransactionStatusUpdateRefunded             = 50
    PaymentTransactionStatusUpdateRefundFailed         = 51
    PaymentTransactionStatusReceiverPendingSetup       = 52
    PaymentTransactionStatusReceiverSuccessAfterHiccup = 53
    PaymentActionAccountSetupReminder                  = 54
    PaymentActionSendPaymentReminder                   = 55
    PaymentActionSendPaymentInvitation                 = 56
    PaymentActionRequestDeclined                       = 57
    PaymentActionRequestExpired                        = 58
    PaymentActionRequestCancelled                      = 59
    BizVerifiedTransitionTopToBottom                   = 60
    BizVerifiedTransitionBottomToTop                   = 61
    BizIntroTop                                        = 62
    BizIntroBottom                                     = 63
    BizNameChange                                      = 64
    BizMoveToConsumerApp                               = 65
    BizTwoTierMigrationTop                             = 66
    BizTwoTierMigrationBottom                          = 67

    keys = ['UNKNOWN', 'REVOKE', 'CIPHERTEXT', 'FUTUREPROOF', 'NON_VERIFIED_TRANSITION', 'UNVERIFIED_TRANSITION', 'VERIFIED_TRANSITION', 'VERIFIED_LOW_UNKNOWN', 'VERIFIED_HIGH', 'VERIFIED_INITIAL_UNKNOWN', 'VERIFIED_INITIAL_LOW', 'VERIFIED_INITIAL_HIGH', 'VERIFIED_TRANSITION_ANY_TO_NONE', 'VERIFIED_TRANSITION_ANY_TO_HIGH', 'VERIFIED_TRANSITION_HIGH_TO_LOW', 'VERIFIED_TRANSITION_HIGH_TO_UNKNOWN', 'VERIFIED_TRANSITION_UNKNOWN_TO_LOW', 'VERIFIED_TRANSITION_LOW_TO_UNKNOWN', 'VERIFIED_TRANSITION_NONE_TO_LOW', 'VERIFIED_TRANSITION_NONE_TO_UNKNOWN', 'GROUP_CREATE', 'GROUP_CHANGE_SUBJECT', 'GROUP_CHANGE_ICON', 'GROUP_CHANGE_INVITE_LINK', 'GROUP_CHANGE_DESCRIPTION', 'GROUP_CHANGE_RESTRICT', 'GROUP_CHANGE_ANNOUNCE', 'GROUP_PARTICIPANT_ADD', 'GROUP_PARTICIPANT_REMOVE', 'GROUP_PARTICIPANT_PROMOTE', 'GROUP_PARTICIPANT_DEMOTE', 'GROUP_PARTICIPANT_INVITE', 'GROUP_PARTICIPANT_LEAVE', 'GROUP_PARTICIPANT_CHANGE_NUMBER', 'BROADCAST_CREATE', 'BROADCAST_ADD', 'BROADCAST_REMOVE', 'GENERIC_NOTIFICATION', 'E2E_IDENTITY_CHANGED', 'E2E_ENCRYPTED', 'CALL_MISSED_VOICE', 'CALL_MISSED_VIDEO', 'INDIVIDUAL_CHANGE_NUMBER', 'GROUP_DELETE', 'GROUP_ANNOUNCE_MODE_MESSAGE_BOUNCE', 'CALL_MISSED_GROUP_VOICE', 'CALL_MISSED_GROUP_VIDEO', 'PAYMENT_CIPHERTEXT', 'PAYMENT_FUTUREPROOF', 'PAYMENT_TRANSACTION_STATUS_UPDATE_FAILED', 'PAYMENT_TRANSACTION_STATUS_UPDATE_REFUNDED', 'PAYMENT_TRANSACTION_STATUS_UPDATE_REFUND_FAILED', 'PAYMENT_TRANSACTION_STATUS_RECEIVER_PENDING_SETUP', 'PAYMENT_TRANSACTION_STATUS_RECEIVER_SUCCESS_AFTER_HICCUP', 'PAYMENT_ACTION_ACCOUNT_SETUP_REMINDER', 'PAYMENT_ACTION_SEND_PAYMENT_REMINDER', 'PAYMENT_ACTION_SEND_PAYMENT_INVITATION', 'PAYMENT_ACTION_REQUEST_DECLINED', 'PAYMENT_ACTION_REQUEST_EXPIRED', 'PAYMENT_ACTION_REQUEST_CANCELLED', 'BIZ_VERIFIED_TRANSITION_TOP_TO_BOTTOM', 'BIZ_VERIFIED_TRANSITION_BOTTOM_TO_TOP', 'BIZ_INTRO_TOP', 'BIZ_INTRO_BOTTOM', 'BIZ_NAME_CHANGE', 'BIZ_MOVE_TO_CONSUMER_APP', 'BIZ_TWO_TIER_MIGRATION_TOP', 'BIZ_TWO_TIER_MIGRATION_BOTTOM', 'OVERSIZED']

    def get(value):
        for key_id in range(len(MessageStubType.keys)):
            if value == MessageStubType.keys[key_id]:
                return key_id
        raise ValueError('MessageStubType {} unexist'.format(value))

    def to_string(value):
        if value < 0 or value >= len(MessageStubType.keys):
            raise ValueError('MessageStubType key_id {} unexist'.format(value))
        return MessageStubType.keys[value]

class UserStatus:
    Unknown     = 0
    Unavailable = 1
    Available   = 2
    Composing   = 3
    Recording   = 4

    keys = ['unknown', 'unavailable', 'available', 'composing', 'recording']

    def get(value):
        for key_id in range(len(UserStatus.keys)):
            if value == UserStatus.keys[key_id]:
                return key_id
        raise ValueError('UserStatus {} unexist'.format(value))

    def to_string(value):
        if value < 0 or value >= len(UserStatus.keys):
            raise ValueError('UserStatus key_id {} unexist'.format(value))
        return UserStatus.keys[value]