# see LICENSE
"""Classes for processing received SMS"""

from datetime import datetime, timedelta

from messaging.utils import (swap, swap_number, encode_bytes, debug,
                             unpack_msg, unpack_msg2, to_array)
from messaging.sms import consts
from messaging.sms.base import SmsBase
from messaging.sms.udh import UserDataHeader


class SmsDeliver(SmsBase):
    """I am a delivered SMS in your Inbox"""

    def __init__(self, pdu, strict=True):
        super(SmsDeliver, self).__init__()
        self._pdu = None
        self._strict = strict
        self.date = None
        self.mtype = None
        self.sr = None

        #2bit SC to MS Message type
        self.tp_mti = None
        #Boolean, indicate if there is more message to send
        self.tp_mms = None
        #Boolean, indicate if udh presend
        self.tp_udhi = None

        self.pdu = pdu

    @property
    def data(self):
        """
        Returns a dict populated with the SMS attributes

        It mimics the old API to ease the port to the new API
        """
        ret = {
            'text': self.text,
            'pid': self.pid,
            'dcs': self.dcs,
            'csca': self.csca,
            'number': self.number,
            'type': self.tp_mti,
            'date': self.date,
            'fmt': self.fmt,
            'sr': self.sr,
        }

        if self.udh is not None:
            if self.udh.concat is not None:
                ret.update({
                    'ref': self.udh.concat.ref,
                    'cnt': self.udh.concat.cnt,
                    'seq': self.udh.concat.seq,
                })

        return ret

    def _set_pdu(self, pdu):
        if not self._strict and len(pdu) % 2:
            # if not strict and PDU-length is odd, remove the last character
            # and make it even. See the discussion of this bug at
            # http://github.com/pmarti/python-messaging/issues#issue/7
            pdu = pdu[:-1]

        if len(pdu) % 2:
            raise ValueError("Can not decode an odd-length pdu")

        # XXX: Should we keep the original PDU or the modified one?
        self._pdu = pdu

        data = to_array(self._pdu)

        # Service centre address
        smscl = data.pop(0)
        if smscl > 0:
            smscertype = data.pop(0)
            smscl -= 1
            self.csca = swap_number(encode_bytes(data[:smscl]))
            if (smscertype >> 4) & 0x07 == consts.INTERNATIONAL:
                self.csca = '+%s' % self.csca
            data = data[smscl:]
        else:
            self.csca = None

        # 1 byte(octet) == 2 HEX char
        # TP_MTI, Message type bits 0,1
        # TP_MMS, More messages to send/deliver bit 2
        # TP_SRI, Status report request indicated bit 5
        # TP_UHDI, User Data Header Indicator bit 6
        # TP_RP, Reply path set bit 7
        try:
            self.mtype = data.pop(0)
        except TypeError:
            raise ValueError("Decoding this type of SMS is not supported yet")

        #0 0    SC->MS  SMS-DELIVER
        #0 1    SC->MS  SMS-SUBMIT-REPORT ( Not supported yet )
        #1 0    SC->MS  SMS-STATUS-REPORT
        #1 1    Any     Reserved
        self.tp_mti = self.mtype & 0b00000011

        #TP-More-Messages-to-Send (TP-MMS) in SMS-DELIVER (0 = more messages)
        self.tp_mms = False if self.mtype & 0b00000100 else True

        #Indicate if message has UDH
        self.tp_udhi = True if self.mtype & 0b01000000 else False

        if self.tp_mti == 0b11:
            raise ValueError("Decoding this type of SMS is not supported")

        if self.tp_mti == 0b10:
            return self._decode_status_report_pdu(data)

        if self.tp_mti == 0b01:
            raise ValueError("Cannot decode a SmsSubmitReport message yet")

        sndlen = data.pop(0)
        if sndlen % 2:
            sndlen += 1
        sndlen = int(sndlen / 2.0)

        sndtype = (data.pop(0) >> 4) & 0x07
        if sndtype == consts.ALPHANUMERIC:
            # coded according to 3GPP TS 23.038 [9] GSM 7-bit default alphabet
            sender = unpack_msg2(data[:sndlen]).decode("gsm0338")
        else:
            # Extract phone number of sender
            sender = swap_number(encode_bytes(data[:sndlen]))
            if sndtype == consts.INTERNATIONAL:
                sender = '+%s' % sender

        self.number = sender
        data = data[sndlen:]

        # 1 byte TP-PID (Protocol IDentifier)
        self.pid = data.pop(0)
        # 1 byte TP-DCS (Data Coding Scheme)
        self.dcs = data.pop(0)
        if self.dcs & (0x04 | 0x08) == 0:
            self.fmt = 0x00
        elif self.dcs & 0x04:
            self.fmt = 0x04
        elif self.dcs & 0x08:
            self.fmt = 0x08

        datestr = ''
        # Get date stamp (sender's local time)
        date = list(encode_bytes(data[:6]))
        for n in range(1, len(date), 2):
            date[n - 1], date[n] = date[n], date[n - 1]

        data = data[6:]

        # Get sender's offset from GMT (TS 23.040 TP-SCTS)
        tz = data.pop(0)

        offset = ((tz & 0x07) * 10 + ((tz & 0xf0) >> 4)) * 15
        if (tz & 0x08):
            offset = offset * -1

        #  02/08/26 19:37:41
        datestr = "%s%s/%s%s/%s%s %s%s:%s%s:%s%s" % tuple(date)
        outputfmt = '%y/%m/%d %H:%M:%S'

        sndlocaltime = datetime.strptime(datestr, outputfmt)
        sndoffset = timedelta(minutes=offset)
        # date as UTC
        self.date = sndlocaltime - sndoffset

        self._process_message(data)

    def _process_message(self, data):
        # Now get message body
        msgl = data.pop(0)
        msg = encode_bytes(data[:msgl])
        # check for header
        headlen = ud_len = 0

        if self.tp_udhi:  # UDHI present
            ud_len = data.pop(0)
            self.udh = UserDataHeader.from_bytes(data[:ud_len])
            headlen = (ud_len + 1) * 8
            if self.fmt == 0x00:
                while headlen % 7:
                    headlen += 1
                headlen /= 7

            headlen = int(headlen)

        if self.fmt == 0x00:
            # XXX: Use unpack_msg2
            data = data[ud_len:].tolist()
            #self.text = unpack_msg2(data).decode("gsm0338")
            self.text = unpack_msg(msg)[headlen:msgl].decode("gsm0338")

        elif self.fmt == 0x04:
            self.text = data[ud_len:].tostring()

        elif self.fmt == 0x08:
            data = data[ud_len:].tolist()
            _bytes = [int("%02X%02X" % (data[i], data[i + 1]), 16)
                      for i in range(0, len(data), 2)]
            self.text = u''.join(list(map(unichr, _bytes)))

    pdu = property(lambda self: self._pdu, _set_pdu)

    def _decode_status_report_pdu(self, data):
        self.udh = UserDataHeader.from_status_report_ref(data.pop(0))

        sndlen = data.pop(0)
        if sndlen % 2:
            sndlen += 1
        sndlen = int(sndlen / 2.0)

        sndtype = data.pop(0)
        recipient = swap_number(encode_bytes(data[:sndlen]))
        if (sndtype >> 4) & 0x07 == consts.INTERNATIONAL:
            recipient = '+%s' % recipient

        data = data[sndlen:]

        datestr = ''
        # Get date stamp (sender's local time)
        date = list(encode_bytes(data[:6]))
        for n in range(1, len(date), 2):
            date[n - 1], date[n] = date[n], date[n - 1]

        data = data[6:]

        # Get sender's offset from GMT (TS 23.040 TP-SCTS)
        tz = data.pop(0)

        offset = ((tz & 0x07) * 10 + ((tz & 0xf0) >> 4)) * 15
        if (tz & 0x08):
            offset = offset * -1

        #  02/08/26 19:37:41
        datestr = "%s%s/%s%s/%s%s %s%s:%s%s:%s%s" % tuple(date)
        outputfmt = '%y/%m/%d %H:%M:%S'

        sndlocaltime = datetime.strptime(datestr, outputfmt)
        sndoffset = timedelta(minutes=offset)
        # date as UTC
        self.date = sndlocaltime - sndoffset
        scts_str = datestr


        datestr = ''
        # Get date stamp (sender's local time)
        date = list(encode_bytes(data[:6]))
        for n in range(1, len(date), 2):
            date[n - 1], date[n] = date[n], date[n - 1]

        data = data[6:]

        # Get sender's offset from GMT (TS 23.040 TP-SCTS)
        tz = data.pop(0)

        offset = ((tz & 0x07) * 10 + ((tz & 0xf0) >> 4)) * 15
        if (tz & 0x08):
            offset = offset * -1

        #  02/08/26 19:37:41
        datestr = "%s%s/%s%s/%s%s %s%s:%s%s:%s%s" % tuple(date)
        outputfmt = '%y/%m/%d %H:%M:%S'

        sndlocaltime = datetime.strptime(datestr, outputfmt)
        sndoffset = timedelta(minutes=offset)
        # date as UTC
        dt = sndlocaltime - sndoffset
        dt_str = datestr


        msg_l = [recipient, scts_str]
        try:
            status = data.pop(0)
        except IndexError:
            # Yes it is entirely possible that a status report comes
            # with no status at all! I'm faking for now the values and
            # set it to SR-UNKNOWN as that's all we can do
            _status = None
            status = 0x1
            sender = 'SR-UNKNOWN'
            msg_l.append(dt_str)
        else:
            _status = status
            if status == 0x00:
                msg_l.append(dt_str)
            else:
                msg_l.append('')
            if status == 0x00:
                sender = "SR-OK"
            elif status == 0x1:
                sender = "SR-UNKNOWN"
            elif status == 0x30:
                sender = "SR-STORED"
            else:
                sender = "SR-UNKNOWN"

        self.number = sender
        self.text = "|".join(msg_l)
        self.fmt = 0x08   # UCS2

        self.sr = {
            'recipient': recipient,
            'scts': self.date,
            'dt': dt,
            'status': _status
        }
