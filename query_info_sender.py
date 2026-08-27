import impacket.ntlm as ntlm

_orig_type3 = ntlm.getNTLMSSPType3
def _anon_type3(*args, **kwargs):
    kwargs['use_ntlmv2'] = False
    type3, key = _orig_type3(*args, **kwargs)
    # chimera requires the AUTHENTICATE blob to be >= 88 bytes (real clients pad
    # it out with Version/MIC fields); impacket's minimal anonymous message is
    # only 64 bytes, so pad it here.
    orig_getData = type3.getData
    def _padded_getData():
        data = orig_getData()
        if len(data) < 88:
            data = data + b'\x00' * (88 - len(data))
        return data
    type3.getData = _padded_getData
    return type3, key
ntlm.getNTLMSSPType3 = _anon_type3

# impacket's NTLMv1 anonymous shortcut returns str '' instead of bytes b'',
# which crashes KXKEY's byte-string concat; coerce it here.
_orig_v1 = ntlm.computeResponseNTLMv1
def _v1_bytes(*args, **kwargs):
    nt, lm, key = _orig_v1(*args, **kwargs)
    if isinstance(nt, str):
        nt = nt.encode()
    if isinstance(lm, str):
        lm = lm.encode()
    return nt, lm, key
ntlm.computeResponseNTLMv1 = _v1_bytes

from impacket.smbconnection import SMBConnection
from impacket.smb3structs import SMB2_QUERY_INFO, SMB2QueryInfo, SMB2QueryInfo_Response

HOST = "127.0.0.1"
SHARE = "share"
FILENAME = "big.txt"

conn = SMBConnection(HOST, HOST)
conn.login('', '')
tid = conn.connectTree(SHARE)
fid = conn.openFile(tid, '\\' + FILENAME)
smb3 = conn.getSMBServer()

def raw_query_info(treeId, fileId, infoType, fileInfoClass, outputBufferLength):
    packet = smb3.SMB_PACKET()
    packet['Command'] = SMB2_QUERY_INFO
    packet['TreeID']  = treeId

    qi = SMB2QueryInfo()
    qi['FileID']             = fileId
    qi['InfoType']           = infoType
    qi['FileInfoClass']      = fileInfoClass
    qi['OutputBufferLength'] = outputBufferLength
    qi['InputBufferOffset']  = 0
    qi['Buffer']             = b'\x00'

    packet['Data'] = qi
    packetID = smb3.sendSMB(packet)
    ans = smb3.recvSMB(packetID)

    status = ans['Status']
    buf = b''
    if len(ans['Data']) >= 8:
        resp = SMB2QueryInfo_Response(ans['Data'])
        buf = resp['Buffer']
    return status, buf

for length in (8, 40, 65535, 526):
    status, buf = raw_query_info(tid, fid, infoType=1, fileInfoClass=0x16, outputBufferLength=length)
    print("length=%-6d status=0x%08x actual_bytes=%d" % (length, status, len(buf)))

conn.close()