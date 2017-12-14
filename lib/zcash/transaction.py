# Copyright (C) 2017 Jack Grigg <jack@z.cash>
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from electrum.bitcoin import (
    bfh,
    bh2u,
    int_to_hex,
    var_int,
)
from electrum.transaction import (
    BCDataStream,
    Transaction,
    parse_input,
    parse_output,
)


# Zcash constants
G1_PREFIX_MASK = 0x02
G2_PREFIX_MASK = 0x0a

ZC_NUM_JS_INPUTS = 2
ZC_NUM_JS_OUTPUTS = 2
INCREMENTAL_MERKLE_TREE_DEPTH = 29
INCREMENTAL_MERKLE_TREE_DEPTH_TESTING = 4

ZC_NOTEPLAINTEXT_LEADING = 1
ZC_V_SIZE = 8
ZC_RHO_SIZE = 32
ZC_R_SIZE = 32
ZC_MEMO_SIZE = 512

ZC_NOTEPLAINTEXT_SIZE = ZC_NOTEPLAINTEXT_LEADING + ZC_V_SIZE + ZC_RHO_SIZE + ZC_R_SIZE + ZC_MEMO_SIZE

NOTEENCRYPTION_AUTH_BYTES = 16

ZC_NOTECIPHERTEXT_SIZE = ZC_NOTEPLAINTEXT_SIZE + NOTEENCRYPTION_AUTH_BYTES


def parse_g1(vds):
    d = {}
    leading_byte = vds.read_bytes(1)[0]
    if (leading_byte & (~1)) != G1_PREFIX_MASK:
        raise ValueError('lead byte of G1 point not recognized')
    d['y_lsb'] = leading_byte & 1
    d['x'] = vds.read_bytes(32)
    return d


def parse_g2(vds):
    d = {}
    leading_byte = vds.read_bytes(1)[0]
    if (leading_byte & (~1)) != G2_PREFIX_MASK:
        raise ValueError('lead byte of G2 point not recognized')
    d['y_gt'] = leading_byte & 1
    d['x'] = vds.read_bytes(64)
    return d


def parse_proof(vds):
    d = {}
    d['g_A']       = parse_g1(vds)
    d['g_A_prime'] = parse_g1(vds)
    d['g_B']       = parse_g2(vds)
    d['g_B_prime'] = parse_g1(vds)
    d['g_C']       = parse_g1(vds)
    d['g_C_prime'] = parse_g1(vds)
    d['g_K']       = parse_g1(vds)
    d['g_H']       = parse_g1(vds)
    return d


def parse_joinsplit(vds):
    d = {}
    d['vpub_old'] = vds.read_int64()
    d['vpub_new'] = vds.read_int64()
    d['anchor'] = vds.read_bytes(32)
    d['nullifiers'] = [vds.read_bytes(32) for i in range(ZC_NUM_JS_INPUTS)]
    d['commitments'] = [vds.read_bytes(32) for i in range(ZC_NUM_JS_OUTPUTS)]
    d['onetimePubKey'] = vds.read_bytes(32)
    d['randomSeed'] = vds.read_bytes(32)
    d['macs'] = [vds.read_bytes(32) for i in range(ZC_NUM_JS_INPUTS)]
    d['proof'] = parse_proof(vds)
    d['ciphertexts'] = [vds.read_bytes(ZC_NOTECIPHERTEXT_SIZE) for i in range(ZC_NUM_JS_OUTPUTS)]
    return d


def deserialize(raw):
    vds = BCDataStream()
    vds.write(bfh(raw))
    d = {}
    d['version'] = vds.read_int32()
    n_vin = vds.read_compact_size()
    d['inputs'] = [parse_input(vds) for i in range(n_vin)]
    n_vout = vds.read_compact_size()
    d['outputs'] = [parse_output(vds, i) for i in range(n_vout)]
    d['lockTime'] = vds.read_uint32()
    if d['version'] >= 2:
        n_vjoinsplit = vds.read_compact_size()
        d['joinsplits'] = [parse_joinsplit(vds) for i in range(n_vjoinsplit)]
        if d['joinsplits']:
            d['joinSplitPubKey'] = vds.read_bytes(32)
            d['joinSplitSig'] = vds.read_bytes(64)
    return d


class ZcashTransaction(Transaction):

    def __init__(self, raw):
        Transaction.__init__(self, raw)
        self._joinsplits = None
        self.joinSplitPubKey = None
        self.joinSplitSig = None

    def joinsplits(self):
        if self._joinsplits is None:
            self.deserialize()
        return self._joinsplits

    def deserialize(self):
        if self.raw is None:
            return
        if self._inputs is not None:
            return
        d = deserialize(self.raw)
        self._inputs = d['inputs']
        self._outputs = [(x['type'], x['address'], x['value']) for x in d['outputs']]
        self.locktime = d['lockTime']
        self.version = d['version']
        # Below are None if self.version == 2
        self._joinsplits = d.get('joinsplits')
        self.joinSplitPubKey = d.get('joinSplitPubKey')
        self.joinSplitSig = d.get('joinSplitSig')
        return d

    def serialize_g1(self, p):
        leading_byte = G1_PREFIX_MASK;
        if p['y_lsb']:
            leading_byte |= 1
        s = int_to_hex(leading_byte, 1)
        s += bh2u(p['x'])
        return s

    def serialize_g2(self, p):
        leading_byte = G2_PREFIX_MASK;
        if p['y_gt']:
            leading_byte |= 1
        s = int_to_hex(leading_byte, 1)
        s += bh2u(p['x'])
        return s

    def serialize_proof(self, proof):
        s  = self.serialize_g1(proof['g_A'])
        s += self.serialize_g1(proof['g_A_prime'])
        s += self.serialize_g2(proof['g_B'])
        s += self.serialize_g1(proof['g_B_prime'])
        s += self.serialize_g1(proof['g_C'])
        s += self.serialize_g1(proof['g_C_prime'])
        s += self.serialize_g1(proof['g_K'])
        s += self.serialize_g1(proof['g_H'])
        return s

    def serialize_joinsplit(self, jsdesc):
        s  = int_to_hex(jsdesc['vpub_old'], 8)
        s += int_to_hex(jsdesc['vpub_new'], 8)
        s += bh2u(jsdesc['anchor'])
        s += ''.join([bh2u(nf) for nf in jsdesc['nullifiers']])
        s += ''.join([bh2u(cm) for cm in jsdesc['commitments']])
        s += bh2u(jsdesc['onetimePubKey'])
        s += bh2u(jsdesc['randomSeed'])
        s += ''.join([bh2u(mac) for mac in jsdesc['macs']])
        s += self.serialize_proof(jsdesc['proof'])
        s += ''.join([bh2u(ct) for ct in jsdesc['ciphertexts']])
        return s

    def serialize(self, estimate_size=False, witness=False):
        if (witness):
            raise ValueError('No wtxid for Zcash')
        nVersion = int_to_hex(self.version, 4)
        nLocktime = int_to_hex(self.locktime, 4)
        inputs = self.inputs()
        outputs = self.outputs()
        txins = var_int(len(inputs)) + ''.join(self.serialize_input(txin, self.input_script(txin, estimate_size)) for txin in inputs)
        txouts = var_int(len(outputs)) + ''.join(self.serialize_output(o) for o in outputs)
        if self.version >= 2:
            joinsplits = self.joinsplits()
            txjoinsplits = var_int(len(joinsplits)) + ''.join(self.serialize_joinsplit(jsdesc) for jsdesc in joinsplits)
            if joinsplits:
                joinsplitpubkey = bh2u(self.joinSplitPubKey)
                joinsplitsig = bh2u(self.joinSplitSig)
                return nVersion + txins + txouts + nLocktime + txjoinsplits + joinsplitpubkey + joinsplitsig
            else:
                return nVersion + txins + txouts + nLocktime + txjoinsplits
        else:
            return nVersion + txins + txouts + nLocktime
