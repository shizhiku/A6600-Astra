"""Attach a diagnostic-only SIO ch0 responder to the local QEMU board model.

Clearly an assumption: it fabricates a reply byte so the firmware's wait can be
tested. Enabled only when REA_CH0_REPLY is set. Not a fidelity model.
"""
from pathlib import Path

p = Path('/root/qemu-11.1.3/hw/arm/sony_a6400.c')
s = p.read_text()

helper = '''
/*
 * DIAGNOSTIC ONLY (REA_CH0_REPLY=1): synthetic SIO ch0 peer.
 * The real ch0 peer is not modelled; without it the channel leaves the FIFO
 * unchanged and the guest reads back its own TX words. This hook fabricates a
 * reply so the effect of that missing peer can be measured. It is not a
 * fidelity model and must never be treated as original firmware behaviour.
 */
static void sony_a6400_ch0_diag(void *opaque, int ch, uint32_t mode,
                                uint8_t *buf, int len)
{
    if (!getenv("REA_CH0_REPLY") || len < 4) {
        return;
    }
    buf[3] = 0x40;
}

'''

anchor = 'static void sony_a6400_submicro_xfer(void *opaque, int ch, uint32_t mode,'
assert anchor in s
s = s.replace(anchor, helper + anchor, 1)

old = """            cxd90014_sio_attach_dir(sio, i, i == 3 ?
                                    sony_a6400_submicro_xfer :"""
new = """            cxd90014_sio_attach_dir(sio, i, i == 3 ?
                                    sony_a6400_submicro_xfer :
                                    i == 0 ? sony_a6400_ch0_diag :"""
assert old in s
s = s.replace(old, new, 1)

p.write_text(s)
print('patched ch0 diagnostic responder')
