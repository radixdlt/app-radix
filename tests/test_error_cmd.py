import pytest

from radix_client.exception import *


@pytest.mark.xfail(raises=ClaNotSupportedError)
def test_bad_cla(cmd):
    sw, _ = cmd.transport.exchange(
        cla=0xA0, ins=0x03, p1=0x00, p2=0x00, cdata=b""  # 0xa0 instead of 0xAA
    )

    raise DeviceException(error_code=sw)


@pytest.mark.xfail(raises=InsNotSupportedError)
def test_bad_ins(cmd):
    sw, _ = cmd.transport.exchange(
        cla=0xAA, ins=0xFF, p1=0x00, p2=0x00, cdata=b""  # bad INS
    )

    raise DeviceException(error_code=sw)


@pytest.mark.xfail(raises=WrongP1P2Error)
def test_wrong_p1p2(cmd):
    sw, _ = cmd.transport.exchange(
        cla=0xAA, ins=0x03, p1=0x01, p2=0x00, cdata=b""  # 0x01 instead of 0x00
    )

    raise DeviceException(error_code=sw)


@pytest.mark.xfail(raises=WrongDataLengthError)
def test_wrong_data_length(cmd):
    # APDUs must be at least 5 bytes: CLA, INS, P1, P2, Lc.
    sw, _ = cmd.transport.exchange_raw("E000")

    raise DeviceException(error_code=sw)
