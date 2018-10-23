package com.github.xuejike.rtp;

import com.github.xuejike.unsigned.number.UByte;
import com.github.xuejike.unsigned.number.UInt;
import com.github.xuejike.unsigned.number.UShort;

import java.util.Arrays;

/**
 * @author xuejike
 */
public class RtpPacket implements Comparable{
    protected byte[] rawData;
    protected UByte payloadType;
    protected UShort seq;
    protected String destIp;
    protected String srcIp;
    protected String destMac;
    protected String srcMac;
    protected String ssrc;
    protected UInt timestamp;
    protected byte[] payload;



    public RtpPacket(byte[] rawData) {
        this.rawData = rawData;
        payloadType=new UByte(rawData[1]);
        seq=new UShort(Arrays.copyOfRange(rawData,2,4));
        timestamp=new UInt(Arrays.copyOfRange(rawData,4,8));
        ssrc=PCMHelper.bytesToHexString(Arrays.copyOfRange(rawData,8,12));
        payload=Arrays.copyOfRange(rawData,12,rawData.length);
    }

    public RtpPacket(byte[] rawData, String destIp, String srcIp, String srcMac, String destMac) {
        this(rawData);
        this.destIp = destIp;
        this.srcIp = srcIp;
        this.srcMac = srcMac;
        this.destMac = destMac;
    }

    @Override
    public int compareTo(Object o) {
        long l = ((RtpPacket) o).seq.longValue();
        return (int) (seq.longValue()-l);
    }


    public byte[] getRawData() {
        return rawData;
    }

    public UByte getPayloadType() {
        return payloadType;
    }

    public UShort getSeq() {
        return seq;
    }

    public String getDestIp() {
        return destIp;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public String getDestMac() {
        return destMac;
    }

    public String getSrcMac() {
        return srcMac;
    }

    public String getSsrc() {
        return ssrc;
    }

    public UInt getTimestamp() {
        return timestamp;
    }

    public byte[] getPayload() {
        return payload;
    }
}
