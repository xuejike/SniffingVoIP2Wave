package com.github.xuejike.rtp;

import java.util.Objects;

public class MacMappingSSRC {
    private String srcMac;
    private String destMac;
    private String ssrc;
    private Long createTime = System.currentTimeMillis();

    public MacMappingSSRC() {
    }

    public MacMappingSSRC(String srcMac, String destMac, String ssrc) {
        this.srcMac = srcMac;
        this.destMac = destMac;
        this.ssrc = ssrc;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        MacMappingSSRC that = (MacMappingSSRC) o;

        if (!Objects.equals(srcMac, that.srcMac)) return false;
        if (!Objects.equals(destMac, that.destMac)) return false;
        return Objects.equals(ssrc, that.ssrc);
    }

    @Override
    public int hashCode() {
        int result = srcMac != null ? srcMac.hashCode() : 0;
        result = 31 * result + (destMac != null ? destMac.hashCode() : 0);
        result = 31 * result + (ssrc != null ? ssrc.hashCode() : 0);
        return result;
    }

    public String getSrcMac() {
        return srcMac;
    }

    public void setSrcMac(String srcMac) {
        this.srcMac = srcMac;
    }

    public String getDestMac() {
        return destMac;
    }

    public void setDestMac(String destMac) {
        this.destMac = destMac;
    }

    public String getSsrc() {
        return ssrc;
    }

    public void setSsrc(String ssrc) {
        this.ssrc = ssrc;
    }

    public Long getCreateTime() {
        return createTime;
    }

    public void setCreateTime(Long createTime) {
        this.createTime = createTime;
    }
}
