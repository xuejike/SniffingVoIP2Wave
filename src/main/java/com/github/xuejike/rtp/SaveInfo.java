package com.github.xuejike.rtp;

public class SaveInfo<T> {
    private String no;
    private String mac;
    private String file;
    private String destMac;
    private String srcMac;
    private Long begin = System.currentTimeMillis();
    private T target;
    public SaveInfo() {
    }

    public SaveInfo(String mac, String file) {
        this.mac = mac;
        this.file = file;
    }

    public String getNo() {
        return no;
    }

    public void setNo(String no) {
        this.no = no;
    }


    public String getMac() {
        return mac;
    }

    public void setMac(String mac) {
        this.mac = mac;
    }

    public String getFile() {
        return file;
    }

    public void setFile(String file) {
        this.file = file;
    }

    public T getTarget() {
        return target;
    }

    public void setTarget(T target) {
        this.target = target;
    }

    public String getDestMac() {
        return destMac;
    }

    public void setDestMac(String destMac) {
        this.destMac = destMac;
    }

    public String getSrcMac() {
        return srcMac;
    }

    public void setSrcMac(String srcMac) {
        this.srcMac = srcMac;
    }

    public Long getBegin() {
        return begin;
    }
}
