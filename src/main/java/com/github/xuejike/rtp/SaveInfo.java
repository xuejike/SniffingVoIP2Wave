package com.github.xuejike.rtp;

public class SaveInfo {
    private String no;
    private String mac;
    private String file;
    private String destSSRC;
    private String srcSSRC;

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

    public String getDestSSRC() {
        return destSSRC;
    }

    public void setDestSSRC(String destSSRC) {
        this.destSSRC = destSSRC;
    }

    public String getSrcSSRC() {
        return srcSSRC;
    }

    public void setSrcSSRC(String srcSSRC) {
        this.srcSSRC = srcSSRC;
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
}
