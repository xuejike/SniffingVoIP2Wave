package com.github.xuejike.rtp;

import java.util.LinkedList;
import java.util.List;

public class SaveInfo<T> {
    private String no;
    private String mac;
    private String file;
    private List<String> destSSRC = new LinkedList<>();
    private List<String> srcSSRC = new LinkedList<>();
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

    public List<String> getDestSSRC() {
        return destSSRC;
    }

    public void setDestSSRC(List<String> destSSRC) {
        this.destSSRC = destSSRC;
    }

    public List<String> getSrcSSRC() {
        return srcSSRC;
    }

    public void setSrcSSRC(List<String> srcSSRC) {
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

    public T getTarget() {
        return target;
    }

    public void setTarget(T target) {
        this.target = target;
    }
}
