package com.github.xuejike.rtp;

/**
 * @author xuejike
 */
public interface SaveRTPCallback {
    void saveEvent(String srcMac,String destMac,byte[] waveData);

}
