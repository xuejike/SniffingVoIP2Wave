package com.github.xuejike.rtp;

import org.pcap4j.packet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * @author xuejike
 */
public class RtpAnalysis {
    private static Logger logger= LoggerFactory.getLogger(RtpAnalysis.class);
    protected ExecutorService dealPool;
    protected Timer cleanTimer=new Timer(true);
    protected HashMap<String, List<RtpPacket>> rtpMap=new HashMap<>();
    protected HashMap<String,String> macRTPMap=new HashMap<>();
    protected HashMap<String,Long> rtpUpdate = new HashMap<>();
    protected List<String> cleanKey=new ArrayList<>(10);
    protected SaveRTPCallback saveRTPCallback= (srcMac, destMac, waveData) -> {
        logger.info("saveEvent : {}->{}",srcMac,destMac);
    };

    protected FindRTPCallback findRTPCallback = (srcMac, destMac, ssrc) -> {
        logger.info("findNewEvent : {}->{} ={}",srcMac,destMac,ssrc);
    };
    protected long saveLimit=1000*5;

    public RtpAnalysis(int threadPoolSize) {
        dealPool= Executors.newFixedThreadPool(threadPoolSize);
        cleanTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                for (Map.Entry<String, Long> entry : rtpUpdate.entrySet()) {
                    // 超过5秒 自动保存
                    if ((System.currentTimeMillis()-entry.getValue())>saveLimit){
                        String key = entry.getKey();

                        checkSaveRTP(key);

                    }
                }
                cleanKey.stream().forEach(k->{
                    rtpUpdate.remove(k);
                });
                cleanKey.clear();


            }
        },1000*5,1000*5);

    }

    public RtpAnalysis() {
        this(3);
    }

    public void setSaveRTPCallback(SaveRTPCallback saveRTPCallback) {
        this.saveRTPCallback = saveRTPCallback;
    }

    public void setFindRTPCallback(FindRTPCallback findRTPCallback) {
        this.findRTPCallback = findRTPCallback;
    }

    /**
     * 检测保存
     * @param key
     */
    private void checkSaveRTP(String key) {
        List<RtpPacket> rtpPackets = rtpMap.get(key);
        if (rtpPackets !=null && rtpPackets.size()>0){
            RtpPacket rtpPacket = rtpPackets.get(0);
            String destSSRC = macRTPMap.get(rtpPacket.destMac);
            if (destSSRC != null & rtpMap.get(destSSRC) != null){
                saveRtpDouble(rtpPackets,rtpMap.get(destSSRC));
                cleanRtpPacket(rtpPacket);
                cleanRtpPacket(rtpMap.get(destSSRC).get(0));
            }else{
                saveRtp(rtpPackets);
                cleanRtpPacket(rtpPacket);
            }
        }else{
            cleanKey.add(key);
            rtpMap.remove(key);
        }
    }

    /**
     * 清空无用Map
     * @param rtpPacket
     */
    private void cleanRtpPacket(RtpPacket rtpPacket) {
        rtpMap.remove(rtpPacket.ssrc);
        macRTPMap.remove(rtpPacket.srcMac);
        cleanKey.add(rtpPacket.ssrc);
    }

    /**
     * 保存单通道
     * @param rtpPackets
     */
    private void saveRtp(List<RtpPacket> rtpPackets) {
        RtpPacket rtpPacket = rtpPackets.get(0);
        byte[] baos = getRtpDataArray(rtpPackets);
        byte[] wave = PCMHelper.PCM2Wave(baos, 1, 8000, 8);
        saveRTPCallback.saveEvent(rtpPacket.srcMac,rtpPacket.destMac,wave);
    }

    /**
     * 获取RTP数据集
     * @param rtpPackets
     * @return
     */
    private byte[] getRtpDataArray(List<RtpPacket> rtpPackets) {
        Collections.sort(rtpPackets);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (RtpPacket packet : rtpPackets) {
            try {
                baos.write(packet.payload);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return baos.toByteArray();
    }

    /**
     * 保存双通道
     * @param rtpPackets1
     * @param rtpPackets2
     */
    private void saveRtpDouble(List<RtpPacket> rtpPackets1, List<RtpPacket> rtpPackets2) {
        if (rtpPackets1 != null || rtpPackets2 != null){
            if (rtpPackets1 ==null){
                saveRtp(rtpPackets2);
                return;
            }
            if (rtpPackets2 == null){
                saveRtp(rtpPackets1);
                return;
            }
            byte[] rtpArray1 = getRtpDataArray(rtpPackets1);
            byte[] rtpArray2 = getRtpDataArray(rtpPackets2);
            try {
                byte[] mergeRtp = mergeRtp(rtpArray1, rtpArray2);
                byte[] pcm2Wave = PCMHelper.PCM2Wave(mergeRtp, 2, 8000, 8);
                RtpPacket rtpPacket = rtpPackets1.get(0);
                saveRTPCallback.saveEvent(rtpPacket.srcMac,rtpPacket.destMac,pcm2Wave);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }

    private byte[] mergeRtp(byte[] rtpArray1, byte[] rtpArray2) throws IOException {
        if (rtpArray1.length <= rtpArray2.length){
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            for (int i = 0; i < rtpArray1.length; i++) {
                stream.write(new byte[]{rtpArray1[i],rtpArray2[i]});
            }
            for (int i = rtpArray1.length; i < rtpArray2.length; i++) {
                stream.write(new byte[]{(byte) 128,rtpArray2[i]});
            }
            return stream.toByteArray();
        }else{
            return mergeRtp(rtpArray2,rtpArray1);
        }


    }

    private void saveRtp(String key) {

        List<RtpPacket> rtpPackets = rtpMap.get(key);
        if (rtpPackets == null){
            return;
        }
        cleanKey.add(key);
        System.out.println("save --> "+key);
        rtpMap.remove(key);

    }

    public void read(Packet packet){
        dealPool.submit(()->{

            if (packet instanceof EthernetPacket){
                EthernetPacket.EthernetHeader header = ((EthernetPacket) packet).getHeader();
                if (packet.getPayload() instanceof IpV4Packet){
                    IpV4Packet ipV4Packet = (IpV4Packet) packet.getPayload();
                    if (ipV4Packet.getPayload() instanceof UdpPacket){
                        UdpPacket udpPacket = (UdpPacket) ipV4Packet.getPayload();
                        //判断是RTP包,RTP用UDP偶数端口
                        UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
                        if (udpHeader.getDstPort().valueAsInt() %2 == 0 && udpHeader.getSrcPort().valueAsInt() % 2 == 0){
                            if (udpPacket.getPayload() instanceof UnknownPacket){
                                UnknownPacket payload = (UnknownPacket) udpPacket.getPayload();
                                if (payload.getRawData()[0] == (byte) 0x80){

                                    String srcIpAddr = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
                                    String dstIpAddr = ipV4Packet.getHeader().getDstAddr().getHostAddress();
                                    String dstMacAddr = header.getDstAddr().toString().replaceAll(":","-");
                                    String srcMacAddr = header.getSrcAddr().toString().replaceAll(":","-");
                                    RtpPacket rtpPacket = new RtpPacket(payload.getRawData(), dstIpAddr, srcIpAddr, srcMacAddr, dstMacAddr);
                                    if (macRTPMap.get(srcMacAddr) != null && !macRTPMap.get(srcMacAddr).equals(rtpPacket.ssrc)){
                                        checkSaveRTP(macRTPMap.get(srcMacAddr));
                                    }
                                    findRTPCallback.findRTP(srcMacAddr,dstMacAddr,rtpPacket.ssrc);
                                    macRTPMap.put(srcMacAddr,rtpPacket.ssrc);
                                    List<RtpPacket> packetList = rtpMap.get(rtpPacket.ssrc);
                                    if (packetList == null){
                                        packetList=new LinkedList<RtpPacket>();
                                        rtpMap.put(rtpPacket.ssrc,packetList);
                                    }
                                    packetList.add(rtpPacket);
                                    rtpUpdate.put(rtpPacket.ssrc,System.currentTimeMillis());
//                                rtpMap.get(rtpPacket.ssrc)
//                                if (rtpMap.get(rtpPacket.ssrc))
                                }
                            }
                        }

                    }
                }
            }
        });

    }

    public void close(){
        cleanTimer.cancel();
        dealPool.shutdown();
    }

    public HashMap<String, List<RtpPacket>> getRtpMap() {
        return rtpMap;
    }

    public long getSaveLimit() {
        return saveLimit;
    }

    public void setSaveLimit(long saveLimit) {
        this.saveLimit = saveLimit;
    }

    public interface SaveRTPCallback{
        void saveEvent(String srcMac,String destMac,byte[] waveData);
    }
    public interface FindRTPCallback {
        void findRTP(String srcMac,String destMac,String ssrc);
    }
}
