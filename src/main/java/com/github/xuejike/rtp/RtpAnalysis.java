package com.github.xuejike.rtp;

import com.github.xuejike.unsigned.number.UShort;
import org.pcap4j.packet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * @author xuejike
 */
public class RtpAnalysis {
    private static Logger logger= LoggerFactory.getLogger(RtpAnalysis.class);
    protected ExecutorService dealPool;
    protected Timer cleanTimer=new Timer(true);
    /**
     * SSRC Map
     */
    protected Map<String, List<RtpPacket>> rtpMap=new ConcurrentHashMap<>();
    protected Map<String,String> macRTPMap=new ConcurrentHashMap<>();
    protected Map<String,Long> rtpUpdate = new ConcurrentHashMap<>();
    protected List<String> cleanKey=new ArrayList<>(10);

    protected Map<String,SaveInfo> saveKeyList = new ConcurrentHashMap<>(20);

    protected SaveRTPCallback saveRTPCallback= (srcMac, destMac, waveData) -> {
        logger.info("saveEvent : {}->{}",srcMac,destMac);
    };

    protected FindRTPCallback findRTPCallback = (srcMac, destMac, ssrc) -> {
        logger.info("findNewEvent : {}->{} ={}",srcMac,destMac,ssrc);
    };
    protected long saveLimit=1000*60*60*10;

    public RtpAnalysis(int threadPoolSize) {
        dealPool= Executors.newFixedThreadPool(threadPoolSize);
        //3秒执行一次
        cleanTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                saveListToFile();
                cleanDataMap();

            }
        },1000*3,1000*3);

    }

    private void saveListToFile() {
        logger.info("=========当前数据============");
        for (Map.Entry<String, List<RtpPacket>> entry : rtpMap.entrySet()) {
            logger.info("SSRC=>{},size=>{}",entry.getKey(),entry.getValue().size());
        }

        logger.info("=========end============");
//        logger.info("========执行数据保存=========");
//        List<SaveInfo> cacheList = saveKeyList;
//        saveKeyList = new Vector<>(20);
//        int saveCount = 0;
//        for (SaveInfo item : cacheList) {
//            saveCount = saveMp3(item);
//
//        }
//        logger.info("保存数据{}条",saveCount);
//        logger.info("========执行完成=========");
    }

    public int saveMp3(SaveInfo item) {

        byte[] saveRTP = checkSaveRTP(item);
        if (saveRTP.length > 0){
            PCMHelper.pcm2Mp3(saveRTP,item.getFile());
            logger.info("保存数据:客户端={},mac={},file={}",item.getNo(),item.getMac(),item.getFile());

            saveKeyList.remove(item.getSrcSSRC());
        }else{
            logger.info("保存失败:mac:{}",item.getMac());
        }
        return 0;
    }

    private void cleanDataMap() {

        logger.info("========无效缓存数据清理({})=========",rtpUpdate.size());
        for (Map.Entry<String, Long> entry : rtpUpdate.entrySet()) {
            // 超过10分钟 清空数据
            if ((System.currentTimeMillis()-entry.getValue()) > saveLimit){
                String key = entry.getKey();
                cleanKey.add(key);
            }
        }

        cleanKey.forEach(k->{
            SaveInfo info = saveKeyList.remove(k);
            logger.info("===丢失保存数据===");
            saveMp3(info);
        });

        cleanKey.forEach(k-> {
            rtpUpdate.remove(k);
            List<RtpPacket> remove = rtpMap.remove(k);
            Optional.ofNullable(remove)
                    .flatMap(list-> list.stream().findFirst())
                    .ifPresent(item->{
                        logger.info("清理:destIp={},destMac={},srcIp={},srcMac={},ssrc={}"
                                ,item.getDestIp(),item.getDestMac(),item.getSrcIp()
                                ,item.getSrcMac(),item.getSsrc());
                    });
        });


        cleanKey.clear();
        logger.info("========清理完成({})=========",rtpUpdate.size());

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
     * @param item
     */
    public byte[] checkSaveRTP(SaveInfo item) {


        List<RtpPacket> srcList = rtpMap.remove(item.getSrcSSRC());
        logger.info("checkSave=>Src:{}=>{}",item.getSrcSSRC(),Optional
                .ofNullable(srcList)
                .map(List::size).orElse(0));
        List<RtpPacket> destList = rtpMap.remove(item.getDestSSRC());
        logger.info("checkSave=>Dest:{}=>{}",item.getDestSSRC(),Optional
                .ofNullable(destList)
                .map(List::size).orElse(0));
        if (srcList !=null && srcList.size()>0 && destList != null && destList.size() > 0){
            return saveRtpDouble(srcList, destList);
        }
        byte[] rs = Optional.ofNullable(srcList)
                .filter(l->l.size()>0)
                .map(this::saveRtp).orElseGet(()-> Optional.ofNullable(destList)
                        .filter(l -> l.size() > 0)
                        .map(this::saveRtp).orElse(new byte[0]));
        return rs;
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
    private byte[] saveRtp(List<RtpPacket> rtpPackets) {
        RtpPacket rtpPacket = rtpPackets.get(0);
        byte[] baos = getRtpDataArray(rtpPackets);
        byte[] wave = PCMHelper.PCM2Wave(baos, 1, 8000, 8);
        return wave;
    }

    /**
     * 获取RTP数据集
     * @param rtpPackets
     * @return
     */
    private byte[] getRtpDataArray(List<RtpPacket> rtpPackets) {
        Collections.sort(rtpPackets);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        rtpPackets.stream().findFirst().ifPresent(f->{
            UShort lastSeq = f.seq;
            for (RtpPacket packet : rtpPackets) {
                try {
                    if (packet.seq.intValue() > lastSeq.intValue()+1){
                        for (int i = lastSeq.intValue()+1; i < packet.seq.intValue(); i++) {
                            baos.write(new byte[packet.payload.length]);
                        }
                    }
                    baos.write(packet.payload);
                    lastSeq = packet.seq;
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });

        return baos.toByteArray();
    }

    /**
     * 保存双通道
     * @param rtpPackets1
     * @param rtpPackets2
     */
    private byte[] saveRtpDouble(List<RtpPacket> rtpPackets1, List<RtpPacket> rtpPackets2) {
        if (rtpPackets1 != null || rtpPackets2 != null){
            if (rtpPackets1 ==null){
                saveRtp(rtpPackets2);
                return new byte[0];
            }
            if (rtpPackets2 == null){
                saveRtp(rtpPackets1);
                return new byte[0];
            }
            byte[] rtpArray1 = getRtpDataArray(rtpPackets1);
            byte[] rtpArray2 = getRtpDataArray(rtpPackets2);
            try {
                byte[] mergeRtp = mergeRtp(rtpArray1, rtpArray2);
                byte[] pcm2Wave = PCMHelper.PCM2Wave(mergeRtp, 2, 8000, 8);
                return pcm2Wave;
            } catch (IOException e) {
                logger.error("抓包保存失败",e);
            }
        }

        return new byte[0];
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

                                    findRTPCallback.findRTP(srcMacAddr,dstMacAddr,rtpPacket.ssrc);
                                    macRTPMap.put(srcMacAddr,rtpPacket.ssrc);
                                    List<RtpPacket> packetList = rtpMap.computeIfAbsent(rtpPacket.ssrc,k->{
                                        logger.info("新增SSRC=>{},srcMac=>{},destMac={}"
                                                ,k,rtpPacket.getSrcMac(),rtpPacket.getDestMac());
                                        return new Vector<>();
                                    });
                                    packetList.add(rtpPacket);
                                    rtpUpdate.put(rtpPacket.ssrc,System.currentTimeMillis());
//
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

    public Map<String, List<RtpPacket>> getRtpMap() {
        return rtpMap;
    }

    public long getSaveLimit() {
        return saveLimit;
    }

    public void setSaveLimit(long saveLimit) {
        this.saveLimit = saveLimit;
    }

    public void addSaveKeyItem(SaveInfo saveInfo) {

        String srcSSRC = macRTPMap.get(saveInfo.getMac());

        if (srcSSRC == null){
            logger.error("无法获取到SSRC:mac={}",saveInfo.getMac());
        }else{
            saveInfo.setSrcSSRC(srcSSRC);
            List<RtpPacket> destPacket = rtpMap.get(srcSSRC);
            if (destPacket !=null && destPacket.size() >0){
                String destMac = destPacket.get(0).getDestMac();
                if (destMac != null){
                    saveInfo.setDestSSRC(macRTPMap.getOrDefault(destMac,"-"));
                }else{
                    saveInfo.setDestSSRC("-");
                }
            }else{
                logger.error("无法获取到录音数据包:mac:{}",saveInfo.getMac());
            }
//            saveMp3(saveInfo);
            saveKeyList.put(srcSSRC,saveInfo);

        }

    }
}
