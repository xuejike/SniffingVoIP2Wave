package com.github.xuejike.rtp;
import	java.io.File;

import com.github.xuejike.unsigned.number.UShort;
import org.apache.commons.codec.Charsets;
import org.apache.commons.io.FileUtils;
import org.pcap4j.packet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * @author xuejike
 */
public class RtpAnalysis {

    public static final String TEMP_PATH = "./temp/";
    private static Logger logger= LoggerFactory.getLogger(RtpAnalysis.class);
    private KCache kCache = new KCache();
    protected ExecutorService dealPool;
    protected Timer cleanTimer=new Timer(true);
    /**
     * SSRC Map
     */
    protected Map<String, List<RtpPacket>> rtpMap=new ConcurrentHashMap<>();

    Vector<MacMappingSSRC> macMappingList = new Vector<>();
    /**
     * SSRC update
     */
    protected Map<String,Long> rtpUpdate = new ConcurrentHashMap<>();
    protected List<String> cleanKey=new ArrayList<>(10);

    protected Map<String,SaveInfo> saveKeyList = new ConcurrentHashMap<>(20);




    protected SaveRTPCallback saveRTPCallback= (srcMac, destMac, waveData) -> {
        logger.info("saveEvent : {}->{}",srcMac,destMac);
    };

    protected FindRTPCallback findRTPCallback = (srcMac, destMac, ssrc) -> {
        logger.info("findNewEvent : {}->{} ={}",srcMac,destMac,ssrc);
    };
    protected long saveLimit=1000*60*3;
    private long cleanMacLimit = 1000*60*60*3;
    private Map<String, String> srcMacRTPMap = new ConcurrentHashMap<>();

    public RtpAnalysis(int threadPoolSize) {
        dealPool= Executors.newFixedThreadPool(threadPoolSize);
        cleanTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                logger.info("清理磁盘");
                File file = new File(TEMP_PATH);
                for (File pFile : file.listFiles()) {
                    if (pFile.isDirectory()){
                        try {
                            Arrays.stream(pFile.listFiles())
                                    .filter(f-> System.currentTimeMillis()-f.lastModified()>1000*60*60)
                                    .forEach(File::delete);
                        }catch (Exception e ){

                        }

                    }
                }
            }
        }, 1000, 1000 * 60 * 60);
    }


    public RtpAnalysis() {
        this(5);
    }

    public void setSaveRTPCallback(SaveRTPCallback saveRTPCallback) {
        this.saveRTPCallback = saveRTPCallback;
    }

    public void setFindRTPCallback(FindRTPCallback findRTPCallback) {
        this.findRTPCallback = findRTPCallback;
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
                        //补充空白字符,弥补丢失数据
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
    private byte[] saveRtpDouble (List<RtpPacket> rtpPackets1, List<RtpPacket> rtpPackets2) {
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


    //读取 RTP包,并自动关联双向语音


    private KCache rtpDataSaveCache = new KCache();
    public static final int SAVE_LIMIT = 1;


    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd_HH_mm_ss");
    //临时文件存储目录  /src-mac&port/时间
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
                        int srcPort = udpHeader.getSrcPort().valueAsInt();
                        int destPort = udpHeader.getDstPort().valueAsInt();
                        if (destPort %2 == 0 && srcPort % 2 == 0){
                            if (udpPacket.getPayload() instanceof UnknownPacket){
                                UnknownPacket payload = (UnknownPacket) udpPacket.getPayload();
                                if (payload.getRawData()[0] == (byte) 0x80){

                                    String srcIpAddr = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
                                    String dstIpAddr = ipV4Packet.getHeader().getDstAddr().getHostAddress();
                                    String dstMacAddr = header.getDstAddr().toString().replaceAll(":","-")+"&"+destPort;
                                    String srcMacAddr = header.getSrcAddr().toString().replaceAll(":","-")+"&"+srcPort;
                                    RtpPacket rtpPacket = new RtpPacket(payload.getRawData(), dstIpAddr, srcIpAddr, srcMacAddr, dstMacAddr);
                                    logger.info("更新映射关系 {} -> {}",srcMacAddr,dstMacAddr);

                                    addRTPCacheSave(srcMacAddr, rtpPacket);
                                    String[] srcMacPort = srcMacAddr.split("&");
                                    //记录映射关系 保存10分钟
                                    rtpDataSaveCache.put("map_"+srcMacAddr,dstMacAddr,20L);
                                    rtpDataSaveCache.put("src_"+srcMacPort[0],srcMacAddr,20L);

                                    findRTPCallback.findRTP(srcMacAddr,dstIpAddr,rtpPacket.ssrc);
                                }
                            }
                        }

                    }
                }
            }
        });

    }

    private void addRTPCacheSave(String srcMacAddr, RtpPacket rtpPacket) {
//        logger.info("add-save-cache -> {}",srcMacAddr);
        KCache.KCacheItem<Vector<RtpPacket>> cacheItem = rtpDataSaveCache
                .putOrGet(srcMacAddr, new Vector<RtpPacket>(),SAVE_LIMIT);
        cacheItem.getValue().add(rtpPacket);
        String[] macs = srcMacAddr.split("&");
        if (cacheItem.getClearCallBack() == null) {
            String path = TEMP_PATH + macs[0];
            if(!new File(path).exists()){
                new File(path).mkdirs();
            }
            String file =path+"/"+dateFormat.format(new Date())+"@"+macs[1]+"@"+System.currentTimeMillis()+".rtp";

            cacheItem.setClearCallBack(d->{
                byte[] saveRtp = getRtpDataArray(d);
                try {
                    logger.info("cache->save:{}",file);
                    new File(file).createNewFile();
                    FileUtils.writeByteArrayToFile(new File(file),saveRtp);
                } catch (IOException e) {
                    logger.error("录音定时保存失败",e);
                }
            });
        }
    }

    public void close(){
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

    public long getCleanMacLimit() {
        return cleanMacLimit;
    }

    public void setCleanMacLimit(long cleanMacLimit) {
        this.cleanMacLimit = cleanMacLimit;
    }


    public void saveFile(String srcMac, String destMac,  Long begin, Long end ,String file) throws IOException {
        new File(file).createNewFile();
        String[] srcMacs = srcMac.split("&");
        String[] destMacs = destMac.split("&");
        File srcDir = new File(TEMP_PATH + srcMacs[0]);
        File destDir = new File(TEMP_PATH + destMacs[0]);
        final String srcPort = "@" + srcMacs[1] + "@";
        final String destPort = "@" + destMacs[1] + "@";
        long rcBegin = begin - SAVE_LIMIT * 1000;
        long rcEnd = end + SAVE_LIMIT*1000;
        List<FileItem> srcFileList = getMacFiles(srcDir, srcPort, rcBegin,rcEnd);
        List<FileItem> destFileList = getMacFiles(destDir, destPort, rcBegin,rcEnd);

        StringBuilder logSb = new StringBuilder();
        String br = "\r\n";
        logSb.append("mac:")
                .append(srcMac)
                .append(" => ")
                .append(destMac)
                .append(br)
                .append("beginTime => ")
                .append(begin).append(br)
                .append("1->").append(br)
                .append(srcFileList.stream()
                        .map(fileItem -> fileItem.file.getName())
                        .collect(Collectors.joining(br)))
                .append(br)
                .append("2->").append(br)
                .append(destFileList.stream()
                        .map(fileItem -> fileItem.file.getName())
                        .collect(Collectors.joining(br)));
        FileUtils.write(new File(file+".log"),logSb.toString(), Charsets.UTF_8);
        byte[] srcArray = mergeFile2Bytes(srcFileList);
        byte[] destArray = mergeFile2Bytes(destFileList);
        byte[] pcm2Wave = new byte [0];
        if (srcArray.length == 0){
            pcm2Wave = PCMHelper.PCM2Wave(destArray, 1, 8000, 8);
        } else if (destArray.length == 0){
            pcm2Wave = PCMHelper.PCM2Wave(srcArray, 1, 8000, 8);
        }else{
            byte[] mergeRtp = mergeRtp(srcArray, destArray);
            pcm2Wave = PCMHelper.PCM2Wave(mergeRtp, 2, 8000, 8);
        }


        PCMHelper.wav2Mp3(pcm2Wave,file);
        //删除已合并数据
//        destFileList.forEach(it->{
//            it.file.delete();
//        });
//        srcFileList.forEach(it->{
//            it.file.delete();
//        });
    }

    private byte[] mergeFile2Bytes(List<FileItem> fileList) {
        List<byte[]> srcByteList = fileList.stream().map(f -> {
            try {
                return FileUtils.readFileToByteArray(f.file);
            } catch (IOException e) {
                return new byte[0];
            }
        }).collect(Collectors.toList());
        int srcLen = srcByteList.stream().mapToInt(b -> b.length).sum();
        ByteArrayOutputStream stream = new ByteArrayOutputStream(srcLen);

        srcByteList.forEach(d->{
            try {
                stream.write(d);
            } catch (IOException e) {
                e.printStackTrace();
            }

        });
        return stream.toByteArray();
    }
    public String[] getAllMacs(String clientMac){
        String lowMac = clientMac.toLowerCase();
        String macPort = rtpDataSaveCache.get("src_" + lowMac);
        if (macPort == null) {
            logger.info("getAllMacs({}) --> null",lowMac);
            return new String []{"",""};
        }
        String destMac = rtpDataSaveCache.get("map_"+macPort);
        return new String[]{macPort,destMac};
    }
    private List<FileItem> getMacFiles(File srcDir, String srcPort, long rcBegin, long rcEnd) {
        return Optional.ofNullable(srcDir.listFiles((dir, name)
                -> name.contains(srcPort)))
                .map(ls -> {
                    AtomicReference<Long> lastTime = new AtomicReference<>(rcBegin);
                    List<FileItem> list = Arrays.stream(ls)
                            .map(FileItem::new)
                            .sorted()
                            .filter(f -> {
                                if (f.time > rcBegin && f.time < rcEnd ){
                                    return true;
                                }
                                return false;
                            })
                            .collect(Collectors.toList());
                    return list;
                }).orElse(new LinkedList<>());
    }

    public static class FileItem implements Comparable{
        private File file;
        private Long time;

        public FileItem(File file, Long time) {
            this.file = file;
            this.time = time;
        }

        public FileItem(File file) {
            this.file = file;
            String[] split = file.getName().split("@");
            String t = split[split.length - 1].replace(".rtp", "");
            this.time = Long.parseLong(t);
        }


        @Override
        public int compareTo(Object o) {
            return Math.toIntExact(this.time - ((FileItem) o).time);
        }
    }
}
