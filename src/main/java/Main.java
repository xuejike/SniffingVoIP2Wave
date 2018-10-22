import com.github.xuejike.rtp.RtpAnalysis;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;

import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeoutException;

/**
 * @author xuejike
 */
public class Main {

    protected static Packet nextPacket;
    protected static Packet payload;

    public static void   main(String [] args) throws PcapNativeException, NotOpenException, InterruptedException, IOException, TimeoutException {
        byte[] bytes = {0, 1, 2, 3};
        byte[] bytes1 = Arrays.copyOfRange(bytes, 1, 3);
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        PcapNetworkInterface nif = Pcaps.getDevByName(allDevs.get(2).getName());
// 抓取包长度
        int snaplen = 64 * 1024;
        // 超时50ms
        int timeout = 50;
        // 初始化抓包器
        PcapHandle.Builder phb = new PcapHandle.Builder(nif.getName()).snaplen(snaplen)
                .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS).timeoutMillis(timeout)
                .bufferSize(1 * 1024 * 1024);
        PcapHandle handle = phb.build();
        handle = nif.openLive(snaplen, PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, timeout);
//
//        /** 设置TCP过滤规则 */
        String filter = "udp";
//
//        // 设置过滤器
        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
        RtpAnalysis rtpAnalysis = new RtpAnalysis();
        SimpleDateFormat format = new SimpleDateFormat("hh:mm:ss");
        rtpAnalysis.setSaveRTPCallback(new RtpAnalysis.SaveRTPCallback() {
            @Override
            public void saveEvent(String srcMac, String destMac, byte[] waveData) {
                File file = new File("./" + srcMac + "-" + destMac + "-" + format.format(new Date()) + ".wav");

                if (!file.exists()){
                    try {
                        file.createNewFile();
                        System.out.println("save ->"+file.getName());
                        FileOutputStream stream = new FileOutputStream(file);
                        stream.write(waveData);
                        stream.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        });
        rtpAnalysis.setCheckRTPCallback(new RtpAnalysis.CheckRTPCallback() {
            @Override
            public void findRTP(String srcMac, String destMac, String ssrc) {
                System.out.println("find -> "+srcMac+"->"+destMac+":"+ssrc);
            }
        });
        PcapHandle finalHandle = handle;
        new Thread(()->{
            do {

                try {
                    payload=nextPacket = finalHandle.getNextPacketEx();
                } catch (Exception e) {
//                    e.printStackTrace();
                }
                rtpAnalysis.read(payload);

            }while (nextPacket !=null);
        }).start();
        Thread.sleep(1000*60*60*24);


//        fileOutputStream.close();

    }



}
