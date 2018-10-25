import com.github.xuejike.rtp.RtpAnalysis;
import com.github.xuejike.rtp.RtpSniffing;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.factory.StaticUdpPortPacketFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;

/**
 * @author xuejike
 */
public class Main {

    protected static Packet nextPacket;
    protected static Packet payload;

    public static void   smain(String [] args) throws PcapNativeException, NotOpenException, InterruptedException, IOException, TimeoutException, IllegalRawDataException, UnirestException {
//        byte[] bytes = {0, 1, 2, 3};
//        byte[] bytes1 = Arrays.copyOfRange(bytes, 1, 3);
//        RtpSniffing rtpSniffing = new RtpSniffing(new RtpAnalysis());
//        rtpSniffing.start("192.168.1.155");
//        Thread.sleep(1000*60*60*24);


//        fileOutputStream.close();
        InetAddress addr = InetAddress.getByName("192.168.1.155");

        PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
        int snaplen = 64 * 1024;
        // 超时50ms
        int timeout = 50;
        // 初始化抓包器

        PcapHandle handle = nif.openLive(snaplen, PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, timeout);
//
        PcapHandle offline = Pcaps.openOffline("D:\\winsys\\Desktop\\t (1).cap");
        while (true){
            Packet udpPacket = offline.getNextPacket();

            if (udpPacket !=null){
                EthernetPacket packets = EthernetPacket.newPacket(udpPacket.getRawData(), 0, udpPacket.length());
//                System.out.println(packets);
                HttpResponse<String> response = Unirest.post("http://127.0.0.1:8080/rtpTest")
                        .body(udpPacket.getRawData()).asString();
                System.out.println(response.getBody());
                Thread.sleep(5);
            }else{
                offline = Pcaps.openOffline("D:\\winsys\\Desktop\\t (1).cap");

            }



        }
//

    }



}
